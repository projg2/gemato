# gemato: Recursive loader for Manifests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import os.path

import gemato.compression
import gemato.exceptions
import gemato.manifest
import gemato.util
import gemato.verify


class ManifestRecursiveLoader(object):
    """
    A class encapsulating a tree covered by multiple Manifests.
    Automatically verifies and loads additional sub-Manifests,
    and provides methods to access the entries in them.
    """

    def __init__(self, top_manifest_path):
        """
        Instantiate the loader for a Manifest tree starting at top-level
        Manifest @top_manifest_path.
        """
        self.root_directory = os.path.dirname(top_manifest_path)
        self.loaded_manifests = {}
        self.load_manifest(os.path.basename(top_manifest_path))

    def load_manifest(self, relpath, verify_entry=None):
        """
        Load a single Manifest file whose relative path within Manifest
        tree is @relpath. If @verify_entry is not null, the Manifest
        file is verified against the entry. If the file is compressed,
        it is decompressed transparently.
        """
        m = gemato.manifest.ManifestFile()
        path = os.path.join(self.root_directory, relpath)
        if verify_entry is not None:
            ret, diff = gemato.verify.verify_path(path, verify_entry)
            if not ret:
                raise gemato.exceptions.ManifestMismatch(
                        relpath, verify_entry, diff)
        with gemato.compression.open_potentially_compressed_path(
                path, 'r', encoding='utf8') as f:
            m.load(f)
            st = os.fstat(f.fileno())
            self.manifest_device = st.st_dev
        self.loaded_manifests[relpath] = m

    def _iter_manifests_for_path(self, path, recursive=False):
        """
        Iterate over loaded Manifests that can apply to path.
        If @recursive is True, returns also Manifests for subdirectories
        of @path. Yields a tuple of (relative_path, manifest).
        """
        for k, v in self.loaded_manifests.items():
            d = os.path.dirname(k)
            if gemato.util.path_starts_with(path, d):
                yield (d, v)
            elif recursive and gemato.util.path_starts_with(d, path):
                yield (d, v)

    def load_manifests_for_path(self, path, recursive=False):
        """
        Load all Manifests that may apply to the specified path,
        recursively. If @recursive is True, also loads Manifests
        for all subdirectories of @path.
        """
        # TODO: figure out how to avoid confusing uses of 'recursive'
        while True:
            to_load = []
            for relpath, m in self._iter_manifests_for_path(path, recursive):
                for e in m.entries:
                    if not isinstance(e, gemato.manifest.ManifestEntryMANIFEST):
                        continue
                    mpath = os.path.join(relpath, e.path)
                    if mpath in self.loaded_manifests:
                        continue
                    mdir = os.path.dirname(mpath)
                    if gemato.util.path_starts_with(path, mdir):
                        to_load.append((mpath, e))
                    elif recursive and gemato.util.path_starts_with(mdir, path):
                        to_load.append((mpath, e))
            if not to_load:
                break
            for mpath, e in to_load:
                self.load_manifest(mpath, e)

    def find_timestamp(self):
        """
        Find a timestamp entry and return it. Returns None if there
        is no timestamp.
        """

        self.load_manifests_for_path('')
        for p, m in self._iter_manifests_for_path(''):
            for e in m.entries:
                if isinstance(e, gemato.manifest.ManifestEntryTIMESTAMP):
                    return e
        return None

    def find_path_entry(self, path):
        """
        Find a matching entry for path @path and return it. Returns
        None when no path matches. DIST entries are not included.
        """

        self.load_manifests_for_path(path)
        for relpath, m in self._iter_manifests_for_path(path):
            for e in m.entries:
                if isinstance(e, gemato.manifest.ManifestEntryIGNORE):
                    # ignore matches recursively, so we process it separately
                    # py<3.5 does not have os.path.commonpath()
                    fullpath = os.path.join(relpath, e.path)
                    if gemato.util.path_starts_with(path, fullpath):
                        return e
                elif isinstance(e, gemato.manifest.ManifestEntryDIST):
                    # distfiles are not local files, so skip them
                    pass
                elif isinstance(e, gemato.manifest.ManifestPathEntry):
                    fullpath = os.path.join(relpath, e.path)
                    if fullpath == path:
                        return e
        return None

    def verify_path(self, relpath):
        """
        Verify the path @relpath against appropriate Manifest entry.
        If there is no matching entry, verification fails (as a stray
        file). Returns result as verify_path().
        """
        real_path = os.path.join(self.root_directory, relpath)
        path_entry = self.find_path_entry(relpath)
        return gemato.verify.verify_path(real_path, path_entry)

    def assert_path_verifies(self, relpath):
        """
        Verify the path @relpath against appropriate Manifest entry.
        If there is no matching entry, verification fails (as a stray
        file). Raises exception for failed verification.
        """
        real_path = os.path.join(self.root_directory, relpath)
        path_entry = self.find_path_entry(relpath)
        ret, diff = gemato.verify.verify_path(real_path, path_entry,
                expected_dev=self.manifest_device)
        if not ret:
            raise gemato.exceptions.ManifestMismatch(
                    relpath, path_entry, diff)

    def find_dist_entry(self, filename, relpath=''):
        """
        Find a matching entry for distfile @filename and return it.
        If @relpath is provided, loads all Manifests up to @relpath
        (which can be e.g. a relevant package directory).
        Returns None when no DIST entry matches.
        """

        self.load_manifests_for_path(relpath+'/')
        for p, m in self._iter_manifests_for_path(relpath+'/'):
            for e in m.entries:
                if isinstance(e, gemato.manifest.ManifestEntryDIST):
                    if e.path == filename:
                        return e
        return None

    def get_file_entry_dict(self, path=''):
        """
        Find all file entries that apply to paths starting with @path.
        Return a dictionary mapping relative paths to entries. Raises
        an exception if multiple entries for file collide.
        """

        self.load_manifests_for_path(path, recursive=True)
        out = {}
        for relpath, m in self._iter_manifests_for_path(path, recursive=True):
            for e in m.entries:
                if isinstance(e, gemato.manifest.ManifestEntryDIST):
                    # distfiles are not local files, so skip them
                    pass
                elif isinstance(e, gemato.manifest.ManifestPathEntry):
                    fullpath = os.path.join(relpath, e.path)
                    if gemato.util.path_starts_with(fullpath, path):
                        if fullpath in out:
                            # compare the two entries
                            ret, diff = gemato.verify.verify_entry_compatibility(
                                    out[fullpath], e)
                            if not ret:
                                raise gemato.exceptions.ManifestIncompatibleEntry(out[fullpath], e, diff)
                            # we need to construct a single entry with both checksums
                            if diff:
                                new_checksums = dict(e.checksums)
                                for k, d1, d2 in diff:
                                    if d2 is None:
                                        new_checksums[k] = d1
                                e = type(e)(e.path, e.size, new_checksums)
                        out[fullpath] = e
        return out

    def _verify_one_file(self, path, relpath, e, fail_handler, warn_handler):
        ret, diff = gemato.verify.verify_path(path, e,
                expected_dev=self.manifest_device)

        if not ret:
            if (isinstance(e, gemato.manifest.ManifestEntryOPTIONAL)
                    or isinstance(e, gemato.manifest.ManifestEntryMISC)):
                h = warn_handler
            else:
                h = fail_handler
            err = gemato.exceptions.ManifestMismatch(relpath, e, diff)
            ret = h(err)
            if ret is None:
                ret = True

        return ret

    def assert_directory_verifies(self, path='',
            fail_handler=gemato.util.throw_exception,
            warn_handler=None):
        """
        Verify the complete directory tree starting at @path (relative
        to top Manifest directory). Includes testing for stray files.
        Raises an exception if any of the files does not pass
        verification.

        @fail_handler is the callback called whenever verification
        fails for 'strong' entries (or stray files). @warn_handler
        is called whenever verification fails for MISC/OPTIONAL entries.

        The handlers are passed a ManifestMismatch exception object.
        The default fail handler raises the exception. Unless specified
        explicitly, the warn handler defaults to fail handler. However,
        custom handlers can be used to provide a non-strict mode,
        or continue the scan after the first failure.

        If none of the handlers raise exceptions, the function returns
        boolean. It returns False if at least one of the handler calls
        returned explicit False; True otherwise.
        """

        entry_dict = self.get_file_entry_dict(path)
        it = os.walk(os.path.join(self.root_directory, path),
                onerror=gemato.util.throw_exception,
                followlinks=True)
        ret = True

        if warn_handler is None:
            warn_handler = fail_handler

        for dirpath, dirnames, filenames in it:
            relpath = os.path.relpath(dirpath, self.root_directory)
            # strip dot to avoid matching problems
            if relpath == '.':
                relpath = ''

            skip_dirs = []
            for d in dirnames:
                # skip dotfiles
                if d.startswith('.'):
                    skip_dirs.append(d)
                    continue

                dpath = os.path.join(relpath, d)
                de = entry_dict.pop(dpath, None)
                if de is None:
                    syspath = os.path.join(dirpath, d)
                    st = os.stat(syspath)
                    if st.st_dev != self.manifest_device:
                        raise gemato.exceptions.ManifestCrossDevice(syspath)
                    continue

                if isinstance(de, gemato.manifest.ManifestEntryIGNORE):
                    skip_dirs.append(d)
                else:
                    ret &= self._verify_one_file(os.path.join(dirpath, d),
                            dpath, de, fail_handler, warn_handler)

            # skip scanning ignored directories
            for d in skip_dirs:
                dirnames.remove(d)

            for f in filenames:
                # skip dotfiles
                if f.startswith('.'):
                    continue

                fpath = os.path.join(relpath, f)
                # skip top-level Manifest, we obviously can't have
                # an entry for it
                if fpath in (gemato.compression
                        .get_potential_compressed_names('Manifest')):
                    continue
                fe = entry_dict.pop(fpath, None)
                ret &= self._verify_one_file(os.path.join(dirpath, f),
                        fpath, fe, fail_handler, warn_handler)

        # check for missing files
        for relpath, e in entry_dict.items():
            syspath = os.path.join(self.root_directory, relpath)
            ret &= self._verify_one_file(syspath, relpath, e,
                            fail_handler, warn_handler)

        return ret
