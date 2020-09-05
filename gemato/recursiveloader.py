# gemato: Recursive loader for Manifests
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import os.path

from gemato.compression import (
    open_potentially_compressed_path,
    get_potential_compressed_names,
    get_compressed_suffix_from_filename,
    InvalidCompressedFileExceptions,
    )
from gemato.exceptions import (
    ManifestMismatch,
    ManifestIncompatibleEntry,
    ManifestCrossDevice,
    ManifestSymlinkLoop,
    ManifestInvalidPath,
    ManifestSyntaxError,
    )
from gemato.manifest import (
    ManifestFile,
    ManifestEntryIGNORE,
    ManifestEntryTIMESTAMP,
    new_manifest_entry,
    ManifestEntryMANIFEST,
    )
from gemato.profile import DefaultProfile
from gemato.util import (
    path_starts_with,
    MultiprocessingPoolWrapper,
    throw_exception,
    path_inside_dir,
    )
from gemato.verify import (
    verify_path,
    verify_entry_compatibility,
    update_entry_for_path,
    )


class ManifestLoader:
    """
    Helper class to load Manifests in subprocesses.
    """

    __slots__ = ['root_directory', 'verify_openpgp', 'openpgp_env']

    def __init__(self, root_directory, verify_openpgp, openpgp_env):
        """
        @root_directory specifies top directory of Manifest tree.

        If @verify_openpgp is True and a Manifest contain an OpenPGP
        signature, the signature will be verified. @openpgp_env
        is the OpenPGP environment to use.
        """
        self.root_directory = root_directory
        self.verify_openpgp = verify_openpgp
        self.openpgp_env = openpgp_env

    def verify_and_load(self, relpath, verify_entry=None):
        """
        Load the Manifest from file @relpath (relative to
        root_directory). If the file is compressed, it is decompressed
        transparently.

        If @verify_entry is not None, the Manifest file is verified
        against the entry. If the verification fails, ManifestMismatch
        exception is raised.

        Returns a tuple of (ManifestFile instance, file stat result).
        """
        m = ManifestFile()
        path = os.path.join(self.root_directory, relpath)

        if verify_entry is not None:
            ret, diff = verify_path(path, verify_entry)
            if not ret:
                raise ManifestMismatch(relpath, verify_entry, diff)

        with open_potentially_compressed_path(path, 'r',
                                              encoding='utf8') as f:
            m.load(f, self.verify_openpgp, self.openpgp_env)
            st = os.fstat(f.fileno())

        return m, st

    def __call__(self, args):
        """
        Load the Manifest file by passing @args to verify_and_load()
        method. @args should be an iterable specifying the file relative
        path and verification entry (or None).

        Returns a tuple of (relpath, ManifestFile instance).

        Intended to be used via multiprocessing.Pool.map().
        """
        return (args[0], self.verify_and_load(*args)[0])


class SubprocessVerifier:
    """
    Helper class used to verify directories in subprocesses.
    """

    __slots__ = ['top_level_manifest_filename',
                 'manifest_device', 'fail_handler', 'last_mtime']

    def __init__(self, top_level_manifest_filename,
                 manifest_device, fail_handler, last_mtime):
        self.top_level_manifest_filename = top_level_manifest_filename
        self.manifest_device = manifest_device
        self.fail_handler = fail_handler
        self.last_mtime = last_mtime

    def _verify_one_file(self, path, relpath, e):
        ret, diff = verify_path(path, e,
                                expected_dev=self.manifest_device,
                                last_mtime=self.last_mtime)

        if not ret:
            err = ManifestMismatch(relpath, e, diff)
            ret = self.fail_handler(err)
            if ret is None:
                ret = True

        return ret

    def __call__(self, vals):
        """
        Verify the specified directory and return the boolean value
        (or raise an exception).
        """

        ret = True
        dirpath, relpath, dirnames, filenames, dirdict = vals

        for d in dirnames:
            # we already stripped ignored directories in walker,
            # so go straight for verification
            de = dirdict.pop(d, None)
            if de is not None:
                dpath = os.path.join(relpath, d)
                ret &= self._verify_one_file(os.path.join(dirpath, d),
                                             dpath, de)

        for f in filenames:
            # skip dotfiles
            if f.startswith('.'):
                continue

            fpath = os.path.join(relpath, f)
            # skip top-level Manifest, we obviously can't have
            # an entry for it
            if fpath == self.top_level_manifest_filename:
                continue
            fe = dirdict.pop(f, None)
            ret &= self._verify_one_file(os.path.join(dirpath, f),
                                         fpath, fe)

        # check for missing files
        for f, e in dirdict.items():
            fpath = os.path.join(relpath, f)
            ret &= self._verify_one_file(os.path.join(dirpath, f),
                                         fpath, e)

        return ret


class ManifestRecursiveLoader:
    """
    A class encapsulating a tree covered by multiple Manifests.
    Automatically verifies and loads additional sub-Manifests,
    and provides methods to access the entries in them.
    """

    __slots__ = [
        # configuration properties
        'root_directory',
        'openpgp_env',
        'sign_openpgp',
        'openpgp_keyid',
        'hashes',
        'openpgp_signed',
        'openpgp_signature',
        'sort',
        'compress_watermark',
        'compress_format',
        'profile',
        # internal variables
        'manifest_loader',
        'top_level_manifest_filename',
        'loaded_manifests',
        'updated_manifests',
        'manifest_device',
        'max_jobs',
    ]

    def __init__(self,
                 top_manifest_path,
                 verify_openpgp=None,
                 openpgp_env=None,
                 sign_openpgp=None,
                 openpgp_keyid=None,
                 hashes=None,
                 allow_create=False,
                 sort=None,
                 compress_watermark=None,
                 compress_format=None,
                 profile=DefaultProfile(),
                 max_jobs=None,
                 allow_xdev=True,
                 ):
        """
        Instantiate the loader for a Manifest tree starting at top-level
        Manifest @top_manifest_path.

        @verify_openpgp and @openpgp_env are passed down
        to ManifestFile. If the top-level Manifest is OpenPGP-signed
        and the verification succeeds, openpgp_signed property
        is set to True and openpgp_signature will contain the signature
        data. @verify_openpgp is True by default.

        @sign_openpgp is passed down to ManifestFile when writing
        the top-level Manifest. If it is True, the top-level Manifest
        will be signed. If it is False, it will not be signed.
        If it is left as None, then it will be signed if it was
        originally signed. @openpgp_keyid can be used to select the key.

        Sub-Manifests are never signed.

        @hashes can be used to specify a default hash set
        for the Manifest. If it is specified, they will be used for all
        subsequent update*() calls that do not specify another set
        of hashes explicitly.

        If @allow_create is True and @top_manifest_path does not exist,
        a new Manifest tree will be initialized. Otherwise, opening
        a non-existing file will cause an exception.

        If @sort is True, the Manifest entries will be sorted prior
        to saving. By default they are not.

        If @compress_watermark is not None, then the uncompressed
        Manifest files whose size is larger than or equal to the value
        will be compressed using @compress_format. The Manifest files
        whose size is smaller will be uncompressed. To compress all
        Manifest files, pass a size of 0.

        If @compress_watermark is None, the compression is left as-is.
        The default @compress_format is 'gz'.

        @profile can be used to provide the profile for the repository.

        @max_jobs defines the number of subprocesses that can be spawned
        to optimize some operations. If None (the default), the number
        will automatically be determined based on CPU count. Otherwise,
        the specified number will be used.

        If @allow_xdev is true, Manifest can contain files located
        across different filesystem. If it is false, gemato will raise
        an exception upon crossing filesystem boundaries. It defaults
        to false.
        """

        self.root_directory = os.path.dirname(top_manifest_path)
        self.openpgp_env = openpgp_env
        self.sign_openpgp = sign_openpgp
        self.openpgp_keyid = openpgp_keyid
        self.hashes = hashes
        self.profile = profile
        self.sort = sort
        self.compress_watermark = compress_watermark
        self.compress_format = compress_format
        self.max_jobs = max_jobs

        self.profile.set_loader_options(self)

        if verify_openpgp is None:
            verify_openpgp = True
        if self.sort is None:
            self.sort = False
        if self.compress_format is None:
            self.compress_format = 'gz'

        self.manifest_loader = ManifestLoader(
            self.root_directory, verify_openpgp, self.openpgp_env)
        self.top_level_manifest_filename = os.path.basename(
            top_manifest_path)
        self.loaded_manifests = {}
        self.updated_manifests = set()
        self.manifest_device = None

        # TODO: allow catching OpenPGP exceptions somehow?
        m = self.load_manifest(self.top_level_manifest_filename,
                               allow_create=allow_create,
                               store_dev=not allow_xdev)
        self.openpgp_signed = m.openpgp_signed
        self.openpgp_signature = m.openpgp_signature

    def load_manifest(self,
                      relpath,
                      verify_entry=None,
                      allow_create=False,
                      store_dev=False,
                      ):
        """
        Load a single Manifest file whose relative path within Manifest
        tree is @relpath. If @verify_entry is not null, the Manifest
        file is verified against the entry. If the file is compressed,
        it is decompressed transparently.

        If @allow_create is True and the Manifest does not exist,
        a new Manifest will be added. Otherwise, opening a non-existing
        file will cause an exception.

        If @store_dev is True, the st_dev for this Manifest will
        be stored for cross-device checks. Defaults to false.
        """

        try:
            m, st = self.manifest_loader.verify_and_load(
                    relpath, verify_entry)
        except FileNotFoundError:
            if not allow_create:
                raise
            m = ManifestFile()
            path = os.path.join(self.root_directory, relpath)
            st = os.stat(os.path.dirname(path))
            # trigger saving
            self.updated_manifests.add(relpath)

            # add initial IGNORE entries to top-level Manifest
            if relpath == 'Manifest':
                for ip in (self.profile
                           .get_ignore_paths_for_new_manifest('')):
                    ie = ManifestEntryIGNORE(ip)
                    m.entries.append(ie)

        if store_dev:
            self.manifest_device = st.st_dev
        self.loaded_manifests[relpath] = m
        return m

    def save_manifest(self, relpath, sort=False):
        """
        Save a single Manifest file whose relative path within Manifest
        tree is @relpath. The Manifest must already be loaded.
        If the name indicates compression, it will be compressed
        transparently. If it was OpenPGP-signed, a new signature
        will be created.

        If @sort is True, the Manifest entries will be sorted prior
        to saving.

        Returns the uncompressed size of the Manifest (number
        of characters written).
        """
        m = self.loaded_manifests[relpath]
        path = os.path.join(self.root_directory, relpath)

        # is it top-level Manifest?
        if relpath == self.top_level_manifest_filename:
            sign = self.sign_openpgp
        else:
            sign = False

        with open_potentially_compressed_path(path, 'w',
                                              encoding='utf8') as f:
            m.dump(f,
                   sign_openpgp=sign,
                   sort=sort,
                   openpgp_env=self.openpgp_env,
                   openpgp_keyid=self.openpgp_keyid)
            f.flush()
            return f.buffer.tell()

    def _iter_unordered_manifests_for_path(self, path, recursive=False):
        """
        Iterate over loaded Manifests that can apply to path.
        If @recursive is True, returns also Manifests for subdirectories
        of @path. Yields a tuple of (manifest_path, dir_path, manifest).

        The entries will be returned in any order.
        """
        for k, v in self.loaded_manifests.items():
            d = os.path.dirname(k)
            if path_starts_with(path, d):
                yield (k, d, v)
            elif recursive and path_starts_with(d, path):
                yield (k, d, v)

    def _iter_manifests_for_path(self, path, recursive=False):
        """
        Iterate over loaded Manifests that can apply to path.
        If @recursive is True, returns also Manifests for subdirectories
        of @path. Yields a tuple of (manifest_path, dir_path, manifest).

        The function guarantees that the Manifests for subdirectories
        (more specific) will always be returned before the Manifests
        for parent directories. The order is otherwise undefined.
        """
        return sorted(
                self._iter_unordered_manifests_for_path(
                    path, recursive=recursive),
                key=lambda kdv: len(kdv[1]),
                reverse=True)

    def load_manifests_for_path(self, path, recursive=False, verify=True):
        """
        Load all Manifests that may apply to the specified path,
        recursively. If @recursive is True, also loads Manifests
        for all subdirectories of @path.

        If @verify is True, sub-Manifests will be tested against entries
        in parent Manifests and ManifestMismatch will be raised
        on mismatch. Otherwise, sub-Manifests will be loaded
        unconditionally of whether they match parent checksums.
        """

        with MultiprocessingPoolWrapper(self.max_jobs) as pool:
            # TODO: figure out how to avoid confusing uses of 'recursive'
            while True:
                to_load = []
                for curmpath, relpath, m in self._iter_manifests_for_path(
                                                path, recursive):
                    for e in m.entries:
                        if e.tag != 'MANIFEST':
                            continue
                        mpath = os.path.join(relpath, e.path)
                        if curmpath == mpath or mpath in self.loaded_manifests:
                            continue
                        mdir = os.path.dirname(mpath)
                        if not verify:
                            e = None
                        if path_starts_with(path, mdir):
                            to_load.append((mpath, e))
                        elif recursive and path_starts_with(mdir, path):
                            to_load.append((mpath, e))
                if not to_load:
                    break

                manifests = pool.imap_unordered(
                    self.manifest_loader, to_load, chunksize=16)
                self.loaded_manifests.update(manifests)

    def find_timestamp(self):
        """
        Find a timestamp entry and return it. Returns None if there
        is no timestamp.
        """

        self.load_manifests_for_path('')
        for mpath, p, m in self._iter_manifests_for_path(''):
            for e in m.entries:
                if e.tag == 'TIMESTAMP':
                    return e
        return None

    def set_timestamp(self, ts):
        """
        Set Manifest timestamp to @ts.

        If the Manifest already contains a TIMESTAMP entry, it will
        be updated. Otherwise, a new entry will be created.
        """

        e = self.find_timestamp()
        if e is not None:
            e.ts = ts
        else:
            m = self.loaded_manifests[self.top_level_manifest_filename]
            e = ManifestEntryTIMESTAMP(ts)
            m.entries.append(e)

    def find_path_entry(self, path):
        """
        Find a matching entry for path @path and return it. Returns
        None when no path matches. DIST entries are not included.
        """

        self.load_manifests_for_path(path)
        for mpath, relpath, m in self._iter_manifests_for_path(path):
            for e in m.entries:
                if e.tag == 'IGNORE':
                    # ignore matches recursively, so we process it separately
                    # py<3.5 does not have os.path.commonpath()
                    fullpath = os.path.join(relpath, e.path)
                    if path_starts_with(path, fullpath):
                        return e
                elif e.tag in ('DIST', 'TIMESTAMP'):
                    # distfiles are not local files, so skip them
                    # timestamp is not a file ;-)
                    pass
                else:
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
        return verify_path(real_path, path_entry)

    def assert_path_verifies(self, relpath):
        """
        Verify the path @relpath against appropriate Manifest entry.
        If there is no matching entry, verification fails (as a stray
        file). Raises exception for failed verification.
        """
        real_path = os.path.join(self.root_directory, relpath)
        path_entry = self.find_path_entry(relpath)
        ret, diff = verify_path(real_path, path_entry,
                                expected_dev=self.manifest_device)
        if not ret:
            raise ManifestMismatch(relpath, path_entry, diff)

    def find_dist_entry(self, filename, relpath=''):
        """
        Find a matching entry for distfile @filename and return it.
        If @relpath is provided, loads all Manifests up to @relpath
        (which can be e.g. a relevant package directory).
        Returns None when no DIST entry matches.
        """

        self.load_manifests_for_path(relpath+'/')
        for mpath, p, m in self._iter_manifests_for_path(relpath+'/'):
            for e in m.entries:
                if e.tag == 'DIST' and e.path == filename:
                    return e
        return None

    def get_file_entry_dict(self, path='', only_types=None,
                            verify_manifests=True):
        """
        Find all file entries that apply to paths starting with @path.
        Returns a nested dictionary that maps directories -> filenames
        inside the directory -> entries. Raises an exception if multiple
        entries for file collide.

        If @only_types are specified as a list, only files of specified
        types will be collected. If it is not specified, then all types
        for local files will be processed.

        @verify_manifests determines whether loaded Manifests will
        be verified against MANIFEST entries. Pass False only when
        doing updates.
        """

        self.load_manifests_for_path(path, recursive=True,
                                     verify=verify_manifests)
        out = {}
        for mpath, relpath, m in self._iter_manifests_for_path(
                path, recursive=True):
            for e in m.entries:
                if only_types is not None:
                    if e.tag not in only_types:
                        continue
                    # DIST entries always specify plain filename
                    if e.tag == 'DIST':
                        relpath = ''
                elif e.tag in ('DIST', 'TIMESTAMP'):
                    # distfiles are not local files, so skip them
                    # timestamp is not a file ;-)
                    continue

                fullpath = os.path.join(relpath, e.path)
                if path_starts_with(fullpath, path):
                    dirpath = os.path.dirname(fullpath)
                    filename = os.path.basename(e.path)
                    dirout = out.setdefault(dirpath, {})
                    if filename in dirout:
                        # compare the two entries
                        ret, diff = verify_entry_compatibility(
                            dirout[filename], e)
                        if not ret:
                            raise ManifestIncompatibleEntry(
                                dirout[filename], e, diff)
                        # we need to construct a single entry with both
                        # checksums
                        if diff:
                            new_checksums = dict(e.checksums)
                            for k, d1, d2 in diff:
                                if d2 is None:
                                    new_checksums[k] = d1
                            e = type(e)(e.path, e.size, new_checksums)
                    dirout[filename] = e
        return out

    def assert_directory_verifies(self,
                                  path='',
                                  fail_handler=throw_exception,
                                  last_mtime=None,
                                  ):
        """
        Verify the complete directory tree starting at @path (relative
        to top Manifest directory). Includes testing for stray files.
        Raises an exception if any of the files does not pass
        verification.

        @fail_handler is the callback called whenever verification
        fails (ether for mismatch, missing or stray file). The handler
        is passed a ManifestMismatch exception object. The default fail
        handler raises the exception. However, a custom handler can be
        used to provide a non-strict mode, or continue the scan after
        the first failure.

        If none of the handler calls raise an exception, the function
        returns boolean. It returns False if at least one of the handler
        calls returned explicit False; True otherwise.

        If @last_mtime is not None, then only files whose mtime is newer
        than that value (in st_mtime format) will be checked. Use this
        option *only* if mtimes can not be manipulated (i.e. do not use
        it with 'rsync --times')!

        @jobs specifies the number of parallel jobs to use. If set
        to None (the default), the number of system CPUs will be used.
        """

        entry_dict = self.get_file_entry_dict(path)
        it = os.walk(os.path.join(self.root_directory, path),
                     onerror=throw_exception,
                     followlinks=True)

        def _walk_directory(it):
            """
            Pre-process os.walk() result for verification. Yield objects
            suitable to passing to subprocesses.
            """
            directory_ids = {}

            for dirpath, dirnames, filenames in it:
                dir_st = os.stat(dirpath)
                if (self.manifest_device is not None
                        and dir_st.st_dev != self.manifest_device):
                    raise ManifestCrossDevice(dirpath)

                dir_id = (dir_st.st_dev, dir_st.st_ino)
                # if this directory was already processed for one of its
                # parents, we're in a loop
                parent_dir = os.path.dirname(dirpath)
                parent_dir_ids = directory_ids.get(parent_dir, [])
                if dir_id in parent_dir_ids:
                    raise ManifestSymlinkLoop(dirpath)

                relpath = os.path.relpath(dirpath, self.root_directory)
                # strip dot to avoid matching problems
                if relpath == '.':
                    relpath = ''
                dirdict = entry_dict.pop(relpath, {})

                skip_dirs = []
                for d in dirnames:
                    # skip dotfiles
                    if d.startswith('.'):
                        skip_dirs.append(d)
                        continue

                    de = dirdict.get(d)
                    if de is None:
                        continue

                    # if we have an entry for the directory, it's either
                    # ignored, or is supposed to be a file -- in both
                    # cases, we want not to recur
                    skip_dirs.append(d)
                    if de.tag == 'IGNORE':
                        del dirdict[d]

                # skip scanning ignored directories
                for d in skip_dirs:
                    dirnames.remove(d)
                # if we are planning to recur, record this dir
                if dirnames:
                    directory_ids[dirpath] = parent_dir_ids + [dir_id]

                yield (dirpath, relpath, dirnames, filenames, dirdict)

        verifier = SubprocessVerifier(
                self.top_level_manifest_filename,
                self.manifest_device,
                fail_handler, last_mtime)

        with MultiprocessingPoolWrapper(self.max_jobs) as pool:
            # verify the directories in parallel
            ret = all(pool.imap_unordered(
                verifier, _walk_directory(it), chunksize=64))

            # check for missing directories
            for relpath, dirdict in entry_dict.items():
                for f, e in dirdict.items():
                    fpath = os.path.join(relpath, f)
                    syspath = os.path.join(self.root_directory, fpath)
                    ret &= verifier._verify_one_file(syspath, fpath, e)

        return ret

    def save_manifests(self,
                       hashes=None,
                       force=False,
                       sort=None,
                       compress_watermark=None,
                       compress_format=None,
                       ):
        """
        Save the Manifests modified since the last save_manifests()
        call.

        @hashes, @sort, @compress_watermark and @compress_format
        override the value specified in the constructor. If None,
        the values from the constructor are used. If those were None
        as well, the defaults are used.

        @hashes specifies the requested hash set. The effective value
        must be non-null since new entries can be created.

        If @force is True, all Manifests will be rewritten even
        if they were not modified.

        If @sort is True, the Manifest entries will be sorted prior
        to saving. By default they are not.

        If @compress_watermark is not None, then the uncompressed
        Manifest files whose size is larger than or equal to the value
        will be compressed using @compress_format. The Manifest files
        whose size is smaller will be uncompressed. To compress all
        Manifest files, pass a size of 0.

        If @compress_watermark is None, the compression is left as-is.
        """

        if hashes is None:
            hashes = self.hashes
        if sort is None:
            sort = self.sort
        if compress_watermark is None:
            compress_watermark = self.compress_watermark
        if compress_format is None:
            compress_format = self.compress_format
        if force:
            self.load_manifests_for_path('', recursive=True)

        fixed_manifests = set()
        renamed_manifests = {}
        for mpath, relpath, m in self._iter_manifests_for_path(
                '', recursive=True):
            for e in m.entries:
                if e.tag != 'MANIFEST':
                    continue

                fullpath = os.path.join(relpath, e.path)
                if not force and fullpath not in self.updated_manifests:
                    assert fullpath not in renamed_manifests
                    continue
                if fullpath in renamed_manifests:
                    fullpath = renamed_manifests[fullpath]
                    e.path = os.path.relpath(fullpath, relpath)

                update_entry_for_path(
                    os.path.join(self.root_directory, fullpath),
                    e,
                    hashes=hashes,
                    expected_dev=self.manifest_device)

                # do not remove it from self.updated_manifests
                # immediately as we may have to deal with multiple
                # entries
                fixed_manifests.add(fullpath)
                self.updated_manifests.add(mpath)

            # we've apparently modified this Manifest, so store it now
            if force or mpath in self.updated_manifests:
                unc_size = self.save_manifest(mpath, sort=sort)
                # let's see if we want to recompress it
                if compress_watermark is not None:
                    compr = get_compressed_suffix_from_filename(mpath)
                    is_compr = compr is not None
                    want_compr = self.profile.want_compressed_manifest(
                            mpath, m, unc_size, compress_watermark)
                    if want_compr is not None and is_compr != want_compr:
                        if want_compr:
                            # compress it!
                            new_mpath = mpath + '.' + compress_format
                        else:
                            new_mpath = mpath[:-len(compr)-1]

                        # do the rename!
                        self.loaded_manifests[new_mpath] = m
                        self.save_manifest(new_mpath)
                        del self.loaded_manifests[mpath]
                        os.unlink(os.path.join(self.root_directory,
                                               mpath))
                        renamed_manifests[mpath] = new_mpath

                        if mpath == self.top_level_manifest_filename:
                            self.top_level_manifest_filename = new_mpath

        # now, discard all the Manifests whose entries we've updated
        self.updated_manifests -= fixed_manifests
        # ...and those which we renamed
        self.updated_manifests -= set(renamed_manifests.keys())
        # ...and top-level Manifest which has no entries
        self.updated_manifests.discard(self.top_level_manifest_filename)
        # at this point, the list should be empty
        assert not self.updated_manifests, (
            f'Unlinked but updated Manifests: {self.updated_manifests}')

    def update_entry_for_path(self,
                              path,
                              new_entry_type='DATA',
                              hashes=None,
                              ):
        """
        Update the Manifest entries for @path and queue the containing
        Manifests for update. @path must not be covered by IGNORE.
        You need to invoke save_manifests() to store the Manifest
        updates afterwards.

        If the path exists and has a matching Manifest entry, the most
        specific existing entry will be updated. If the path has more
        entries, the remaining entries will be removed. This function
        does not check if they were compatible.

        The type of MANIFEST and DATA derived entries is preserved.

        If the path exists and has no Manifest entry, a new entry
        of type @new_entry_type will be created in the Manifest most
        specific to the location. Note that AUX entries can only
        be created if they're located in 'files/' directory relative
        to an existing Manifest.

        If the path does not exist, all Manifest entries for it will
        be removed.

        @hashes override the value specified in the constructor.
        If None, the values from the constructor are used. If those were
        None as well, the defaults are used.

        @hashes specifies the requested hash set. If the effective value
        is None, the routine reuses the existing hash set in the entry.
        When creating a new entry, @hashes must be non-null.
        """

        had_entry = False
        if hashes is None:
            hashes = self.hashes

        self.load_manifests_for_path(path)
        for mpath, relpath, m in self._iter_manifests_for_path(path):
            entries_to_remove = []
            for e in m.entries:
                if e.tag == 'IGNORE':
                    # ignore matches recursively, so we process it separately
                    # py<3.5 does not have os.path.commonpath()
                    fullpath = os.path.join(relpath, e.path)
                    assert not path_starts_with(path, fullpath)
                elif e.tag in ('DIST', 'TIMESTAMP'):
                    # distfiles are not local files, so skip them
                    # timestamp is not a file ;-)
                    pass
                else:
                    # we update either file at the specified path
                    # or any relevant Manifests
                    fullpath = os.path.join(relpath, e.path)
                    if fullpath != path:
                        continue

                    if had_entry:
                        # duplicate entry!
                        entries_to_remove.append(e)
                        continue

                    try:
                        update_entry_for_path(
                            os.path.join(self.root_directory, fullpath),
                            e,
                            hashes=hashes,
                            expected_dev=self.manifest_device)
                    except ManifestInvalidPath as err:
                        if err.detail[0] == '__exists__':
                            # file does not exist anymore, so remove
                            # the entry
                            entries_to_remove.append(e)
                            had_entry = True
                        else:
                            raise err
                    else:
                        self.updated_manifests.add(mpath)
                        had_entry = True

            if entries_to_remove:
                for e in entries_to_remove:
                    m.entries.remove(e)
                self.updated_manifests.add(mpath)

        if not had_entry:
            assert hashes is not None
            for mpath, relpath, m in self._iter_manifests_for_path(path):
                # add to the first relevant Manifest
                assert new_entry_type not in ('DIST', 'IGNORE')
                newpath = os.path.relpath(path, relpath)
                if new_entry_type == 'AUX':
                    # AUX has implicit files/ prefix
                    assert path_inside_dir(newpath, 'files')
                    # drop files/ prefix
                    newpath = os.path.relpath(newpath, 'files')
                e = new_manifest_entry(new_entry_type, newpath, 0, {})
                update_entry_for_path(
                    os.path.join(self.root_directory, path),
                    e,
                    hashes=hashes,
                    expected_dev=self.manifest_device)
                m.entries.append(e)
                self.updated_manifests.add(mpath)
                had_entry = True
                break

    def get_deduplicated_file_entry_dict_for_update(self,
                                                    path='',
                                                    verify_manifests=True,
                                                    ):
        """
        Find all file entries that apply to paths starting with @path.
        Remove all duplicate entries and queue the relevant Manifests
        for update. Return a dictionary mapping relative paths
        to tuple of (manifest path, entry).

        You need to invoke save_manifests() to store the Manifest
        updates afterwards. However, note that the resulting tree
        may no longer validate.

        If the path is referenced by multiple entries of incompatible
        semantics, raises an exception. If the entries have compatible
        semantics, all but the first (deepest) are removed, even
        if they have colliding sizes or hashes. If the duplicate
        entries use different hash sets, the preserved entry is updated
        to have the union of their hashes.

        @verify_manifests determines whether loaded Manifests will
        be verified against MANIFEST entries. Pass False only when
        doing updates.
        """

        self.load_manifests_for_path(path, recursive=True,
                                     verify=verify_manifests)
        out = {}
        for mpath, relpath, m in self._iter_manifests_for_path(
                path, recursive=True):
            entries_to_remove = []
            for e in m.entries:
                if e.tag in ('DIST', 'TIMESTAMP'):
                    # distfiles are not local files, so skip them
                    # timestamp is not a file ;-)
                    continue

                fullpath = os.path.join(relpath, e.path)
                if path_starts_with(fullpath, path):
                    if fullpath in out:
                        # compare the two entries
                        ret, diff = verify_entry_compatibility(
                            out[fullpath][1], e)
                        # if semantically incompatible, throw
                        if not ret and diff[0][0] == '__type__':
                            raise ManifestIncompatibleEntry(
                                out[fullpath][1], e, diff)
                        # otherwise, make sure we have all checksums
                        out[fullpath][1].checksums.update(e.checksums)
                        # and drop the duplicate
                        entries_to_remove.append(e)
                    else:
                        out[fullpath] = (mpath, e)

            if entries_to_remove:
                for e in entries_to_remove:
                    m.entries.remove(e)
                self.updated_manifests.add(mpath)

        return out

    def load_unregistered_manifests(self, path='', verify_manifests=True):
        """
        Scan the directory @path (relative to top directory)
        for unregistered (not listed in MANIFEST entries) Manifest
        files and load them if they are valid.

        Returns a list of files found. The respective MANIFEST entries
        need to be added to other Manifests manually to ensure
        integrity. Note that the list may contain files that are
        referenced within added Manifests, so the list should
        be verified with regards to existing entries.

        @verify_manifests determines whether loaded Manifests will
        be verified against MANIFEST entries. Pass False only when
        doing updates.
        """

        manifest_filenames = get_potential_compressed_names('Manifest')

        entry_dict = self.get_file_entry_dict(
            path,
            only_types=['IGNORE'],
            verify_manifests=verify_manifests)
        new_manifests = []
        directory_ids = {}
        it = os.walk(os.path.join(self.root_directory, path),
                     onerror=throw_exception,
                     followlinks=True)

        for dirpath, dirnames, filenames in it:
            dir_st = os.stat(dirpath)
            if (self.manifest_device is not None
                    and dir_st.st_dev != self.manifest_device):
                raise ManifestCrossDevice(dirpath)

            dir_id = (dir_st.st_dev, dir_st.st_ino)
            # if this directory was already processed for one of its
            # parents, we're in a loop
            parent_dir = os.path.dirname(dirpath)
            parent_dir_ids = directory_ids.get(parent_dir, [])
            if dir_id in parent_dir_ids:
                raise ManifestSymlinkLoop(dirpath)

            relpath = os.path.relpath(dirpath, self.root_directory)
            # strip dot to avoid matching problems
            if relpath == '.':
                relpath = ''
            dirdict = entry_dict.get(relpath, {})

            skip_dirs = []
            for d in dirnames:
                # skip dotfiles
                if d.startswith('.'):
                    skip_dirs.append(d)
                    continue

                de = dirdict.get(d, None)
                if de is None:
                    continue

                assert de.tag == 'IGNORE'
                skip_dirs.append(d)

            # skip scanning ignored directories
            for d in skip_dirs:
                dirnames.remove(d)
            # if we are planning to recur, record this dir
            if dirnames:
                directory_ids[dirpath] = parent_dir_ids + [dir_id]

            # check for unregistered Manifest
            for mname in manifest_filenames:
                if mname in filenames:
                    fpath = os.path.join(relpath, mname)
                    if fpath in self.loaded_manifests:
                        continue

                    # we've just found ourselves a new Manifest,
                    # let's try to load it
                    try:
                        self.load_manifest(fpath)
                    except ManifestSyntaxError:
                        # syntax error? probably not a Manifest then.
                        pass
                    except OSError as exc:
                        # bz2 returns generic OSError without errno
                        # so non-null errno probably means something
                        # else happened
                        if exc.errno is not None:
                            raise
                    except InvalidCompressedFileExceptions:
                        pass
                    else:
                        new_manifests.append(fpath)

        return new_manifests

    def update_entries_for_directory(self,
                                     path='',
                                     hashes=None,
                                     last_mtime=None,
                                     verify_manifests=False,
                                     ):
        """
        Update the Manifest entries for the contents of directory
        @path (top directory by default), recursively. Includes adding
        new files and removing entries for those that no longer exist.
        The behavior for various cases is the same
        as for update_entry_for_path() except as noted below.

        New entries are currently created with DATA type. This will
        be extended in the future.

        @hashes override the value specified in the constructor.
        If None, the values from the constructor are used. If those were
        None as well, the defaults are used.

        @hashes specifies the requested hash set. The effective value
        must be non-null since new entries can be created.

        If @last_mtime is not None, then only files whose mtime is newer
        than that value (in st_mtime format) will be updated. Use this
        option *only* if you can rely on mtimes being bumped
        monotonically on modified files. Afterwards, the value
        of @last_mtime should be put into the TIMESTAMP entry.

        @verify_manifests determines whether loaded Manifests will
        be verified against MANIFEST entries. Disabled by default since
        the MANIFEST entries would be updated anyway.
        """

        if hashes is None:
            hashes = self.hashes
        assert hashes is not None

        manifest_filenames = get_potential_compressed_names('Manifest')

        new_manifests = self.load_unregistered_manifests(
            path, verify_manifests=verify_manifests)
        entry_dict = self.get_deduplicated_file_entry_dict_for_update(
            path, verify_manifests=verify_manifests)
        manifest_stack = []
        for mpath, mrpath, m in (self._iter_manifests_for_path(path)):
            manifest_stack.append((mpath, mrpath, m))
            break
        directory_ids = {}

        it = os.walk(os.path.join(self.root_directory, path),
                     onerror=throw_exception,
                     followlinks=True)

        for dirpath, dirnames, filenames in it:
            dir_st = os.stat(dirpath)
            if (self.manifest_device is not None
                    and dir_st.st_dev != self.manifest_device):
                raise ManifestCrossDevice(dirpath)

            dir_id = (dir_st.st_dev, dir_st.st_ino)
            # if this directory was already processed for one of its
            # parents, we're in a loop
            parent_dir = os.path.dirname(dirpath)
            parent_dir_ids = directory_ids.get(parent_dir, [])
            if dir_id in parent_dir_ids:
                raise ManifestSymlinkLoop(dirpath)

            relpath = os.path.relpath(dirpath, self.root_directory)
            # strip dot to avoid matching problems
            if relpath == '.':
                relpath = ''

            # drop Manifest paths until we get to a common directory
            while not path_starts_with(relpath, manifest_stack[-1][1]):
                manifest_stack.pop()

            want_manifest = self.profile.want_manifest_in_directory(
                    relpath, dirnames, filenames)

            skip_dirs = []
            for d in dirnames:
                # skip dotfiles
                if d.startswith('.'):
                    skip_dirs.append(d)
                    continue

                dpath = os.path.join(relpath, d)
                mpath, de = entry_dict.pop(dpath, (None, None))
                if de is None:
                    continue

                if de.tag == 'IGNORE':
                    skip_dirs.append(d)
                else:
                    # trigger the exception indirectly
                    update_entry_for_path(os.path.join(dirpath, d),
                                          de,
                                          hashes=hashes,
                                          expected_dev=self.manifest_device)
                    assert False, "exception should have been raised"

            # skip scanning ignored directories
            for d in skip_dirs:
                dirnames.remove(d)
            # if we are planning to recur, record this dir
            if dirnames:
                directory_ids[dirpath] = parent_dir_ids + [dir_id]

            new_entries = []
            for f in filenames:
                # skip dotfiles
                if f.startswith('.'):
                    continue

                fpath = os.path.join(relpath, f)
                mpath, fe = entry_dict.pop(fpath, (None, None))
                if fe is not None:
                    if fe.tag == 'IGNORE':
                        continue
                    if fe.tag == 'MANIFEST':
                        manifest_stack.append(
                            (fpath, relpath, self.loaded_manifests[fpath]))
                        # do not update the Manifest entry if
                        # the relevant Manifest is going to be updated
                        # anyway
                        if relpath in self.updated_manifests:
                            continue
                else:
                    # skip top-level Manifest, we obviously can't have
                    # an entry for it
                    if fpath in manifest_filenames:
                        continue
                    if fpath in new_manifests:
                        ftype = 'MANIFEST'
                        manifest_stack.append(
                            (fpath, relpath, self.loaded_manifests[fpath]))
                    else:
                        ftype = self.profile.get_entry_type_for_path(
                                fpath)

                    # note: .path needs to be corrected below
                    fe = new_manifest_entry(ftype, fpath, 0, {})
                    new_entries.append(fe)
                    if relpath in self.updated_manifests:
                        continue

                changed = update_entry_for_path(
                    os.path.join(dirpath, f),
                    fe,
                    hashes=hashes,
                    expected_dev=self.manifest_device,
                    last_mtime=last_mtime)
                if changed and mpath is not None:
                    self.updated_manifests.add(mpath)

            # do we have Manifest in this directory?
            new_ignore_paths = []
            if want_manifest and manifest_stack[-1][1] != relpath:
                mpath = os.path.join(relpath, 'Manifest')
                m = self.create_manifest(mpath)
                manifest_stack.append((mpath, relpath, m))
                fe = ManifestEntryMANIFEST(mpath, 0, {})
                new_entries.append(fe)

                for ip in (self.profile
                           .get_ignore_paths_for_new_manifest(relpath)):
                    ie = ManifestEntryIGNORE(ip)
                    iep = os.path.join(relpath, ip)

                    if self.find_path_entry(iep):
                        raise NotImplementedError(
                            'Need to remove old parent entry for '
                            'now-ignored path')

                    m.entries.append(ie)
                    new_ignore_paths.append(iep)

            if new_entries:
                mpath, mdirpath, m = manifest_stack[-1]
                for fe in new_entries:
                    # skip files that should have been ignored
                    if fe.path in new_ignore_paths:
                        continue

                    if fe.tag == 'MANIFEST':
                        # Manifest needs to go level up
                        mmpath = mpath
                        mm = m
                        mmdirpath = mdirpath
                        i = -1
                        while mmdirpath == os.path.dirname(fe.path):
                            i -= 1
                            mmpath, mmdirpath, mm = manifest_stack[i]

                        fe.path = os.path.relpath(fe.path, mmdirpath)
                        mm.entries.append(fe)
                        self.updated_manifests.add(mmpath)
                    else:
                        if ftype == 'AUX':
                            # AUX has implicit files/ prefix in .path
                            # but for now, we've shoved our path
                            # into .aux_path
                            fe.path = os.path.relpath(fe.aux_path,
                                                      mdirpath)
                            assert path_inside_dir(fe.path, 'files')
                            # drop files/ prefix for the entry
                            fe.aux_path = os.path.relpath(
                                fe.path, 'files')
                        else:
                            fe.path = os.path.relpath(fe.path, mdirpath)
                        # do not add duplicate entry if the path is ignored
                        m.entries.append(fe)
                self.updated_manifests.add(mpath)

        # check for removed files
        for relpath, me in entry_dict.items():
            mpath, fe = me
            if fe.tag == 'IGNORE':
                continue

            self.loaded_manifests[mpath].entries.remove(fe)
            self.updated_manifests.add(mpath)

    def create_manifest(self, path):
        """
        Create a new empty sub-Manifest instance at relative path @path.
        The file will not be written until save_manifests(). No MANIFEST
        entry for the file will be created.

        Returns the new ManifestFile instance.
        """

        return self.load_manifest(path, allow_create=True)
