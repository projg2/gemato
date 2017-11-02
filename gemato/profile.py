# gemato: Profile support
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import os.path


class DefaultProfile(object):
    """
    Profile is a class describing the specific properties of a directory
    tree. It is used when updating Manifests to determine the most
    correct behavior for a given use case.
    """

    def set_loader_options(self, loader):
        """
        Alter loader @loader with profile-specific options. This
        is called after applying the user-specified options, so it
        should check them for None if overwriting is not desired.
        """
        pass

    def get_entry_type_for_path(self, path):
        """
        Get Manifest entry type appropriate for the specified path.
        Must return an appropriate Manifest tag for file-style entry
        (i.e. one of DATA, MISC, EBUILD, AUX).
        """
        return 'DATA'

    def want_manifest_in_directory(self, relpath, dirnames, filenames):
        """
        Determine whether a Manifest file is expected in the specified
        directory. @relpath is the relative path to the directory,
        @dirnames and @filenames list respectively all directories
        and files directly underneath it.

        Should return True if Manifest is expected, False otherwise.
        If True is returned and the directory does not contain a single
        file of Manifest type, a new one will be created as 'Manifest'.
        """
        return False


class EbuildRepositoryProfile(DefaultProfile):
    """
    A profile suited for a modern ebuild repository.
    """

    def want_manifest_in_directory(self, relpath, dirnames, filenames):
        # a quick way to catch most of packages and ::gentoo categories
        if 'metadata.xml' in filenames:
            return True
        spl = relpath.split(os.path.sep)
        # top level directories...
        if len(spl) == 1:
            # with any subdirectories (categories, metadata, profiles)
            if len(dirnames) > 0:
                return True
            # plus some unconditional standard directories
            if relpath in ('eclass', 'licenses', 'metadata',
                    'profiles'):
                return True
        elif len(spl) == 2:
            # 'slow' way of detecting package directories
            if any(f.endswith('.ebuild') for f in filenames):
                return True
            # some standard directories worth separate Manifests
            if spl[0] == 'metadata' and spl[1] in ('glsa', 'md5-cache',
                    'news'):
                return True
        elif len(spl) == 3:
            # metadata cache -> per-directory Manifests
            if spl[0:2] == ['metadata', 'md5-cache']:
                return True
        return False

    def set_loader_options(self, loader):
        if loader.hashes is None:
            # layout.conf as of 2017-11-02
            loader.hashes = ['SHA256', 'SHA512', 'WHIRLPOOL']
        if loader.sort is None:
            loader.sort = True
        if loader.compress_watermark is None:
            # GLEP 61 suggested value
            loader.compress_watermark = 32768
        if loader.compress_format is None:
            loader.compress_format = 'gz'


class BackwardsCompatEbuildRepositoryProfile(EbuildRepositoryProfile):
    """
    A profile for ebuild repository that maintains compatibility
    with Manifest2 format.
    """

    def get_entry_type_for_path(self, path):
        spl = path.split(os.path.sep)
        if len(spl) == 3:
            if path.endswith('.ebuild'):
                return 'EBUILD'
            elif spl[2] == 'metadata.xml':
                return 'MISC'
        if spl[2:3] == ['files']:
            return 'AUX'

        return (super(BackwardsCompatEbuildRepositoryProfile, self)
                .get_entry_type_for_path(path))


PROFILE_MAPPING = {
    'default': DefaultProfile,
    'ebuild': EbuildRepositoryProfile,
    'old-ebuild': BackwardsCompatEbuildRepositoryProfile,
}


def get_profile_by_name(name):
    return PROFILE_MAPPING[name]()
