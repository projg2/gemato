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

    def get_entry_type_for_path(self, path):
        """
        Get Manifest entry type appropriate for the specified path.
        Must return an appropriate Manifest tag for file-style entry
        (i.e. one of DATA, MISC, EBUILD, AUX).
        """
        return 'DATA'


class EbuildRepositoryProfile(DefaultProfile):
    """
    A profile suited for a modern ebuild repository.
    """
    pass


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
