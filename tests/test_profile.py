# gemato: Profile behavior tests
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import itertools
import os
import os.path

import pytest

import gemato.cli
from gemato.profile import (
    EbuildRepositoryProfile,
    BackwardsCompatEbuildRepositoryProfile,
    )
from gemato.recursiveloader import ManifestRecursiveLoader


DIRS = [
    'dev-foo',
    'dev-foo/bar',
    'dev-foo/bar/files',
    'eclass',
    'eclass/tests',
    'licenses',
    'metadata',
    'metadata/dtd',
    'metadata/glsa',
    'metadata/install-qa-check.d',
    'metadata/md5-cache',
    'metadata/md5-cache/dev-foo',
    'metadata/news',
    'metadata/news/2020-01-01-foo',
    'metadata/xml-schema',
    'profiles',
    'profiles/arch',
    'profiles/arch/foo',
    'profiles/desc',
    'profiles/updates',
]
PACKAGE_MANIFESTS = ['dev-foo/bar/Manifest']
EXPECTED_MANIFESTS = [
    'dev-foo/Manifest',
    'eclass/Manifest',
    'licenses/Manifest',
    'metadata/Manifest',
    'metadata/dtd/Manifest',
    'metadata/glsa/Manifest',
    'metadata/md5-cache/Manifest',
    'metadata/md5-cache/dev-foo/Manifest',
    'metadata/news/Manifest',
    'metadata/xml-schema/Manifest',
    'profiles/Manifest',
]
EXPECTED_TYPES = {
    EbuildRepositoryProfile: {
        'header.txt': 'DATA',
        'skel.ebuild': 'DATA',
        'skel.metadata.xml': 'DATA',
        'dev-foo/metadata.xml': 'DATA',
        'dev-foo/bar/bar-1.ebuild': 'DATA',
        'dev-foo/bar/metadata.xml': 'DATA',
        'dev-foo/bar/files/test.patch': 'DATA',
        'eclass/foo.eclass': 'DATA',
        'eclass/tests/foo.sh': 'DATA',
        'licenses/foo': 'DATA',
        'metadata/layout.conf': 'DATA',
        'metadata/projects.xml': 'DATA',
        'metadata/pkg_desc_index': 'DATA',
        'metadata/dtd/foo.dtd': 'DATA',
        'metadata/glsa/glsa-202001-01.xml': 'DATA',
        'metadata/install-qa-check.d/50foo': 'DATA',
        'metadata/md5-cache/dev-foo/bar-1': 'DATA',
        'metadata/news/2020-01-01-foo/2020-01-01-foo.en.txt': 'DATA',
        'metadata/news/2020-01-01-foo/2020-01-01-foo.en.txt.asc': 'DATA',
        'metadata/xml-schema/foo.xsd': 'DATA',
        'profiles/arch.desc': 'DATA',
        'profiles/categories': 'DATA',
        'profiles/eapi': 'DATA',
        'profiles/info_pkgs': 'DATA',
        'profiles/info_vars': 'DATA',
        'profiles/license_groups': 'DATA',
        'profiles/package.mask': 'DATA',
        'profiles/profiles.desc': 'DATA',
        'profiles/repo_name': 'DATA',
        'profiles/thirdpartymirrors': 'DATA',
        'profiles/use.desc': 'DATA',
        'profiles/use.local.desc': 'DATA',
        'profiles/arch/foo/eapi': 'DATA',
        'profiles/arch/foo/parent': 'DATA',
        'profiles/desc/foo.desc': 'DATA',
        'profiles/updates/1Q-2020': 'DATA',
    },
}
FILES = list(EXPECTED_TYPES[EbuildRepositoryProfile]) + [
    'metadata/timestamp',
    'metadata/timestamp.chk',
    'metadata/timestamp.commit',
    'metadata/timestamp.x',
]
EXPECTED_IGNORE = [
    'distfiles',
    'local',
    'lost+found',
    'packages',
    'metadata/timestamp',
    'metadata/timestamp.chk',
    'metadata/timestamp.commit',
    'metadata/timestamp.x',
    'metadata/dtd/timestamp.chk',
    'metadata/dtd/timestamp.commit',
    'metadata/glsa/timestamp.chk',
    'metadata/glsa/timestamp.commit',
    'metadata/news/timestamp.chk',
    'metadata/news/timestamp.commit',
    'metadata/xml-schema/timestamp.chk',
    'metadata/xml-schema/timestamp.commit',
]

EXPECTED_TYPES[BackwardsCompatEbuildRepositoryProfile] = (
    dict(EXPECTED_TYPES[EbuildRepositoryProfile]))
EXPECTED_TYPES[BackwardsCompatEbuildRepositoryProfile].update({
    'dev-foo/bar/bar-1.ebuild': 'EBUILD',
    'dev-foo/bar/metadata.xml': 'MISC',
    'dev-foo/bar/files/test.patch': 'AUX',
})

PKG_MANIFEST_SUFFIX = {
    EbuildRepositoryProfile: '.gz',
    BackwardsCompatEbuildRepositoryProfile: '',
}

ALL_PROFILES = [
    EbuildRepositoryProfile,
    BackwardsCompatEbuildRepositoryProfile,
]


@pytest.fixture
def test_repo(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp('profile-')
    for d in DIRS:
        os.mkdir(tmp_path / d)
    for f in FILES:
        with open(tmp_path / f, 'w'):
            pass
    yield tmp_path


@pytest.mark.parametrize(
    'profile,path,expected',
    [(profile, path, EXPECTED_TYPES[profile][path])
     for profile in ALL_PROFILES
     for path in EXPECTED_TYPES[profile]])
def test_get_entry_type_for_path(profile, path, expected):
    assert profile().get_entry_type_for_path(path) == expected


def make_entry_match(manifest_loader, path):
    entry = manifest_loader.find_path_entry(path)
    if entry is not None:
        if entry.tag == 'MANIFEST':
            return (entry.tag,
                    os.path.exists(
                        os.path.join(manifest_loader.root_directory,
                                     path)))
        elif entry.tag == 'AUX':
            return (entry.tag, entry.path, entry.aux_path)
        return (entry.tag,)


def make_expect_match(path, entry_type, manifests_exist=True):
    if entry_type == 'MANIFEST':
        return (entry_type, manifests_exist)
    elif entry_type == 'AUX':
        return (entry_type,
                os.path.join('files', os.path.basename(path)),
                os.path.basename(path))
    return (entry_type,)


@pytest.mark.parametrize('profile', ALL_PROFILES)
def test_update_entries_for_directory(test_repo, profile):
    m = ManifestRecursiveLoader(
        test_repo / 'Manifest',
        hashes=['SHA256', 'SHA512'],
        allow_create=True,
        profile=profile())
    m.update_entries_for_directory('')

    expected = dict(
        [(path, make_expect_match(path, entry_type))
         for path, entry_type in EXPECTED_TYPES[profile].items()] +
        [(path, make_expect_match(path, 'MANIFEST', manifests_exist=False))
         for path in EXPECTED_MANIFESTS + PACKAGE_MANIFESTS] +
        [(path, make_expect_match(path, 'IGNORE'))
         for path in EXPECTED_IGNORE])
    found = dict((path, make_entry_match(m, path))
                 for path in expected)
    assert found == expected

    m.save_manifests()
    manifests_expected = dict(
        itertools.chain(
            ((path + '.gz', make_expect_match(path, 'MANIFEST'))
             for path in EXPECTED_MANIFESTS),
            ((path + PKG_MANIFEST_SUFFIX[profile],
             make_expect_match(path, 'MANIFEST'))
             for path in PACKAGE_MANIFESTS)))
    manifests_found = dict((path, make_entry_match(m, path))
                           for path in manifests_expected)
    assert manifests_found == manifests_expected

    m.assert_directory_verifies('')


@pytest.mark.parametrize('profile', ALL_PROFILES)
def test_cli_update(test_repo, profile):
    assert gemato.cli.main(['gemato', 'create',
                            '--profile', profile.name,
                            str(test_repo)]) == 0

    m = ManifestRecursiveLoader(test_repo / 'Manifest')
    expected = dict(
        [(path, make_expect_match(path, entry_type))
         for path, entry_type in EXPECTED_TYPES[profile].items()] +
        [(path + '.gz', make_expect_match(path, 'MANIFEST'))
         for path in EXPECTED_MANIFESTS] +
        [(path + PKG_MANIFEST_SUFFIX[profile],
          make_expect_match(path, 'MANIFEST'))
         for path in PACKAGE_MANIFESTS] +
        [(path, make_expect_match(path, 'IGNORE'))
         for path in EXPECTED_IGNORE])
    found = dict((path, make_entry_match(m, path))
                 for path in expected)
    assert found == expected

    assert gemato.cli.main(['gemato', 'verify', str(test_repo)]) == 0


@pytest.mark.parametrize('profile', ALL_PROFILES)
def test_set_loader_options(test_repo, profile):
    m = ManifestRecursiveLoader(
        test_repo / 'Manifest',
        profile=profile(),
        allow_create=True)
    assert m.hashes is not None
    assert m.sort
    assert m.compress_watermark is not None
    assert m.compress_format is not None


@pytest.mark.parametrize('profile', ALL_PROFILES)
def test_regression_top_level_ignore_in_all_manifests(test_repo, profile):
    """Regression test for IGNORE wrongly applying to all Manifests"""
    m = ManifestRecursiveLoader(
        test_repo / 'Manifest',
        hashes=['SHA256', 'SHA512'],
        allow_create=True,
        profile=profile())
    m.update_entries_for_directory('')

    expected = {
        'distfiles': ('IGNORE',),
        'dev-foo/Manifest': ('MANIFEST', False),
        'dev-foo/distfiles': None,
    }
    found = dict((path, make_entry_match(m, path))
                 for path in expected)
    assert found == expected
