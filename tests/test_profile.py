# gemato: Profile behavior tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import os.path

import gemato.cli
import gemato.profile
import gemato.recursiveloader

from tests.testutil import TempDirTestCase


class EbuildRepositoryTests(TempDirTestCase):
    """
    Tests for ebuild repository profiles.
    """

    PROFILE = gemato.profile.EbuildRepositoryProfile
    PROFILE_NAME = 'ebuild'
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
    EXPECTED_MANIFESTS = [
        'dev-foo/Manifest',
        'dev-foo/bar/Manifest',
        'eclass/Manifest',
        'licenses/Manifest',
        'metadata/Manifest',
        'metadata/glsa/Manifest',
        'metadata/md5-cache/Manifest',
        'metadata/md5-cache/dev-foo/Manifest',
        'metadata/news/Manifest',
        'profiles/Manifest',
    ]
    EXPECTED_TYPES = {
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
        'metadata/timestamp': 'DATA',
        'metadata/timestamp.chk': 'DATA',
        'metadata/timestamp.commit': 'DATA',
        'metadata/timestamp.x': 'DATA',
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
    }
    FILES = dict.fromkeys(EXPECTED_TYPES, u'')

    def test_get_entry_type_for_path(self):
        p = self.PROFILE()
        for f, expt in self.EXPECTED_TYPES.items():
            self.assertEqual(
                    p.get_entry_type_for_path(f),
                    expt,
                    "type mismatch for {}".format(f))

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                os.path.join(self.dir, 'Manifest'),
                hashes=['SHA256', 'SHA512'],
                allow_create=True,
                profile=self.PROFILE())
        m.update_entries_for_directory('')
        for f, expt in self.EXPECTED_TYPES.items():
            self.assertEqual(
                    m.find_path_entry(f).tag,
                    expt,
                    "type mismatch for {}".format(f))
        for f in self.EXPECTED_MANIFESTS:
            self.assertEqual(m.find_path_entry(f).tag, 'MANIFEST',
                    "type mismatch for {}".format(f))
        return m

    def test_set_loader_options(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                os.path.join(self.dir, 'Manifest'),
                profile=self.PROFILE(),
                allow_create=True)
        self.assertIsNotNone(m.hashes)
        self.assertTrue(m.sort)
        self.assertIsNotNone(m.compress_watermark)
        self.assertIsNotNone(m.compress_format)

    def test_cli_update(self):
        self.assertEqual(
                gemato.cli.main(['gemato', 'create',
                    '--profile', self.PROFILE_NAME,
                    self.dir]),
                0)

        m = gemato.recursiveloader.ManifestRecursiveLoader(
                os.path.join(self.dir, 'Manifest'))
        for f, expt in self.EXPECTED_TYPES.items():
            self.assertEqual(
                    m.find_path_entry(f).tag,
                    expt,
                    "type mismatch for {}".format(f))
        for f in self.EXPECTED_MANIFESTS:
            self.assertEqual(m.find_path_entry(f).tag, 'MANIFEST',
                    "type mismatch for {}".format(f))
        return m


class BackwardsCompatEbuildRepositoryTests(EbuildRepositoryTests):
    PROFILE = gemato.profile.BackwardsCompatEbuildRepositoryProfile
    PROFILE_NAME = 'old-ebuild'

    def __init__(self, *args, **kwargs):
        self.EXPECTED_TYPES = self.EXPECTED_TYPES.copy()
        self.EXPECTED_TYPES.update({
            'dev-foo/bar/bar-1.ebuild': 'EBUILD',
            'dev-foo/bar/metadata.xml': 'MISC',
            'dev-foo/bar/files/test.patch': 'AUX',
        })
        super(BackwardsCompatEbuildRepositoryTests, self).__init__(
                *args, **kwargs)

    def test_update_entries_for_directory(self):
        m = (super(BackwardsCompatEbuildRepositoryTests, self)
                .test_update_entries_for_directory())
        self.assertEqual(
                m.find_path_entry('dev-foo/bar/files/test.patch').path,
                'files/test.patch')
        self.assertEqual(
                m.find_path_entry('dev-foo/bar/files/test.patch').aux_path,
                'test.patch')

    def test_cli_update(self):
        m = (super(BackwardsCompatEbuildRepositoryTests, self)
                .test_cli_update())
        self.assertEqual(
                m.find_path_entry('dev-foo/bar/files/test.patch').path,
                'files/test.patch')
        self.assertEqual(
                m.find_path_entry('dev-foo/bar/files/test.patch').aux_path,
                'test.patch')

    def test_compression(self):
        """
        Test that package directory Manifests are not compressed.
        """

        m = gemato.recursiveloader.ManifestRecursiveLoader(
                os.path.join(self.dir, 'Manifest'),
                hashes=['SHA256', 'SHA512'],
                compress_watermark=0,
                allow_create=True,
                profile=self.PROFILE())
        m.update_entries_for_directory('')
        m.save_manifests()

        for mpath in self.EXPECTED_MANIFESTS:
            # package manifest should be left uncompressed
            if mpath == 'dev-foo/bar/Manifest':
                self.assertTrue(os.path.exists(os.path.join(
                    self.dir, mpath)))
            else:
                self.assertTrue(os.path.exists(os.path.join(
                    self.dir, mpath + '.gz')))
                self.assertFalse(os.path.exists(os.path.join(
                    self.dir, mpath)))

    def test_cli_compression(self):
        self.assertEqual(
                gemato.cli.main(['gemato', 'create',
                    '--profile', self.PROFILE_NAME,
                    '--compress-watermark=0',
                    self.dir]),
                0)

        for mpath in self.EXPECTED_MANIFESTS:
            # package manifest should be left uncompressed
            if mpath == 'dev-foo/bar/Manifest':
                self.assertTrue(os.path.exists(os.path.join(
                    self.dir, mpath)))
            else:
                self.assertTrue(os.path.exists(os.path.join(
                    self.dir, mpath + '.gz')))
                self.assertFalse(os.path.exists(os.path.join(
                    self.dir, mpath)))
