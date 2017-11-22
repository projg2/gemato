# gemato: Recursive loader tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import base64
import datetime
import gzip
import io
import os
import unittest

import gemato.cli
import gemato.exceptions
import gemato.recursiveloader

from tests.testutil import TempDirTestCase


class BasicNestingTest(TempDirTestCase):
    DIRS = ['sub', 'sub/deeper', 'other']
    FILES = {
        'Manifest': u'''
TIMESTAMP 2017-01-01T01:01:01Z
MANIFEST sub/Manifest 128 MD5 30fd28b98a23031c72793908dd35c530
MANIFEST other/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DIST topdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/Manifest': u'''
MANIFEST deeper/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a
DIST subdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/stray': u'',
        'sub/deeper/Manifest': u'''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/deeper/test': u'',
        'other/Manifest': u'',
    }

    def test_init(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertIn('Manifest', m.loaded_manifests)

    def test_load_sub_manifest(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest', m.loaded_manifests)
        m.load_manifests_for_path('sub/test')
        self.assertIn('sub/Manifest', m.loaded_manifests)
        self.assertNotIn('sub/deeper/Manifest', m.loaded_manifests)
        m.load_manifests_for_path('sub/deeper/test')
        self.assertIn('sub/deeper/Manifest', m.loaded_manifests)
        self.assertNotIn('other/Manifest', m.loaded_manifests)

    def test_recursive_load_manifest(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest', m.loaded_manifests)
        self.assertNotIn('sub/deeper/Manifest', m.loaded_manifests)
        m.load_manifests_for_path('sub/deeper/test')
        self.assertIn('sub/Manifest', m.loaded_manifests)
        self.assertIn('sub/deeper/Manifest', m.loaded_manifests)
        self.assertNotIn('other/Manifest', m.loaded_manifests)

    def test_load_manifests_recursively(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest', m.loaded_manifests)
        self.assertNotIn('sub/deeper/Manifest', m.loaded_manifests)
        self.assertNotIn('other/Manifest', m.loaded_manifests)
        m.load_manifests_for_path('', recursive=True)
        self.assertIn('sub/Manifest', m.loaded_manifests)
        self.assertIn('sub/deeper/Manifest', m.loaded_manifests)
        self.assertIn('other/Manifest', m.loaded_manifests)

    def test__iter_manifests_for_path_order(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.load_manifests_for_path('', recursive=True)
        self.assertListEqual([d for mpath, d, k
                                in m._iter_manifests_for_path('sub/deeper')],
            ['sub/deeper', 'sub', ''])
        self.assertListEqual([d for mpath, d, k
                                in m._iter_manifests_for_path('other')],
            ['other', ''])

    def test__iter_manifests_for_path_recursively_order(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.load_manifests_for_path('', recursive=True)
        self.assertListEqual([d for mpath, d, k
                                in m._iter_manifests_for_path('sub',
                                    recursive=True)],
            ['sub/deeper', 'sub', ''])

    def test_load_sub_manifest_recursively(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest', m.loaded_manifests)
        self.assertNotIn('sub/deeper/Manifest', m.loaded_manifests)
        m.load_manifests_for_path('sub', recursive=True)
        self.assertIn('sub/Manifest', m.loaded_manifests)
        self.assertIn('sub/deeper/Manifest', m.loaded_manifests)
        self.assertNotIn('other/Manifest', m.loaded_manifests)

    def test_find_timestamp(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_timestamp().ts,
                datetime.datetime(2017, 1, 1, 1, 1, 1))

    def test_set_timestamp(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.set_timestamp(datetime.datetime(2010, 7, 7, 7, 7, 7))
        self.assertEqual(m.find_timestamp().ts,
                datetime.datetime(2010, 7, 7, 7, 7, 7))
        self.assertEqual(
                len([x for x in m.loaded_manifests['Manifest'].entries
                             if x.tag == 'TIMESTAMP']),
                1)

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertIsNone(m.find_path_entry('test'))
        self.assertIsNone(m.find_path_entry('sub/test'))
        self.assertEqual(m.find_path_entry('sub/deeper/test').path, 'test')

    def test_find_top_dist_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_dist_entry('topdistfile-1.txt').path, 'topdistfile-1.txt')
        self.assertIsNone(m.find_dist_entry('subdistfile-1.txt'))

    def test_find_sub_dist_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_dist_entry('topdistfile-1.txt', 'sub').path, 'topdistfile-1.txt')
        self.assertEqual(m.find_dist_entry('subdistfile-1.txt', 'sub').path, 'subdistfile-1.txt')

    def test_find_sub_dist_entry_with_slash_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_dist_entry('topdistfile-1.txt', 'sub/').path, 'topdistfile-1.txt')
        self.assertEqual(m.find_dist_entry('subdistfile-1.txt', 'sub/').path, 'subdistfile-1.txt')

    def test_find_sub_dist_entry_with_file_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_dist_entry('topdistfile-1.txt', 'sub/file').path, 'topdistfile-1.txt')
        self.assertEqual(m.find_dist_entry('subdistfile-1.txt', 'sub/file').path, 'subdistfile-1.txt')

    def test_verify_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.verify_path('sub/deeper/test'), (True, []))

    def test_verify_nonexistent_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.verify_path('sub/deeper/nonexist'), (True, []))

    def test_verify_stray_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.verify_path('sub/stray'),
                (False, [('__exists__', False, True)]))

    def test_assert_path_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_path_verifies('sub/deeper/test')

    def test_assert_path_verifies_nonexistent_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_path_verifies('sub/deeper/nonexist')

    def test_assert_path_verifies_stray_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestMismatch,
                m.assert_path_verifies, 'sub/stray')

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('')
        self.assertSetEqual(frozenset(entries),
            frozenset((
                'other/Manifest',
                'sub/Manifest',
                'sub/deeper/Manifest',
                'sub/deeper/test',
            )))
        self.assertEqual(entries['other/Manifest'].path, 'other/Manifest')
        self.assertEqual(entries['sub/Manifest'].path, 'sub/Manifest')
        self.assertEqual(entries['sub/deeper/Manifest'].path, 'deeper/Manifest')
        self.assertEqual(entries['sub/deeper/test'].path, 'test')

    def test_get_file_entry_dict_only_types(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('', only_types=['MANIFEST'])
        self.assertSetEqual(frozenset(entries),
            frozenset((
                'other/Manifest',
                'sub/Manifest',
                'sub/deeper/Manifest',
            )))
        self.assertEqual(entries['other/Manifest'].path, 'other/Manifest')
        self.assertEqual(entries['sub/Manifest'].path, 'sub/Manifest')
        self.assertEqual(entries['sub/deeper/Manifest'].path, 'deeper/Manifest')

    def test_get_file_entry_dict_only_types_DIST(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('', only_types=['DIST'])
        self.assertSetEqual(frozenset(entries),
            frozenset((
                'subdistfile-1.txt',
                'topdistfile-1.txt',
            )))
        self.assertEqual(entries['subdistfile-1.txt'].path, 'subdistfile-1.txt')
        self.assertEqual(entries['topdistfile-1.txt'].path, 'topdistfile-1.txt')

    def test_get_deduplicated_file_entry_dict_for_update(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_deduplicated_file_entry_dict_for_update('')
        self.assertSetEqual(m.updated_manifests, set())
        self.assertSetEqual(frozenset(entries),
            frozenset((
                'other/Manifest',
                'sub/Manifest',
                'sub/deeper/Manifest',
                'sub/deeper/test',
            )))
        self.assertEqual(entries['other/Manifest'][0], 'Manifest')
        self.assertEqual(entries['sub/Manifest'][0], 'Manifest')
        self.assertEqual(entries['sub/deeper/Manifest'][0], 'sub/Manifest')
        self.assertEqual(entries['sub/deeper/test'][0], 'sub/deeper/Manifest')
        self.assertEqual(entries['other/Manifest'][1].path, 'other/Manifest')
        self.assertEqual(entries['sub/Manifest'][1].path, 'sub/Manifest')
        self.assertEqual(entries['sub/deeper/Manifest'][1].path, 'deeper/Manifest')
        self.assertEqual(entries['sub/deeper/test'][1].path, 'test')

    def test_get_file_entry_dict_for_sub(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('sub')
        self.assertSetEqual(frozenset(entries),
            frozenset((
                'sub/Manifest',
                'sub/deeper/Manifest',
                'sub/deeper/test',
            )))
        self.assertEqual(entries['sub/Manifest'].path, 'sub/Manifest')
        self.assertEqual(entries['sub/deeper/Manifest'].path, 'deeper/Manifest')
        self.assertEqual(entries['sub/deeper/test'].path, 'test')

    def test_get_deduplicated_file_entry_dict_for_update_for_sub(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_deduplicated_file_entry_dict_for_update('sub')
        self.assertSetEqual(m.updated_manifests, set())
        self.assertSetEqual(frozenset(entries),
            frozenset((
                'sub/Manifest',
                'sub/deeper/Manifest',
                'sub/deeper/test',
            )))
        self.assertEqual(entries['sub/Manifest'][0], 'Manifest')
        self.assertEqual(entries['sub/deeper/Manifest'][0], 'sub/Manifest')
        self.assertEqual(entries['sub/deeper/test'][0], 'sub/deeper/Manifest')
        self.assertEqual(entries['sub/Manifest'][1].path, 'sub/Manifest')
        self.assertEqual(entries['sub/deeper/Manifest'][1].path, 'deeper/Manifest')
        self.assertEqual(entries['sub/deeper/test'][1].path, 'test')

    def test_get_file_entry_dict_for_invalid(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertDictEqual(m.get_file_entry_dict('nonexist'), {})

    def test_get_deduplicated_file_entry_dict_for_update_for_invalid(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertDictEqual(
                m.get_deduplicated_file_entry_dict_for_update('nonexist'),
                {})
        self.assertSetEqual(m.updated_manifests, set())

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('other')

    def test_assert_directory_verifies_stray_file(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestMismatch,
                m.assert_directory_verifies, 'sub')

    def test_assert_directory_verifies_stray_file_nofail(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertTrue(m.assert_directory_verifies(
                'sub', fail_handler=lambda x: True))

    def test_assert_directory_verifies_stray_file_nofail_false(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertFalse(m.assert_directory_verifies(
                'sub', fail_handler=lambda x: False))

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify',
                os.path.join(self.dir, 'other')]),
            0)

    def test_cli_verifies_stray_file(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify',
                os.path.join(self.dir, 'sub')]),
            1)

    def test_cli_verifies_stray_file_keep_going(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', '--keep-going',
                os.path.join(self.dir, 'sub')]),
            1)

    def test_cli_fails_without_signed_manifest(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify',
                '--require-signed-manifest',
                os.path.join(self.dir, 'other')]),
            1)

    def test_save_manifest(self):
        """
        Test if saving the (unmodified) Manifest works.
        """
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.save_manifest('Manifest')
        with io.open(os.path.join(self.dir, 'Manifest'),
                'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['Manifest'].lstrip())

    def test_save_manifests_unmodified(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'Manifest'),
                'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['Manifest'])
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['sub/Manifest'])
        with io.open(os.path.join(self.dir, 'other/Manifest'),
                'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['other/Manifest'])

    def test_save_manifests_force(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.save_manifests(force=True)
        # Manifest checksums change
        with io.open(os.path.join(self.dir, 'Manifest'),
                'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest'])

    def test_save_manifests_force_sort(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.save_manifests(force=True, sort=True)
        with io.open(os.path.join(self.dir, 'Manifest'),
                'r', encoding='utf8') as f:
            self.assertEqual(f.read(), u'''
DIST topdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST other/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST sub/Manifest 127 MD5 de990fbccb1261da02c7513dfec56045
TIMESTAMP 2017-01-01T01:01:01Z
'''.lstrip())
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                'r', encoding='utf8') as f:
            self.assertEqual(f.read(), u'''
DIST subdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST deeper/Manifest 49 MD5 b86a7748346d54c6455886306f017e6c
'''.lstrip())

    def test_update_entry_for_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('sub/stray', hashes=['SHA256', 'SHA512'])
        self.assertIsInstance(m.find_path_entry('sub/stray'),
                gemato.manifest.ManifestEntryDATA)
        m.save_manifests()
        # relevant Manifests should have been updated
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entry_for_path_MANIFEST(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('sub/stray', hashes=['SHA256', 'SHA512'],
                new_entry_type='MANIFEST')
        self.assertIsInstance(m.find_path_entry('sub/stray'),
                gemato.manifest.ManifestEntryMANIFEST)
        m.save_manifests()
        # relevant Manifests should have been updated
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()
        self.assertIn('sub/stray', m.loaded_manifests)

    def test_update_entry_for_path_MISC(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('sub/stray', hashes=['SHA256', 'SHA512'],
                new_entry_type='MISC')
        self.assertIsInstance(m.find_path_entry('sub/stray'),
                gemato.manifest.ManifestEntryMISC)
        m.save_manifests()
        # relevant Manifests should have been updated
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entry_for_path_EBUILD(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('sub/stray', hashes=['SHA256', 'SHA512'],
                new_entry_type='EBUILD')
        self.assertIsInstance(m.find_path_entry('sub/stray'),
                gemato.manifest.ManifestEntryEBUILD)
        m.save_manifests()
        # relevant Manifests should have been updated
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entry_for_path_AUX_invalid(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(AssertionError,
                m.update_entry_for_path, 'sub/stray',
                hashes=['SHA256', 'SHA512'],
                new_entry_type='AUX')

    def test_update_entry_for_path_nohash(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(AssertionError,
                m.update_entry_for_path, 'sub/stray')

    def test_update_entry_for_path_hash_via_ctor(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entry_for_path('sub/stray')
        self.assertListEqual(
                sorted(m.find_path_entry('sub/stray').checksums),
                ['SHA256', 'SHA512'])
        m.save_manifests()
        # relevant Manifests should have been updated
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entry_for_path_hash_via_ctor_and_override(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entry_for_path('sub/stray', hashes=['MD5'])
        self.assertListEqual(
                sorted(m.find_path_entry('sub/stray').checksums),
                ['MD5'])
        m.save_manifests()
        # relevant Manifests should have been updated
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entry_for_path_discard(self):
        """
        Test that files are not modified if save_manifests()
        is not called.
        """
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('sub/stray', hashes=['SHA256', 'SHA512'])
        self.assertIsInstance(m.find_path_entry('sub/stray'),
                gemato.manifest.ManifestEntryDATA)
        del m
        # relevant Manifests should not have been touched
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                     'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['sub/Manifest'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['Manifest'])

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entries_for_directory('', hashes=['SHA256', 'SHA512'])
        self.assertIsInstance(m.find_path_entry('sub/stray'),
                gemato.manifest.ManifestEntryDATA)
        m.save_manifests()
        # relevant Manifests should have been updated
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_cli_update(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'update', '--hashes=SHA256 SHA512',
                self.dir]),
            0)
        # relevant Manifests should have been updated
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest'])
        m = gemato.manifest.ManifestFile()
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            m.load(f)
        self.assertNotEqual(m.find_timestamp().ts,
                datetime.datetime(2017, 1, 1, 1, 1, 1))

    def test_compress_manifests_low_watermark(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.save_manifests(force=True, compress_watermark=0)
        # top-level Manifest should not be compressed
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'Manifest')))
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'Manifest.gz')))
        # but sub/Manifest should definitely be compressed
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'sub/Manifest')))
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'sub/Manifest.gz')))

    def test_compress_manifests_low_watermark_bz2(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        try:
            m.save_manifests(force=True, compress_watermark=0,
                    compress_format='bz2')
        except gemato.exceptions.UnsupportedCompression:
            raise unittest.SkipTest('bz2 compression unsupported')
        else:
            # top-level Manifest should not be compressed
            self.assertTrue(os.path.exists(
                os.path.join(self.dir, 'Manifest')))
            self.assertFalse(os.path.exists(
                os.path.join(self.dir, 'Manifest.bz2')))
            # but sub/Manifest should definitely be compressed
            self.assertFalse(os.path.exists(
                os.path.join(self.dir, 'sub/Manifest')))
            self.assertTrue(os.path.exists(
                os.path.join(self.dir, 'sub/Manifest.bz2')))

    def test_compress_manifests_low_watermark_lzma(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        try:
            m.save_manifests(force=True, compress_watermark=0,
                    compress_format='lzma')
        except gemato.exceptions.UnsupportedCompression:
            raise unittest.SkipTest('lzma compression unsupported')
        else:
            # top-level Manifest should not be compressed
            self.assertTrue(os.path.exists(
                os.path.join(self.dir, 'Manifest')))
            self.assertFalse(os.path.exists(
                os.path.join(self.dir, 'Manifest.lzma')))
            # but sub/Manifest should definitely be compressed
            self.assertFalse(os.path.exists(
                os.path.join(self.dir, 'sub/Manifest')))
            self.assertTrue(os.path.exists(
                os.path.join(self.dir, 'sub/Manifest.lzma')))

    def test_compress_manifests_low_watermark_xz(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        try:
            m.save_manifests(force=True, compress_watermark=0,
                    compress_format='xz')
        except gemato.exceptions.UnsupportedCompression:
            raise unittest.SkipTest('xz compression unsupported')
        else:
            # top-level Manifest should not be compressed
            self.assertTrue(os.path.exists(
                os.path.join(self.dir, 'Manifest')))
            self.assertFalse(os.path.exists(
                os.path.join(self.dir, 'Manifest.xz')))
            # but sub/Manifest should definitely be compressed
            self.assertFalse(os.path.exists(
                os.path.join(self.dir, 'sub/Manifest')))
            self.assertTrue(os.path.exists(
                os.path.join(self.dir, 'sub/Manifest.xz')))


class MultipleManifestTest(TempDirTestCase):
    DIRS = ['sub']
    FILES = {
        'Manifest': u'''
MANIFEST sub/Manifest.a 50 MD5 33fd9df6d410a93ff859d75e088bde7e
MANIFEST sub/Manifest.b 32 MD5 95737355786df5760d6369a80935cf8a
''',
        'sub/Manifest.a': u'''
DATA foo 32 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/Manifest.b': u'''
TIMESTAMP 2017-01-01T01:01:01Z
''',
        'sub/foo': u'1234567890123456',
    }

    def test_load_sub_manifest(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest.a', m.loaded_manifests)
        self.assertNotIn('sub/Manifest.b', m.loaded_manifests)
        m.load_manifests_for_path('sub/test')
        self.assertIn('sub/Manifest.a', m.loaded_manifests)
        self.assertIn('sub/Manifest.b', m.loaded_manifests)

    def test_load_manifests_recursively(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest.a', m.loaded_manifests)
        self.assertNotIn('sub/Manifest.b', m.loaded_manifests)
        m.load_manifests_for_path('', recursive=True)
        self.assertIn('sub/Manifest.a', m.loaded_manifests)
        self.assertIn('sub/Manifest.b', m.loaded_manifests)

    def test_find_timestamp(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        # here it is expected to fail since TIMESTAMP is supposed
        # to be top-level
        self.assertIsNone(m.find_timestamp())

    def test_verify_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.verify_path('sub/foo'),
                (False, [('__size__', 32, 16)]))

    def test_update_entry_for_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('sub/foo')
        m.save_manifests()
        # relevant Manifests should have been updated
        # but sub/Manifest.b should be left intact
        with io.open(os.path.join(self.dir, 'sub/Manifest.a'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest.a'])
        with io.open(os.path.join(self.dir, 'sub/Manifest.b'),
                     'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['sub/Manifest.b'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entry_for_path_hashes(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('sub/foo', hashes=['SHA256', 'SHA512'])
        # check for checksums
        self.assertListEqual(
                sorted(m.find_path_entry('sub/foo').checksums),
                ['SHA256', 'SHA512'])
        m.save_manifests()
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.a').checksums),
                ['MD5'])
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.b').checksums),
                ['MD5'])
        # relevant Manifests should have been updated
        # but sub/Manifest.b should be left intact
        with io.open(os.path.join(self.dir, 'sub/Manifest.a'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest.a'])
        with io.open(os.path.join(self.dir, 'sub/Manifest.b'),
                     'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['sub/Manifest.b'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entry_for_path_hashes_plus_manifest(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('sub/foo', hashes=['SHA256', 'SHA512'])
        # check for checksums
        self.assertListEqual(
                sorted(m.find_path_entry('sub/foo').checksums),
                ['SHA256', 'SHA512'])
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.a').checksums),
                ['MD5'])
        m.save_manifests(hashes=['SHA1'])
        self.assertListEqual(
                sorted(m.find_path_entry('sub/foo').checksums),
                ['SHA256', 'SHA512'])
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.a').checksums),
                ['SHA1'])
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.b').checksums),
                ['MD5'])
        # relevant Manifests should have been updated
        # but sub/Manifest.b should be left intact
        with io.open(os.path.join(self.dir, 'sub/Manifest.a'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest.a'])
        with io.open(os.path.join(self.dir, 'sub/Manifest.b'),
                     'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['sub/Manifest.b'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entry_for_path_hashes_via_ctor(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entry_for_path('sub/foo')
        # check for checksums
        self.assertListEqual(
                sorted(m.find_path_entry('sub/foo').checksums),
                ['SHA256', 'SHA512'])
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.a').checksums),
                ['MD5'])
        m.save_manifests()
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.a').checksums),
                ['SHA256', 'SHA512'])
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.b').checksums),
                ['MD5'])
        # relevant Manifests should have been updated
        # but sub/Manifest.b should be left intact
        with io.open(os.path.join(self.dir, 'sub/Manifest.a'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest.a'])
        with io.open(os.path.join(self.dir, 'sub/Manifest.b'),
                     'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['sub/Manifest.b'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entry_for_path_hashes_via_ctor_and_override(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entry_for_path('sub/foo', hashes=['SHA1'])
        # check for checksums
        self.assertListEqual(
                sorted(m.find_path_entry('sub/foo').checksums),
                ['SHA1'])
        m.save_manifests()
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.a').checksums),
                ['SHA256', 'SHA512'])
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.b').checksums),
                ['MD5'])
        # relevant Manifests should have been updated
        # but sub/Manifest.b should be left intact
        with io.open(os.path.join(self.dir, 'sub/Manifest.a'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest.a'])
        with io.open(os.path.join(self.dir, 'sub/Manifest.b'),
                     'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['sub/Manifest.b'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entries_for_directory('')
        # check for checksums
        self.assertListEqual(
                sorted(m.find_path_entry('sub/foo').checksums),
                ['SHA256', 'SHA512'])
        m.save_manifests()
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.a').checksums),
                ['SHA256', 'SHA512'])
        self.assertListEqual(
                sorted(m.find_path_entry('sub/Manifest.b').checksums),
                ['SHA256', 'SHA512'])
        # relevant Manifests should have been updated
        # but sub/Manifest.b should be left intact
        with io.open(os.path.join(self.dir, 'sub/Manifest.a'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['sub/Manifest.a'])
        with io.open(os.path.join(self.dir, 'sub/Manifest.b'),
                     'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['sub/Manifest.b'])
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()


class MultipleTopLevelManifestTest(TempDirTestCase):
    FILES = {
        'Manifest': u'''
MANIFEST Manifest.a 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST Manifest.b 32 MD5 95737355786df5760d6369a80935cf8a
''',
        'Manifest.a': u'',
        'Manifest.b': u'''
TIMESTAMP 2017-01-01T01:01:01Z
''',
    }

    def test_load_extra_manifests(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.load_manifests_for_path('')
        self.assertIn('Manifest.a', m.loaded_manifests)
        self.assertIn('Manifest.b', m.loaded_manifests)

    def test_find_timestamp(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_timestamp().ts,
                datetime.datetime(2017, 1, 1, 1, 1, 1))


class DuplicateFileEntryTest(TempDirTestCase):
    """
    Test for specifying the entry for the same file twice.
    """

    FILES = {
        'Manifest': u'''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'test': u'',
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('test').path, 'test')

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('')
        self.assertSetEqual(frozenset(entries), frozenset(('test',)))
        self.assertEqual(entries['test'].path, 'test')

    def test_get_deduplicated_file_entry_dict_for_update(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_deduplicated_file_entry_dict_for_update('')
        self.assertSetEqual(frozenset(entries), frozenset(('test',)))
        self.assertEqual(entries['test'][0], 'Manifest')
        self.assertEqual(entries['test'][1].path, 'test')
        self.assertSetEqual(frozenset(entries['test'][1].checksums),
                            frozenset(('MD5',)))

        m.save_manifests()
        m2 = gemato.manifest.ManifestFile()
        with io.open(os.path.join(self.dir, 'Manifest'), 'r',
                encoding='utf8') as f:
            m2.load(f)
        self.assertEqual(len(m2.entries), 1)

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('')

    def test_set_timestamp(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertIsNone(m.find_timestamp())
        m.set_timestamp(datetime.datetime(2010, 7, 7, 7, 7, 7))
        self.assertEqual(m.find_timestamp().ts,
                datetime.datetime(2010, 7, 7, 7, 7, 7))

    def test_cli_update_with_timestamp(self):
        self.assertEqual(
                gemato.cli.main(['gemato', 'update',
                    '--hashes=SHA256 SHA512',
                    '--timestamp',
                    self.dir]),
                0)

        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertIsNotNone(m.find_timestamp())


class DuplicateManifestFileEntryTest(TempDirTestCase):
    """
    Test for specifying the entry for the same Manifest twice.
    """

    DIRS = ['sub']
    FILES = {
        'Manifest': u'''
MANIFEST sub/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST sub/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/Manifest': u''
    }

    def test_load_sub_manifest(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest', m.loaded_manifests)
        m.load_manifests_for_path('sub/test')
        self.assertIn('sub/Manifest', m.loaded_manifests)


class DuplicateManifestDATAFileEntryTest(TempDirTestCase):
    """
    Test for specifying the entry for the same Manifest as MANIFEST
    and DATA.
    """

    DIRS = ['sub']
    FILES = {
        'Manifest': u'''
DATA sub/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST sub/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/Manifest': u''
    }

    def test_load_sub_manifest(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest', m.loaded_manifests)
        m.load_manifests_for_path('sub/test')
        self.assertIn('sub/Manifest', m.loaded_manifests)


class DuplicateFileEntryInSubManifestTest(TempDirTestCase):
    """
    Test for specifying the entry for the same file twice in different
    Manifest files.
    """

    DIRS = ['sub']
    FILES = {
        'Manifest': u'''
MANIFEST sub/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a
DATA sub/test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/Manifest': u'''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('sub/test').size, 0)

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('')
        self.assertSetEqual(frozenset(entries),
                frozenset(('sub/test', 'sub/Manifest')))
        self.assertEqual(entries['sub/test'].size, 0)

    def test_get_deduplicated_file_entry_dict_for_update(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_deduplicated_file_entry_dict_for_update('')
        self.assertSetEqual(frozenset(entries),
                frozenset(('sub/test', 'sub/Manifest')))
        self.assertEqual(entries['sub/test'][0], 'sub/Manifest')
        self.assertEqual(entries['sub/test'][1].path, 'test')
        self.assertSetEqual(frozenset(entries['sub/test'][1].checksums),
                            frozenset(('MD5',)))

        m.save_manifests()
        m2 = gemato.manifest.ManifestFile()
        with io.open(os.path.join(self.dir, 'Manifest'), 'r',
                encoding='utf8') as f:
            m2.load(f)
        self.assertEqual(len(m2.entries), 1)


class DuplicateCompatibleTypeFileEntryTest(TempDirTestCase):
    """
    Test for specifying the entry for the same file twice, with
    compatible types.
    """

    FILES = {
        'Manifest': u'''
DATA test.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e
EBUILD test.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'test.ebuild': u'',
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('test.ebuild').path, 'test.ebuild')

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('')
        self.assertSetEqual(frozenset(entries), frozenset(('test.ebuild',)))
        self.assertEqual(entries['test.ebuild'].path, 'test.ebuild')

    def test_get_deduplicated_file_entry_dict_for_update(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_deduplicated_file_entry_dict_for_update('')
        self.assertSetEqual(frozenset(entries), frozenset(('test.ebuild',)))
        self.assertEqual(entries['test.ebuild'][0], 'Manifest')
        self.assertEqual(entries['test.ebuild'][1].path, 'test.ebuild')

        m.save_manifests()
        m2 = gemato.manifest.ManifestFile()
        with io.open(os.path.join(self.dir, 'Manifest'), 'r',
                encoding='utf8') as f:
            m2.load(f)
        self.assertEqual(len(m2.entries), 1)

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('')


class DuplicateAUXTypeFileEntryTest(TempDirTestCase):
    """
    Test for specifying the entry for the same file twice, using AUX
    type (because of path weirdness).
    """

    DIRS = ['files']
    FILES = {
        'Manifest': u'''
DATA files/test.patch 0 MD5 d41d8cd98f00b204e9800998ecf8427e
AUX test.patch 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'files/test.patch': u'',
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('files/test.patch').path, 'files/test.patch')

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('')
        self.assertSetEqual(frozenset(entries), frozenset(('files/test.patch',)))
        self.assertEqual(entries['files/test.patch'].path, 'files/test.patch')

    def test_get_deduplicated_file_entry_dict_for_update(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_deduplicated_file_entry_dict_for_update('')
        self.assertSetEqual(frozenset(entries), frozenset(('files/test.patch',)))
        self.assertEqual(entries['files/test.patch'][0], 'Manifest')
        self.assertEqual(entries['files/test.patch'][1].path, 'files/test.patch')

        m.save_manifests()
        m2 = gemato.manifest.ManifestFile()
        with io.open(os.path.join(self.dir, 'Manifest'), 'r',
                encoding='utf8') as f:
            m2.load(f)
        self.assertEqual(len(m2.entries), 1)

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('')

class DuplicateAUXTypeFileRemovalTest(TempDirTestCase):
    DIRS = ['files']
    FILES = {
        'Manifest': u'''
DATA files/test.patch 0 MD5 d41d8cd98f00b204e9800998ecf8427e
AUX test.patch 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }

    def test_update_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('files/test.patch')
        self.assertIsNone(m.find_path_entry('files/test.patch'))
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entry_wrong_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestInvalidPath,
                m.update_entry_for_path, 'test.patch', hashes=['MD5'])

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entries_for_directory('')
        self.assertIsNone(m.find_path_entry('files/test.patch'))
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()


class AUXTypeFileAdditionTest(TempDirTestCase):
    DIRS = ['files']
    FILES = {
        'Manifest': u'',
        'files/test.txt': u'test',
    }

    def test_update_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('files/test.txt',
                hashes=['MD5'], new_entry_type='AUX')
        self.assertIsInstance(m.find_path_entry('files/test.txt'),
                gemato.manifest.ManifestEntryAUX)
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entry_wrong_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(AssertionError,
                m.update_entry_for_path, 'test.txt',
                hashes=['MD5'], new_entry_type='AUX')


class DuplicateDifferentHashSetFileEntryTest(TempDirTestCase):
    """
    Test for specifying the entry for the same file twice,
    with different hash sets (and both of them mismatched).
    """

    FILES = {
        'Manifest': u'''
DATA test 0 MD5 9e107d9d372bb6826bd81d3542a419d6
DATA test 0 SHA1 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
''',
        'test': u'',
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('test').path, 'test')

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('')
        self.assertSetEqual(frozenset(entries), frozenset(('test',)))
        self.assertEqual(entries['test'].path, 'test')
        self.assertSetEqual(frozenset(entries['test'].checksums),
            frozenset(('MD5', 'SHA1')))

    def test_get_deduplicated_file_entry_dict_for_update(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_deduplicated_file_entry_dict_for_update('')
        self.assertSetEqual(frozenset(entries), frozenset(('test',)))
        self.assertEqual(entries['test'][0], 'Manifest')
        self.assertEqual(entries['test'][1].path, 'test')
        self.assertSetEqual(frozenset(entries['test'][1].checksums),
            frozenset(('MD5', 'SHA1')))

        m.save_manifests()
        m2 = gemato.manifest.ManifestFile()
        with io.open(os.path.join(self.dir, 'Manifest'), 'r',
                encoding='utf8') as f:
            m2.load(f)
        self.assertEqual(len(m2.entries), 1)

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        with self.assertRaises(gemato.exceptions.ManifestMismatch) as cm:
            m.assert_directory_verifies('')
        self.assertListEqual(cm.exception.diff,
            [
                ('MD5', '9e107d9d372bb6826bd81d3542a419d6', 'd41d8cd98f00b204e9800998ecf8427e'),
                ('SHA1', '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
            ])

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', self.dir]),
            1)

    def test_update_entry_for_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('test')
        # either of the entries could have been taken
        self.assertIn(
                tuple(m.find_path_entry('test').checksums),
                (('MD5',), ('SHA1',)))
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entries_for_directory('')
        self.assertEqual(m.find_path_entry('test').checksums,
                {
                    'SHA256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                    'SHA512': 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
                })
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()


class DuplicateIncompatibleDataMiscTypeFileEntryTest(TempDirTestCase):
    """
    Test for specifying the entry for the same file twice, with
    incompatible types.
    """

    FILES = {
        'Manifest': u'''
DATA test.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MISC test.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('test.ebuild').path, 'test.ebuild')

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestIncompatibleEntry,
                m.get_file_entry_dict, '')

    def test_get_file_entry_dict_only_types(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('', only_types=['DATA'])
        self.assertListEqual(sorted(entries), ['test.ebuild'])
        self.assertEqual(entries['test.ebuild'].tag, 'DATA')

    def test_deduplicated_get_file_entry_dict_for_update(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestIncompatibleEntry,
                m.get_deduplicated_file_entry_dict_for_update, '')


class DuplicateDifferentSizeFileEntryTest(TempDirTestCase):
    """
    Test for specifying the entry for the same file twice, with
    different sizes.
    """

    FILES = {
        'Manifest': u'''
DATA test.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DATA test.ebuild 32 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('test.ebuild').path, 'test.ebuild')

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestIncompatibleEntry,
                m.get_file_entry_dict, '')

    def test_get_deduplicated_file_entry_dict_for_update(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_deduplicated_file_entry_dict_for_update('')
        self.assertSetEqual(frozenset(entries),
                            frozenset(('test.ebuild',)))
        self.assertEqual(entries['test.ebuild'][0], 'Manifest')
        self.assertIsInstance(entries['test.ebuild'][1],
                gemato.manifest.ManifestEntryDATA)

        m.save_manifests()
        m2 = gemato.manifest.ManifestFile()
        with io.open(os.path.join(self.dir, 'Manifest'), 'r',
                encoding='utf8') as f:
            m2.load(f)
        self.assertEqual(len(m2.entries), 1)


class DuplicateDifferentHashFileEntryTest(TempDirTestCase):
    """
    Test for specifying the entry for the same file twice, with
    different sizes.
    """

    FILES = {
        'Manifest': u'''
DATA test.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DATA test.ebuild 0 MD5 9e107d9d372bb6826bd81d3542a419d6
''',
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('test.ebuild').path, 'test.ebuild')

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestIncompatibleEntry,
                m.get_file_entry_dict, '')

    def test_get_deduplicated_file_entry_dict_for_update(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_deduplicated_file_entry_dict_for_update('')
        self.assertSetEqual(frozenset(entries),
                            frozenset(('test.ebuild',)))
        self.assertEqual(entries['test.ebuild'][0], 'Manifest')
        self.assertIsInstance(entries['test.ebuild'][1],
                gemato.manifest.ManifestEntryDATA)
        self.assertSetEqual(
                frozenset(entries['test.ebuild'][1].checksums),
                frozenset(('MD5',)))

        m.save_manifests()
        m2 = gemato.manifest.ManifestFile()
        with io.open(os.path.join(self.dir, 'Manifest'), 'r',
                encoding='utf8') as f:
            m2.load(f)
        self.assertEqual(len(m2.entries), 1)

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestIncompatibleEntry,
            m.assert_directory_verifies, '')

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', self.dir]),
            1)


class ManifestIgnoreEntryTest(TempDirTestCase):
    """
    Test for a Manifest file with IGNOREs.
    """

    DIRS = ['bar']
    FILES = {
        'Manifest': u'''
IGNORE foo
IGNORE bar
''',
        'foo': u'test',
        'bar/baz': u'test',
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('foo').path, 'foo')
        self.assertEqual(m.find_path_entry('bar').path, 'bar')
        self.assertEqual(m.find_path_entry('bar/baz').path, 'bar')

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('')

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', self.dir]),
            0)


class ManifestMiscEntryTest(TempDirTestCase):
    """
    Test for a Manifest file with MISC.
    """

    FILES = {
        'Manifest': u'''
MISC foo 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestMismatch,
                m.assert_directory_verifies, '')

    def test_assert_directory_verifies_nonstrict_via_fail_handler(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertTrue(m.assert_directory_verifies('',
                fail_handler=lambda x: True))

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', self.dir]),
            1)

    def test_update_entry_for_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entry_for_path('foo')
        self.assertIsNone(m.find_path_entry('foo'))
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entries_for_directory('')
        self.assertIsNone(m.find_path_entry('foo'))
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()


class CrossDeviceManifestTest(TempDirTestCase):
    """
    Test for a Manifest that crosses filesystem boundaries.
    """

    FILES = {
        'Manifest': u'''
DATA sub/version 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
    }

    def setUp(self):
        super(CrossDeviceManifestTest, self).setUp()
        os.symlink('/proc', os.path.join(self.dir, 'sub'))

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestCrossDevice,
                m.assert_directory_verifies, '')

    def test_assert_directory_verifies_nonstrict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestCrossDevice,
                m.assert_directory_verifies, '',
                fail_handler=lambda x: True)

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', self.dir]),
            1)

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        self.assertRaises(gemato.exceptions.ManifestCrossDevice,
                m.update_entries_for_directory, '')

    def test_cli_update(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'update', '--hashes=SHA256 SHA512',
                self.dir]),
            1)


class CrossDeviceEmptyManifestTest(TempDirTestCase):
    """
    Test for a Manifest that crosses filesystem boundaries without
    explicit entries.
    """

    FILES = {
        'Manifest': u'',
    }

    def setUp(self):
        super(CrossDeviceEmptyManifestTest, self).setUp()
        os.symlink('/proc', os.path.join(self.dir, 'sub'))

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestCrossDevice,
                m.assert_directory_verifies, '')

    def test_assert_directory_verifies_nonstrict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestCrossDevice,
                m.assert_directory_verifies, '',
                fail_handler=lambda x: True)

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', self.dir]),
            1)

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        self.assertRaises(gemato.exceptions.ManifestCrossDevice,
                m.update_entries_for_directory, '')

    def test_cli_update(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'update', '--hashes=SHA256 SHA512',
                self.dir]),
            1)


class CrossDeviceIgnoreManifestTest(TempDirTestCase):
    """
    Test for a Manifest that crosses filesystem boundaries without
    explicit entries.
    """

    FILES = {
        'Manifest': u'''
IGNORE sub
''',
    }

    def setUp(self):
        super(CrossDeviceIgnoreManifestTest, self).setUp()
        os.symlink('/proc', os.path.join(self.dir, 'sub'))

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('')

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', self.dir]),
            0)

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entries_for_directory('')
        self.assertEqual(len(m.loaded_manifests['Manifest'].entries), 1)


class DotfileManifestTest(TempDirTestCase):
    """
    Test for implicitly ignoring dotfiles.
    """

    DIRS = ['.bar']
    FILES = {
        'Manifest': u'',
        '.foo': u'',
        '.bar/baz': u'',
    }

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies()

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', self.dir]),
            0)

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entries_for_directory('')
        self.assertIsNone(m.find_path_entry('.bar/baz'))
        self.assertIsNone(m.find_path_entry('.foo'))
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()


class DirectoryInPlaceOfFileManifestTest(TempDirTestCase):
    """
    Test a tree where an expected file was replaced by a directory.
    """

    DIRS = ['test']
    FILES = {
        'Manifest': u'''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''
    }

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestMismatch,
                m.assert_directory_verifies)

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', self.dir]),
            1)

    def test_update_entry_for_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestInvalidPath,
                m.update_entry_for_path, 'test')

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        self.assertRaises(gemato.exceptions.ManifestInvalidPath,
                m.update_entries_for_directory, '')

    def test_cli_update(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'update', '--hashes=SHA256 SHA512',
                self.dir]),
            1)


class UnreadableDirectoryTest(TempDirTestCase):
    """
    Test a tree where a directory can not be read.
    """

    DIRS = ['test']
    FILES = {
        'Manifest': u''
    }

    def setUp(self):
        super(UnreadableDirectoryTest, self).setUp()
        os.chmod(os.path.join(self.dir, 'test'), 0)

    def tearDown(self):
        os.chmod(os.path.join(self.dir, 'test'), 0o555)
        super(UnreadableDirectoryTest, self).tearDown()

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(OSError, m.assert_directory_verifies)

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        self.assertRaises(OSError, m.update_entries_for_directory, '')


class CompressedTopManifestTest(TempDirTestCase):
    """
    Test a tree with top-level Manifest being compressed.
    """

    MANIFEST = b'''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''
    FILES = {
        'test': u'',
    }

    def setUp(self):
        super(CompressedTopManifestTest, self).setUp()
        self.manifest_gz = os.path.join(self.dir, 'Manifest.gz')
        with gzip.GzipFile(self.manifest_gz, 'wb') as f:
            f.write(self.MANIFEST)

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                self.manifest_gz)
        self.assertEqual(m.find_path_entry('test').path, 'test')

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                self.manifest_gz)
        m.assert_directory_verifies('')

    def test_save_manifest(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest.gz'))
        m.save_manifest('Manifest.gz')
        with gemato.compression.open_potentially_compressed_path(
                os.path.join(self.dir, 'Manifest.gz'), 'rb') as f:
            self.assertEqual(f.read(), self.MANIFEST.lstrip())

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest.gz'),
            hashes=['SHA256', 'SHA512'])
        m.update_entries_for_directory('')
        self.assertEqual(m.find_path_entry('test').checksums,
                {
                    'SHA256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                    'SHA512': 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
                })
        m.save_manifests()
        with gemato.compression.open_potentially_compressed_path(
                os.path.join(self.dir, 'Manifest.gz'), 'rb') as f:
            self.assertNotEqual(f.read(), self.MANIFEST.lstrip())
        m.assert_directory_verifies()

    def test_decompress_manifests_low_watermark(self):
        """
        Try decompression with watermark low enough to keep this one
        compressed.
        """
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest.gz'),
            hashes=['SHA256', 'SHA512'])
        m.save_manifests(force=True, compress_watermark=0)
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'Manifest.gz')))

    def test_decompress_manifests_high_watermark(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest.gz'),
            hashes=['SHA256', 'SHA512'])
        m.save_manifests(force=True, compress_watermark=4096)
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'Manifest.gz')))
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'Manifest')))


class CompressedSubManifestTest(TempDirTestCase):
    """
    Test a tree with top-level Manifest being compressed.
    """

    # we can't compress locally here since we need stable result
    SUB_MANIFEST = b'''
H4sICHX68FkCA01hbmlmZXN0AHNxDHFUKEktLlEwUPB1MVVIMTFMsUhOsbRIMzBIMjIwSbW0MDCw
tLRITU6zMDEyT+UCAJqyznMxAAAA
'''
    DIRS = ['sub']
    FILES = {
        'Manifest': u'''
MANIFEST sub/Manifest.gz 78 MD5 9c158f87b2445279d7c8aac439612fba
''',
        'sub/test': u'',
    }

    def setUp(self):
        super(CompressedSubManifestTest, self).setUp()
        self.manifest_gz = os.path.join(self.dir, 'sub/Manifest.gz')
        with io.open(self.manifest_gz, 'wb') as f:
            f.write(base64.b64decode(self.SUB_MANIFEST))

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('sub/test').path, 'test')

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('')

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', self.dir]),
            0)

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entries_for_directory('')
        self.assertEqual(m.find_path_entry('sub/test').checksums,
                {
                    'SHA256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                    'SHA512': 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
                })
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'sub/Manifest.gz'),
                'rb') as f:
            self.assertNotEqual(f.read(),
                    base64.b64decode(self.SUB_MANIFEST))
        m.assert_directory_verifies()

    def test_recompress_manifests_low_watermark(self):
        """
        Try decompression with watermark low enough to keep all
        compressed.
        """
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.save_manifests(force=True, compress_watermark=0)
        self.assertEqual(m.find_path_entry('sub/Manifest.gz').path,
                'sub/Manifest.gz')
        self.assertIsNone(m.find_path_entry('sub/Manifest'))
        # top-level is never compressed
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'Manifest.gz')))
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'Manifest')))
        # sub can be compressed
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'sub/Manifest.gz')))
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'sub/Manifest')))

    def test_recompress_manifests_high_watermark(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.save_manifests(force=True, compress_watermark=4096)
        self.assertEqual(m.find_path_entry('sub/Manifest').path,
                'sub/Manifest')
        self.assertIsNone(m.find_path_entry('sub/Manifest.gz'))
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'Manifest')))
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'sub/Manifest')))
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'Manifest.gz')))
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'sub/Manifest.gz')))

    def test_cli_recompress_manifests_low_watermark(self):
        self.assertEqual(
                gemato.cli.main(['gemato', 'update',
                    '--hashes=SHA256 SHA512',
                    '--compress-watermark=0',
                    self.dir]),
                0)
        # top-level Manifest should not be compressed
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'Manifest')))
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'Manifest.gz')))
        # but sub/Manifest should be compressed
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'sub/Manifest.gz')))
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'sub/Manifest')))

    def test_cli_recompress_manifests_high_watermark(self):
        self.assertEqual(
                gemato.cli.main(['gemato', 'update',
                    '--hashes=SHA256 SHA512',
                    '--compress-watermark=4096',
                    self.dir]),
                0)
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'Manifest')))
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'sub/Manifest')))
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'Manifest.gz')))
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'sub/Manifest.gz')))


class CompressedManifestOrderingTest(TempDirTestCase):
    """
    Compressed Manifest paths can be shorter than regular, resulting
    in wrong sort order.
    """

    MANIFEST = b'''
MANIFEST a/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''
    DIRS = ['a']
    FILES = {
        'a/Manifest': u'',
        'a/stray': u'',
    }

    def setUp(self):
        super(CompressedManifestOrderingTest, self).setUp()
        self.manifest_gz = os.path.join(self.dir, 'Manifest.gz')
        with gzip.GzipFile(self.manifest_gz, 'wb') as f:
            f.write(self.MANIFEST)

    def test__iter_manifests_for_path_order(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                self.manifest_gz)
        m.load_manifests_for_path('', recursive=True)
        self.assertListEqual([d for mpath, d, k
                                in m._iter_manifests_for_path('a')],
            ['a', ''])

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                self.manifest_gz)
        m.update_entries_for_directory('', hashes=['SHA256', 'SHA512'])
        self.assertIsInstance(m.find_path_entry('a/stray'),
                gemato.manifest.ManifestEntryDATA)
        m.save_manifests()
        m.assert_directory_verifies()


class MultipleSubdirectoryFilesTest(TempDirTestCase):
    """
    Regression test for adding a directory with multiple stray files.
    """

    DIRS = ['sub']
    FILES = {
        'Manifest': u'',
        'sub/file.a': u'',
        'sub/file.b': u'',
        'sub/file.c': u'',
    }

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entries_for_directory('', hashes=['SHA256', 'SHA512'])
        self.assertEqual(m.find_path_entry('sub/file.a').path,
                'sub/file.a')
        self.assertEqual(m.find_path_entry('sub/file.b').path,
                'sub/file.b')
        self.assertEqual(m.find_path_entry('sub/file.c').path,
                'sub/file.c')
        m.save_manifests()
        m.assert_directory_verifies()


class UnregisteredManifestTestCase(TempDirTestCase):
    """
    Test for finding a sub-Manifest that's not listed as MANIFEST.
    """

    DIRS = ['sub']
    FILES = {
        'Manifest': u'',
        'sub/Manifest': u'''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/test': u'',
    }

    def test_load_manifests(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest', m.loaded_manifests)
        m.load_manifests_for_path('sub/test')
        self.assertNotIn('sub/Manifest', m.loaded_manifests)

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entries_for_directory('', hashes=['SHA256', 'SHA512'])
        self.assertIn('sub/Manifest', m.loaded_manifests)
        # entry for sub-Manifest should go into parent dir
        # and for test into the sub-Manifest
        self.assertEqual(m.find_path_entry('sub/Manifest').path,
                'sub/Manifest')
        self.assertEqual(m.find_path_entry('sub/test').path, 'test')
        m.save_manifests()
        m.assert_directory_verifies()

    def test_cli_update(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'update', '--hashes=SHA256 SHA512',
                self.dir]),
            0)
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify',
                self.dir]),
            0)


class UnregisteredCompressedManifestTestCase(TempDirTestCase):
    """
    Test for finding a compressed sub-Manifest that's not listed
    as MANIFEST.
    """

    SUB_MANIFEST = b'''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
'''
    DIRS = ['sub']
    FILES = {
        'Manifest': u'',
        'sub/test': u'',
    }

    def setUp(self):
        super(UnregisteredCompressedManifestTestCase, self).setUp()
        self.manifest_gz = os.path.join(self.dir, 'sub/Manifest.gz')
        with gemato.compression.open_potentially_compressed_path(
                os.path.join(self.dir, 'sub/Manifest.gz'), 'wb') as f:
            f.write(self.SUB_MANIFEST)

    def test_load_manifests(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest.gz', m.loaded_manifests)
        m.load_manifests_for_path('sub/test')
        self.assertNotIn('sub/Manifest.gz', m.loaded_manifests)

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entries_for_directory('', hashes=['SHA256', 'SHA512'])
        self.assertIn('sub/Manifest.gz', m.loaded_manifests)
        # entry for sub-Manifest should go into parent dir
        # and for test into the sub-Manifest
        self.assertEqual(m.find_path_entry('sub/Manifest.gz').path,
                'sub/Manifest.gz')
        self.assertEqual(m.find_path_entry('sub/test').path, 'test')
        m.save_manifests()
        m.assert_directory_verifies()

    def test_cli_update(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'update', '--hashes=SHA256 SHA512',
                self.dir]),
            0)
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify',
                self.dir]),
            0)


class InvalidManifestTestCase(TempDirTestCase):
    """
    Test for ignoring a stray "Manifest" file that's invalid.
    """

    DIRS = ['sub']
    FILES = {
        'Manifest': u'',
        'sub/Manifest': u'''
INVALID STUFF IN HERE
''',
        'sub/test': u'',
    }

    def test_load_manifests(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest', m.loaded_manifests)
        m.load_manifests_for_path('sub/test')
        self.assertNotIn('sub/Manifest', m.loaded_manifests)

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entries_for_directory('', hashes=['SHA256', 'SHA512'])
        self.assertNotIn('sub/Manifest', m.loaded_manifests)
        # entry for sub-Manifest should go into parent dir
        # and for test into the sub-Manifest
        self.assertIsInstance(m.find_path_entry('sub/Manifest'),
                gemato.manifest.ManifestEntryDATA)
        self.assertEqual(m.find_path_entry('sub/test').path,
                'sub/test')
        m.save_manifests()
        # ensure that the file was not modified
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['sub/Manifest'])
        m.assert_directory_verifies()

    def test_cli_update(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'update', '--hashes=SHA256 SHA512',
                self.dir]),
            0)
        with io.open(os.path.join(self.dir, 'sub/Manifest'),
                'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['sub/Manifest'])
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify',
                self.dir]),
            0)


class CreateNewManifestTest(TempDirTestCase):
    DIRS = ['sub']
    FILES = {
        'test': u'',
        'sub/test': u'',
    }

    def setUp(self):
        super(CreateNewManifestTest, self).setUp()
        self.path = os.path.join(self.dir, 'Manifest')

    def test_load_without_create(self):
        self.assertRaises(IOError,
                gemato.recursiveloader.ManifestRecursiveLoader,
                self.path)

    def test_create_without_save(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                self.path, allow_create=True)
        del m
        self.assertFalse(os.path.exists(self.path))

    def test_create_empty(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                self.path, allow_create=True)
        m.save_manifests()
        self.assertTrue(os.path.exists(self.path))

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                self.path, allow_create=True, hashes=['MD5'])
        m.update_entries_for_directory('')
        m.save_manifests()
        m.assert_directory_verifies('')

        m2 = gemato.manifest.ManifestFile()
        with io.open(self.path, 'r', encoding='utf8') as f:
            m2.load(f)
        self.assertEqual(len(m2.entries), 2)

    def test_cli(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'create', '--hashes=SHA256 SHA512',
                self.dir]),
            0)

        m2 = gemato.manifest.ManifestFile()
        with io.open(self.path, 'r', encoding='utf8') as f:
            m2.load(f)
        self.assertEqual(len(m2.entries), 2)

        self.assertEqual(
            gemato.cli.main(['gemato', 'verify',
                self.dir]),
            0)

    def test_compress_manifests(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            allow_create=True,
            hashes=['SHA256', 'SHA512'])
        m.save_manifests(force=True, compress_watermark=0)
        # top-level Manifest can not be compressed
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'Manifest')))
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'Manifest.gz')))

    def test_cli_compress_manifests(self):
        self.assertEqual(
                gemato.cli.main(['gemato', 'create',
                    '--hashes=SHA256 SHA512',
                    '--compress-watermark=0',
                    self.dir]),
                0)
        # top-level Manifest can not be compressed
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'Manifest.gz')))
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'Manifest')))


class CreateNewCompressedManifestTest(TempDirTestCase):
    """
    Check that the tooling can create a compressed Manifest file
    when explicitly requested to. Note that this file is not a valid
    top-level Manifest since compressing that file is disallowed.
    """

    DIRS = ['sub']
    FILES = {
        'test': u'',
        'sub/test': u'',
    }

    def setUp(self):
        super(CreateNewCompressedManifestTest, self).setUp()
        self.path = os.path.join(self.dir, 'Manifest.gz')

    def test_load_without_create(self):
        self.assertRaises(IOError,
                gemato.recursiveloader.ManifestRecursiveLoader,
                self.path)

    def test_create_without_save(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                self.path, allow_create=True)
        del m
        self.assertFalse(os.path.exists(self.path))

    def test_create_empty(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                self.path, allow_create=True)
        m.save_manifests()
        with gemato.compression.open_potentially_compressed_path(
                self.path, 'rb') as f:
            self.assertEqual(f.read(), b'')

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                self.path, allow_create=True, hashes=['MD5'])
        m.update_entries_for_directory('')
        m.save_manifests()
        m.assert_directory_verifies('')

        m2 = gemato.manifest.ManifestFile()
        with gemato.compression.open_potentially_compressed_path(
                self.path, 'r', encoding='utf8') as f:
            m2.load(f)
        self.assertEqual(len(m2.entries), 2)

    def test_decompress_manifests_low_watermark(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest.gz'),
            allow_create=True,
            hashes=['SHA256', 'SHA512'])
        m.save_manifests(force=True, compress_watermark=0)
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'Manifest')))
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'Manifest.gz')))

    def test_decompress_manifests_high_watermark(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest.gz'),
            allow_create=True,
            hashes=['SHA256', 'SHA512'])
        m.save_manifests(force=True, compress_watermark=4096)
        self.assertFalse(os.path.exists(
            os.path.join(self.dir, 'Manifest.gz')))
        self.assertTrue(os.path.exists(
            os.path.join(self.dir, 'Manifest')))


class MultipleDeepNestedManifestTest(TempDirTestCase):
    DIRS = ['a', 'a/x', 'a/y', 'a/z', 'b']
    FILES = {
        'Manifest': u'''
MANIFEST a/Manifest 119 MD5 6956767cfbb3276adbdce86cca559719
MANIFEST b/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'test': u'',
        'a/Manifest': u'''
MANIFEST x/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST z/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'a/test': u'',
        'a/x/Manifest': u'',
        'a/x/test': u'',
        'a/y/test': u'',
        'a/z/Manifest': u'',
        'a/z/test': u'',
        'b/Manifest': u'',
        'b/test': u'',
    }

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entries_for_directory('', hashes=['SHA256', 'SHA512'])
        m.save_manifests()
        m.assert_directory_verifies()

    def test_load_unregistered_manifests(self):
        # remove the top Manifest
        os.unlink(os.path.join(self.dir, 'Manifest'))

        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            allow_create=True)
        # we allow extra entries for files that referenced within
        # newly added Manifest
        self.assertListEqual(sorted(m.load_unregistered_manifests('')),
                ['a/Manifest', 'a/x/Manifest', 'a/z/Manifest',
                    'b/Manifest'])
        self.assertIn('a/Manifest', m.loaded_manifests)
        self.assertNotIn('a/Manifest', m.updated_manifests)
        self.assertIsNone(m.find_path_entry('a/Manifest'))
        self.assertIn('b/Manifest', m.loaded_manifests)
        self.assertNotIn('b/Manifest', m.updated_manifests)
        self.assertIsNone(m.find_path_entry('b/Manifest'))

    def test_update_entries_for_directory_without_manifests(self):
        # remove the top Manifest
        os.unlink(os.path.join(self.dir, 'Manifest'))

        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            allow_create=True)
        m.update_entries_for_directory('', hashes=['SHA256', 'SHA512'])
        m.save_manifests()
        m.assert_directory_verifies()

    def test_create_manifest(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertIsNotNone(m.create_manifest('a/y/Manifest'))
        self.assertFalse(os.path.exists(os.path.join(
            self.dir, 'a/y/Manifest')))
        m.loaded_manifests['Manifest'].entries.append(
                gemato.manifest.ManifestEntryMANIFEST(
                    'a/y/Manifest', 0, {}))
        m.save_manifests()
        self.assertTrue(os.path.exists(os.path.join(
            self.dir, 'a/y/Manifest')))


class AddingToMultipleManifestsTest(TempDirTestCase):
    """
    Check that we are handling a directory containing multiple Manifests
    correctly, and that we can cleanly add an additional 'Manifest' file
    in it.
    """

    DIRS = ['a', 'b']
    FILES = {
        'Manifest': u'''
MANIFEST a/Manifest.a 47 MD5 89b9c1e9e5a063ee60b91b632c84c7c8
MANIFEST a/Manifest.b 47 MD5 1b1504046a2023ed75a2a89aed7c52f4
''',
        'a/Manifest.a': u'''
DATA a 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'a/Manifest.b': u'''
DATA b 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'a/Manifest': u'''
DATA c 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'a/a': u'',
        'a/b': u'',
        'a/c': u'',
        'b/test': u'',
    }

    def test_load_unregistered_manifests(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertListEqual(sorted(m.load_unregistered_manifests('')),
                ['a/Manifest'])
        self.assertIn('a/Manifest', m.loaded_manifests)
        self.assertNotIn('a/Manifest', m.updated_manifests)
        self.assertIsNone(m.find_path_entry('a/Manifest'))

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.update_entries_for_directory('', hashes=['SHA256', 'SHA512'])
        m.save_manifests()
        self.assertListEqual(sorted(m.loaded_manifests),
                ['Manifest', 'a/Manifest', 'a/Manifest.a',
                    'a/Manifest.b'])
        self.assertListEqual(sorted(
            e.path for e in m.loaded_manifests['Manifest'].entries),
            ['a/Manifest', 'a/Manifest.a', 'a/Manifest.b', 'b/test'])
        self.assertListEqual(sorted(
            e.path for e in m.loaded_manifests['a/Manifest.a'].entries),
            ['a'])
        self.assertListEqual(sorted(
            e.path for e in m.loaded_manifests['a/Manifest.b'].entries),
            ['b'])
        self.assertListEqual(sorted(
            e.path for e in m.loaded_manifests['a/Manifest'].entries),
            ['c'])
        m.assert_directory_verifies()


class ManifestMTimeTests(TempDirTestCase):
    """
    Tests for mtime-limited verification/update.
    """

    FILES = {
        'Manifest': u'''
DATA test 11 MD5 5f8db599de986fab7a21625b7916589c
''',
        'test': u'test string',
    }

    def test_assert_directory_verifies_old_mtime(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.exceptions.ManifestMismatch,
                m.assert_directory_verifies, '', last_mtime=0)

    def test_assert_directory_verifies_new_mtime(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        st = os.stat(os.path.join(self.dir, 'test'))
        m.assert_directory_verifies('', last_mtime=st.st_mtime)

    def test_update_entries_for_directory_old_mtime(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
                os.path.join(self.dir, 'Manifest'),
                hashes=['MD5'])
        m.update_entries_for_directory('', last_mtime=0)
        self.assertEqual(m.find_path_entry('test').checksums['MD5'],
                '6f8db599de986fab7a21625b7916589c')

    def test_update_entries_for_directory_new_mtime(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
                hashes=['MD5'])
        st = os.stat(os.path.join(self.dir, 'test'))
        m.update_entries_for_directory('', last_mtime=st.st_mtime)
        self.assertEqual(m.find_path_entry('test').checksums['MD5'],
                '5f8db599de986fab7a21625b7916589c')


class ManifestWhitespaceInFilenameTest(TempDirTestCase):
    """
    Test for a Manifest tree where filename contains whitespace.
    """

    FILENAME = '  foo bar  '
    FILES = {
        'Manifest': u'''
DATA \\x20\\x20foo\\x20bar\\x20\\x20 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        FILENAME: u''
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertIsNotNone(m.find_path_entry(self.FILENAME))

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('')

    def test_cli_verifies(self):
        self.assertEqual(
            gemato.cli.main(['gemato', 'verify', self.dir]),
            0)

    def test_rewrite_manifest(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.save_manifests(force=True)
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertEqual(f.read(), self.FILES['Manifest'].lstrip())

    def test_update_entry_for_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA1'])
        m.update_entry_for_path(self.FILENAME)
        self.assertIsNotNone(m.find_path_entry(self.FILENAME))
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()

    def test_update_entries_for_directory(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'),
            hashes=['SHA256', 'SHA512'])
        m.update_entries_for_directory('')
        self.assertIsNotNone(m.find_path_entry(self.FILENAME))
        m.save_manifests()
        with io.open(os.path.join(self.dir, 'Manifest'),
                     'r', encoding='utf8') as f:
            self.assertNotEqual(f.read(), self.FILES['Manifest'])
        m.assert_directory_verifies()


class ManifestBackslashInFilenameTest(ManifestWhitespaceInFilenameTest):
    """
    Test for a Manifest tree where filename contains backslash.
    """

    FILENAME = 'foo\\bar'
    FILES = {
        'Manifest': u'''
DATA foo\\x5Cbar 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        FILENAME: u''
    }
