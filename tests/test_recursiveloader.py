# gemato: Recursive loader tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import io
import os
import tempfile
import unittest

import gemato.recursiveloader


class BasicNestingTest(unittest.TestCase):
    DIRS = ['sub', 'sub/deeper', 'other']
    FILES = {
        'Manifest': u'''
TIMESTAMP 2017-01-01T01:01:01Z
MANIFEST sub/Manifest 146 MD5 81180715a77069664b4b695e53bb856d
MANIFEST other/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e
DIST topdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/Manifest': u'''
MANIFEST deeper/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a
OPTIONAL nonstray
DIST subdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/stray': u'',
        'sub/deeper/Manifest': u'''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/deeper/test': u'',
        'other/Manifest': u'',
    }

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        for k in self.DIRS:
            os.mkdir(os.path.join(self.dir, k))
        for k, v in self.FILES.items():
            with io.open(os.path.join(self.dir, k), 'w', encoding='utf8') as f:
                f.write(v)

    def tearDown(self):
        for k in self.FILES:
            os.unlink(os.path.join(self.dir, k))
        for k in reversed(self.DIRS):
            os.rmdir(os.path.join(self.dir, k))
        os.rmdir(self.dir)

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

    def test_verify_optional_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.verify_path('sub/nonstray'), (True, []))

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

    def test_verify_optional_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_path_verifies('sub/nonstray')

    def test_verify_nonexistent_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_path_verifies('sub/deeper/nonexist')

    def test_verify_stray_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.verify.ManifestMismatch,
                m.assert_path_verifies, 'sub/stray')

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('')
        self.assertSetEqual(frozenset(entries),
            frozenset((
                'other/Manifest',
                'sub/Manifest',
                'sub/nonstray',
                'sub/deeper/Manifest',
                'sub/deeper/test',
            )))
        self.assertEqual(entries['other/Manifest'].path, 'other/Manifest')
        self.assertEqual(entries['sub/Manifest'].path, 'sub/Manifest')
        self.assertEqual(entries['sub/nonstray'].path, 'nonstray')
        self.assertEqual(entries['sub/deeper/Manifest'].path, 'deeper/Manifest')
        self.assertEqual(entries['sub/deeper/test'].path, 'test')

    def test_get_file_entry_dict_for_sub(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        entries = m.get_file_entry_dict('sub')
        self.assertSetEqual(frozenset(entries),
            frozenset((
                'sub/Manifest',
                'sub/nonstray',
                'sub/deeper/Manifest',
                'sub/deeper/test',
            )))
        self.assertEqual(entries['sub/Manifest'].path, 'sub/Manifest')
        self.assertEqual(entries['sub/nonstray'].path, 'nonstray')
        self.assertEqual(entries['sub/deeper/Manifest'].path, 'deeper/Manifest')
        self.assertEqual(entries['sub/deeper/test'].path, 'test')

    def test_get_file_entry_dict_for_invalid(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertDictEqual(m.get_file_entry_dict('nonexist'), {})


class MultipleManifestTest(unittest.TestCase):
    DIRS = ['sub']
    FILES = {
        'Manifest': u'''
MANIFEST sub/Manifest.a 0 MD5 d41d8cd98f00b204e9800998ecf8427e
MANIFEST sub/Manifest.b 32 MD5 95737355786df5760d6369a80935cf8a
''',
        'sub/Manifest.a': u'',
        'sub/Manifest.b': u'''
TIMESTAMP 2017-01-01T01:01:01Z
''',
    }

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        for k in self.DIRS:
            os.mkdir(os.path.join(self.dir, k))
        for k, v in self.FILES.items():
            with io.open(os.path.join(self.dir, k), 'w', encoding='utf8') as f:
                f.write(v)

    def tearDown(self):
        for k in self.FILES:
            os.unlink(os.path.join(self.dir, k))
        for k in reversed(self.DIRS):
            os.rmdir(os.path.join(self.dir, k))
        os.rmdir(self.dir)

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


class MultipleTopLevelManifestTest(unittest.TestCase):
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

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        for k, v in self.FILES.items():
            with io.open(os.path.join(self.dir, k), 'w', encoding='utf8') as f:
                f.write(v)

    def tearDown(self):
        for k in self.FILES:
            os.unlink(os.path.join(self.dir, k))
        os.rmdir(self.dir)

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
