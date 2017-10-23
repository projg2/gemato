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
    DIRS = ['sub', 'sub/deeper']
    FILES = {
        'Manifest': u'''
TIMESTAMP 2017-01-01T01:01:01Z
MANIFEST sub/Manifest 128 MD5 30fd28b98a23031c72793908dd35c530
DIST topdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/Manifest': u'''
MANIFEST deeper/Manifest 50 MD5 0f7cd9ed779a4844f98d28315dd9176a
DIST subdistfile-1.txt 0 MD5 d41d8cd98f00b204e9800998ecf8427e
''',
        'sub/deeper/Manifest': u'''
DATA test 0 MD5 d41d8cd98f00b204e9800998ecf8427e
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

    def test_recursive_load_manifest(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertNotIn('sub/Manifest', m.loaded_manifests)
        self.assertNotIn('sub/deeper/Manifest', m.loaded_manifests)
        m.load_manifests_for_path('sub/deeper/test')
        self.assertIn('sub/Manifest', m.loaded_manifests)
        self.assertIn('sub/deeper/Manifest', m.loaded_manifests)

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
