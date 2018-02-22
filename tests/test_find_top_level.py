# gemato: Top-level Manifest finding tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import gzip
import os
import os.path
import unittest

import gemato.find_top_level

from tests.testutil import TempDirTestCase


class TestCurrentDirectory(TempDirTestCase):
    """
    Test for finding top-level Manifest in a plain tree.
    """

    DIRS = ['suba', 'subb', 'subc', 'subc/sub']
    FILES = {
        'Manifest': u'',
        'subb/Manifest': u'',
        'subc/sub/Manifest': u'',
    }

    def test_find_top_level_manifest(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(self.dir),
                    self.dir),
                'Manifest')

    def test_find_top_level_manifest_from_empty_subdir(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        os.path.join(self.dir, 'suba')),
                    self.dir),
                'Manifest')

    def test_find_top_level_manifest_from_manifest_subdir(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        os.path.join(self.dir, 'subb')),
                    self.dir),
                'Manifest')

    def test_find_top_level_manifest_from_deep_manifest_subdir(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        os.path.join(self.dir, 'subc', 'sub')),
                    self.dir),
                'Manifest')


class TestUnreadableManifest(TempDirTestCase):
    """
    Test whether the function fails correctly when it can not read
    a Manifest file.
    """

    FILES = {
        'Manifest': u'',
    }

    def setUp(self):
        super(TestUnreadableManifest, self).setUp()
        os.chmod(os.path.join(self.dir, 'Manifest'), 0)

    def test_find_top_level_manifest(self):
        self.assertRaises(IOError,
                gemato.find_top_level.find_top_level_manifest, self.dir)


class TestIgnoredSubdir(TempDirTestCase):
    """
    Test for ignoring irrelevant Manifest.
    """

    DIRS = ['sub', 'sub/sub', 'subb', 'subempty']
    FILES = {
        'Manifest': u'''
IGNORE sub
IGNORE subempty
''',
        'sub/Manifest': u'',
    }

    def test_find_top_level_manifest(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(self.dir),
                    self.dir),
                'Manifest')

    def test_find_top_level_manifest_from_ignored_subdir(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        os.path.join(self.dir, 'sub')),
                    self.dir),
                'sub/Manifest')

    def test_find_top_level_manifest_from_sub_subdir(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        os.path.join(self.dir, 'sub/sub')),
                    self.dir),
                'sub/Manifest')

    def test_find_top_level_manifest_from_non_ignored_subdir(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        os.path.join(self.dir, 'subb')),
                    self.dir),
                'Manifest')

    def test_find_top_level_manifest_from_ignored_empty_subdir(self):
        self.assertIsNone(
                gemato.find_top_level.find_top_level_manifest(
                    os.path.join(self.dir, 'subempty')))


class TestEmptyTree(TempDirTestCase):
    """
    Test for finding top-level Manifest in a tree without a Manifest
    """

    def test_find_top_level_manifest(self):
        self.assertIsNone(
                gemato.find_top_level.find_top_level_manifest(self.dir))


class TestRootDirectory(unittest.TestCase):
    """
    Test behavior when run on the system root directory.
    """

    def test_find_top_level_manifest(self):
        if os.path.exists('/Manifest'):
            raise unittest.SkipTest('/Manifest is present')
        self.assertIsNone(
                gemato.find_top_level.find_top_level_manifest('/'))


class TestCrossDevice(TempDirTestCase):
    """
    Test behavior when attempting to cross device boundary.
    """

    FILES = {
        'Manifest': u'',
    }

    def setUp(self):
        if not os.path.ismount('/proc'):
            raise unittest.SkipTest('/proc is not a mountpoint')
        super(TestCrossDevice, self).setUp()
        os.symlink('/proc', os.path.join(self.dir, 'test'))

    def test_find_top_level_manifest(self):
        self.assertIsNone(
                gemato.find_top_level.find_top_level_manifest(
                    os.path.join(self.dir, 'test')))


class TestCompressedManifest(TempDirTestCase):
    """
    Test for finding compressed Manifest in a plain tree.
    """

    DIRS = ['suba', 'subb', 'subc', 'subc/sub']
    FILES = {
        'subb/Manifest': u'',
    }

    def setUp(self):
        super(TestCompressedManifest, self).setUp()
        with gzip.GzipFile(os.path.join(self.dir, 'Manifest.gz'), 'wb'):
            pass
        with gzip.GzipFile(os.path.join(self.dir, 'subc/sub/Manifest.gz'), 'wb'):
            pass

    def test_find_top_level_manifest_no_allow_compressed(self):
        self.assertIsNone(
                gemato.find_top_level.find_top_level_manifest(self.dir))

    def test_find_top_level_manifest(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        self.dir, allow_compressed=True),
                    self.dir),
                'Manifest.gz')

    def test_find_top_level_manifest_from_empty_subdir(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        os.path.join(self.dir, 'suba'),
                        allow_compressed=True),
                    self.dir),
                'Manifest.gz')

    def test_find_top_level_manifest_from_manifest_subdir(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        os.path.join(self.dir, 'subb'),
                        allow_compressed=True),
                    self.dir),
                'Manifest.gz')

    def test_find_top_level_manifest_from_deep_manifest_subdir(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        os.path.join(self.dir, 'subc', 'sub'),
                        allow_compressed=True),
                    self.dir),
                'Manifest.gz')


class TestCompressedManifestWithIgnore(TempDirTestCase):
    DIRS = ['suba', 'subb', 'subc', 'subc/sub']
    FILES = {
        'subb/Manifest': u'',
    }

    def setUp(self):
        super(TestCompressedManifestWithIgnore, self).setUp()
        with gzip.GzipFile(os.path.join(self.dir, 'Manifest.gz'), 'wb') as f:
            f.write(b'IGNORE suba\n')
            f.write(b'IGNORE subc\n')
        with gzip.GzipFile(os.path.join(self.dir, 'subc/sub/Manifest.gz'), 'wb'):
            pass

    def test_find_top_level_manifest(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        self.dir, allow_compressed=True),
                    self.dir),
                'Manifest.gz')

    def test_find_top_level_manifest_from_ignored_empty_subdir(self):
        self.assertIsNone(
                gemato.find_top_level.find_top_level_manifest(
                    os.path.join(self.dir, 'suba'),
                    allow_compressed=True))

    def test_find_top_level_manifest_from_manifest_subdir(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        os.path.join(self.dir, 'subb'),
                        allow_compressed=True),
                    self.dir),
                'Manifest.gz')

    def test_find_top_level_manifest_from_deep_ignored_subdir(self):
        self.assertEqual(
                os.path.relpath(
                    gemato.find_top_level.find_top_level_manifest(
                        os.path.join(self.dir, 'subc', 'sub'),
                        allow_compressed=True),
                    self.dir),
                'subc/sub/Manifest.gz')
