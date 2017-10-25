# gemato: Top-level Manifest finding tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

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
        if not os.path.exists('/proc'):
            raise unittest.SkipTest('/proc does not exist')
        super(TestCrossDevice, self).setUp()
        os.symlink('/proc', os.path.join(self.dir, 'test'))

    def tearDown(self):
        os.unlink(os.path.join(self.dir, 'test'))
        super(TestCrossDevice, self).tearDown()

    def test_find_top_level_manifest(self):
        self.assertIsNone(
                gemato.find_top_level.find_top_level_manifest(
                    os.path.join(self.dir, 'test')))


class TestCrossDeviceManifest(TempDirTestCase):
    """
    Test behavior when attempting to use a Manifest from other device
    (symlinked).
    """

    DIRS = ['sub']

    def setUp(self):
        if not os.path.exists('/proc/version'):
            raise unittest.SkipTest('/proc/version does not exist')
        super(TestCrossDeviceManifest, self).setUp()
        os.symlink('/proc/version', os.path.join(self.dir, 'Manifest'))

    def tearDown(self):
        os.unlink(os.path.join(self.dir, 'Manifest'))
        super(TestCrossDeviceManifest, self).tearDown()

    def test_find_top_level_manifest(self):
        self.assertIsNone(
                gemato.find_top_level.find_top_level_manifest(
                    os.path.join(self.dir, 'sub')))
