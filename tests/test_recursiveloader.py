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


class TempDirTestCase(unittest.TestCase):
    DIRS = []
    FILES = {}

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


class BasicNestingTest(TempDirTestCase):
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

    def test_assert_path_verifies_optional_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_path_verifies('sub/nonstray')

    def test_assert_path_verifies_nonexistent_path(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_path_verifies('sub/deeper/nonexist')

    def test_assert_path_verifies_stray_path(self):
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

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('other')

    def test_assert_directory_verifies_stray_file(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.verify.ManifestMismatch,
                m.assert_directory_verifies, 'sub')


class MultipleManifestTest(TempDirTestCase):
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

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('')


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

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('')


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

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        with self.assertRaises(gemato.verify.ManifestMismatch) as cm:
            m.assert_directory_verifies('')
        self.assertListEqual(cm.exception.diff,
            [
                ('MD5', '9e107d9d372bb6826bd81d3542a419d6', 'd41d8cd98f00b204e9800998ecf8427e'),
                ('SHA1', '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'),
            ])


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
        self.assertRaises(gemato.recursiveloader.ManifestIncompatibleEntry,
                m.get_file_entry_dict, '')


class DuplicateIncompatibleDataOptionalTypeFileEntryTest(TempDirTestCase):
    """
    Test for specifying the entry for the same file twice, with
    incompatible types.
    """

    FILES = {
        'Manifest': u'''
DATA test.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e
OPTIONAL test.ebuild
''',
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('test.ebuild').path, 'test.ebuild')

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.recursiveloader.ManifestIncompatibleEntry,
                m.get_file_entry_dict, '')


class DuplicateIncompatibleMiscOptionalTypeFileEntryTest(TempDirTestCase):
    """
    Test for specifying the entry for the same file twice, with
    incompatible types.
    """

    FILES = {
        'Manifest': u'''
MISC test.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e
OPTIONAL test.ebuild
''',
    }

    def test_find_path_entry(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertEqual(m.find_path_entry('test.ebuild').path, 'test.ebuild')

    def test_get_file_entry_dict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.recursiveloader.ManifestIncompatibleEntry,
                m.get_file_entry_dict, '')


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
        self.assertRaises(gemato.recursiveloader.ManifestIncompatibleEntry,
                m.get_file_entry_dict, '')


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
        self.assertRaises(gemato.recursiveloader.ManifestIncompatibleEntry,
                m.get_file_entry_dict, '')

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.recursiveloader.ManifestIncompatibleEntry,
            m.assert_directory_verifies, '')


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

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('')


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
        self.assertRaises(gemato.verify.ManifestMismatch,
                m.assert_directory_verifies, '')

    def test_assert_directory_verifies_nonstrict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('', strict=False)


class ManifestOptionalEntryTest(TempDirTestCase):
    """
    Test for a Manifest file with OPTIONAL.
    """

    FILES = {
        'Manifest': u'''
OPTIONAL foo
''',
        'foo': u'test',
    }

    def test_assert_directory_verifies(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        self.assertRaises(gemato.verify.ManifestMismatch,
                m.assert_directory_verifies, '')

    def test_assert_directory_verifies_nonstrict(self):
        m = gemato.recursiveloader.ManifestRecursiveLoader(
            os.path.join(self.dir, 'Manifest'))
        m.assert_directory_verifies('', strict=False)
