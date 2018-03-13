# gemato: Verification tests
# vim:fileencoding=utf-8
# (c) 2017-2018 Michał Górny
# Licensed under the terms of 2-clause BSD license

import io
import os
import os.path
import socket
import stat
import tempfile
import unittest

import gemato.exceptions
import gemato.manifest
import gemato.verify


class NonExistingFileVerificationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        os.rmdir(self.dir)

    def test_get_file_metadata(self):
        self.assertEqual(list(gemato.verify.get_file_metadata(
            os.path.join(self.dir, 'test'), hashes=[])),
            [False])

    def testDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0'))
        self.assertEqual(gemato.verify.verify_path(os.path.join(self.dir, e.path), e),
                (False, [('__exists__', True, False)]))

    def testIGNORE(self):
        e = gemato.manifest.ManifestEntryIGNORE.from_list(
                ('IGNORE', 'test'))
        self.assertEqual(gemato.verify.verify_path(os.path.join(self.dir, e.path), e),
                (True, []))

    def testNone(self):
        self.assertEqual(gemato.verify.verify_path(os.path.join(self.dir, 'test'), None),
                (True, []))

    def test_update(self):
        e = gemato.manifest.ManifestEntryDATA('test', 0, {})
        self.assertRaises(gemato.exceptions.ManifestInvalidPath,
                gemato.verify.update_entry_for_path,
                os.path.join(self.dir, 'test'), e)


class DirectoryVerificationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        os.rmdir(self.dir)

    def test_get_file_metadata(self):
        st = os.stat(self.dir)
        self.assertEqual(list(gemato.verify.get_file_metadata(
            self.dir, hashes=[])),
            [True, st.st_dev, (stat.S_IFDIR, 'directory')])

    def testDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.dir), '0'))
        self.assertEqual(gemato.verify.verify_path(self.dir, e),
                (False, [('__type__', 'regular file', 'directory')]))

    def testIGNORE(self):
        e = gemato.manifest.ManifestEntryIGNORE.from_list(
                ('IGNORE', os.path.basename(self.dir)))
        self.assertEqual(gemato.verify.verify_path(self.dir, e),
                (True, []))

    def testNone(self):
        self.assertEqual(gemato.verify.verify_path(self.dir, None),
                (False, [('__exists__', False, True)]))

    def test_update(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.dir), 0, {})
        self.assertRaises(gemato.exceptions.ManifestInvalidPath,
                gemato.verify.update_entry_for_path, self.dir, e)


class CharacterDeviceVerificationTest(unittest.TestCase):
    def setUp(self):
        self.path = '/dev/null'

    def test_get_file_metadata(self):
        st = os.stat(self.path)
        self.assertEqual(list(gemato.verify.get_file_metadata(
            self.path, hashes=[])),
            [True, st.st_dev, (stat.S_IFCHR, 'character device')])

    def testDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__type__', 'regular file', 'character device')]))

    def testIGNORE(self):
        e = gemato.manifest.ManifestEntryIGNORE.from_list(
                ('IGNORE', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testNone(self):
        self.assertEqual(gemato.verify.verify_path(self.path, None),
                (False, [('__exists__', False, True)]))

    def test_update(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {})
        self.assertRaises(gemato.exceptions.ManifestInvalidPath,
                gemato.verify.update_entry_for_path, self.path, e)


class NamedPipeVerificationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'test')
        os.mkfifo(self.path)

    def tearDown(self):
        os.unlink(self.path)
        os.rmdir(self.dir)

    def test_get_file_metadata(self):
        st = os.stat(self.path)
        self.assertEqual(list(gemato.verify.get_file_metadata(
            self.path, hashes=[])),
            [True, st.st_dev, (stat.S_IFIFO, 'named pipe')])

    def testDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__type__', 'regular file', 'named pipe')]))

    def testIGNORE(self):
        e = gemato.manifest.ManifestEntryIGNORE.from_list(
                ('IGNORE', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testNone(self):
        self.assertEqual(gemato.verify.verify_path(self.path, None),
                (False, [('__exists__', False, True)]))

    def test_update(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {})
        self.assertRaises(gemato.exceptions.ManifestInvalidPath,
                gemato.verify.update_entry_for_path, self.path, e)


class UNIXSocketVerificationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'test')
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        self.sock.listen(1)

    def tearDown(self):
        self.sock.close()
        os.unlink(self.path)
        os.rmdir(self.dir)

    def test_get_file_metadata(self):
        st = os.stat(self.path)
        self.assertEqual(list(gemato.verify.get_file_metadata(
            self.path, hashes=[])),
            [True, st.st_dev, (stat.S_IFSOCK, 'UNIX socket')])

    def testDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__type__', 'regular file', 'UNIX socket')]))

    def testIGNORE(self):
        e = gemato.manifest.ManifestEntryIGNORE.from_list(
                ('IGNORE', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testNone(self):
        self.assertEqual(gemato.verify.verify_path(self.path, None),
                (False, [('__exists__', False, True)]))

    def test_update(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {})
        self.assertRaises(gemato.exceptions.ManifestInvalidPath,
                gemato.verify.update_entry_for_path, self.path, e)


class EmptyFileVerificationTest(unittest.TestCase):
    def setUp(self):
        self.f = tempfile.NamedTemporaryFile()
        self.path = self.f.name

    def tearDown(self):
        self.f.close()

    def test_get_file_metadata(self):
        st = os.stat(self.path)
        self.assertEqual(list(gemato.verify.get_file_metadata(
            self.path, hashes=['MD5', 'SHA1'])),
            [True, st.st_dev, (stat.S_IFREG, 'regular file'),
                0, st.st_mtime, {
                    'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
                    'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                    '__size__': 0,
                }])

    def testDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testChecksumDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0',
                    'MD5', 'd41d8cd98f00b204e9800998ecf8427e',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testWrongSizeDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '5'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__size__', 5, 0)]))

    def testWrongSingleChecksumDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0',
                    'MD5', '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('MD5', '9e107d9d372bb6826bd81d3542a419d6', 'd41d8cd98f00b204e9800998ecf8427e')]))

    def testWrongAllChecksumDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0',
                    'MD5', '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1', '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('MD5', '9e107d9d372bb6826bd81d3542a419d6', 'd41d8cd98f00b204e9800998ecf8427e'),
                    ('SHA1', '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12', 'da39a3ee5e6b4b0d3255bfef95601890afd80709')]))

    def testWrongAllChecksumAndSizeDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '39',
                    'MD5', '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1', '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__size__', 39, 0),
                    ('MD5', '9e107d9d372bb6826bd81d3542a419d6', 'd41d8cd98f00b204e9800998ecf8427e'),
                    ('SHA1', '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12', 'da39a3ee5e6b4b0d3255bfef95601890afd80709')]))

    def testIGNORE(self):
        e = gemato.manifest.ManifestEntryIGNORE.from_list(
                ('IGNORE', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testNone(self):
        self.assertEqual(gemato.verify.verify_path(self.path, None),
                (False, [('__exists__', False, True)]))

    def testCrossFilesystem(self):
        if not os.path.ismount('/proc'):
            raise unittest.SkipTest('/proc is not a mountpoint')

        try:
            st = os.stat('/proc')
        except OSError:
            raise unittest.SkipTest('Unable to stat /proc')

        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0'))
        self.assertRaises(gemato.exceptions.ManifestCrossDevice,
                gemato.verify.verify_path, self.path, e,
                expected_dev=st.st_dev)

    def testCrossFilesystemAssert(self):
        if not os.path.ismount('/proc'):
            raise unittest.SkipTest('/proc is not a mountpoint')

        try:
            st = os.stat('/proc')
        except OSError:
            raise unittest.SkipTest('Unable to stat /proc')

        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0'))
        self.assertRaises(gemato.exceptions.ManifestCrossDevice,
                gemato.verify.verify_path, self.path, e,
                expected_dev=st.st_dev)

    def test_update(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {})
        self.assertFalse(
                gemato.verify.update_entry_for_path(self.path, e))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 0)
        self.assertDictEqual(e.checksums, {})

    def test_update_with_hashes(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {})
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e,
                    ['MD5', 'SHA1']))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 0)
        self.assertDictEqual(e.checksums, {
                'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
                'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            })

    def test_update_with_hashes_from_manifest(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {'MD5': '', 'SHA1': ''})
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 0)
        self.assertDictEqual(e.checksums, {
                'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
                'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            })

    def test_update_with_hashes_unchanged(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {
                    'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
                    'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                })
        self.assertFalse(
                gemato.verify.update_entry_for_path(self.path, e,
                    ['MD5', 'SHA1']))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 0)
        self.assertDictEqual(e.checksums, {
                'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
                'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            })

    def test_update_cross_filesystem(self):
        if not os.path.ismount('/proc'):
            raise unittest.SkipTest('/proc is not a mountpoint')

        try:
            st = os.stat('/proc')
        except OSError:
            raise unittest.SkipTest('Unable to stat /proc')

        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {})
        self.assertRaises(gemato.exceptions.ManifestCrossDevice,
                gemato.verify.update_entry_for_path, self.path, e,
                expected_dev=st.st_dev)

    def test_update_MISC(self):
        e = gemato.manifest.ManifestEntryMISC(
                os.path.basename(self.path), 0, {})
        self.assertFalse(
                gemato.verify.update_entry_for_path(self.path, e))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 0)
        self.assertDictEqual(e.checksums, {})

    def test_update_IGNORE(self):
        e = gemato.manifest.ManifestEntryIGNORE(
                os.path.basename(self.path))
        self.assertRaises(AssertionError,
                gemato.verify.update_entry_for_path, self.path, e)

    def test_update_AUX(self):
        e = gemato.manifest.ManifestEntryAUX(
                os.path.basename(self.path), 0, {})
        self.assertFalse(
                gemato.verify.update_entry_for_path(self.path, e))
        self.assertEqual(e.path,
                os.path.join('files', os.path.basename(self.path)))
        self.assertEqual(e.size, 0)
        self.assertDictEqual(e.checksums, {})

    def test_wrong_checksum_DATA_with_old_mtime(self):
        """
        Test whether the checksums are verified if last mtime is older
        than the current one.
        """
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0',
                    'MD5', '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        self.assertEqual(
                gemato.verify.verify_path(self.path, e,
                    last_mtime=0),
                (False, [('MD5', '9e107d9d372bb6826bd81d3542a419d6', 'd41d8cd98f00b204e9800998ecf8427e')]))

    def test_wrong_checksum_DATA_with_new_mtime(self):
        """
        Test whether the checksums are verified if last mtime indicates
        that the file did not change (with st_size == 0).
        """
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0',
                    'MD5', '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        st = os.stat(self.path)
        self.assertEqual(
                gemato.verify.verify_path(self.path, e,
                    last_mtime=st.st_mtime),
                (False, [('MD5', '9e107d9d372bb6826bd81d3542a419d6', 'd41d8cd98f00b204e9800998ecf8427e')]))

    def test_update_with_hashes_and_old_mtime(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {
                    'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                })
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e,
                    ['MD5', 'SHA1'], last_mtime=0))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 0)
        self.assertDictEqual(e.checksums, {
                'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
                'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            })

    def test_update_with_hashes_and_new_mtime(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {
                    'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                })
        st = os.stat(self.path)
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e,
                    ['MD5', 'SHA1'], last_mtime=st.st_mtime))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 0)
        self.assertDictEqual(e.checksums, {
                'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
                'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            })

    def test_None_with_mtime(self):
        """
        Test that mtime does not cause stray files to go unnoticed.
        """
        st = os.stat(self.path)
        self.assertEqual(
                gemato.verify.verify_path(self.path, None,
                    last_mtime=st.st_mtime),
                (False, [('__exists__', False, True)]))


class NonEmptyFileVerificationTest(unittest.TestCase):
    def setUp(self):
        TEST_STRING = b'The quick brown fox jumps over the lazy dog'
        self.f = tempfile.NamedTemporaryFile()
        self.f.write(TEST_STRING)
        self.f.flush()
        self.path = self.f.name

    def tearDown(self):
        self.f.close()

    def test_get_file_metadata(self):
        st = os.stat(self.path)
        self.assertEqual(list(gemato.verify.get_file_metadata(
            self.path, hashes=['MD5', 'SHA1'])),
            [True, st.st_dev, (stat.S_IFREG, 'regular file'),
                st.st_size, st.st_mtime, {
                    'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1': '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
                    '__size__': 43,
                }])

    def testDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '43'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testChecksumDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '43',
                    'MD5', '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1', '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testWrongSizeDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__size__', 0, 43)]))

    def testWrongSingleChecksumDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '43',
                    'MD5', '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')]))

    def testWrongAllChecksumDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '43',
                    'MD5', 'd41d8cd98f00b204e9800998ecf8427e',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('MD5', 'd41d8cd98f00b204e9800998ecf8427e', '9e107d9d372bb6826bd81d3542a419d6'),
                    ('SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')]))

    def testWrongAllChecksumAndSizeDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0',
                    'MD5', 'd41d8cd98f00b204e9800998ecf8427e',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__size__', 0, 43)]))

    def testIGNORE(self):
        e = gemato.manifest.ManifestEntryIGNORE.from_list(
                ('IGNORE', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testNone(self):
        self.assertEqual(gemato.verify.verify_path(self.path, None),
                (False, [('__exists__', False, True)]))

    def test_update(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {})
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 43)
        self.assertDictEqual(e.checksums, {})

    def test_update_with_hashes(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {})
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e,
                    ['MD5', 'SHA1']))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 43)
        self.assertDictEqual(e.checksums, {
                'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                'SHA1': '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
            })

    def test_update_with_hashes_from_manifest(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {'MD5': '', 'SHA1': ''})
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 43)
        self.assertDictEqual(e.checksums, {
                'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                'SHA1': '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
            })

    def test_wrong_checksum_DATA_with_old_mtime(self):
        """
        Test whether the checksums are verified if last mtime is older
        than the current one.
        """
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '43',
                    'MD5', '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        self.assertEqual(
                gemato.verify.verify_path(self.path, e,
                    last_mtime=0),
                (False, [('SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')]))

    def test_wrong_checksum_DATA_with_new_mtime(self):
        """
        Test whether the checksums are verified if last mtime indicates
        that the file did not change.
        """
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '43',
                    'MD5', '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        st = os.stat(self.path)
        self.assertEqual(
                gemato.verify.verify_path(self.path, e,
                    last_mtime=st.st_mtime),
                (True, []))

    def test_wrong_checksum_DATA_with_new_mtime_and_wrong_size(self):
        """
        Test whether the checksums are verified if last mtime indicates
        that the file did not change but size is different.
        """
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '33',
                    'MD5', '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        st = os.stat(self.path)
        self.assertEqual(
                gemato.verify.verify_path(self.path, e,
                    last_mtime=st.st_mtime),
                (False, [('__size__', 33, 43)]))

    def test_update_with_hashes_and_old_mtime(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {
                    'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                })
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e,
                    ['MD5', 'SHA1'], last_mtime=0))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 43)
        self.assertDictEqual(e.checksums, {
                'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                'SHA1': '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
            })

    def test_update_with_hashes_and_new_mtime(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 43, {
                    'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                })
        st = os.stat(self.path)
        self.assertFalse(
                gemato.verify.update_entry_for_path(self.path, e,
                    ['MD5', 'SHA1'], last_mtime=st.st_mtime))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 43)
        self.assertDictEqual(e.checksums, {
                'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            })

    def test_update_with_hashes_and_new_mtime_but_wrong_size(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 33, {
                    'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                })
        st = os.stat(self.path)
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e,
                    ['MD5', 'SHA1'], last_mtime=st.st_mtime))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, 43)
        self.assertDictEqual(e.checksums, {
                'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                'SHA1': '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
            })

    def test_None_with_mtime(self):
        """
        Test that mtime does not cause stray files to go unnoticed.
        """
        st = os.stat(self.path)
        self.assertEqual(
                gemato.verify.verify_path(self.path, None,
                    last_mtime=st.st_mtime),
                (False, [('__exists__', False, True)]))


class SymbolicLinkVerificationTest(NonEmptyFileVerificationTest):
    """
    A variant of regular file test using symlink.
    """

    def setUp(self):
        TEST_STRING = b'The quick brown fox jumps over the lazy dog'
        self.dir = tempfile.mkdtemp()
        self.real_path = os.path.join(self.dir, 'real')
        self.path = os.path.join(self.dir, 'symlink')
        with io.open(self.real_path, 'wb') as f:
            f.write(TEST_STRING)
        os.symlink('real', self.path)

    def tearDown(self):
        os.unlink(self.path)
        os.unlink(self.real_path)
        os.rmdir(self.dir)


class SymbolicLinkDirectoryVerificationTest(DirectoryVerificationTest):
    """
    A variant of directory test using symlink.
    """

    def setUp(self):
        self.top_dir = tempfile.mkdtemp()
        self.real_dir = os.path.join(self.top_dir, 'real')
        self.dir = os.path.join(self.top_dir, 'symlink')
        os.mkdir(self.real_dir)
        os.symlink('real', self.dir)

    def tearDown(self):
        os.unlink(self.dir)
        os.rmdir(self.real_dir)
        os.rmdir(self.top_dir)


class BrokenSymbolicLinkVerificationTest(NonExistingFileVerificationTest):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'test')
        os.symlink('broken', self.path)

    def tearDown(self):
        os.unlink(self.path)
        os.rmdir(self.dir)


class ProcFileVerificationTest(unittest.TestCase):
    """
    Attempt to verify a file from /proc to verify that we can handle
    filesystems that do not report st_size.
    """

    def setUp(self):
        self.path = '/proc/version'
        try:
            with io.open(self.path, 'rb') as f:
                data = f.read()
                st = os.fstat(f.fileno())
        except:
            raise unittest.SkipTest('{} not readable'.format(self.path))

        if st.st_size != 0:
            raise unittest.SkipTest('{} st_size is not 0'.format(self.path))

        self.size = len(data)
        if self.size == 0:
            raise unittest.SkipTest('{} empty'.format(self.path))
        self.md5 = gemato.hash.hash_bytes(data, 'md5')
        self.sha1 = gemato.hash.hash_bytes(data, 'sha1')

    def test_get_file_metadata(self):
        st = os.stat(self.path)
        metadata = list(gemato.verify.get_file_metadata(
            self.path, hashes=['MD5', 'SHA1']))
        # mtime is not meaningful on procfs, and changes with every stat
        metadata[4] = 0
        self.assertEqual(metadata,
            [True, st.st_dev, (stat.S_IFREG, 'regular file'),
                st.st_size, 0, {
                    'MD5': self.md5,
                    'SHA1': self.sha1,
                    '__size__': self.size,
                }])

    def testDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), str(self.size)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testChecksumDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), str(self.size),
                    'MD5', self.md5,
                    'SHA1', self.sha1))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testWrongSizeDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '47474'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__size__', 47474, self.size)]))

    def testWrongSingleChecksumDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), self.size,
                    'MD5', self.md5,
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', self.sha1)]))

    def testWrongAllChecksumDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), self.size,
                    'MD5', 'd41d8cd98f00b204e9800998ecf8427e',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('MD5', 'd41d8cd98f00b204e9800998ecf8427e', self.md5),
                    ('SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', self.sha1)]))

    def testWrongAllChecksumAndSizeDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '47474',
                    'MD5', 'd41d8cd98f00b204e9800998ecf8427e',
                    'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__size__', 47474, self.size),
                    ('MD5', 'd41d8cd98f00b204e9800998ecf8427e', self.md5),
                    ('SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', self.sha1)]))

    def testIGNORE(self):
        e = gemato.manifest.ManifestEntryIGNORE.from_list(
                ('IGNORE', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (True, []))

    def testNone(self):
        self.assertEqual(gemato.verify.verify_path(self.path, None),
                (False, [('__exists__', False, True)]))

    def test_update(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {})
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, self.size)
        self.assertDictEqual(e.checksums, {})

    def test_update_with_hashes(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {})
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e,
                    ['MD5', 'SHA1']))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, self.size)
        self.assertDictEqual(e.checksums, {
                'MD5': self.md5,
                'SHA1': self.sha1,
            })

    def test_update_with_hashes_from_manifest(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {'MD5': '', 'SHA1': ''})
        self.assertTrue(
                gemato.verify.update_entry_for_path(self.path, e))
        self.assertEqual(e.path, os.path.basename(self.path))
        self.assertEqual(e.size, self.size)
        self.assertDictEqual(e.checksums, {
                'MD5': self.md5,
                'SHA1': self.sha1,
            })


class UnreadableFileVerificationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'test')
        with io.open(self.path, 'w'):
            pass
        os.chmod(self.path, 0)

    def tearDown(self):
        os.unlink(self.path)
        os.rmdir(self.dir)

    def test_get_file_metadata(self):
        with self.assertRaises(OSError):
            list(gemato.verify.get_file_metadata(
                os.path.join(self.dir, self.path), []))

    def testDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0'))
        self.assertRaises(OSError, gemato.verify.verify_path,
                os.path.join(self.dir, e.path), e)

    def test_update(self):
        e = gemato.manifest.ManifestEntryDATA(
                os.path.basename(self.path), 0, {})
        self.assertRaises(OSError,
                gemato.verify.update_entry_for_path, self.path, e)


class EntryCompatibilityVerificationTest(unittest.TestCase):
    def test_matching_entry(self):
        e1 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        e2 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        self.assertEqual(gemato.verify.verify_entry_compatibility(e1, e2),
                (True, []))

    def test_compatible_types(self):
        e1 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        e2 = gemato.manifest.ManifestEntryEBUILD.from_list(
                ('EBUILD', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        self.assertEqual(gemato.verify.verify_entry_compatibility(e1, e2),
                (True, []))

    def test_compatible_types_AUX(self):
        e1 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'files/test.patch', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        e2 = gemato.manifest.ManifestEntryAUX.from_list(
                ('AUX', 'test.patch', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        self.assertEqual(gemato.verify.verify_entry_compatibility(e1, e2),
                (True, []))

    def test_compatible_types_MANIFEST(self):
        e1 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        e2 = gemato.manifest.ManifestEntryMANIFEST.from_list(
                ('MANIFEST', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        self.assertEqual(gemato.verify.verify_entry_compatibility(e1, e2),
                (True, []))

    def test_incompatible_types_DATA_MISC(self):
        e1 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        e2 = gemato.manifest.ManifestEntryMISC.from_list(
                ('MISC', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        self.assertEqual(gemato.verify.verify_entry_compatibility(e1, e2),
                (False, [('__type__', 'DATA', 'MISC')]))

    def test_incompatible_types_DATA_IGNORE(self):
        e1 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        e2 = gemato.manifest.ManifestEntryIGNORE.from_list(
                ('IGNORE', 'test'))
        self.assertEqual(gemato.verify.verify_entry_compatibility(e1, e2),
                (False, [('__type__', 'DATA', 'IGNORE')]))

    def test_incompatible_types_DATA_DIST(self):
        e1 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        e2 = gemato.manifest.ManifestEntryDIST.from_list(
                ('DIST', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        self.assertEqual(gemato.verify.verify_entry_compatibility(e1, e2),
                (False, [('__type__', 'DATA', 'DIST')]))

    def test_mismatched_size(self):
        e1 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        e2 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '32', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        self.assertEqual(gemato.verify.verify_entry_compatibility(e1, e2),
                (False, [('__size__', 0, 32)]))

    def test_mismatched_md5(self):
        e1 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        e2 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'MD5', '9e107d9d372bb6826bd81d3542a419d6'))
        self.assertEqual(gemato.verify.verify_entry_compatibility(e1, e2),
                (False, [('MD5', 'd41d8cd98f00b204e9800998ecf8427e', '9e107d9d372bb6826bd81d3542a419d6')]))

    def test_different_hashsets(self):
        e1 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e'))
        e2 = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', 'test', '0', 'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709'))
        self.assertEqual(gemato.verify.verify_entry_compatibility(e1, e2),
                (True, [('MD5', 'd41d8cd98f00b204e9800998ecf8427e', None),
                        ('SHA1', None, 'da39a3ee5e6b4b0d3255bfef95601890afd80709')]))
