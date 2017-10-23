# gemato: Verification tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import multiprocessing
import os
import os.path
import socket
import tempfile
import unittest

import gemato.manifest
import gemato.verify


class NonExistingFileVerificationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        os.rmdir(self.dir)

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

    def testOPTIONAL(self):
        e = gemato.manifest.ManifestEntryOPTIONAL.from_list(
                ('OPTIONAL', 'test'))
        self.assertEqual(gemato.verify.verify_path(os.path.join(self.dir, e.path), e),
                (True, []))


class DirectoryVerificationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        os.rmdir(self.dir)

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

    def testOPTIONAL(self):
        e = gemato.manifest.ManifestEntryOPTIONAL.from_list(
                ('OPTIONAL', os.path.basename(self.dir)))
        self.assertEqual(gemato.verify.verify_path(self.dir, e),
                (False, [('__exists__', False, True)]))


class CharacterDeviceVerificationTest(unittest.TestCase):
    def setUp(self):
        self.path = '/dev/null'

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

    def testOPTIONAL(self):
        e = gemato.manifest.ManifestEntryOPTIONAL.from_list(
                ('OPTIONAL', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__exists__', False, True)]))


class NamedPipeVerificationTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'test')
        os.mkfifo(self.path)

    def tearDown(self):
        os.unlink(self.path)
        os.rmdir(self.dir)

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

    def testOPTIONAL(self):
        e = gemato.manifest.ManifestEntryOPTIONAL.from_list(
                ('OPTIONAL', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__exists__', False, True)]))


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

    def testOPTIONAL(self):
        e = gemato.manifest.ManifestEntryOPTIONAL.from_list(
                ('OPTIONAL', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__exists__', False, True)]))


class EmptyFileVerificationTest(unittest.TestCase):
    def setUp(self):
        self.f = tempfile.NamedTemporaryFile()
        self.path = self.f.name

    def tearDown(self):
        self.f.close()

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

    def testOPTIONAL(self):
        e = gemato.manifest.ManifestEntryOPTIONAL.from_list(
                ('OPTIONAL', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
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

    def testOPTIONAL(self):
        e = gemato.manifest.ManifestEntryOPTIONAL.from_list(
                ('OPTIONAL', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__exists__', False, True)]))


class ProcFileVerificationTest(unittest.TestCase):
    """
    Attempt to verify a file from /proc to verify that we can handle
    filesystems that do not report st_size.
    """

    def setUp(self):
        self.path = '/proc/version'
        try:
            with open(self.path, 'rb') as f:
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

    def testOPTIONAL(self):
        e = gemato.manifest.ManifestEntryOPTIONAL.from_list(
                ('OPTIONAL', os.path.basename(self.path)))
        self.assertEqual(gemato.verify.verify_path(self.path, e),
                (False, [('__exists__', False, True)]))


class ExceptionVerificationTest(object):
    def setUp(self):
        TEST_STRING = b'The quick brown fox jumps over the lazy dog'
        self.f = tempfile.NamedTemporaryFile()
        self.f.write(TEST_STRING)
        self.f.flush()
        self.path = self.f.name

    def tearDown(self):
        self.f.close()

    def testDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '43'))
        gemato.verify.assert_path_verifies(self.path, e)

    def testChecksumDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '43',
                    'MD5', '9e107d9d372bb6826bd81d3542a419d6',
                    'SHA1', '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'))
        gemato.verify.assert_path_verifies(self.path, e)

    def testWrongSizeDATA(self):
        e = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA', os.path.basename(self.path), '0'))
        self.assertRaises(gemato.verify.ManifestMismatch,
                gemato.verify.assert_path_verifies, self.path, e)
