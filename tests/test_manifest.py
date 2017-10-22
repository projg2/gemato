# gemato: Manifest file support tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import io
import unittest

import gemato.manifest


TEST_MANIFEST = '''
TIMESTAMP 2017-10-22T18:06:41Z
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
OPTIONAL ChangeLog
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
'''

TEST_DEPRECATED_MANIFEST = '''
EBUILD myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
AUX test.patch 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
'''


class ManifestTest(unittest.TestCase):
    """
    Basic tests for Manifest processing.
    """

    def test_load(self):
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(TEST_MANIFEST))

    def test_load_deprecated(self):
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(TEST_DEPRECATED_MANIFEST))


class ManifestEntryTest(unittest.TestCase):
    """
    Basic tests for Manifest entries.
    """

    file_vals = ('test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e',
            'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
    exp_cksums = {
        'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
        'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
    }

    def test_TIMESTAMP(self):
        self.assertEqual(gemato.manifest.ManifestEntryTIMESTAMP.from_list(
                    ('TIMESTAMP', '2010-01-01T11:12:13Z')).ts,
                datetime.datetime(2010, 1, 1, 11, 12, 13))

    def test_MANIFEST(self):
        m = gemato.manifest.ManifestEntryMANIFEST.from_list(
                ('MANIFEST',) + self.file_vals)
        self.assertEqual(m.path, 'test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)

    def test_IGNORE(self):
        self.assertEqual(gemato.manifest.ManifestEntryIGNORE.from_list(
                    ('IGNORE', 'test')).path,
                'test')

    def test_DATA(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA',) + self.file_vals)
        self.assertEqual(m.path, 'test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)

    def test_MISC(self):
        m = gemato.manifest.ManifestEntryMISC.from_list(
                ('MISC',) + self.file_vals)
        self.assertEqual(m.path, 'test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)

    def test_OPTIONAL(self):
        self.assertEqual(gemato.manifest.ManifestEntryOPTIONAL.from_list(
                    ('OPTIONAL', 'test')).path,
                'test')

    def test_DIST(self):
        m = gemato.manifest.ManifestEntryDIST.from_list(
                ('DIST',) + self.file_vals)
        self.assertEqual(m.path, 'test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)

    def test_EBUILD(self):
        m = gemato.manifest.ManifestEntryEBUILD.from_list(
                ('EBUILD',) + self.file_vals)
        self.assertEqual(m.path, 'test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)

    def test_AUX(self):
        m = gemato.manifest.ManifestEntryAUX.from_list(
                ('AUX',) + self.file_vals)
        self.assertEqual(m.aux_path, 'test')
        self.assertEqual(m.path, 'files/test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)

    def test_timestamp_invalid(self):
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryTIMESTAMP.from_list, ('TIMESTAMP', '',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryTIMESTAMP.from_list, ('TIMESTAMP', '2017-10-22T18:06:41+02:00',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryTIMESTAMP.from_list, ('TIMESTAMP', '2017-10-22T18:06:41',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryTIMESTAMP.from_list, ('TIMESTAMP', '2017-10-22 18:06:41Z',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryTIMESTAMP.from_list, ('TIMESTAMP', '20171022T180641Z',))

    def test_path_invalid(self):
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', '', '0'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', '/foo', '0'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryIGNORE.from_list, ('IGNORE', '',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryIGNORE.from_list, ('IGNORE', '/foo',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryOPTIONAL.from_list, ('OPTIONAL', '',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryOPTIONAL.from_list, ('OPTIONAL', '/foo',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', '',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', '/foo',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', '',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', '/foo',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', '',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', '/foo',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', 'foo/bar.gz',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', '',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', '/foo',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', '',))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', '/foo',))

    def test_size_invalid(self):
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', 'foo', 'asdf'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', 'foo', '5ds'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', 'foo', '-5'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', 'foo', 'asdf'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', 'foo', '5ds'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', 'foo', '-5'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', 'foo', 'asdf'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', 'foo', '5ds'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', 'foo', '-5'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', 'foo', 'asdf'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', 'foo', '5ds'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', 'foo', '-5'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', 'foo', 'asdf'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', 'foo', '5ds'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', 'foo', '-5'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', 'foo', 'asdf'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', 'foo', '5ds'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', 'foo', '-5'))

    def test_checksum_short(self):
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', 'foo', '0', 'md5'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list,
                ('MANIFEST', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', 'foo', '0', 'md5'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list,
                ('DATA', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', 'foo', '0', 'md5'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list,
                ('MISC', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', 'foo', '0', 'md5'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list,
                ('DIST', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', 'foo', '0', 'md5'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list,
                ('EBUILD', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', 'foo', '0', 'md5'))
        self.assertRaises(gemato.manifest.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list,
                ('AUX', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))
