# gemato: Manifest file support tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import io
import unittest

import gemato.exceptions
import gemato.manifest


TEST_MANIFEST = u'''
TIMESTAMP 2017-10-22T18:06:41Z
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DATA foo.txt 0
'''

TEST_DEPRECATED_MANIFEST = u'''
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

    def test_load_via_ctor(self):
        gemato.manifest.ManifestFile(io.StringIO(TEST_MANIFEST))

    def test_load_and_dump(self):
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(TEST_MANIFEST))
        outf = io.StringIO()
        m.dump(outf)
        self.assertEqual(outf.getvalue().strip(), TEST_MANIFEST.strip())

    def test_load_and_dump_deprecated(self):
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(TEST_DEPRECATED_MANIFEST))
        outf = io.StringIO()
        m.dump(outf)
        self.assertEqual(outf.getvalue().strip(), TEST_DEPRECATED_MANIFEST.strip())

    def test_find_timestamp(self):
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(TEST_MANIFEST))
        self.assertEqual(m.find_timestamp().ts,
                datetime.datetime(2017, 10, 22, 18, 6, 41))

    def test_find_timestamp_none(self):
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(u''))
        self.assertIsNone(m.find_timestamp())

    def test_find_path_entry(self):
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(TEST_MANIFEST))
        self.assertIsNone(m.find_path_entry('2017-10-22T18:06:41Z'))
        self.assertEqual(m.find_path_entry('eclass/Manifest').path, 'eclass/Manifest')
        self.assertIsNone(m.find_path_entry('eclass'))
        self.assertEqual(m.find_path_entry('local').path, 'local')
        self.assertEqual(m.find_path_entry('local/foo').path, 'local')
        self.assertIsNone(m.find_path_entry('locale'))
        self.assertEqual(m.find_path_entry('myebuild-0.ebuild').path, 'myebuild-0.ebuild')
        self.assertEqual(m.find_path_entry('metadata.xml').path, 'metadata.xml')
        self.assertIsNone(m.find_path_entry('mydistfile.tar.gz'))

    def test_find_path_entry_AUX(self):
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(TEST_DEPRECATED_MANIFEST))
        self.assertIsNone(m.find_path_entry('test.patch'))
        self.assertEqual(m.find_path_entry('files/test.patch').aux_path, 'test.patch')

    def test_find_dist_entry(self):
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(TEST_MANIFEST))
        self.assertIsNone(m.find_dist_entry('myebuild-0.ebuild'))
        self.assertEqual(m.find_dist_entry('mydistfile.tar.gz').path, 'mydistfile.tar.gz')

    def test_find_manifests_for_path(self):
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(TEST_MANIFEST))
        self.assertListEqual(list(m.find_manifests_for_path('foo')), [])
        self.assertListEqual(list(m.find_manifests_for_path('eclass')), [])
        self.assertListEqual(list(m.find_manifests_for_path('eclass/foo.eclass')),
                [m.find_path_entry('eclass/Manifest')])

    def test_multiple_load(self):
        """
        Test that calling load() multiple times overwrites previously
        loaded data.
        """
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(TEST_MANIFEST))
        m.load(io.StringIO(TEST_DEPRECATED_MANIFEST))
        self.assertIsNone(m.find_timestamp())
        self.assertIsNone(m.find_path_entry('eclass/Manifest'))

    def test_sorted(self):
        m = gemato.manifest.ManifestFile()
        m.load(io.StringIO(TEST_MANIFEST))
        with io.StringIO() as f:
            m.dump(f, sort=True)
            self.assertEqual(f.getvalue(), u'''
DATA foo.txt 0
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
TIMESTAMP 2017-10-22T18:06:41Z
'''.lstrip())


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
        self.assertListEqual(list(gemato.manifest.ManifestEntryTIMESTAMP(
                    datetime.datetime(2010, 1, 1, 11, 12, 13)).to_list()),
                ['TIMESTAMP', '2010-01-01T11:12:13Z'])

    def test_MANIFEST(self):
        m = gemato.manifest.ManifestEntryMANIFEST.from_list(
                ('MANIFEST',) + self.file_vals)
        self.assertEqual(m.path, 'test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)
        self.assertListEqual(list(m.to_list()),
                ['MANIFEST'] + list(self.file_vals))

    def test_IGNORE(self):
        self.assertEqual(gemato.manifest.ManifestEntryIGNORE.from_list(
                    ('IGNORE', 'test')).path,
                'test')
        self.assertListEqual(list(gemato.manifest.ManifestEntryIGNORE('test').to_list()),
                ['IGNORE', 'test'])

    def test_DATA(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(
                ('DATA',) + self.file_vals)
        self.assertEqual(m.path, 'test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)
        self.assertListEqual(list(m.to_list()),
                ['DATA'] + list(self.file_vals))

    def test_MISC(self):
        m = gemato.manifest.ManifestEntryMISC.from_list(
                ('MISC',) + self.file_vals)
        self.assertEqual(m.path, 'test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)
        self.assertListEqual(list(m.to_list()),
                ['MISC'] + list(self.file_vals))

    def test_DIST(self):
        m = gemato.manifest.ManifestEntryDIST.from_list(
                ('DIST',) + self.file_vals)
        self.assertEqual(m.path, 'test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)
        self.assertListEqual(list(m.to_list()),
                ['DIST'] + list(self.file_vals))

    def test_EBUILD(self):
        m = gemato.manifest.ManifestEntryEBUILD.from_list(
                ('EBUILD',) + self.file_vals)
        self.assertEqual(m.path, 'test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)
        self.assertListEqual(list(m.to_list()),
                ['EBUILD'] + list(self.file_vals))

    def test_AUX(self):
        m = gemato.manifest.ManifestEntryAUX.from_list(
                ('AUX',) + self.file_vals)
        self.assertEqual(m.aux_path, 'test')
        self.assertEqual(m.path, 'files/test')
        self.assertEqual(m.size, 0)
        self.assertDictEqual(m.checksums, self.exp_cksums)
        self.assertListEqual(list(m.to_list()),
                ['AUX'] + list(self.file_vals))

    def test_timestamp_invalid(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryTIMESTAMP.from_list, ('TIMESTAMP',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryTIMESTAMP.from_list, ('TIMESTAMP', ''))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryTIMESTAMP.from_list, ('TIMESTAMP', '2017-10-22T18:06:41+02:00'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryTIMESTAMP.from_list, ('TIMESTAMP', '2017-10-22T18:06:41'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryTIMESTAMP.from_list, ('TIMESTAMP', '2017-10-22', '18:06:41Z'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryTIMESTAMP.from_list, ('TIMESTAMP', '20171022T180641Z'))

    def test_path_invalid(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', '', '0'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', '/foo', '0'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryIGNORE.from_list, ('IGNORE', '',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryIGNORE.from_list, ('IGNORE', '/foo',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', '',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', '/foo',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', '',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', '/foo',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', '',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', '/foo',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', 'foo/bar.gz',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', '',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', '/foo',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', '',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', '/foo',))

    def test_size_invalid(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', 'foo', 'asdf'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', 'foo', '5ds'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', 'foo', '-5'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', 'foo', 'asdf'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', 'foo', '5ds'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', 'foo', '-5'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', 'foo', 'asdf'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', 'foo', '5ds'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', 'foo', '-5'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', 'foo', 'asdf'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', 'foo', '5ds'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', 'foo', '-5'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', 'foo', 'asdf'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', 'foo', '5ds'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', 'foo', '-5'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', 'foo', 'asdf'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', 'foo', '5ds'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', 'foo', '-5'))

    def test_checksum_short(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', 'foo', '0', 'md5'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list,
                ('MANIFEST', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', 'foo', '0', 'md5'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list,
                ('DATA', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', 'foo', '0', 'md5'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list,
                ('MISC', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', 'foo', '0', 'md5'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list,
                ('DIST', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', 'foo', '0', 'md5'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list,
                ('EBUILD', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', 'foo', '0', 'md5'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list,
                ('AUX', 'foo', '0', 'md5', 'd41d8cd98f00b204e9800998ecf8427e', 'sha1'))

    def test_invalid_value_count(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMANIFEST.from_list, ('MANIFEST', 'foo'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryIGNORE.from_list, ('IGNORE',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryIGNORE.from_list, ('IGNORE', 'foo', 'bar'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list, ('DATA', 'foo'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryMISC.from_list, ('MISC', 'foo'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDIST.from_list, ('DIST', 'foo'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryEBUILD.from_list, ('EBUILD', 'foo'))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX',))
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryAUX.from_list, ('AUX', 'foo'))


class ManifestUtilityTest(unittest.TestCase):
    def test_manifest_hashes_to_hashlib(self):
        self.assertListEqual(list(
                gemato.manifest.manifest_hashes_to_hashlib(['MD5', 'SHA1'])),
            ['md5', 'sha1'])
        self.assertListEqual(list(
                gemato.manifest.manifest_hashes_to_hashlib(['RMD160'])),
            ['ripemd160'])
        self.assertListEqual(list(
                gemato.manifest.manifest_hashes_to_hashlib(['SHA3_256', 'SHA256'])),
            ['sha3_256', 'sha256'])


class NewManifestEntryTest(unittest.TestCase):
    """
    Tests for new_manifest_entry().
    """

    def test_TIMESTAMP(self):
        self.assertIsInstance(
                gemato.manifest.new_manifest_entry('TIMESTAMP',
                    datetime.datetime(2000, 1, 1, 0, 0, 0)),
                gemato.manifest.ManifestEntryTIMESTAMP)

    def test_MANIFEST(self):
        self.assertIsInstance(
                gemato.manifest.new_manifest_entry('MANIFEST',
                    'test', 32, {}),
                gemato.manifest.ManifestEntryMANIFEST)

    def test_IGNORE(self):
        self.assertIsInstance(
                gemato.manifest.new_manifest_entry('IGNORE', 'test'),
                gemato.manifest.ManifestEntryIGNORE)

    def test_DATA(self):
        self.assertIsInstance(
                gemato.manifest.new_manifest_entry('DATA',
                    'test', 32, {}),
                gemato.manifest.ManifestEntryDATA)

    def test_MISC(self):
        self.assertIsInstance(
                gemato.manifest.new_manifest_entry('MISC',
                    'test', 32, {}),
                gemato.manifest.ManifestEntryMISC)

    def test_DIST(self):
        self.assertIsInstance(
                gemato.manifest.new_manifest_entry('DIST',
                    'test', 32, {}),
                gemato.manifest.ManifestEntryDIST)

    def test_EBUILD(self):
        self.assertIsInstance(
                gemato.manifest.new_manifest_entry('EBUILD',
                    'test', 32, {}),
                gemato.manifest.ManifestEntryEBUILD)

    def test_AUX(self):
        self.assertIsInstance(
                gemato.manifest.new_manifest_entry('AUX',
                    'test', 32, {}),
                gemato.manifest.ManifestEntryAUX)


class ManifestPathEncodingTest(unittest.TestCase):
    """
    Tests for path encoding.
    """

    def test_encode_space_in_filename(self):
        m = gemato.manifest.new_manifest_entry('DATA',
            'tes t', 32, {})
        self.assertEqual(m.path, 'tes t')
        self.assertListEqual(list(m.to_list()),
                ['DATA', 'tes\\x20t', '32'])

    def test_encode_tab_in_filename(self):
        m = gemato.manifest.new_manifest_entry('DATA',
            'tes\tt', 32, {})
        self.assertEqual(m.path, 'tes\tt')
        self.assertListEqual(list(m.to_list()),
                ['DATA', 'tes\\x09t', '32'])

    def test_encode_nbsp_in_filename(self):
        m = gemato.manifest.new_manifest_entry('DATA',
            u'tes\u00a0t', 32, {})
        self.assertEqual(m.path, u'tes\u00a0t')
        self.assertListEqual(list(m.to_list()),
                ['DATA', 'tes\\u00A0t', '32'])

    def test_encode_en_quad_in_filename(self):
        m = gemato.manifest.new_manifest_entry('DATA',
            u'tes\u2000t', 32, {})
        self.assertEqual(m.path, u'tes\u2000t')
        self.assertListEqual(list(m.to_list()),
                ['DATA', 'tes\\u2000t', '32'])

    def test_encode_null_in_filename(self):
        m = gemato.manifest.new_manifest_entry('DATA',
            'tes\x00t', 32, {})
        self.assertEqual(m.path, 'tes\x00t')
        self.assertListEqual(list(m.to_list()),
                ['DATA', 'tes\\x00t', '32'])

    def test_encode_bell_in_filename(self):
        m = gemato.manifest.new_manifest_entry('DATA',
            'tes\at', 32, {})
        self.assertEqual(m.path, 'tes\at')
        self.assertListEqual(list(m.to_list()),
                ['DATA', 'tes\\x07t', '32'])

    def test_encode_del_in_filename(self):
        m = gemato.manifest.new_manifest_entry('DATA',
            'tes\x7Ft', 32, {})
        self.assertEqual(m.path, 'tes\x7Ft')
        self.assertListEqual(list(m.to_list()),
                ['DATA', 'tes\\x7Ft', '32'])

    def test_encode_pad_in_filename(self):
        m = gemato.manifest.new_manifest_entry('DATA',
            u'tes\u0080t', 32, {})
        self.assertEqual(m.path, u'tes\u0080t')
        self.assertListEqual(list(m.to_list()),
                ['DATA', 'tes\\u0080t', '32'])

    def test_encode_backslash_in_filename(self):
        m = gemato.manifest.new_manifest_entry('DATA',
            'tes\\t', 32, {})
        self.assertEqual(m.path, 'tes\\t')
        self.assertListEqual(list(m.to_list()),
                ['DATA', 'tes\\x5Ct', '32'])

    def test_decode_space_in_filename(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\x20t', 32])
        self.assertEqual(m.path, 'tes t')

    def test_decode_space_in_filename_u(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\u0020t', 32])
        self.assertEqual(m.path, 'tes t')

    def test_decode_space_in_filename_lu(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\U00000020t', 32])
        self.assertEqual(m.path, 'tes t')

    def test_decode_tab_in_filename(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\x09t', 32])
        self.assertEqual(m.path, 'tes\tt')

    def test_decode_nbsp_in_filename(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\u00A0t', 32])
        self.assertEqual(m.path, u'tes\u00a0t')

    def test_decode_nbsp_in_filename_lc(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\u00a0t', 32])
        self.assertEqual(m.path, u'tes\u00a0t')

    def test_decode_en_quad_in_filename(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\u2000t', 32])
        self.assertEqual(m.path, u'tes\u2000t')

    def test_decode_null_in_filename(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\x00t', 32])
        self.assertEqual(m.path, 'tes\x00t')

    def test_decode_bell_in_filename(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\x07t', 32])
        self.assertEqual(m.path, 'tes\at')

    def test_decode_del_in_filename(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\x7Ft', 32])
        self.assertEqual(m.path, 'tes\x7Ft')

    def test_decode_del_in_filename_lc(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\x7ft', 32])
        self.assertEqual(m.path, 'tes\x7Ft')

    def test_decode_pad_in_filename(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\u0080t', 32])
        self.assertEqual(m.path, u'tes\u0080t')

    def test_decode_backslash_in_filename(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\x5Ct', 32])
        self.assertEqual(m.path, 'tes\\t')

    def test_decode_backslash_in_filename_lc(self):
        m = gemato.manifest.ManifestEntryDATA.from_list(['DATA',
            'tes\\x5ct', 32])
        self.assertEqual(m.path, 'tes\\t')

    def test_decode_invalid_backslash_in_filename(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list,
                ['DATA', 'tes\\t', 32])

    def test_decode_double_backslash_in_filename(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list,
                ['DATA', 'tes\\\\t', 32])

    def test_decode_trailing_backslash_in_filename(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list,
                ['DATA', 'tes\\', 32])

    def test_decode_empty_x_in_filename(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list,
                ['DATA', 'tes\\xt', 32])

    def test_decode_short_x_in_filename(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list,
                ['DATA', 'tes\\x5t', 32])

    def test_decode_empty_u_in_filename(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list,
                ['DATA', 'tes\\ut', 32])

    def test_decode_short_u_in_filename(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list,
                ['DATA', 'tes\\u345t', 32])

    def test_decode_empty_lu_in_filename(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list,
                ['DATA', 'tes\\Ut', 32])

    def test_decode_short_lu_in_filename(self):
        self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                gemato.manifest.ManifestEntryDATA.from_list,
                ['DATA', 'tes\\U0000345t', 32])
