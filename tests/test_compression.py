# gemato: compressed file tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import base64
import io
import tempfile
import unittest

import gemato.compression


TEST_STRING = b'The quick brown fox jumps over the lazy dog'
# we need to be specific on endianness to avoid unreliably writing BOM
UTF16_TEST_STRING = TEST_STRING.decode('utf8').encode('utf_16_be')


class GzipCompressionTest(unittest.TestCase):
    BASE64 = b'''
H4sIACbJ8FkAAwvJSFUoLM1MzlZIKsovz1NIy69QyCrNLShWyC9LLVIoAUrnJFZVKqTkpwMAOaNP
QSsAAAA=
'''

    EMPTY_BASE64 = b'''
H4sIACbJ8FkAAwMAAAAAAAAAAAA=
'''

    SPLIT_BASE64 = b'''
H4sIACbJ8FkAAwvJSFUoLM1MzlZIKsovz1NIy69QAADidbCIFAAAAB+LCAAmyfBZAAPLKs0tKFbI
L0stUijJSFXISayqVEjJTwcAlGd4GBcAAAA=
'''

    def test_gzip(self):
        with io.BytesIO(base64.b64decode(self.BASE64)) as f:
            with gemato.compression.open_compressed_file('gz', f, "rb") as gz:
                self.assertEqual(gz.read(), TEST_STRING)

    def test_gzip_empty(self):
        with io.BytesIO(base64.b64decode(self.EMPTY_BASE64)) as f:
            with gemato.compression.open_compressed_file('gz', f, "rb") as gz:
                self.assertEqual(gz.read(), b'')

    def test_gzip_split(self):
        with io.BytesIO(base64.b64decode(self.SPLIT_BASE64)) as f:
            with gemato.compression.open_compressed_file('gz', f, "rb") as gz:
                self.assertEqual(gz.read(), TEST_STRING)

    def test_gzip_write(self):
        with io.BytesIO() as f:
            with gemato.compression.open_compressed_file('gz', f, 'wb') as gz:
                gz.write(TEST_STRING)

            f.seek(0)

            with gemato.compression.open_compressed_file('gz', f, 'rb') as gz:
                self.assertEqual(gz.read(), TEST_STRING)

    def test_open_potentially_compressed_path(self):
        with tempfile.NamedTemporaryFile(suffix='.gz') as wf:
            wf.write(base64.b64decode(self.BASE64))
            wf.flush()

            with gemato.compression.open_potentially_compressed_path(
                    wf.name, 'rb') as cf:
                self.assertEqual(cf.read(), TEST_STRING)

    def test_open_potentially_compressed_path_write(self):
        with tempfile.NamedTemporaryFile(suffix='.gz') as rf:
            with gemato.compression.open_potentially_compressed_path(
                    rf.name, 'wb') as cf:
                cf.write(TEST_STRING)

            with gemato.compression.open_compressed_file('gz', rf, 'rb') as gz:
                self.assertEqual(gz.read(), TEST_STRING)

    def test_open_potentially_compressed_path_with_encoding(self):
        with tempfile.NamedTemporaryFile(suffix='.gz') as wf:
            with gemato.compression.open_compressed_file('gz', wf, 'wb') as gz:
                gz.write(UTF16_TEST_STRING)
            wf.flush()

            with gemato.compression.open_potentially_compressed_path(
                    wf.name, 'r', encoding='utf_16_be') as cf:
                self.assertEqual(cf.read(), TEST_STRING.decode('utf8'))

    def test_open_potentially_compressed_path_write_with_unicode(self):
        with tempfile.NamedTemporaryFile(suffix='.gz') as rf:
            with gemato.compression.open_potentially_compressed_path(
                    rf.name, 'w') as cf:
                cf.write(TEST_STRING.decode('utf8'))

            with gemato.compression.open_compressed_file('gz', rf, 'rb') as gz:
                self.assertEqual(gz.read(), TEST_STRING)

    def test_open_potentially_compressed_path_write_with_encoding(self):
        with tempfile.NamedTemporaryFile(suffix='.gz') as rf:
            with gemato.compression.open_potentially_compressed_path(
                    rf.name, 'w', encoding='utf_16_be') as cf:
                cf.write(TEST_STRING.decode('utf8'))

            with gemato.compression.open_compressed_file('gz', rf, 'rb') as gz:
                self.assertEqual(gz.read(), UTF16_TEST_STRING)

    def test_open_potentially_compressed_path_with_encoding_line_api(self):
        with tempfile.NamedTemporaryFile(suffix='.gz') as wf:
            with gemato.compression.open_compressed_file('gz', wf, 'wb') as gz:
                gz.write(UTF16_TEST_STRING)
            wf.flush()

            with gemato.compression.open_potentially_compressed_path(
                    wf.name, 'r', encoding='utf_16_be') as cf:
                self.assertListEqual([x for x in cf],
                        [TEST_STRING.decode('utf8')])

    def test_open_potentially_compressed_path_fileno_passthrough(self):
        with tempfile.NamedTemporaryFile(suffix='.gz') as rf:
            fs1 = gemato.compression.open_potentially_compressed_path(
                    rf.name, 'w', encoding='utf_16_be')
            with fs1 as cf:
                self.assertListEqual([f.fileno() for f in fs1.files],
                                     [cf.fileno() for f in fs1.files])

            fs2 = gemato.compression.open_potentially_compressed_path(
                    rf.name, 'r', encoding='utf_16_be')
            with fs2 as cf:
                self.assertListEqual([f.fileno() for f in fs2.files],
                                     [cf.fileno() for f in fs2.files])


class Bzip2CompressionTest(unittest.TestCase):
    BASE64 = b'''
QlpoOTFBWSZTWUWd7mEAAAQTgEAABAA////wIAEABTQAAAGigAAAAEBoLtBqVm1CpOmzyfUXAw5P
HXD0304jMvvfF3JFOFCQRZ3uYQ==
'''

    EMPTY_BASE64 = b'''
QlpoORdyRThQkAAAAAA=
'''

    SPLIT_BASE64 = b'''
QlpoOTFBWSZTWQgcCrAAAAITgEAABAAbabLAIABBEaDR6jT9UoAAAbUXZJ48gnMg3xdyRThQkAgc
CrBCWmg5MUFZJlNZOxleaAAABRGAQAAm1t8wIACAUaNDRtTaSgAAAcAcViIdSEhzctM/F3JFOFCQ
OxleaA==
'''

    def test_bzip2(self):
        with io.BytesIO(base64.b64decode(self.BASE64)) as f:
            try:
                with gemato.compression.open_compressed_file('bz2', f, "rb") as bz2:
                    self.assertEqual(bz2.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('bz2 compression unsupported')

    def test_bzip2_empty(self):
        with io.BytesIO(base64.b64decode(self.EMPTY_BASE64)) as f:
            try:
                with gemato.compression.open_compressed_file('bz2', f, "rb") as bz2:
                    self.assertEqual(bz2.read(), b'')
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('bz2 compression unsupported')

    def test_bzip2_split(self):
        with io.BytesIO(base64.b64decode(self.SPLIT_BASE64)) as f:
            try:
                with gemato.compression.open_compressed_file('bz2', f, "rb") as bz2:
                    self.assertEqual(bz2.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('bz2 compression unsupported')

    def test_bzip2_write(self):
        with io.BytesIO() as f:
            try:
                with gemato.compression.open_compressed_file('bz2', f, 'wb') as bz2:
                    bz2.write(TEST_STRING)

                f.seek(0)

                with gemato.compression.open_compressed_file('bz2', f, 'rb') as bz2:
                    self.assertEqual(bz2.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('bz2 compression unsupported')

    def test_open_potentially_compressed_path(self):
        with tempfile.NamedTemporaryFile(suffix='.bz2') as wf:
            wf.write(base64.b64decode(self.BASE64))
            wf.flush()

            try:
                with gemato.compression.open_potentially_compressed_path(
                        wf.name, 'rb') as cf:
                    self.assertEqual(cf.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('bz2 compression unsupported')

    def test_open_potentially_compressed_path_write(self):
        with tempfile.NamedTemporaryFile(suffix='.bz2') as rf:
            try:
                with gemato.compression.open_potentially_compressed_path(
                        rf.name, 'wb') as cf:
                    cf.write(TEST_STRING)

                with gemato.compression.open_compressed_file('bz2', rf, 'rb') as bz2:
                    self.assertEqual(bz2.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('bz2 compression unsupported')

    def test_open_potentially_compressed_path_with_encoding(self):
        with tempfile.NamedTemporaryFile(suffix='.bz2') as wf:
            try:
                with gemato.compression.open_compressed_file('bz2', wf, 'wb') as bz2:
                    bz2.write(UTF16_TEST_STRING)
                wf.flush()

                with gemato.compression.open_potentially_compressed_path(
                        wf.name, 'r', encoding='utf_16_be') as cf:
                    self.assertEqual(cf.read(), TEST_STRING.decode('utf8'))
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('bz2 compression unsupported')

    def test_open_potentially_compressed_path_write_with_unicode(self):
        with tempfile.NamedTemporaryFile(suffix='.bz2') as rf:
            try:
                with gemato.compression.open_potentially_compressed_path(
                        rf.name, 'w') as cf:
                    cf.write(TEST_STRING.decode('utf8'))

                with gemato.compression.open_compressed_file('bz2', rf, 'rb') as bz2:
                    self.assertEqual(bz2.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('bz2 compression unsupported')

    def test_open_potentially_compressed_path_write_with_encoding(self):
        with tempfile.NamedTemporaryFile(suffix='.bz2') as rf:
            try:
                with gemato.compression.open_potentially_compressed_path(
                        rf.name, 'w', encoding='utf_16_be') as cf:
                    cf.write(TEST_STRING.decode('utf8'))

                with gemato.compression.open_compressed_file('bz2', rf, 'rb') as bz2:
                    self.assertEqual(bz2.read(), UTF16_TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('bz2 compression unsupported')

    def test_open_potentially_compressed_path_with_encoding_line_api(self):
        with tempfile.NamedTemporaryFile(suffix='.bz2') as wf:
            try:
                with gemato.compression.open_compressed_file('bz2', wf, 'wb') as bz2:
                    bz2.write(UTF16_TEST_STRING)
                wf.flush()

                with gemato.compression.open_potentially_compressed_path(
                        wf.name, 'r', encoding='utf_16_be') as cf:
                    self.assertListEqual([x for x in cf],
                            [TEST_STRING.decode('utf8')])
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('bz2 compression unsupported')

    def test_open_potentially_compressed_path_fileno_passthrough(self):
        with tempfile.NamedTemporaryFile(suffix='.bz2') as rf:
            try:
                fs1 = gemato.compression.open_potentially_compressed_path(
                        rf.name, 'w', encoding='utf_16_be')
                with fs1 as cf:
                    self.assertListEqual([f.fileno() for f in fs1.files],
                                         [cf.fileno() for f in fs1.files])

                fs2 = gemato.compression.open_potentially_compressed_path(
                        rf.name, 'r', encoding='utf_16_be')
                with fs2 as cf:
                    self.assertListEqual([f.fileno() for f in fs2.files],
                                         [cf.fileno() for f in fs2.files])
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('bz2 compression unsupported')


class LZMALegacyCompressionTest(unittest.TestCase):
    BASE64 = b'''
XQAAAAT//////////wAqGgiiAyVm8Ut4xaIF/y7m2dIgGq00+OId6EE2+twGabs85BA0Jwnrs2bs
Ghcv//zOkAA=
'''

    EMPTY_BASE64 = b'''
XQAAAAT//////////wCD//v//8AAAAA=
'''

    SPLIT_BASE64 = b'''
XQAAAAT//////////wAqGgiiAyVm8Ut4xaIF/y7m2dIgGq1EvQql//X0QABdAAAABP//////////
ADUdSd6zBOkOpekGFH46zix9wE9VT65OVeV479//7uUAAA==
'''

    def test_lzma_legacy(self):
        with io.BytesIO(base64.b64decode(self.BASE64)) as f:
            try:
                with gemato.compression.open_compressed_file('lzma', f, "rb") as lzma:
                    self.assertEqual(lzma.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('lzma compression unsupported')

    def test_lzma_legacy_empty(self):
        with io.BytesIO(base64.b64decode(self.EMPTY_BASE64)) as f:
            try:
                with gemato.compression.open_compressed_file('lzma', f, "rb") as lzma:
                    self.assertEqual(lzma.read(), b'')
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('lzma compression unsupported')

    def test_lzma_legacy_split(self):
        with io.BytesIO(base64.b64decode(self.SPLIT_BASE64)) as f:
            try:
                with gemato.compression.open_compressed_file('lzma', f, "rb") as lzma:
                    self.assertEqual(lzma.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('lzma compression unsupported')

    def test_lzma_legacy_write(self):
        with io.BytesIO() as f:
            try:
                with gemato.compression.open_compressed_file('lzma', f, 'wb') as lzma:
                    lzma.write(TEST_STRING)

                f.seek(0)

                with gemato.compression.open_compressed_file('lzma', f, 'rb') as lzma:
                    self.assertEqual(lzma.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('lzma compression unsupported')

    def test_lzma_legacy_as_xz(self):
        """
        Test that the class rejects mislabel files.
        """
        if gemato.compression.lzma is None:
            raise unittest.SkipTest('xz compression unsupported')

        with io.BytesIO(base64.b64decode(self.BASE64)) as f:
            with self.assertRaises(gemato.compression.lzma.LZMAError):
                with gemato.compression.open_compressed_file('xz', f, "rb") as xz:
                    xz.read()

    def test_open_potentially_compressed_path(self):
        with tempfile.NamedTemporaryFile(suffix='.lzma') as wf:
            wf.write(base64.b64decode(self.BASE64))
            wf.flush()

            try:
                with gemato.compression.open_potentially_compressed_path(
                        wf.name, 'rb') as cf:
                    self.assertEqual(cf.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('lzma compression unsupported')

    def test_open_potentially_compressed_path_write(self):
        with tempfile.NamedTemporaryFile(suffix='.lzma') as rf:
            try:
                with gemato.compression.open_potentially_compressed_path(
                        rf.name, 'wb') as cf:
                    cf.write(TEST_STRING)

                with gemato.compression.open_compressed_file('lzma', rf, 'rb') as lzma:
                    self.assertEqual(lzma.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('lzma compression unsupported')

    def test_open_potentially_compressed_path_with_encoding(self):
        with tempfile.NamedTemporaryFile(suffix='.lzma') as wf:
            try:
                with gemato.compression.open_compressed_file('lzma', wf, 'wb') as lzma:
                    lzma.write(UTF16_TEST_STRING)
                wf.flush()

                with gemato.compression.open_potentially_compressed_path(
                        wf.name, 'r', encoding='utf_16_be') as cf:
                    self.assertEqual(cf.read(), TEST_STRING.decode('utf8'))
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('lzma compression unsupported')

    def test_open_potentially_compressed_path_write_with_unicode(self):
        with tempfile.NamedTemporaryFile(suffix='.lzma') as rf:
            try:
                with gemato.compression.open_potentially_compressed_path(
                        rf.name, 'w') as cf:
                    cf.write(TEST_STRING.decode('utf8'))

                with gemato.compression.open_compressed_file('lzma', rf, 'rb') as lzma:
                    self.assertEqual(lzma.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('lzma compression unsupported')

    def test_open_potentially_compressed_path_write_with_encoding(self):
        with tempfile.NamedTemporaryFile(suffix='.lzma') as rf:
            try:
                with gemato.compression.open_potentially_compressed_path(
                        rf.name, 'w', encoding='utf_16_be') as cf:
                    cf.write(TEST_STRING.decode('utf8'))

                with gemato.compression.open_compressed_file('lzma', rf, 'rb') as lzma:
                    self.assertEqual(lzma.read(), UTF16_TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('lzma compression unsupported')

    def test_open_potentially_compressed_path_with_encoding_line_api(self):
        with tempfile.NamedTemporaryFile(suffix='.lzma') as wf:
            try:
                with gemato.compression.open_compressed_file('lzma', wf, 'wb') as lzma:
                    lzma.write(UTF16_TEST_STRING)
                wf.flush()

                with gemato.compression.open_potentially_compressed_path(
                        wf.name, 'r', encoding='utf_16_be') as cf:
                    self.assertListEqual([x for x in cf],
                            [TEST_STRING.decode('utf8')])
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('lzma compression unsupported')

    def test_open_potentially_compressed_path_fileno_passthrough(self):
        with tempfile.NamedTemporaryFile(suffix='.lzma') as rf:
            try:
                fs1 = gemato.compression.open_potentially_compressed_path(
                        rf.name, 'w', encoding='utf_16_be')
                with fs1 as cf:
                    self.assertListEqual([f.fileno() for f in fs1.files],
                                         [cf.fileno() for f in fs1.files])

                fs2 = gemato.compression.open_potentially_compressed_path(
                        rf.name, 'r', encoding='utf_16_be')
                with fs2 as cf:
                    self.assertListEqual([f.fileno() for f in fs2.files],
                                         [cf.fileno() for f in fs2.files])
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('lzma compression unsupported')


class XZCompressionTest(unittest.TestCase):
    BASE64 = b'''
/Td6WFoAAATm1rRGAgAhARwAAAAQz1jMAQAqVGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVy
IHRoZSBsYXp5IGRvZwAAxKFK5cK4XlsAAUMrrVBuVx+2830BAAAAAARZWg==
'''

    EMPTY_BASE64 = b'''
/Td6WFoAAATm1rRGAAAAABzfRCEftvN9AQAAAAAEWVo=
'''

    SPLIT_BASE64 = b'''
/Td6WFoAAATm1rRGAgAhARwAAAAQz1jMAQATVGhlIHF1aWNrIGJyb3duIGZveCAAIEFC5acaLXcA
ASwU+AptAx+2830BAAAAAARZWv03elhaAAAE5ta0RgIAIQEcAAAAEM9YzAEAFmp1bXBzIG92ZXIg
dGhlIGxhenkgZG9nAADjZCTmHjHqggABLxeBCEmxH7bzfQEAAAAABFla
'''

    def test_xz(self):
        with io.BytesIO(base64.b64decode(self.BASE64)) as f:
            try:
                with gemato.compression.open_compressed_file('xz', f, "rb") as xz:
                    self.assertEqual(xz.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('xz compression unsupported')

    def test_xz_empty(self):
        with io.BytesIO(base64.b64decode(self.EMPTY_BASE64)) as f:
            try:
                with gemato.compression.open_compressed_file('xz', f, "rb") as xz:
                    self.assertEqual(xz.read(), b'')
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('xz compression unsupported')

    def test_xz_split(self):
        with io.BytesIO(base64.b64decode(self.SPLIT_BASE64)) as f:
            try:
                with gemato.compression.open_compressed_file('xz', f, "rb") as xz:
                    self.assertEqual(xz.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('xz compression unsupported')

    def test_xz_write(self):
        with io.BytesIO() as f:
            try:
                with gemato.compression.open_compressed_file('xz', f, 'wb') as xz:
                    xz.write(TEST_STRING)

                f.seek(0)

                with gemato.compression.open_compressed_file('xz', f, 'rb') as xz:
                    self.assertEqual(xz.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('xz compression unsupported')

    def test_xz_as_lzma_legacy(self):
        """
        Test that the class rejects mislabel files.
        """
        if gemato.compression.lzma is None:
            raise unittest.SkipTest('xz compression unsupported')

        with io.BytesIO(base64.b64decode(self.BASE64)) as f:
            with self.assertRaises(gemato.compression.lzma.LZMAError):
                with gemato.compression.open_compressed_file('lzma', f, "rb") as lzma:
                    lzma.read()

    def test_open_potentially_compressed_path(self):
        with tempfile.NamedTemporaryFile(suffix='.xz') as wf:
            wf.write(base64.b64decode(self.BASE64))
            wf.flush()

            try:
                with gemato.compression.open_potentially_compressed_path(
                        wf.name, 'rb') as cf:
                    self.assertEqual(cf.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('xz compression unsupported')

    def test_open_potentially_compressed_path_write(self):
        with tempfile.NamedTemporaryFile(suffix='.xz') as rf:
            try:
                with gemato.compression.open_potentially_compressed_path(
                        rf.name, 'wb') as cf:
                    cf.write(TEST_STRING)

                with gemato.compression.open_compressed_file('xz', rf, 'rb') as xz:
                    self.assertEqual(xz.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('xz compression unsupported')

    def test_open_potentially_compressed_path_with_encoding(self):
        with tempfile.NamedTemporaryFile(suffix='.xz') as wf:
            try:
                with gemato.compression.open_compressed_file('xz', wf, 'wb') as xz:
                    xz.write(UTF16_TEST_STRING)
                wf.flush()

                with gemato.compression.open_potentially_compressed_path(
                        wf.name, 'r', encoding='utf_16_be') as cf:
                    self.assertEqual(cf.read(), TEST_STRING.decode('utf8'))
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('xz compression unsupported')

    def test_open_potentially_compressed_path_write_with_unicode(self):
        with tempfile.NamedTemporaryFile(suffix='.xz') as rf:
            try:
                with gemato.compression.open_potentially_compressed_path(
                        rf.name, 'w') as cf:
                    cf.write(TEST_STRING.decode('utf8'))

                with gemato.compression.open_compressed_file('xz', rf, 'rb') as xz:
                    self.assertEqual(xz.read(), TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('xz compression unsupported')

    def test_open_potentially_compressed_path_write_with_encoding(self):
        with tempfile.NamedTemporaryFile(suffix='.xz') as rf:
            try:
                with gemato.compression.open_potentially_compressed_path(
                        rf.name, 'w', encoding='utf_16_be') as cf:
                    cf.write(TEST_STRING.decode('utf8'))

                with gemato.compression.open_compressed_file('xz', rf, 'rb') as xz:
                    self.assertEqual(xz.read(), UTF16_TEST_STRING)
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('xz compression unsupported')

    def test_open_potentially_compressed_path_with_encoding_line_api(self):
        with tempfile.NamedTemporaryFile(suffix='.xz') as wf:
            try:
                with gemato.compression.open_compressed_file('xz', wf, 'wb') as xz:
                    xz.write(UTF16_TEST_STRING)
                wf.flush()

                with gemato.compression.open_potentially_compressed_path(
                        wf.name, 'r', encoding='utf_16_be') as cf:
                    self.assertListEqual([x for x in cf],
                            [TEST_STRING.decode('utf8')])
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('xz compression unsupported')

    def test_open_potentially_compressed_path_fileno_passthrough(self):
        with tempfile.NamedTemporaryFile(suffix='.xz') as rf:
            try:
                fs1 = gemato.compression.open_potentially_compressed_path(
                        rf.name, 'w', encoding='utf_16_be')
                with fs1 as cf:
                    self.assertListEqual([f.fileno() for f in fs1.files],
                                         [cf.fileno() for f in fs1.files])

                fs2 = gemato.compression.open_potentially_compressed_path(
                        rf.name, 'r', encoding='utf_16_be')
                with fs2 as cf:
                    self.assertListEqual([f.fileno() for f in fs2.files],
                                         [cf.fileno() for f in fs2.files])
            except gemato.exceptions.UnsupportedCompression:
                raise unittest.SkipTest('xz compression unsupported')


class NoCompressionTest(unittest.TestCase):
    """
    Tests for non-compressed data.
    """

    def test_open_potentially_compressed_path(self):
        with tempfile.NamedTemporaryFile() as wf:
            wf.write(TEST_STRING)
            wf.flush()

            with gemato.compression.open_potentially_compressed_path(
                    wf.name, 'rb') as cf:
                self.assertEqual(cf.read(), TEST_STRING)

    def test_open_potentially_compressed_path_write(self):
        with tempfile.NamedTemporaryFile() as rf:
            with gemato.compression.open_potentially_compressed_path(
                    rf.name, 'wb') as cf:
                cf.write(TEST_STRING)

            self.assertEqual(rf.read(), TEST_STRING)

    def test_open_potentially_compressed_path_with_encoding(self):
        with tempfile.NamedTemporaryFile() as wf:
            wf.write(UTF16_TEST_STRING)
            wf.flush()

            with gemato.compression.open_potentially_compressed_path(
                    wf.name, 'r', encoding='utf_16_be') as cf:
                self.assertEqual(cf.read(), TEST_STRING.decode('utf8'))

    def test_open_potentially_compressed_path_write_with_unicode(self):
        with tempfile.NamedTemporaryFile() as rf:
            with gemato.compression.open_potentially_compressed_path(
                    rf.name, 'w') as cf:
                cf.write(TEST_STRING.decode('utf8'))

            self.assertEqual(rf.read(), TEST_STRING)

    def test_open_potentially_compressed_path_write_with_encoding(self):
        with tempfile.NamedTemporaryFile() as rf:
            with gemato.compression.open_potentially_compressed_path(
                    rf.name, 'w', encoding='utf_16_be') as cf:
                cf.write(TEST_STRING.decode('utf8'))

            self.assertEqual(rf.read(), UTF16_TEST_STRING)

    def test_open_potentially_compressed_path_with_encoding_line_api(self):
        with tempfile.NamedTemporaryFile() as wf:
            wf.write(UTF16_TEST_STRING)
            wf.flush()

            with gemato.compression.open_potentially_compressed_path(
                    wf.name, 'r', encoding='utf_16_be') as cf:
                self.assertListEqual([x for x in cf],
                        [TEST_STRING.decode('utf8')])


class OtherUtilityTests(unittest.TestCase):
    def test_get_potential_compressed_names(self):
        self.assertSetEqual(frozenset(gemato.compression
            .get_potential_compressed_names('test')),
            frozenset([
                'test',
                'test.gz',
                'test.bz2',
                'test.lzma',
                'test.xz',
            ]))

    def test_get_compressed_suffix_from_filename(self):
        self.assertEqual(
                gemato.compression.get_compressed_suffix_from_filename(
                    'test.gz'), 'gz')
        self.assertEqual(
                gemato.compression.get_compressed_suffix_from_filename(
                    'test.bz2'), 'bz2')
        self.assertEqual(
                gemato.compression.get_compressed_suffix_from_filename(
                    'test.lzma'), 'lzma')
        self.assertEqual(
                gemato.compression.get_compressed_suffix_from_filename(
                    'test.xz'), 'xz')
        self.assertIsNone(
                gemato.compression.get_compressed_suffix_from_filename(
                    'test'))
