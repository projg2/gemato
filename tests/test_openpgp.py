# gemato: OpenPGP signature support tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import io
import unittest

import gemato.manifest
import gemato.openpgp


PUBLIC_KEY = u'''
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFnwXJMBCACgaTVz+d10TGL9zR920sb0GBFsitAJ5ZFzO4E0cg3SHhwI+reM
JQ6LLKmHowY/E1dl5FBbnJoRMxXP7/eScQ7HlhYj1gMPN5XiS2pkPwVkmJKBDV42
DLwoytC+ot0frRTJvSdEPCX81BNMgFiBSpkeZfXqb9XmU03bh6mFnrdd4CsHpTQG
csVXHK8QKhaxuqmHTALdpSzKCb/r0N/Z3sQExZhfLcBf/9UUVXj44Nwc6ooqZLRi
zHydxwQdxNu0aOFGEBn9WTi8Slf7MfR/pF0dI8rs9w6zMzVEq0lhDPpKFGDveoGf
g/+TpvBNXZ7DWH23GM4kID3pk4LLMc24U1PhABEBAAG0D2dlbWF0byB0ZXN0IGtl
eYkBRgQTAQoAMBYhBIHhLBa9jc1gvhgIRRNogOcqexOEBQJZ8FyTAhsDBQsJCg0E
AxUKCAIeAQIXgAAKCRATaIDnKnsThCnkB/0fhTH230idhlfZhFbVgTLxrj4rpsGg
20K8HkMaWzChsONdKkqYaYuRcm2UQZ0Kg5rm9jQsGYuAnzH/7XwmOleY95ycVfBk
je9aXF6BEoGick6C/AK5w77vd1kcBtJDrT4I7vwD4wRkyUdCkpVMVT4z4aZ7lHJ4
ECrrrI/mg0b+sGRyHfXPvIPp7F2959L/dpbhBZDfMOFC0A9LBQBJldKFbQLg3xzX
4tniz/BBrp7KjTOMKU0sufsedI50xc6cvCYCwJElqo86vv69klZHahE/k9nJaUAM
jCvJNJ7pU8YnJSRTQDH0PZEupAdzDU/AhGSrBz5+Jr7N0pQIxq4duE/Q
=r7JK
-----END PGP PUBLIC KEY BLOCK-----
'''

MALFORMED_PUBLIC_KEY = u'''
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFnwXJMBCACgaTVz+d10TGL9zR920sb0GBFsitAJ5ZFzO4E0cg3SHhwI+reM
JQ6LLKmHowY/E1dl5FBbnJoRMxXP7/eScQ7HlhYj1gMPN5XiS2pkPwVkmJKBDV42
DLwoytC+ot0frRTJvSdEPCX81BNMgFiBSpkeZfXqb9XmU03bh6mFnrdd4CsHpTQG
csVXHK8QKhaxuqmHTALdpSzKCb/r0N/Z3sQExZhfLcBf/9UUVXj44Nwc6ooqZLRi
zHydxwQdxNu0aOFGEBn9WTi8Slf7MfR/pF0dI8rs9w6zMzVEq0lhDPpKFGDveoGf
g/+TpvBNXZ7DWH23GM4kID3pk4LLMc24U1PhABEBAAG0D2dlbWF0byB0ZXN0IGtl
eYkBRgQTAQoAMBYhBIHhLBa9jc1gvhgIRRNogOcqexOEBQJZ8FyTAhsDBQsJCg0E
AxUKCAIeAQIXgAAKCRATaIDnKnsThCnkB/0fhTH230idhlfZhFbVgTLxrj4rpsGg
20K8HkMaWzshsONdKkqYaYuRcm2UQZ0Kg5rm9jQsGYuAnzH/7XwmOleY95ycVfBk
je9aXF6BEoGick6C/AK5w77vd1kcBtJDrT4I7vwD4wRkyUdCkpVMVT4z4aZ7lHJ4
ECrrrI/mg0b+sGRyHfXPvIPp7F2959L/dpbhBZDfMOFC0A9LBQBJldKFbQLg3xzX
4tniz/BBrp7KjTOMKU0sufsedI50xc6cvCYCwJElqo86vv69klZHahE/k9nJaUAM
jCvJNJ7pU8YnJSRTQDH0PZEupAdzDU/AhGSrBz5+Jr7N0pQIxq4duE/Q
=r7JK
-----END PGP PUBLIC KEY BLOCK-----
'''

SIGNED_MANIFEST = u'''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

TIMESTAMP 2017-10-22T18:06:41Z
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
OPTIONAL ChangeLog
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
-----BEGIN PGP SIGNATURE-----

iQGTBAEBCgB9FiEEgeEsFr2NzWC+GAhFE2iA5yp7E4QFAlnwXQpfFIAAAAAALgAo
aXNzdWVyLWZwckBub3RhdGlvbnMub3BlbnBncC5maWZ0aGhvcnNlbWFuLm5ldDgx
RTEyQzE2QkQ4RENENjBCRTE4MDg0NTEzNjg4MEU3MkE3QjEzODQACgkQE2iA5yp7
E4ScZAf+IF4suRtuN3bJki2zyYV/1VtSekK96tO+IzXxXDY0OKXmf61R6ZuuXcUD
Q+DlBONMILG+CDY+qiDp6snEWPmeLuh57qjkxilTgEX88W7OSCSdvGzSbC5WIRQG
KHtfZWtVVrZHTzQ6MF3u2Vombkpra/CQrf4Yx+8zdkorsoXwZ6ZjriB3W/zTUWIJ
XUy2tNfupdu72q9ske3dhVLhUEjtBzq5MlTf6gUjLBEsIHCGSafO2VG00lii3q4E
14EEilADJlKAOwK5WQUmAOjeeC60ck5EW5tGBotncd954v6n42pwlVXVmqSOJdYy
9F1V8N1m6n9UEUQ7Hhrv/+BTDPJO0A==
=9naF
-----END PGP SIGNATURE-----
'''

DASH_ESCAPED_SIGNED_MANIFEST = u'''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

- TIMESTAMP 2017-10-22T18:06:41Z
- MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
- DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
- OPTIONAL ChangeLog
- DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
-----BEGIN PGP SIGNATURE-----

iQGTBAEBCgB9FiEEgeEsFr2NzWC+GAhFE2iA5yp7E4QFAlnwXQpfFIAAAAAALgAo
aXNzdWVyLWZwckBub3RhdGlvbnMub3BlbnBncC5maWZ0aGhvcnNlbWFuLm5ldDgx
RTEyQzE2QkQ4RENENjBCRTE4MDg0NTEzNjg4MEU3MkE3QjEzODQACgkQE2iA5yp7
E4ScZAf+IF4suRtuN3bJki2zyYV/1VtSekK96tO+IzXxXDY0OKXmf61R6ZuuXcUD
Q+DlBONMILG+CDY+qiDp6snEWPmeLuh57qjkxilTgEX88W7OSCSdvGzSbC5WIRQG
KHtfZWtVVrZHTzQ6MF3u2Vombkpra/CQrf4Yx+8zdkorsoXwZ6ZjriB3W/zTUWIJ
XUy2tNfupdu72q9ske3dhVLhUEjtBzq5MlTf6gUjLBEsIHCGSafO2VG00lii3q4E
14EEilADJlKAOwK5WQUmAOjeeC60ck5EW5tGBotncd954v6n42pwlVXVmqSOJdYy
9F1V8N1m6n9UEUQ7Hhrv/+BTDPJO0A==
=9naF
-----END PGP SIGNATURE-----
'''

MODIFIED_SIGNED_MANIFEST = u'''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

TIMESTAMP 2017-10-22T18:06:41Z
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 32
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
OPTIONAL ChangeLog
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
-----BEGIN PGP SIGNATURE-----

iQGTBAEBCgB9FiEEgeEsFr2NzWC+GAhFE2iA5yp7E4QFAlnwXQpfFIAAAAAALgAo
aXNzdWVyLWZwckBub3RhdGlvbnMub3BlbnBncC5maWZ0aGhvcnNlbWFuLm5ldDgx
RTEyQzE2QkQ4RENENjBCRTE4MDg0NTEzNjg4MEU3MkE3QjEzODQACgkQE2iA5yp7
E4ScZAf+IF4suRtuN3bJki2zyYV/1VtSekK96tO+IzXxXDY0OKXmf61R6ZuuXcUD
Q+DlBONMILG+CDY+qiDp6snEWPmeLuh57qjkxilTgEX88W7OSCSdvGzSbC5WIRQG
KHtfZWtVVrZHTzQ6MF3u2Vombkpra/CQrf4Yx+8zdkorsoXwZ6ZjriB3W/zTUWIJ
XUy2tNfupdu72q9ske3dhVLhUEjtBzq5MlTf6gUjLBEsIHCGSafO2VG00lii3q4E
14EEilADJlKAOwK5WQUmAOjeeC60ck5EW5tGBotncd954v6n42pwlVXVmqSOJdYy
9F1V8N1m6n9UEUQ7Hhrv/+BTDPJO0A==
=9naF
-----END PGP SIGNATURE-----
'''


class SignedManifestTest(unittest.TestCase):
    """
    Test whether signed Manifest is read correctly.
    """

    def test_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(SIGNED_MANIFEST) as f:
            m.load(f)
        self.assertIsNotNone(m.find_timestamp())
        self.assertIsNotNone(m.find_path_entry('myebuild-0.ebuild'))

    def test_dash_escaped_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(DASH_ESCAPED_SIGNED_MANIFEST) as f:
            m.load(f)
        self.assertIsNotNone(m.find_timestamp())
        self.assertIsNotNone(m.find_path_entry('myebuild-0.ebuild'))

    def test_modified_manifest_load(self):
        """
        Modified Manifest should load correctly since we do not enforce
        implicit verification.
        """
        m = gemato.manifest.ManifestFile()
        with io.StringIO(MODIFIED_SIGNED_MANIFEST) as f:
            m.load(f)
        self.assertIsNotNone(m.find_timestamp())
        self.assertIsNotNone(m.find_path_entry('myebuild-0.ebuild'))

    def test_junk_before_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO('OPTIONAL test\n' + SIGNED_MANIFEST) as f:
            self.assertRaises(gemato.exceptions.ManifestUnsignedData,
                    m.load, f)

    def test_junk_after_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(SIGNED_MANIFEST + 'OPTIONAL test\n') as f:
            self.assertRaises(gemato.exceptions.ManifestUnsignedData,
                    m.load, f)


class OpenPGPCorrectKeyTest(unittest.TestCase):
    """
    Tests performed with correct OpenPGP key set.
    """

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(
                    io.BytesIO(PUBLIC_KEY.encode('utf8')))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))
        except RuntimeError:
            raise unittest.SkipTest('Unable to import OpenPGP key')

    def tearDown(self):
        self.env.close()

    def test_verify_manifest(self):
        with io.BytesIO(SIGNED_MANIFEST.encode('utf8')) as f:
            self.env.verify_file(f)

    def test_verify_dash_escaped_manifest(self):
        with io.BytesIO(DASH_ESCAPED_SIGNED_MANIFEST.encode('utf8')) as f:
            self.env.verify_file(f)

    def test_verify_modified_manifest(self):
        with io.BytesIO(MODIFIED_SIGNED_MANIFEST.encode('utf8')) as f:
            self.assertRaises(gemato.exceptions.OpenPGPVerificationFailure,
                    self.env.verify_file, f)


class OpenPGPNoKeyTest(unittest.TestCase):
    """
    Tests performed without correct OpenPGP key set.
    """

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()

    def tearDown(self):
        self.env.close()

    def test_verify_manifest(self):
        with io.BytesIO(SIGNED_MANIFEST.encode('utf8')) as f:
            try:
                self.assertRaises(gemato.exceptions.OpenPGPVerificationFailure,
                        self.env.verify_file, f)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))


class OpenPGPContextManagerTest(unittest.TestCase):
    """
    Test the context manager API for OpenPGPEnvironment.
    """

    def test_import_key(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            try:
                env.import_key(
                        io.BytesIO(PUBLIC_KEY.encode('utf8')))
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_import_malformed_key(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            try:
                self.assertRaises(RuntimeError,
                        env.import_key,
                        io.BytesIO(MALFORMED_PUBLIC_KEY.encode('utf8')))
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_import_no_keys(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            try:
                self.assertRaises(RuntimeError,
                        env.import_key,
                        io.BytesIO(b''))
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_verify_manifest(self):
        with io.BytesIO(SIGNED_MANIFEST.encode('utf8')) as f:
            with gemato.openpgp.OpenPGPEnvironment() as env:
                try:
                    try:
                        env.import_key(
                                io.BytesIO(PUBLIC_KEY.encode('utf8')))
                    except RuntimeError:
                        raise unittest.SkipTest('Unable to import OpenPGP key')

                    env.verify_file(f)
                except gemato.exceptions.OpenPGPNoImplementation as e:
                    raise unittest.SkipTest(str(e))

    def test_double_close(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            env.close()

    def test_home_after_close(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            env.close()
            with self.assertRaises(RuntimeError):
                env.home
