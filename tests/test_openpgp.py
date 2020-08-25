# gemato: OpenPGP signature support tests
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import io
import os.path
import shutil
import tempfile
import unittest

import gemato.cli
import gemato.compression
import gemato.manifest
import gemato.openpgp
import gemato.recursiveloader

from tests.keydata import (
    PUBLIC_KEY, SECRET_KEY, PUBLIC_SUBKEY,
    UID, EXPIRED_KEY_UID,
    PUBLIC_KEY_SIG, PUBLIC_SUBKEY_SIG, EXPIRED_KEY_SIG, REVOCATION_SIG,
    OTHER_PUBLIC_KEY, OTHER_PUBLIC_KEY_UID, OTHER_PUBLIC_KEY_SIG,
    UNEXPIRE_SIG,
    )
from tests.testutil import HKPServerTestCase

try:
    import responses
except ImportError:
    responses = None


VALID_PUBLIC_KEY = PUBLIC_KEY + UID + PUBLIC_KEY_SIG
EXPIRED_PUBLIC_KEY = PUBLIC_KEY + EXPIRED_KEY_UID + EXPIRED_KEY_SIG
REVOKED_PUBLIC_KEY = PUBLIC_KEY + REVOCATION_SIG + UID + PUBLIC_KEY_SIG
UNEXPIRE_PUBLIC_KEY = PUBLIC_KEY + EXPIRED_KEY_UID + UNEXPIRE_SIG

PRIVATE_KEY = SECRET_KEY + UID + PUBLIC_KEY_SIG
PRIVATE_KEY_ID = b'0x136880E72A7B1384'

MALFORMED_PUBLIC_KEY = b'''
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
Hash: SHA256

TIMESTAMP 2017-10-22T18:06:41Z
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEEgeEsFr2NzWC+GAhFE2iA5yp7E4QFAloCx+YACgkQE2iA5yp7
E4TYrwf+JxjkVDNtvSN3HjQmdtcayLsaliw/2kqjoaQKs0lZD8+NRe7xPmwSm4bP
XKfoouJ0+/s87vuYJpBBCjtUDA9C9yZIeRTo8+eW6XsZbRRUmUD5ylTS+FpSsUrS
bEyYk4yZQMYrat+GQ1QBv+625nqnSDv5LZHBBZ/rG36GGlwHPbIKIishnDfdG2QQ
zuxkqepNq4Inzp//ES7Bv4qbTzyBI//HzfY31vOgdhhs5N5Ytez3Xxv/KNOTYdi1
ZIfqeaQ4NoefmxQunyEjT+8X2DMaEeHQni7dwjQc+FiN4ReV9aWbLo2O2cArqEHR
mkkhTd2Auao4D2K74BePBuiZ9+eDQA==
=khff
-----END PGP SIGNATURE-----
'''

DASH_ESCAPED_SIGNED_MANIFEST = u'''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

- TIMESTAMP 2017-10-22T18:06:41Z
- MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
- DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
- DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEEgeEsFr2NzWC+GAhFE2iA5yp7E4QFAloCx+YACgkQE2iA5yp7
E4TYrwf+JxjkVDNtvSN3HjQmdtcayLsaliw/2kqjoaQKs0lZD8+NRe7xPmwSm4bP
XKfoouJ0+/s87vuYJpBBCjtUDA9C9yZIeRTo8+eW6XsZbRRUmUD5ylTS+FpSsUrS
bEyYk4yZQMYrat+GQ1QBv+625nqnSDv5LZHBBZ/rG36GGlwHPbIKIishnDfdG2QQ
zuxkqepNq4Inzp//ES7Bv4qbTzyBI//HzfY31vOgdhhs5N5Ytez3Xxv/KNOTYdi1
ZIfqeaQ4NoefmxQunyEjT+8X2DMaEeHQni7dwjQc+FiN4ReV9aWbLo2O2cArqEHR
mkkhTd2Auao4D2K74BePBuiZ9+eDQA==
=khff
-----END PGP SIGNATURE-----
'''

MODIFIED_SIGNED_MANIFEST = u'''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

TIMESTAMP 2017-10-22T18:06:41Z
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 32
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEEgeEsFr2NzWC+GAhFE2iA5yp7E4QFAloCx+YACgkQE2iA5yp7
E4TYrwf+JxjkVDNtvSN3HjQmdtcayLsaliw/2kqjoaQKs0lZD8+NRe7xPmwSm4bP
XKfoouJ0+/s87vuYJpBBCjtUDA9C9yZIeRTo8+eW6XsZbRRUmUD5ylTS+FpSsUrS
bEyYk4yZQMYrat+GQ1QBv+625nqnSDv5LZHBBZ/rG36GGlwHPbIKIishnDfdG2QQ
zuxkqepNq4Inzp//ES7Bv4qbTzyBI//HzfY31vOgdhhs5N5Ytez3Xxv/KNOTYdi1
ZIfqeaQ4NoefmxQunyEjT+8X2DMaEeHQni7dwjQc+FiN4ReV9aWbLo2O2cArqEHR
mkkhTd2Auao4D2K74BePBuiZ9+eDQA==
=khff
-----END PGP SIGNATURE-----
'''

EXPIRED_SIGNED_MANIFEST = u'''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

TIMESTAMP 2017-10-22T18:06:41Z
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
-----BEGIN PGP SIGNATURE-----

iQE5BAEBCAAjFiEEgeEsFr2NzWC+GAhFE2iA5yp7E4QFAlnxCXcFgwABUYAACgkQ
E2iA5yp7E4SDpQgAizTfQ6HJ1mawgElYV1LsOKGT8ivC6CAeU3Cs1E8zYpitKuy7
Yu5WrqUgck5GkXfswxHISkV+oWzrA/j0bUV768o+fY2JmlKuc/VWeyYDGnDtgDPz
NXYoqlQ1z3TDeaRktHcblECghf/A9Hbw0L4i0DVvDdk9APtIswgL/RmpXAQS1Bl7
sE1aFIy8CMBf3itco7NGjPpCxRt7ckS+UIKNgzrfnS7WEXHIirykEsMYKTLfuN2u
HSxRUCkTK1jBuP/v/rjdqUJw3LXAbjxFl9SyUX4AgCgHqgso3IZwjAprQRKNSObO
t5pTRGhLWgdLUrs7vRB7wf7F8h4sci/YBKJRFA==
=VGMV
-----END PGP SIGNATURE-----
'''

KEY_FINGERPRINT = '81E12C16BD8DCD60BE180845136880E72A7B1384'
SIG_TIMESTAMP = datetime.datetime(2017, 11, 8, 9, 1, 26)

OTHER_VALID_PUBLIC_KEY = (OTHER_PUBLIC_KEY + OTHER_PUBLIC_KEY_UID +
                          OTHER_PUBLIC_KEY_SIG)
OTHER_KEY_FINGERPRINT = '4B8349B90C56EE7F054D52871822F5424EB6DA81'

VALID_KEY_SUBKEY = (PUBLIC_KEY + UID + PUBLIC_KEY_SIG + PUBLIC_SUBKEY +
                    PUBLIC_SUBKEY_SIG)
SUBKEY_FINGERPRINT = '7E9DDE3CBE47E437418DF74038B9D2F76CC833CC'
SUBKEY_SIG_TIMESTAMP = datetime.datetime(2020, 8, 25, 12, 40, 12)

SUBKEY_SIGNED_MANIFEST = u'''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

TIMESTAMP 2017-10-22T18:06:41Z
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
-----BEGIN PGP SIGNATURE-----

iLMEAQEIAB0WIQR+nd48vkfkN0GN90A4udL3bMgzzAUCX0UGrAAKCRA4udL3bMgz
zH8MA/93/oNkXaA8+ZX7s8umhNMHiovdLJMna7Bl2C/tEdLfOoyp9o3lChhnB49v
g7VRUc//lz5sDUShdUUlTYjCPGLaYf2rBZHqd5POGJOsbzu1Tmtd8uhWFWnl8Kip
n4XmpdPvu+UdAHpQIGzKoNOEDJpZ5CzPLhYa5KgZiJhpYsDXgg==
=lpJi
-----END PGP SIGNATURE-----
'''


def break_sig(sig):
    """Return signature packet mangled to mismatch the signed key"""
    return sig[:-1] + b'\x55'


FORGED_PUBLIC_KEY = PUBLIC_KEY + UID + break_sig(PUBLIC_KEY_SIG)
FORGED_SUBKEY = (PUBLIC_KEY + UID + PUBLIC_KEY_SIG + PUBLIC_SUBKEY +
                 break_sig(PUBLIC_SUBKEY_SIG))
FORGED_UNEXPIRE_KEY = (PUBLIC_KEY + EXPIRED_KEY_UID + EXPIRED_KEY_SIG +
                       break_sig(UNEXPIRE_SIG))


def strip_openpgp(text):
    lines = text.lstrip().splitlines()
    start = lines.index('')
    stop = lines.index('-----BEGIN PGP SIGNATURE-----')
    return '\n'.join(lines[start+1:stop-start+2]) + '\n'


def need_responses(func):
    def skipper(*args, **kwargs):
        raise unittest.SkipTest('responses module is needed for WKD tests')
    if responses is None:
        return skipper
    return responses.activate(func)


class SignedManifestTest(unittest.TestCase):
    """
    Test whether signed Manifest is read correctly.
    """

    def test_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(SIGNED_MANIFEST) as f:
            m.load(f, verify_openpgp=False)
        self.assertIsNotNone(m.find_timestamp())
        self.assertIsNotNone(m.find_path_entry('myebuild-0.ebuild'))
        self.assertFalse(m.openpgp_signed)
        self.assertIsNone(m.openpgp_signature)

    def test_dash_escaped_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(DASH_ESCAPED_SIGNED_MANIFEST) as f:
            m.load(f, verify_openpgp=False)
        self.assertIsNotNone(m.find_timestamp())
        self.assertIsNotNone(m.find_path_entry('myebuild-0.ebuild'))
        self.assertFalse(m.openpgp_signed)
        self.assertIsNone(m.openpgp_signature)

    def test_modified_manifest_load(self):
        """
        Modified Manifest should load correctly since we do not enforce
        implicit verification.
        """
        m = gemato.manifest.ManifestFile()
        with io.StringIO(MODIFIED_SIGNED_MANIFEST) as f:
            m.load(f, verify_openpgp=False)
        self.assertIsNotNone(m.find_timestamp())
        self.assertIsNotNone(m.find_path_entry('myebuild-0.ebuild'))
        self.assertFalse(m.openpgp_signed)
        self.assertIsNone(m.openpgp_signature)

    def test_junk_before_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO('IGNORE test\n' + SIGNED_MANIFEST) as f:
            self.assertRaises(gemato.exceptions.ManifestUnsignedData,
                    m.load, f, verify_openpgp=False)

    def test_junk_after_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(SIGNED_MANIFEST + 'IGNORE test\n') as f:
            self.assertRaises(gemato.exceptions.ManifestUnsignedData,
                    m.load, f, verify_openpgp=False)

    def test_signed_manifest_terminated_before_data(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO('\n'.join(SIGNED_MANIFEST.splitlines()[:3])) as f:
            self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                    m.load, f, verify_openpgp=False)

    def test_signed_manifest_terminated_before_signature(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO('\n'.join(SIGNED_MANIFEST.splitlines()[:7])) as f:
            self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                    m.load, f, verify_openpgp=False)

    def test_signed_manifest_terminated_before_end(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO('\n'.join(SIGNED_MANIFEST.splitlines()[:15])) as f:
            self.assertRaises(gemato.exceptions.ManifestSyntaxError,
                    m.load, f, verify_openpgp=False)

    def test_recursive_manifest_loader(self):
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(MODIFIED_SIGNED_MANIFEST)

            m = gemato.recursiveloader.ManifestRecursiveLoader(
                    os.path.join(d, 'Manifest'),
                    verify_openpgp=False)
            self.assertFalse(m.openpgp_signed)
            self.assertIsNone(m.openpgp_signature)
        finally:
            shutil.rmtree(d)

    def test_cli(self):
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(MODIFIED_SIGNED_MANIFEST)

            os.mkdir(os.path.join(d, 'eclass'))
            with io.open(os.path.join(d, 'eclass/Manifest'), 'w'):
                pass
            with io.open(os.path.join(d, 'myebuild-0.ebuild'), 'wb') as f:
                f.write(b'12345678901234567890123456789012')
            with io.open(os.path.join(d, 'metadata.xml'), 'w'):
                pass

            self.assertEqual(
                    gemato.cli.main(['gemato', 'verify',
                        '--no-openpgp-verify', d]),
                    0)
        finally:
            shutil.rmtree(d)

    def test_recursive_manifest_loader_save_manifest(self):
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(MODIFIED_SIGNED_MANIFEST)

            m = gemato.recursiveloader.ManifestRecursiveLoader(
                    os.path.join(d, 'Manifest'),
                    verify_openpgp=False)
            self.assertFalse(m.openpgp_signed)
            self.assertIsNone(m.openpgp_signature)
            m.save_manifest('Manifest')

            with io.open(os.path.join(d, 'Manifest'), 'r') as f:
                self.assertEqual(f.read(),
                        strip_openpgp(MODIFIED_SIGNED_MANIFEST))
        finally:
            shutil.rmtree(d)


class OpenPGPCorrectKeyTest(unittest.TestCase):
    """
    Tests performed with correct OpenPGP key set.
    """

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(VALID_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))

    def tearDown(self):
        self.env.close()

    def test_verify_manifest(self):
        with io.StringIO(SIGNED_MANIFEST) as f:
            sig = self.env.verify_file(f)
            self.assertEqual(sig.fingerprint, KEY_FINGERPRINT)
            self.assertEqual(sig.timestamp, SIG_TIMESTAMP)
            self.assertIsNone(sig.expire_timestamp)
            self.assertEqual(sig.primary_key_fingerprint, KEY_FINGERPRINT)

    def test_verify_dash_escaped_manifest(self):
        with io.StringIO(DASH_ESCAPED_SIGNED_MANIFEST) as f:
            sig = self.env.verify_file(f)
            self.assertEqual(sig.fingerprint, KEY_FINGERPRINT)
            self.assertEqual(sig.timestamp, SIG_TIMESTAMP)
            self.assertIsNone(sig.expire_timestamp)
            self.assertEqual(sig.primary_key_fingerprint, KEY_FINGERPRINT)

    def test_verify_modified_manifest(self):
        with io.StringIO(MODIFIED_SIGNED_MANIFEST) as f:
            self.assertRaises(gemato.exceptions.OpenPGPVerificationFailure,
                    self.env.verify_file, f)

    def test_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(SIGNED_MANIFEST) as f:
            m.load(f, openpgp_env=self.env)
        self.assertIsNotNone(m.find_timestamp())
        self.assertIsNotNone(m.find_path_entry('myebuild-0.ebuild'))
        self.assertTrue(m.openpgp_signed)
        self.assertEqual(m.openpgp_signature.fingerprint, KEY_FINGERPRINT)
        self.assertEqual(m.openpgp_signature.timestamp, SIG_TIMESTAMP)
        self.assertIsNone(m.openpgp_signature.expire_timestamp)
        self.assertEqual(m.openpgp_signature.primary_key_fingerprint, KEY_FINGERPRINT)

    def test_dash_escaped_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(DASH_ESCAPED_SIGNED_MANIFEST) as f:
            m.load(f, openpgp_env=self.env)
        self.assertIsNotNone(m.find_timestamp())
        self.assertIsNotNone(m.find_path_entry('myebuild-0.ebuild'))
        self.assertTrue(m.openpgp_signed)
        self.assertEqual(m.openpgp_signature.fingerprint, KEY_FINGERPRINT)
        self.assertEqual(m.openpgp_signature.timestamp, SIG_TIMESTAMP)
        self.assertIsNone(m.openpgp_signature.expire_timestamp)
        self.assertEqual(m.openpgp_signature.primary_key_fingerprint, KEY_FINGERPRINT)

    def test_modified_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(MODIFIED_SIGNED_MANIFEST) as f:
            self.assertRaises(gemato.exceptions.OpenPGPVerificationFailure,
                m.load, f, openpgp_env=self.env)

    def test_recursive_manifest_loader(self):
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(SIGNED_MANIFEST)

            m = gemato.recursiveloader.ManifestRecursiveLoader(
                    os.path.join(d, 'Manifest'),
                    verify_openpgp=True,
                    openpgp_env=self.env)
            self.assertTrue(m.openpgp_signed)
            self.assertEqual(m.openpgp_signature.fingerprint, KEY_FINGERPRINT)
            self.assertEqual(m.openpgp_signature.timestamp, SIG_TIMESTAMP)
            self.assertIsNone(m.openpgp_signature.expire_timestamp)
            self.assertEqual(m.openpgp_signature.primary_key_fingerprint, KEY_FINGERPRINT)
        finally:
            shutil.rmtree(d)

    def test_recursive_manifest_loader_compressed(self):
        d = tempfile.mkdtemp()
        try:
            with gemato.compression.open_potentially_compressed_path(
                    os.path.join(d, 'Manifest.gz'), 'w') as cf:
                cf.write(SIGNED_MANIFEST)

            m = gemato.recursiveloader.ManifestRecursiveLoader(
                    os.path.join(d, 'Manifest.gz'),
                    verify_openpgp=True,
                    openpgp_env=self.env)
            self.assertTrue(m.openpgp_signed)
            self.assertEqual(m.openpgp_signature.fingerprint, KEY_FINGERPRINT)
            self.assertEqual(m.openpgp_signature.timestamp, SIG_TIMESTAMP)
            self.assertIsNone(m.openpgp_signature.expire_timestamp)
            self.assertEqual(m.openpgp_signature.primary_key_fingerprint, KEY_FINGERPRINT)
        finally:
            shutil.rmtree(d)

    def test_cli(self):
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, '.key.bin'), 'wb') as f:
                f.write(VALID_PUBLIC_KEY)
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(SIGNED_MANIFEST)

            os.mkdir(os.path.join(d, 'eclass'))
            with io.open(os.path.join(d, 'eclass/Manifest'), 'w'):
                pass
            with io.open(os.path.join(d, 'myebuild-0.ebuild'), 'w'):
                pass
            with io.open(os.path.join(d, 'metadata.xml'), 'w'):
                pass

            self.assertEqual(
                    gemato.cli.main(['gemato', 'verify',
                        '--openpgp-key', os.path.join(d, '.key.bin'),
                        '--no-refresh-keys',
                        '--require-signed-manifest', d]),
                    0)
        finally:
            shutil.rmtree(d)


class OpenPGPNoKeyTest(unittest.TestCase):
    """
    Tests performed without correct OpenPGP key set.
    """

    expected_exception = gemato.exceptions.OpenPGPVerificationFailure

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()

    def tearDown(self):
        self.env.close()

    def test_verify_manifest(self):
        with io.StringIO(SIGNED_MANIFEST) as f:
            try:
                self.assertRaises(self.expected_exception,
                        self.env.verify_file, f)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(SIGNED_MANIFEST) as f:
            try:
                self.assertRaises(self.expected_exception,
                        m.load, f, openpgp_env=self.env)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_manifest_load_exception_caught(self):
        """
        Test that the Manifest is loaded even if exception is raised.
        """
        m = gemato.manifest.ManifestFile()
        with io.StringIO(SIGNED_MANIFEST) as f:
            try:
                m.load(f, openpgp_env=self.env)
            except self.expected_exception:
                pass
            except gemato.exceptions.OpenPGPNoImplementation:
                pass
        self.assertIsNotNone(m.find_timestamp())
        self.assertIsNotNone(m.find_path_entry('myebuild-0.ebuild'))
        self.assertFalse(m.openpgp_signed)
        self.assertIsNone(m.openpgp_signature)

    def test_recursive_manifest_loader(self):
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(SIGNED_MANIFEST)

            try:
                self.assertRaises(self.expected_exception,
                        gemato.recursiveloader.ManifestRecursiveLoader,
                        os.path.join(d, 'Manifest'),
                        verify_openpgp=True,
                        openpgp_env=self.env)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))
        finally:
            shutil.rmtree(d)

    def test_recursive_manifest_loader_compressed(self):
        d = tempfile.mkdtemp()
        try:
            with gemato.compression.open_potentially_compressed_path(
                    os.path.join(d, 'Manifest.gz'), 'w') as cf:
                cf.write(SIGNED_MANIFEST)

            try:
                self.assertRaises(self.expected_exception,
                        gemato.recursiveloader.ManifestRecursiveLoader,
                        os.path.join(d, 'Manifest.gz'),
                        verify_openpgp=True,
                        openpgp_env=self.env)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))
        finally:
            shutil.rmtree(d)

    def test_find_top_level_manifest(self):
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(SIGNED_MANIFEST)

            self.assertEqual(
                    gemato.find_top_level.find_top_level_manifest(d),
                    os.path.join(d, 'Manifest'))
        finally:
            shutil.rmtree(d)


class OpenPGPExpiredKeyTest(OpenPGPNoKeyTest):
    """
    Tests performed with an expired OpenPGP key.
    """

    expected_exception = gemato.exceptions.OpenPGPExpiredKeyFailure

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(EXPIRED_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))

    def tearDown(self):
        self.env.close()


class OpenPGPRevokedKeyTest(OpenPGPNoKeyTest):
    """
    Tests performed with a revoked OpenPGP key.
    """

    expected_exception = gemato.exceptions.OpenPGPRevokedKeyFailure

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(REVOKED_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))

    def tearDown(self):
        self.env.close()


class OpenPGPExpiredSignatureTest(unittest.TestCase):
    """
    Tests for handling of expired signature.
    """

    expected_exception = gemato.exceptions.OpenPGPVerificationFailure

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(VALID_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))

    def tearDown(self):
        self.env.close()

    def test_verify_manifest(self):
        with io.StringIO(EXPIRED_SIGNED_MANIFEST) as f:
            try:
                self.assertRaises(self.expected_exception,
                        self.env.verify_file, f)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_manifest_load(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(EXPIRED_SIGNED_MANIFEST) as f:
            try:
                self.assertRaises(self.expected_exception,
                        m.load, f, openpgp_env=self.env)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_manifest_load_exception_caught(self):
        """
        Test that the Manifest is loaded even if exception is raised.
        """
        m = gemato.manifest.ManifestFile()
        with io.StringIO(EXPIRED_SIGNED_MANIFEST) as f:
            try:
                m.load(f, openpgp_env=self.env)
            except self.expected_exception:
                pass
            except gemato.exceptions.OpenPGPNoImplementation:
                pass
        self.assertIsNotNone(m.find_timestamp())
        self.assertIsNotNone(m.find_path_entry('myebuild-0.ebuild'))
        self.assertFalse(m.openpgp_signed)
        self.assertIsNone(m.openpgp_signature)

    def test_recursive_manifest_loader(self):
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(EXPIRED_SIGNED_MANIFEST)

            try:
                self.assertRaises(self.expected_exception,
                        gemato.recursiveloader.ManifestRecursiveLoader,
                        os.path.join(d, 'Manifest'),
                        verify_openpgp=True,
                        openpgp_env=self.env)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))
        finally:
            shutil.rmtree(d)

    def test_recursive_manifest_loader_compressed(self):
        d = tempfile.mkdtemp()
        try:
            with gemato.compression.open_potentially_compressed_path(
                    os.path.join(d, 'Manifest.gz'), 'w') as cf:
                cf.write(EXPIRED_SIGNED_MANIFEST)

            try:
                self.assertRaises(self.expected_exception,
                        gemato.recursiveloader.ManifestRecursiveLoader,
                        os.path.join(d, 'Manifest.gz'),
                        verify_openpgp=True,
                        openpgp_env=self.env)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))
        finally:
            shutil.rmtree(d)

    def test_find_top_level_manifest(self):
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(EXPIRED_SIGNED_MANIFEST)

            self.assertEqual(
                    gemato.find_top_level.find_top_level_manifest(d),
                    os.path.join(d, 'Manifest'))
        finally:
            shutil.rmtree(d)


class OpenPGPContextManagerTest(unittest.TestCase):
    """
    Test the context manager API for OpenPGPEnvironment.
    """

    def test_import_key(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            try:
                env.import_key(io.BytesIO(VALID_PUBLIC_KEY))
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_import_malformed_key(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            try:
                self.assertRaises(gemato.exceptions.OpenPGPKeyImportError,
                        env.import_key,
                        io.BytesIO(MALFORMED_PUBLIC_KEY))
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_import_no_keys(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            try:
                self.assertRaises(gemato.exceptions.OpenPGPKeyImportError,
                        env.import_key,
                        io.BytesIO(b''))
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_import_forged_key(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            try:
                self.assertRaises(gemato.exceptions.OpenPGPKeyImportError,
                        env.import_key,
                        io.BytesIO(FORGED_PUBLIC_KEY))
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_verify_manifest(self):
        with io.StringIO(SIGNED_MANIFEST) as f:
            with gemato.openpgp.OpenPGPEnvironment() as env:
                try:
                    try:
                        env.import_key(io.BytesIO(VALID_PUBLIC_KEY))
                    except gemato.exceptions.OpenPGPRuntimeError as e:
                        raise unittest.SkipTest(str(e))
                    except gemato.exceptions.OpenPGPNoImplementation as e:
                        raise unittest.SkipTest(str(e))

                    sig = env.verify_file(f)
                    self.assertEqual(sig.fingerprint, KEY_FINGERPRINT)
                    self.assertEqual(sig.timestamp, SIG_TIMESTAMP)
                    self.assertIsNone(sig.expire_timestamp)
                    self.assertEqual(sig.primary_key_fingerprint, KEY_FINGERPRINT)
                except gemato.exceptions.OpenPGPNoImplementation as e:
                    raise unittest.SkipTest(str(e))

    def test_double_close(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            env.close()

    def test_home_after_close(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            env.close()
            with self.assertRaises(AssertionError):
                env.home


class OpenPGPPrivateKeyTest(unittest.TestCase):
    """
    Tests performed with the private key available.
    """

    TEST_STRING = u'The quick brown fox jumps over the lazy dog'

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(PRIVATE_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))

    def tearDown(self):
        self.env.close()

    def test_verify_manifest(self):
        with io.StringIO(SIGNED_MANIFEST) as f:
            sig = self.env.verify_file(f)
            self.assertEqual(sig.fingerprint, KEY_FINGERPRINT)
            self.assertEqual(sig.timestamp, SIG_TIMESTAMP)
            self.assertIsNone(sig.expire_timestamp)
            self.assertEqual(sig.primary_key_fingerprint, KEY_FINGERPRINT)

    def test_sign_data(self):
        with io.StringIO(self.TEST_STRING) as f:
            with io.StringIO() as wf:
                self.env.clear_sign_file(f, wf)
                wf.seek(0)
                self.env.verify_file(wf)

    def test_sign_data_keyid(self):
        with io.StringIO(self.TEST_STRING) as f:
            with io.StringIO() as wf:
                self.env.clear_sign_file(f, wf, keyid=PRIVATE_KEY_ID)
                wf.seek(0)
                self.env.verify_file(wf)

    def test_dump_signed_manifest(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(SIGNED_MANIFEST) as f:
            m.load(f, openpgp_env=self.env)
        with io.StringIO() as f:
            m.dump(f, openpgp_env=self.env)
            f.seek(0)
            m.load(f, openpgp_env=self.env)
        self.assertTrue(m.openpgp_signed)
        self.assertIsNotNone(m.openpgp_signature)

    def test_dump_signed_manifest_keyid(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(SIGNED_MANIFEST) as f:
            m.load(f, openpgp_env=self.env)
        with io.StringIO() as f:
            m.dump(f, openpgp_keyid=PRIVATE_KEY_ID, openpgp_env=self.env)
            f.seek(0)
            m.load(f, openpgp_env=self.env)
        self.assertTrue(m.openpgp_signed)
        self.assertIsNotNone(m.openpgp_signature)

    def test_dump_force_signed_manifest(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(SIGNED_MANIFEST) as f:
            m.load(f, verify_openpgp=False, openpgp_env=self.env)
        self.assertFalse(m.openpgp_signed)
        self.assertIsNone(m.openpgp_signature)
        with io.StringIO() as f:
            m.dump(f, sign_openpgp=True, openpgp_env=self.env)
            f.seek(0)
            m.load(f, openpgp_env=self.env)
        self.assertTrue(m.openpgp_signed)
        self.assertIsNotNone(m.openpgp_signature)

    def test_dump_force_unsigned_manifest(self):
        m = gemato.manifest.ManifestFile()
        with io.StringIO(SIGNED_MANIFEST) as f:
            m.load(f, openpgp_env=self.env)
        self.assertTrue(m.openpgp_signed)
        with io.StringIO() as f:
            m.dump(f, sign_openpgp=False, openpgp_env=self.env)
            f.seek(0)
            m.load(f, openpgp_env=self.env)
        self.assertFalse(m.openpgp_signed)
        self.assertIsNone(m.openpgp_signature)

    def test_recursive_manifest_loader_save_manifest(self):
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(SIGNED_MANIFEST)

            m = gemato.recursiveloader.ManifestRecursiveLoader(
                    os.path.join(d, 'Manifest'),
                    verify_openpgp=True,
                    openpgp_env=self.env)
            self.assertTrue(m.openpgp_signed)

            m.save_manifest('Manifest')
            m2 = gemato.manifest.ManifestFile()
            with io.open(os.path.join(d, 'Manifest'), 'r') as f:
                m2.load(f, openpgp_env=self.env)
            self.assertTrue(m2.openpgp_signed)
            self.assertIsNotNone(m.openpgp_signature)
        finally:
            shutil.rmtree(d)

    def test_recursive_manifest_loader_save_manifest_compressed(self):
        d = tempfile.mkdtemp()
        try:
            with gemato.compression.open_potentially_compressed_path(
                    os.path.join(d, 'Manifest.gz'), 'w') as cf:
                cf.write(SIGNED_MANIFEST)

            m = gemato.recursiveloader.ManifestRecursiveLoader(
                    os.path.join(d, 'Manifest.gz'),
                    verify_openpgp=True,
                    openpgp_env=self.env)
            self.assertTrue(m.openpgp_signed)

            m.save_manifest('Manifest.gz')
            m2 = gemato.manifest.ManifestFile()
            with gemato.compression.open_potentially_compressed_path(
                    os.path.join(d, 'Manifest.gz'), 'r') as cf:
                m2.load(cf, openpgp_env=self.env)
            self.assertTrue(m2.openpgp_signed)
            self.assertIsNotNone(m.openpgp_signature)
        finally:
            shutil.rmtree(d)

    def test_recursive_manifest_loader_save_manifest_force_sign(self):
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(SIGNED_MANIFEST)

            m = gemato.recursiveloader.ManifestRecursiveLoader(
                    os.path.join(d, 'Manifest'),
                    verify_openpgp=False,
                    sign_openpgp=True,
                    openpgp_env=self.env)
            self.assertFalse(m.openpgp_signed)
            self.assertIsNone(m.openpgp_signature)

            m.save_manifest('Manifest')
            m2 = gemato.manifest.ManifestFile()
            with io.open(os.path.join(d, 'Manifest'), 'r') as f:
                m2.load(f, openpgp_env=self.env)
            self.assertTrue(m2.openpgp_signed)
            self.assertIsNotNone(m2.openpgp_signature)
        finally:
            shutil.rmtree(d)

    def test_recursive_manifest_loader_save_manifest_compressed_force_sign(self):
        d = tempfile.mkdtemp()
        try:
            with gemato.compression.open_potentially_compressed_path(
                    os.path.join(d, 'Manifest.gz'), 'w') as cf:
                cf.write(SIGNED_MANIFEST)

            m = gemato.recursiveloader.ManifestRecursiveLoader(
                    os.path.join(d, 'Manifest.gz'),
                    verify_openpgp=False,
                    sign_openpgp=True,
                    openpgp_env=self.env)
            self.assertFalse(m.openpgp_signed)
            self.assertIsNone(m.openpgp_signature)

            m.save_manifest('Manifest.gz')
            m2 = gemato.manifest.ManifestFile()
            with gemato.compression.open_potentially_compressed_path(
                    os.path.join(d, 'Manifest.gz'), 'r') as cf:
                m2.load(cf, openpgp_env=self.env)
            self.assertTrue(m2.openpgp_signed)
            self.assertIsNotNone(m2.openpgp_signature)
        finally:
            shutil.rmtree(d)

    def test_recursive_manifest_loader_save_submanifest_force_sign(self):
        """
        Test that sub-Manifests are not signed.
        """
        d = tempfile.mkdtemp()
        try:
            with io.open(os.path.join(d, 'Manifest'), 'w') as f:
                f.write(SIGNED_MANIFEST)
            os.mkdir(os.path.join(d, 'eclass'))
            with io.open(os.path.join(d, 'eclass/Manifest'), 'w'):
                pass

            m = gemato.recursiveloader.ManifestRecursiveLoader(
                    os.path.join(d, 'Manifest'),
                    verify_openpgp=False,
                    sign_openpgp=True,
                    openpgp_env=self.env)
            self.assertFalse(m.openpgp_signed)
            self.assertIsNone(m.openpgp_signature)

            m.load_manifest('eclass/Manifest')
            m.save_manifest('eclass/Manifest')

            m2 = gemato.manifest.ManifestFile()
            with io.open(os.path.join(d, 'eclass/Manifest'), 'r') as f:
                m2.load(f, openpgp_env=self.env)
            self.assertFalse(m2.openpgp_signed)
            self.assertIsNone(m2.openpgp_signature)
        finally:
            shutil.rmtree(d)


class OpenPGPRefreshTest(HKPServerTestCase):
    """
    Test that refresh_keys() correctly handles revocation.
    """

    SERVER_KEYS = {
        KEY_FINGERPRINT: REVOKED_PUBLIC_KEY,
    }

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(VALID_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        super(OpenPGPRefreshTest, self).setUp()

    def tearDown(self):
        self.env.close()
        super(OpenPGPRefreshTest, self).tearDown()

    def test_refresh_keys(self):
        try:
            with io.StringIO(SIGNED_MANIFEST) as f:
                self.env.verify_file(f)

            self.env.refresh_keys(allow_wkd=False,
                                  keyserver=self.server_addr)

            with io.StringIO(SIGNED_MANIFEST) as f:
                self.assertRaises(gemato.exceptions.OpenPGPRevokedKeyFailure,
                        self.env.verify_file, f)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class OpenPGPFailRefreshTest(HKPServerTestCase):
    """
    Test that refresh_keys() correctly handles missing key on server.
    """

    SERVER_KEYS = {}

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(VALID_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        super(OpenPGPFailRefreshTest, self).setUp()

    def tearDown(self):
        self.env.close()
        super(OpenPGPFailRefreshTest, self).tearDown()

    def test_refresh_keys(self):
        try:
            self.assertRaises(gemato.exceptions.OpenPGPKeyRefreshError,
                              self.env.refresh_keys, allow_wkd=False,
                              keyserver=self.server_addr)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class OpenPGPUnrevokeRefreshTest(HKPServerTestCase):
    """
    Test that refresh_keys() does not ignore local revocation when
    keyserver sends outdated (non-revoked) key.
    """

    SERVER_KEYS = {
        KEY_FINGERPRINT: VALID_PUBLIC_KEY,
    }

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(REVOKED_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        super(OpenPGPUnrevokeRefreshTest, self).setUp()

    def tearDown(self):
        self.env.close()
        super(OpenPGPUnrevokeRefreshTest, self).tearDown()

    def test_refresh_keys(self):
        try:
            self.env.refresh_keys(allow_wkd=False,
                                  keyserver=self.server_addr)

            with io.StringIO(SIGNED_MANIFEST) as f:
                self.assertRaises(gemato.exceptions.OpenPGPRevokedKeyFailure,
                        self.env.verify_file, f)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class OpenPGPFakeKeyRefreshTest(HKPServerTestCase):
    """
    Test that refresh_keys() does not allow maliciously replacing key
    with another.
    """

    SERVER_KEYS = {
        OTHER_KEY_FINGERPRINT: VALID_PUBLIC_KEY,
    }

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(OTHER_VALID_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        super(OpenPGPFakeKeyRefreshTest, self).setUp()

    def tearDown(self):
        self.env.close()
        super(OpenPGPFakeKeyRefreshTest, self).tearDown()

    def test_refresh_keys(self):
        try:
            self.assertRaises(gemato.exceptions.OpenPGPKeyRefreshError,
                              self.env.refresh_keys, allow_wkd=False,
                              keyserver=self.server_addr)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class OpenPGPWKDRefreshTest(unittest.TestCase):
    """
    Test that WKD variant of refresh_keys() correctly handles
    revocation.
    """

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(VALID_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))

    def tearDown(self):
        self.env.close()

    @need_responses
    def test_refresh_keys(self):
        try:
            with io.StringIO(SIGNED_MANIFEST) as f:
                self.env.verify_file(f)

            responses.add(
                responses.GET,
                'https://example.com/.well-known/openpgpkey/hu/'
                '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                body=REVOKED_PUBLIC_KEY,
                content_type='application/pgp-keys')
            self.env.refresh_keys(allow_wkd=True)

            with io.StringIO(SIGNED_MANIFEST) as f:
                self.assertRaises(gemato.exceptions.OpenPGPRevokedKeyFailure,
                        self.env.verify_file, f)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class OpenPGPWKDFallbackRefreshTest(HKPServerTestCase):
    """
    Test that WKD variant of refresh_keys() correctly falls back
    to keyserver ops.
    """

    SERVER_KEYS = {
        KEY_FINGERPRINT: REVOKED_PUBLIC_KEY,
    }

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(VALID_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        super(OpenPGPWKDFallbackRefreshTest, self).setUp()

    def tearDown(self):
        self.env.close()
        super(OpenPGPWKDFallbackRefreshTest, self).tearDown()

    @need_responses
    def test_refresh_keys(self):
        try:
            with io.StringIO(SIGNED_MANIFEST) as f:
                self.env.verify_file(f)

            responses.add(
                responses.GET,
                'https://example.com/.well-known/openpgpkey/hu/'
                '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                status=404)
            self.env.refresh_keys(allow_wkd=True,
                                  keyserver=self.server_addr)

            with io.StringIO(SIGNED_MANIFEST) as f:
                self.assertRaises(gemato.exceptions.OpenPGPRevokedKeyFailure,
                        self.env.verify_file, f)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class OpenPGPWKDFailRefreshTest(HKPServerTestCase):
    """
    Test that WKD variant of refresh_keys() correctly handles missing
    key on server.

    Note: we also run HKP server to handle failed WKD fallback.
    """

    SERVER_KEYS = {}

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(VALID_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        super(OpenPGPWKDFailRefreshTest, self).setUp()

    def tearDown(self):
        self.env.close()
        super(OpenPGPWKDFailRefreshTest, self).tearDown()

    @need_responses
    def test_refresh_keys(self):
        try:
            responses.add(
                responses.GET,
                'https://example.com/.well-known/openpgpkey/hu/'
                '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                status=404)
            self.assertRaises(gemato.exceptions.OpenPGPKeyRefreshError,
                              self.env.refresh_keys, allow_wkd=True,
                              keyserver=self.server_addr)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class OpenPGPWKDUnrevokeRefreshTest(unittest.TestCase):
    """
    Test that WKD refresh_keys() does not ignore local revocation when
    keyserver sends outdated (non-revoked) key.
    """

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(REVOKED_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))

    def tearDown(self):
        self.env.close()

    @need_responses
    def test_refresh_keys(self):
        try:
            responses.add(
                responses.GET,
                'https://example.com/.well-known/openpgpkey/hu/'
                '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                body=VALID_PUBLIC_KEY,
                content_type='application/pgp-keys')
            self.env.refresh_keys(allow_wkd=True)

            with io.StringIO(SIGNED_MANIFEST) as f:
                self.assertRaises(gemato.exceptions.OpenPGPRevokedKeyFailure,
                        self.env.verify_file, f)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class OpenPGPWKDFakeKeyRefreshTest(unittest.TestCase):
    """
    Test that WKD refresh_keys() does not allow injecting another key.
    """

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(OTHER_VALID_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))

    def tearDown(self):
        self.env.close()

    @need_responses
    def test_refresh_keys(self):
        try:
            responses.add(
                responses.GET,
                'https://example.com/.well-known/openpgpkey/hu/'
                '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                body=OTHER_VALID_PUBLIC_KEY + VALID_PUBLIC_KEY,
                content_type='application/pgp-keys')
            self.env.refresh_keys(allow_wkd=True)

            with io.StringIO(SIGNED_MANIFEST) as f:
                self.assertRaises(gemato.exceptions.OpenPGPVerificationFailure,
                        self.env.verify_file, f)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class OpenPGPWKDReplaceKeyRefreshTest(HKPServerTestCase):
    """
    Test that WKD refresh_keys() does not allow replacing the key with
    another (of the same UID).
    """

    SERVER_KEYS = {}

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(OTHER_VALID_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        super(OpenPGPWKDReplaceKeyRefreshTest, self).setUp()

    def tearDown(self):
        self.env.close()
        super(OpenPGPWKDReplaceKeyRefreshTest, self).tearDown()

    @need_responses
    def test_refresh_keys(self):
        try:
            responses.add(
                responses.GET,
                'https://example.com/.well-known/openpgpkey/hu/'
                '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                body=VALID_PUBLIC_KEY,
                content_type='application/pgp-keys')
            self.assertRaises(gemato.exceptions.OpenPGPKeyRefreshError,
                              self.env.refresh_keys, allow_wkd=True,
                              keyserver=self.server_addr)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class OpenPGPSubKeyTest(unittest.TestCase):
    """
    Tests that a signature made using a subkey works.
    """

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(VALID_KEY_SUBKEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))

    def tearDown(self):
        self.env.close()

    def test_verify_manifest(self):
        with io.StringIO(SUBKEY_SIGNED_MANIFEST) as f:
            sig = self.env.verify_file(f)
            self.assertEqual(sig.fingerprint, SUBKEY_FINGERPRINT)
            self.assertEqual(sig.timestamp, SUBKEY_SIG_TIMESTAMP)
            self.assertIsNone(sig.expire_timestamp)
            self.assertEqual(sig.primary_key_fingerprint, KEY_FINGERPRINT)


class OpenPGPForgedSubKeyTest(unittest.TestCase):
    """
    Tests that a subkey is not used if its signature is wrong.
    """

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(FORGED_SUBKEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))

    def tearDown(self):
        self.env.close()

    def test_verify_manifest(self):
        with io.StringIO(SUBKEY_SIGNED_MANIFEST) as f:
            self.assertRaises(
                gemato.exceptions.OpenPGPVerificationFailure,
                self.env.verify_file, f)


class OpenPGPForgedSubKeyKeyserverTest(HKPServerTestCase):
    """
    Tests that a forged subkey can not be injected via keyserver.
    """

    SERVER_KEYS = {
        KEY_FINGERPRINT: FORGED_SUBKEY,
    }

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(VALID_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        super(OpenPGPForgedSubKeyKeyserverTest, self).setUp()

    def tearDown(self):
        self.env.close()
        super(OpenPGPForgedSubKeyKeyserverTest, self).tearDown()

    def test_verify_manifest(self):
        self.env.refresh_keys(allow_wkd=False,
                              keyserver=self.server_addr)

        with io.StringIO(SUBKEY_SIGNED_MANIFEST) as f:
            self.assertRaises(
                gemato.exceptions.OpenPGPVerificationFailure,
                self.env.verify_file, f)


class OpenPGPUnexpireRefreshTest(HKPServerTestCase):
    """
    Test that refresh_keys() correctly unexpires keys.
    """

    SERVER_KEYS = {
        KEY_FINGERPRINT: UNEXPIRE_PUBLIC_KEY,
    }

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(EXPIRED_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        super(OpenPGPUnexpireRefreshTest, self).setUp()

    def tearDown(self):
        self.env.close()
        super(OpenPGPUnexpireRefreshTest, self).tearDown()

    def test_refresh_keys(self):
        try:
            with io.StringIO(SIGNED_MANIFEST) as f:
                self.assertRaises(gemato.exceptions.OpenPGPExpiredKeyFailure,
                        self.env.verify_file, f)

            self.env.refresh_keys(allow_wkd=False,
                                  keyserver=self.server_addr)

            with io.StringIO(SIGNED_MANIFEST) as f:
                sig = self.env.verify_file(f)
                self.assertEqual(sig.fingerprint, KEY_FINGERPRINT)
                self.assertEqual(sig.timestamp, SIG_TIMESTAMP)
                self.assertIsNone(sig.expire_timestamp)
                self.assertEqual(sig.primary_key_fingerprint, KEY_FINGERPRINT)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class OpenPGPForgedUnexpireRefreshTest(HKPServerTestCase):
    """
    Test that a forged signature can not be used to unexpire key.
    """

    SERVER_KEYS = {
        KEY_FINGERPRINT: FORGED_UNEXPIRE_KEY,
    }

    def setUp(self):
        self.env = gemato.openpgp.OpenPGPEnvironment()
        try:
            self.env.import_key(io.BytesIO(EXPIRED_PUBLIC_KEY))
        except gemato.exceptions.OpenPGPRuntimeError as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        except gemato.exceptions.OpenPGPNoImplementation as e:
            self.env.close()
            raise unittest.SkipTest(str(e))
        super(OpenPGPForgedUnexpireRefreshTest, self).setUp()

    def tearDown(self):
        self.env.close()
        super(OpenPGPForgedUnexpireRefreshTest, self).tearDown()

    def test_refresh_keys(self):
        try:
            with io.StringIO(SIGNED_MANIFEST) as f:
                self.assertRaises(gemato.exceptions.OpenPGPExpiredKeyFailure,
                        self.env.verify_file, f)

            self.env.refresh_keys(allow_wkd=False,
                                  keyserver=self.server_addr)

            with io.StringIO(SIGNED_MANIFEST) as f:
                self.assertRaises(gemato.exceptions.OpenPGPExpiredKeyFailure,
                        self.env.verify_file, f)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            raise unittest.SkipTest(str(e))


class WKDUrlTests(unittest.TestCase):
    """Tests for get_wkd_url() helper"""

    def test_get_wkd_url(self):
        self.assertEqual(
            gemato.openpgp.OpenPGPEnvironment.get_wkd_url(
                'gemato@example.com'),
            'https://example.com/.well-known/openpgpkey/hu/'
            '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato')
        self.assertEqual(
            gemato.openpgp.OpenPGPEnvironment.get_wkd_url(
                'Joe.Doe@Example.ORG'),
            'https://example.org/.well-known/openpgpkey/hu/'
            'iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe')
