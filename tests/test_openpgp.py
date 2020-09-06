# gemato: OpenPGP signature support tests
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import io
import os
import shlex
import signal
import tempfile

import pytest

import gemato.cli
from gemato.compression import open_potentially_compressed_path
from gemato.exceptions import (
    ManifestUnsignedData,
    ManifestSyntaxError,
    OpenPGPNoImplementation,
    OpenPGPVerificationFailure,
    OpenPGPExpiredKeyFailure,
    OpenPGPRevokedKeyFailure,
    OpenPGPKeyImportError,
    OpenPGPKeyRefreshError,
    OpenPGPRuntimeError,
    OpenPGPUntrustedSigFailure,
    )
from gemato.manifest import ManifestFile
from gemato.openpgp import (
    SystemGPGEnvironment,
    IsolatedGPGEnvironment,
    get_wkd_url,
    )
from gemato.recursiveloader import ManifestRecursiveLoader

from tests.keydata import (
    PUBLIC_KEY, SECRET_KEY, PUBLIC_SUBKEY, UID,
    UID_NOEMAIL, PUBLIC_KEY_NOEMAIL_SIG,
    PUBLIC_KEY_SIG, PUBLIC_SUBKEY_SIG, EXPIRED_KEY_SIG, REVOCATION_SIG,
    OTHER_PUBLIC_KEY, OTHER_PUBLIC_KEY_UID, OTHER_PUBLIC_KEY_SIG,
    UNEXPIRE_SIG,
    )
from tests.testutil import HKPServer


VALID_PUBLIC_KEY = PUBLIC_KEY + UID + PUBLIC_KEY_SIG
EXPIRED_PUBLIC_KEY = PUBLIC_KEY + UID + EXPIRED_KEY_SIG
REVOKED_PUBLIC_KEY = PUBLIC_KEY + REVOCATION_SIG + UID + PUBLIC_KEY_SIG
OLD_UNEXPIRE_PUBLIC_KEY = PUBLIC_KEY + UID + PUBLIC_KEY_SIG
UNEXPIRE_PUBLIC_KEY = PUBLIC_KEY + UID + UNEXPIRE_SIG

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
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
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
- MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
- DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
- DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
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
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 32
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
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
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
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

VALID_KEY_NOEMAIL = PUBLIC_KEY + UID_NOEMAIL + PUBLIC_KEY_NOEMAIL_SIG

VALID_KEY_SUBKEY = (PUBLIC_KEY + UID + PUBLIC_KEY_SIG + PUBLIC_SUBKEY +
                    PUBLIC_SUBKEY_SIG)
SUBKEY_FINGERPRINT = '7E9DDE3CBE47E437418DF74038B9D2F76CC833CC'
SUBKEY_SIG_TIMESTAMP = datetime.datetime(2020, 8, 25, 12, 40, 12)

SUBKEY_SIGNED_MANIFEST = u'''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

TIMESTAMP 2017-10-22T18:06:41Z
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
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
FORGED_UNEXPIRE_KEY = (PUBLIC_KEY + UID + EXPIRED_KEY_SIG +
                       break_sig(UNEXPIRE_SIG))

UNSIGNED_PUBLIC_KEY = PUBLIC_KEY + UID
UNSIGNED_SUBKEY = PUBLIC_KEY + UID + PUBLIC_KEY_SIG + PUBLIC_SUBKEY


def strip_openpgp(text):
    lines = text.lstrip().splitlines()
    start = lines.index('')
    stop = lines.index('-----BEGIN PGP SIGNATURE-----')
    return '\n'.join(lines[start+1:stop-start+2]) + '\n'


MANIFESTS_GOOD_SIG = [
    'SIGNED_MANIFEST',
    'DASH_ESCAPED_SIGNED_MANIFEST',
    'SUBKEY_SIGNED_MANIFEST',
]
MANIFESTS_BAD_SIG = [
    'MODIFIED_SIGNED_MANIFEST',
    'EXPIRED_SIGNED_MANIFEST'
]


@pytest.mark.parametrize('manifest_var',
                         MANIFESTS_GOOD_SIG + MANIFESTS_BAD_SIG)
def test_noverify_goodish_manifest_load(manifest_var):
    """Test Manifest files that should succeed (OpenPGP disabled)"""
    m = ManifestFile()
    with io.StringIO(globals()[manifest_var]) as f:
        m.load(f, verify_openpgp=False)
    assert m.find_timestamp() is not None
    assert m.find_path_entry('myebuild-0.ebuild') is not None
    assert not m.openpgp_signed
    assert m.openpgp_signature is None


SIGNED_MANIFEST_JUNK_BEFORE = 'IGNORE test\n' + SIGNED_MANIFEST
SIGNED_MANIFEST_JUNK_AFTER = SIGNED_MANIFEST + 'IGNORE test\n'
SIGNED_MANIFEST_CUT_BEFORE_DATA = '\n'.join(
    SIGNED_MANIFEST.splitlines()[:3])
SIGNED_MANIFEST_CUT_BEFORE_SIGNATURE = '\n'.join(
    SIGNED_MANIFEST.splitlines()[:7])
SIGNED_MANIFEST_CUT_BEFORE_END = '\n'.join(
    SIGNED_MANIFEST.splitlines()[:15])


@pytest.mark.parametrize('manifest_var,expected',
                         [('SIGNED_MANIFEST_JUNK_BEFORE',
                           ManifestUnsignedData),
                          ('SIGNED_MANIFEST_JUNK_AFTER',
                           ManifestUnsignedData),
                          ('SIGNED_MANIFEST_CUT_BEFORE_DATA',
                           ManifestSyntaxError),
                          ('SIGNED_MANIFEST_CUT_BEFORE_SIGNATURE',
                           ManifestSyntaxError),
                          ('SIGNED_MANIFEST_CUT_BEFORE_END',
                           ManifestSyntaxError),
                          ])
def test_noverify_bad_manifest_load(manifest_var, expected):
    """Test Manifest files that should fail"""
    m = ManifestFile()
    with io.StringIO(globals()[manifest_var]) as f:
        with pytest.raises(expected):
            m.load(f, verify_openpgp=False)


@pytest.mark.parametrize('write_back', [False, True])
def test_noverify_recursive_manifest_loader(tmp_path, write_back):
    """Test reading signed Manifest"""
    with open(tmp_path / 'Manifest', 'w') as f:
        f.write(MODIFIED_SIGNED_MANIFEST)

    m = ManifestRecursiveLoader(tmp_path / 'Manifest',
                                verify_openpgp=False)
    assert not m.openpgp_signed
    assert m.openpgp_signature is None

    if write_back:
        m.save_manifest('Manifest')
        with open(tmp_path / 'Manifest', 'r') as f:
            assert f.read() == strip_openpgp(MODIFIED_SIGNED_MANIFEST)


def test_noverify_load_cli(tmp_path):
    """Test reading signed Manifest via CLI"""
    with open(tmp_path / 'Manifest', 'w') as f:
        f.write(MODIFIED_SIGNED_MANIFEST)
    os.mkdir(tmp_path / 'eclass')
    with open(tmp_path / 'eclass' / 'Manifest', 'w'):
        pass
    with open(tmp_path / 'myebuild-0.ebuild', 'wb') as f:
        f.write(b'12345678901234567890123456789012')
    with open(tmp_path / 'metadata.xml', 'wb'):
        pass

    assert 0 == gemato.cli.main(['gemato', 'verify',
                                 '--no-openpgp-verify', str(tmp_path)])


class MockedSystemGPGEnvironment(SystemGPGEnvironment):
    """System environment variant mocked to use isolated GNUPGHOME"""
    def __init__(self, *args, **kwargs):
        self._tmpdir = tempfile.TemporaryDirectory()
        os.environ['GNUPGHOME'] = self._tmpdir.name
        super().__init__(*args, **kwargs)

    def close(self):
        if self._tmpdir is not None:
            self._tmpdir.cleanup()
            self._tmpdir = None
            os.environ.pop('GNUPGHOME', None)

    def import_key(self, keyfile, trust=True):
        IsolatedGPGEnvironment.import_key(self, keyfile, trust=trust)


@pytest.fixture(params=[IsolatedGPGEnvironment,
                        MockedSystemGPGEnvironment])
def openpgp_env(request):
    """OpenPGP environment fixture"""
    env = request.param()
    yield env
    env.close()


@pytest.fixture(params=[IsolatedGPGEnvironment])
def openpgp_env_with_refresh(request):
    """OpenPGP environments that support refreshing keys"""
    env = request.param()
    yield env
    env.close()


MANIFEST_VARIANTS = [
    # manifest, key, expected fpr/exception
    # == good manifests ==
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', None),
    ('SIGNED_MANIFEST', 'VALID_KEY_NOEMAIL', None),
    ('DASH_ESCAPED_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', None),
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_KEY_SUBKEY', None),
    # == using private key ==
    ('SIGNED_MANIFEST', 'PRIVATE_KEY', None),
    # == bad manifests ==
    ('MODIFIED_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY',
     OpenPGPVerificationFailure),
    ('EXPIRED_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY',
     OpenPGPVerificationFailure),
    # == bad keys ==
    ('SIGNED_MANIFEST', None,
     OpenPGPVerificationFailure),
    ('SIGNED_MANIFEST', 'EXPIRED_PUBLIC_KEY',
     OpenPGPExpiredKeyFailure),
    ('SIGNED_MANIFEST', 'REVOKED_PUBLIC_KEY',
     OpenPGPRevokedKeyFailure),
]


def assert_signature(sig, manifest_var):
    """Make assertions about the signature"""
    if manifest_var == 'SUBKEY_SIGNED_MANIFEST':
        assert sig.fingerprint == SUBKEY_FINGERPRINT
        assert sig.timestamp == SUBKEY_SIG_TIMESTAMP
        assert sig.expire_timestamp is None
        assert sig.primary_key_fingerprint == KEY_FINGERPRINT
    else:
        assert sig.fingerprint == KEY_FINGERPRINT
        assert sig.timestamp == SIG_TIMESTAMP
        assert sig.expire_timestamp is None
        assert sig.primary_key_fingerprint == KEY_FINGERPRINT


@pytest.mark.parametrize('manifest_var,key_var,expected',
                         MANIFEST_VARIANTS)
def test_verify_manifest(openpgp_env, manifest_var, key_var, expected):
    """Test direct Manifest data verification"""
    try:
        if key_var is not None:
            with io.BytesIO(globals()[key_var]) as f:
                openpgp_env.import_key(f)

        with io.StringIO(globals()[manifest_var]) as f:
            if expected is None:
                sig = openpgp_env.verify_file(f)
                assert_signature(sig, manifest_var)
            else:
                with pytest.raises(expected):
                    openpgp_env.verify_file(f)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


def test_verify_untrusted_key():
    try:
        openpgp_env = MockedSystemGPGEnvironment()
        with io.BytesIO(VALID_PUBLIC_KEY) as f:
            openpgp_env.import_key(f, trust=False)

        with io.StringIO(SIGNED_MANIFEST) as f:
            with pytest.raises(OpenPGPUntrustedSigFailure):
                openpgp_env.verify_file(f)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.mark.parametrize('manifest_var,key_var,expected',
                         MANIFEST_VARIANTS)
def test_manifest_load(openpgp_env, manifest_var, key_var, expected):
    """Test Manifest verification via ManifestFile.load()"""
    try:
        if key_var is not None:
            with io.BytesIO(globals()[key_var]) as f:
                openpgp_env.import_key(f)

        m = ManifestFile()
        with io.StringIO(globals()[manifest_var]) as f:
            if expected is None:
                m.load(f, openpgp_env=openpgp_env)
                assert m.openpgp_signed
                assert_signature(m.openpgp_signature, manifest_var)
            else:
                with pytest.raises(expected):
                    m.load(f, openpgp_env=openpgp_env)
                assert not m.openpgp_signed
                assert m.openpgp_signature is None

        # Manifest entries should be loaded even if verification failed
        assert m.find_timestamp() is not None
        assert m.find_path_entry('myebuild-0.ebuild') is not None
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.mark.parametrize('filename', ['Manifest', 'Manifest.gz'])
@pytest.mark.parametrize('manifest_var,key_var,expected',
                         MANIFEST_VARIANTS)
def test_recursive_manifest_loader(tmp_path, openpgp_env, filename,
                                   manifest_var, key_var, expected):
    """Test Manifest verification via ManifestRecursiveLoader"""
    try:
        if key_var is not None:
            with io.BytesIO(globals()[key_var]) as f:
                openpgp_env.import_key(f)

        with open_potentially_compressed_path(tmp_path / filename, 'w') as cf:
            cf.write(globals()[manifest_var])

        if expected is None:
            m = ManifestRecursiveLoader(tmp_path / filename,
                                        verify_openpgp=True,
                                        openpgp_env=openpgp_env)
            assert m.openpgp_signed
            assert_signature(m.openpgp_signature, manifest_var)
        else:
            with pytest.raises(expected):
                ManifestRecursiveLoader(tmp_path / filename,
                                        verify_openpgp=True,
                                        openpgp_env=openpgp_env)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.mark.parametrize('manifest_var,key_var,expected',
                         [(m, k, e) for m, k, e in MANIFEST_VARIANTS
                          if k is not None])
def test_cli(tmp_path, caplog, manifest_var, key_var, expected):
    """Test Manifest verification via CLI"""
    with open(tmp_path / '.key.bin', 'wb') as f:
        f.write(globals()[key_var])
    with open(tmp_path / 'Manifest', 'w') as f:
        f.write(globals()[manifest_var])
    os.mkdir(tmp_path / 'eclass')
    with open(tmp_path / 'eclass' / 'Manifest', 'w'):
        pass
    with open(tmp_path / 'myebuild-0.ebuild', 'wb') as f:
        if manifest_var == 'MODIFIED_SIGNED_MANIFEST':
            f.write(b'12345678901234567890123456789012')
    with open(tmp_path / 'metadata.xml', 'wb'):
        pass

    retval = gemato.cli.main(['gemato', 'verify',
                              '--openpgp-key',
                              str(tmp_path / '.key.bin'),
                              '--no-refresh-keys',
                              '--require-signed-manifest',
                              str(tmp_path)])
    if str(OpenPGPNoImplementation('')) in caplog.text:
        pytest.skip('OpenPGP implementation missing')

    eexit = 0 if expected is None else 1
    assert retval == eexit
    if expected is not None:
        assert str(expected('')) in caplog.text


EMPTY_DATA = b''


@pytest.mark.parametrize(
    'key_var,success',
    [('VALID_PUBLIC_KEY', True),
     ('VALID_KEY_NOEMAIL', True),
     ('MALFORMED_PUBLIC_KEY', False),
     ('EMPTY_DATA', False),
     ('FORGED_PUBLIC_KEY', False),
     ('UNSIGNED_PUBLIC_KEY', False),
     ])
def test_env_import_key(openpgp_env, key_var, success):
    """Test importing valid and invalid keys"""
    try:
        if success:
            openpgp_env.import_key(io.BytesIO(globals()[key_var]))
        else:
            with pytest.raises(OpenPGPKeyImportError):
                openpgp_env.import_key(io.BytesIO(globals()[key_var]))
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


def test_env_double_close():
    """Test that env can be closed multiple times"""
    with IsolatedGPGEnvironment() as env:
        env.close()


def test_env_home_after_close():
    """Test that .home can not be referenced after closing"""
    with IsolatedGPGEnvironment() as env:
        env.close()
        with pytest.raises(AssertionError):
            env.home


@pytest.fixture
def privkey_env(openpgp_env):
    """Environment with private key loaded"""
    try:
        openpgp_env.import_key(io.BytesIO(PRIVATE_KEY))
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))
    return openpgp_env


TEST_STRING = u'The quick brown fox jumps over the lazy dog'


@pytest.mark.parametrize('keyid', [None, PRIVATE_KEY_ID])
def test_sign_data(privkey_env, keyid):
    """Test signing data"""
    with io.StringIO(TEST_STRING) as f:
        with io.StringIO() as wf:
            privkey_env.clear_sign_file(f, wf, keyid=keyid)
            wf.seek(0)
            privkey_env.verify_file(wf)


@pytest.mark.parametrize('keyid', [None, PRIVATE_KEY_ID])
@pytest.mark.parametrize('sign', [None, False, True])
def test_dump_signed_manifest(privkey_env, keyid, sign):
    """Test dumping a signed Manifest"""
    m = ManifestFile()
    verify = True if sign is None else False
    with io.StringIO(SIGNED_MANIFEST) as f:
        m.load(f, verify_openpgp=verify, openpgp_env=privkey_env)
    assert m.openpgp_signed == verify

    with io.StringIO() as f:
        m.dump(f, openpgp_keyid=keyid, openpgp_env=privkey_env,
               sign_openpgp=sign)
        f.seek(0)
        m.load(f, openpgp_env=privkey_env)
    if sign is not False:
        assert m.openpgp_signed
        assert m.openpgp_signature is not None
    else:
        assert not m.openpgp_signed
        assert m.openpgp_signature is None


@pytest.mark.parametrize('filename', ['Manifest', 'Manifest.gz'])
@pytest.mark.parametrize('sign', [None, True])
def test_recursive_manifest_loader_save_manifest(tmp_path, privkey_env,
                                                 filename, sign):
    """Test signing Manifests via ManifestRecursiveLoader"""
    with open_potentially_compressed_path(tmp_path / filename, 'w') as cf:
        cf.write(SIGNED_MANIFEST)

    verify = not sign
    m = ManifestRecursiveLoader(tmp_path / filename,
                                verify_openpgp=verify,
                                sign_openpgp=sign,
                                openpgp_env=privkey_env)
    assert m.openpgp_signed == verify

    m.save_manifest(filename)
    m2 = ManifestFile()
    with open_potentially_compressed_path(tmp_path / filename, 'r') as cf:
        m2.load(cf, openpgp_env=privkey_env)
    assert m2.openpgp_signed
    assert m2.openpgp_signature is not None


def test_recursive_manifest_loader_save_submanifest(tmp_path, privkey_env):
    """Test that sub-Manifests are not signed"""
    with open(tmp_path / 'Manifest', 'w') as f:
        f.write(SIGNED_MANIFEST)
    os.mkdir(tmp_path / 'eclass')
    with open(tmp_path / 'eclass' / 'Manifest', 'w'):
        pass

    m = ManifestRecursiveLoader(tmp_path / 'Manifest',
                                verify_openpgp=False,
                                sign_openpgp=True,
                                openpgp_env=privkey_env)
    assert not m.openpgp_signed
    assert m.openpgp_signature is None

    m.load_manifest('eclass/Manifest')
    m.save_manifest('eclass/Manifest')

    m2 = ManifestFile()
    with open(tmp_path / 'eclass' / 'Manifest', 'r') as f:
        m2.load(f, openpgp_env=privkey_env)
    assert not m2.openpgp_signed
    assert m2.openpgp_signature is None


@pytest.mark.parametrize(
    'key_var,expected',
    [('VALID_PUBLIC_KEY', {KEY_FINGERPRINT: ['gemato@example.com']}),
     ('OTHER_VALID_PUBLIC_KEY',
      {OTHER_KEY_FINGERPRINT: ['gemato@example.com']}),
     ('VALID_KEY_SUBKEY', {KEY_FINGERPRINT: ['gemato@example.com']}),
     ('VALID_KEY_NOEMAIL', {KEY_FINGERPRINT: []}),
     ])
def test_list_keys(openpgp_env_with_refresh, key_var, expected):
    try:
        openpgp_env_with_refresh.import_key(io.BytesIO(globals()[key_var]))
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))
    assert openpgp_env_with_refresh.list_keys() == expected


@pytest.fixture(scope='module')
def global_hkp_server():
    """A fixture that starts a single HKP server instance for tests"""
    server = HKPServer()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def hkp_server(global_hkp_server):
    """A fixture that resets the global HKP server with empty keys"""
    global_hkp_server.keys.clear()
    yield global_hkp_server


COMBINED_PUBLIC_KEYS = OTHER_VALID_PUBLIC_KEY + VALID_PUBLIC_KEY


REFRESH_VARIANTS = [
    # manifest, key, server key fpr, server key, expected exception
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', None),
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'REVOKED_PUBLIC_KEY', OpenPGPRevokedKeyFailure),
    # test fetching subkey for primary key
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'VALID_KEY_SUBKEY', None),
    # refresh should fail if key is not on server
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', None, None,
     OpenPGPKeyRefreshError),
    # unrevocation should not be possible
    ('SIGNED_MANIFEST', 'REVOKED_PUBLIC_KEY', KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', OpenPGPRevokedKeyFailure),
    # unexpiration should be possible
    ('SIGNED_MANIFEST', 'EXPIRED_PUBLIC_KEY', KEY_FINGERPRINT,
     'UNEXPIRE_PUBLIC_KEY', None),
    # ...but only with a new signature
    ('SIGNED_MANIFEST', 'EXPIRED_PUBLIC_KEY', KEY_FINGERPRINT,
     'OLD_UNEXPIRE_PUBLIC_KEY', OpenPGPExpiredKeyFailure),
    # make sure server can't malicously inject or replace key
    ('SIGNED_MANIFEST', 'OTHER_VALID_PUBLIC_KEY', OTHER_KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', OpenPGPKeyRefreshError),
    ('SIGNED_MANIFEST', 'OTHER_VALID_PUBLIC_KEY', OTHER_KEY_FINGERPRINT,
     'COMBINED_PUBLIC_KEYS', OpenPGPRuntimeError),
    # test that forged keys are rejected
    ('SIGNED_MANIFEST', 'EXPIRED_PUBLIC_KEY', KEY_FINGERPRINT,
     'FORGED_UNEXPIRE_KEY', OpenPGPExpiredKeyFailure),
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'FORGED_SUBKEY', OpenPGPVerificationFailure),
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'UNSIGNED_SUBKEY', OpenPGPVerificationFailure),
]


@pytest.mark.parametrize(
    'manifest_var,key_var,server_key_fpr,server_key_var,expected',
    REFRESH_VARIANTS +
    [('SIGNED_MANIFEST', 'VALID_KEY_NOEMAIL', KEY_FINGERPRINT,
      'VALID_PUBLIC_KEY', None),
     ])
def test_refresh_hkp(openpgp_env_with_refresh, hkp_server, manifest_var,
                     key_var, server_key_fpr, server_key_var, expected):
    """Test refreshing against a HKP keyserver"""
    try:
        if key_var is not None:
            with io.BytesIO(globals()[key_var]) as f:
                openpgp_env_with_refresh.import_key(f)

        if server_key_var is not None:
            hkp_server.keys[server_key_fpr] = globals()[server_key_var]

        if expected is None:
            openpgp_env_with_refresh.refresh_keys(
                allow_wkd=False, keyserver=hkp_server.addr)
            with io.StringIO(globals()[manifest_var]) as f:
                openpgp_env_with_refresh.verify_file(f)
        else:
            with pytest.raises(expected):
                openpgp_env_with_refresh.refresh_keys(
                    allow_wkd=False, keyserver=hkp_server.addr)
                with io.StringIO(globals()[manifest_var]) as f:
                    openpgp_env_with_refresh.verify_file(f)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.mark.parametrize(
    'manifest_var,key_var,server_key_fpr,server_key_var,expected,'
    'expect_hit',
    [args + (True,) for args in REFRESH_VARIANTS] +
    [('SIGNED_MANIFEST', 'VALID_KEY_NOEMAIL', KEY_FINGERPRINT,
      'VALID_PUBLIC_KEY', OpenPGPKeyRefreshError, False),
     ])
def test_refresh_wkd(openpgp_env_with_refresh,
                     manifest_var,
                     key_var,
                     server_key_fpr,
                     server_key_var,
                     expected,
                     expect_hit):
    """Test refreshing against WKD"""
    with pytest.importorskip('responses').RequestsMock(
            assert_all_requests_are_fired=expect_hit) as responses:
        try:
            if key_var is not None:
                with io.BytesIO(globals()[key_var]) as f:
                    openpgp_env_with_refresh.import_key(f)

            if server_key_var is not None:
                responses.add(
                    responses.GET,
                    'https://example.com/.well-known/openpgpkey/hu/'
                    '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                    body=globals()[server_key_var],
                    content_type='application/pgp-keys')
            else:
                responses.add(
                    responses.GET,
                    'https://example.com/.well-known/openpgpkey/hu/'
                    '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                    status=404)

            if expected is None:
                openpgp_env_with_refresh.refresh_keys(
                    allow_wkd=True, keyserver='hkps://block.invalid/')
                with io.StringIO(globals()[manifest_var]) as f:
                    openpgp_env_with_refresh.verify_file(f)
            else:
                with pytest.raises(expected):
                    openpgp_env_with_refresh.refresh_keys(
                        allow_wkd=True, keyserver='hkps://block.invalid/')
                    with io.StringIO(globals()[manifest_var]) as f:
                        openpgp_env_with_refresh.verify_file(f)
        except OpenPGPNoImplementation as e:
            pytest.skip(str(e))


def test_refresh_wkd_fallback_to_hkp(openpgp_env_with_refresh,
                                     hkp_server):
    """Test whether WKD refresh failure falls back to HKP"""
    with pytest.importorskip('responses').RequestsMock() as responses:
        try:
            with io.BytesIO(VALID_PUBLIC_KEY) as f:
                openpgp_env_with_refresh.import_key(f)
            hkp_server.keys[KEY_FINGERPRINT] = REVOKED_PUBLIC_KEY
            responses.add(
                responses.GET,
                'https://example.com/.well-known/openpgpkey/hu/'
                '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                status=404)

            openpgp_env_with_refresh.refresh_keys(
                allow_wkd=True, keyserver=hkp_server.addr)

            with pytest.raises(OpenPGPRevokedKeyFailure):
                with io.StringIO(SIGNED_MANIFEST) as f:
                    openpgp_env_with_refresh.verify_file(f)
        except OpenPGPNoImplementation as e:
            pytest.skip(str(e))


@pytest.mark.parametrize(
    'email,expected',
    [('gemato@example.com',
      'https://example.com/.well-known/openpgpkey/hu/'
      '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato'),
     ('Joe.Doe@Example.ORG',
      'https://example.org/.well-known/openpgpkey/hu/'
      'iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe'),
     ])
def test_get_wkd_url(email, expected):
    assert get_wkd_url(email) == expected


def signal_desc(sig):
    if hasattr(signal, 'strsignal'):
        return signal.strsignal(sig)
    else:
        return sig


@pytest.mark.parametrize(
    'command,expected,match',
    [('true', 0, None),
     ('false', 1, None),
     ('gpg --verify {tmp_path}/Manifest', 0, None),
     ('gpg --verify {tmp_path}/Manifest.subkey', 2, None),
     ('sh -c "kill $$"', -signal.SIGTERM,
      f'Child process terminated due to signal: '
      f'{signal_desc(signal.SIGTERM)}'),
     ('sh -c "kill -USR1 $$"', -signal.SIGUSR1,
      f'Child process terminated due to signal: '
      f'{signal_desc(signal.SIGUSR1)}'),
     ])
def test_cli_gpg_wrap(tmp_path, caplog, command, expected, match):
    with open(tmp_path / '.key.bin', 'wb') as f:
        f.write(VALID_PUBLIC_KEY)
    with open(tmp_path / 'Manifest', 'w') as f:
        f.write(SIGNED_MANIFEST)
    with open(tmp_path / 'Manifest.subkey', 'w') as f:
        f.write(SUBKEY_SIGNED_MANIFEST)

    command = [x.replace('{tmp_path}', str(tmp_path))
               for x in shlex.split(command)]
    retval = gemato.cli.main(['gemato', 'gpg-wrap',
                              '--openpgp-key',
                              str(tmp_path / '.key.bin'),
                              '--no-refresh-keys',
                              '--'] + command)
    if str(OpenPGPNoImplementation('')) in caplog.text:
        pytest.skip('OpenPGP implementation missing')

    assert retval == expected
    if match is not None:
        assert match in caplog.text
