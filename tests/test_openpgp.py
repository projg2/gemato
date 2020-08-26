# gemato: OpenPGP signature support tests
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import io
import os

import pytest

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
from tests.testutil import hkp_server


# workaround pyflakes
hkp_server = hkp_server


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
    m = gemato.manifest.ManifestFile()
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
                           gemato.exceptions.ManifestUnsignedData),
                          ('SIGNED_MANIFEST_JUNK_AFTER',
                           gemato.exceptions.ManifestUnsignedData),
                          ('SIGNED_MANIFEST_CUT_BEFORE_DATA',
                           gemato.exceptions.ManifestSyntaxError),
                          ('SIGNED_MANIFEST_CUT_BEFORE_SIGNATURE',
                           gemato.exceptions.ManifestSyntaxError),
                          ('SIGNED_MANIFEST_CUT_BEFORE_END',
                           gemato.exceptions.ManifestSyntaxError),
                          ])
def test_noverify_bad_manifest_load(manifest_var, expected):
    """Test Manifest files that should fail"""
    m = gemato.manifest.ManifestFile()
    with io.StringIO(globals()[manifest_var]) as f:
        with pytest.raises(expected):
            m.load(f, verify_openpgp=False)


@pytest.mark.parametrize('write_back', [False, True])
def test_noverify_recursive_manifest_loader(tmp_path, write_back):
    """Test reading signed Manifest"""
    with open(tmp_path / 'Manifest', 'w') as f:
        f.write(MODIFIED_SIGNED_MANIFEST)

    m = gemato.recursiveloader.ManifestRecursiveLoader(
            tmp_path / 'Manifest',
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


@pytest.fixture
def openpgp_env():
    """OpenPGP environment fixture"""
    env = gemato.openpgp.OpenPGPEnvironment()
    yield env
    env.close()


@pytest.fixture
def openpgp_env_valid_key(openpgp_env):
    """OpenPGP environment with good key loaded"""
    try:
        openpgp_env.import_key(io.BytesIO(VALID_PUBLIC_KEY))
    except gemato.exceptions.OpenPGPNoImplementation as e:
        pytest.skip(str(e))
    yield openpgp_env


MANIFEST_VARIANTS = [
    # manifest, key, expected fpr/exception
    # == good manifests ==
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', None),
    ('DASH_ESCAPED_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', None),
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_KEY_SUBKEY', None),
    # == using private key ==
    ('SIGNED_MANIFEST', 'PRIVATE_KEY', None),
    # == bad manifests ==
    ('MODIFIED_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY',
     gemato.exceptions.OpenPGPVerificationFailure),
    ('EXPIRED_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY',
     gemato.exceptions.OpenPGPVerificationFailure),
    # == bad keys ==
    ('SIGNED_MANIFEST', None,
     gemato.exceptions.OpenPGPVerificationFailure),
    ('SIGNED_MANIFEST', 'EXPIRED_PUBLIC_KEY',
     gemato.exceptions.OpenPGPExpiredKeyFailure),
    ('SIGNED_MANIFEST', 'REVOKED_PUBLIC_KEY',
     gemato.exceptions.OpenPGPRevokedKeyFailure),
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
    except gemato.exceptions.OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.mark.parametrize('manifest_var,key_var,expected',
                         MANIFEST_VARIANTS)
def test_manifest_load(openpgp_env, manifest_var, key_var, expected):
    """Test Manifest verification via ManifestFile.load()"""
    try:
        if key_var is not None:
            with io.BytesIO(globals()[key_var]) as f:
                openpgp_env.import_key(f)

        m = gemato.manifest.ManifestFile()
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
    except gemato.exceptions.OpenPGPNoImplementation as e:
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

        with gemato.compression.open_potentially_compressed_path(
                tmp_path / filename, 'w') as cf:
            cf.write(globals()[manifest_var])

        if expected is None:
            m = gemato.recursiveloader.ManifestRecursiveLoader(
                tmp_path / filename,
                verify_openpgp=True,
                openpgp_env=openpgp_env)
            assert m.openpgp_signed
            assert_signature(m.openpgp_signature, manifest_var)
        else:
            with pytest.raises(expected):
                gemato.recursiveloader.ManifestRecursiveLoader(
                    tmp_path / filename,
                    verify_openpgp=True,
                    openpgp_env=openpgp_env)
    except gemato.exceptions.OpenPGPNoImplementation as e:
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

    eexit = 0 if expected is None else 1
    assert eexit == gemato.cli.main(['gemato', 'verify',
                                     '--openpgp-key',
                                     str(tmp_path / '.key.bin'),
                                     '--no-refresh-keys',
                                     '--require-signed-manifest',
                                     str(tmp_path)])

    if expected is not None:
        assert str(expected('')) in caplog.text


EMPTY_DATA = b''


@pytest.mark.parametrize('key_var,success', [('VALID_PUBLIC_KEY', True),
                                             ('MALFORMED_PUBLIC_KEY', False),
                                             ('EMPTY_DATA', False),
                                             ('FORGED_PUBLIC_KEY', False)])
def test_env_import_key(openpgp_env, key_var, success):
    """Test importing valid and invalid keys"""
    try:
        if success:
            openpgp_env.import_key(io.BytesIO(globals()[key_var]))
        else:
            with pytest.raises(gemato.exceptions.OpenPGPKeyImportError):
                openpgp_env.import_key(io.BytesIO(globals()[key_var]))
    except gemato.exceptions.OpenPGPNoImplementation as e:
        pytest.skip(str(e))


def test_env_double_close():
    """Test that env can be closed multiple times"""
    with gemato.openpgp.OpenPGPEnvironment() as env:
        env.close()


def test_env_home_after_close():
    """Test that .home can not be referenced after closing"""
    with gemato.openpgp.OpenPGPEnvironment() as env:
        env.close()
        with pytest.raises(AssertionError):
            env.home


@pytest.fixture
def privkey_env(openpgp_env):
    """Environment with private key loaded"""
    try:
        openpgp_env.import_key(io.BytesIO(PRIVATE_KEY))
    except gemato.exceptions.OpenPGPNoImplementation as e:
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
    m = gemato.manifest.ManifestFile()
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
    with gemato.compression.open_potentially_compressed_path(
            tmp_path / filename, 'w') as cf:
        cf.write(SIGNED_MANIFEST)

    verify = not sign
    m = gemato.recursiveloader.ManifestRecursiveLoader(
        tmp_path / filename,
        verify_openpgp=verify,
        sign_openpgp=sign,
        openpgp_env=privkey_env)
    assert m.openpgp_signed == verify

    m.save_manifest(filename)
    m2 = gemato.manifest.ManifestFile()
    with gemato.compression.open_potentially_compressed_path(
            tmp_path / filename, 'r') as cf:
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

    m = gemato.recursiveloader.ManifestRecursiveLoader(
        tmp_path / 'Manifest',
        verify_openpgp=False,
        sign_openpgp=True,
        openpgp_env=privkey_env)
    assert not m.openpgp_signed
    assert m.openpgp_signature is None

    m.load_manifest('eclass/Manifest')
    m.save_manifest('eclass/Manifest')

    m2 = gemato.manifest.ManifestFile()
    with open(tmp_path / 'eclass' / 'Manifest', 'r') as f:
        m2.load(f, openpgp_env=privkey_env)
    assert not m2.openpgp_signed
    assert m2.openpgp_signature is None


COMBINED_PUBLIC_KEYS = OTHER_VALID_PUBLIC_KEY + VALID_PUBLIC_KEY


REFRESH_VARIANTS = [
    # manifest, key, server key fpr, server key, expected exception
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', None),
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'REVOKED_PUBLIC_KEY', gemato.exceptions.OpenPGPRevokedKeyFailure),
    # test fetching subkey for primary key
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'VALID_KEY_SUBKEY', None),
    # refresh should fail if key is not on server
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', None, None,
     gemato.exceptions.OpenPGPKeyRefreshError),
    # unrevocation should not be possible
    ('SIGNED_MANIFEST', 'REVOKED_PUBLIC_KEY', KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', gemato.exceptions.OpenPGPRevokedKeyFailure),
    # unexpiration should be possible
    ('SIGNED_MANIFEST', 'EXPIRED_PUBLIC_KEY', KEY_FINGERPRINT,
     'UNEXPIRE_PUBLIC_KEY', None),
    # make sure server can't malicously inject or replace key
    ('SIGNED_MANIFEST', 'OTHER_VALID_PUBLIC_KEY', OTHER_KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', gemato.exceptions.OpenPGPKeyRefreshError),
    ('SIGNED_MANIFEST', 'OTHER_VALID_PUBLIC_KEY', OTHER_KEY_FINGERPRINT,
     'COMBINED_PUBLIC_KEYS', gemato.exceptions.OpenPGPRuntimeError),
    # test that forged keys are rejected
    ('SIGNED_MANIFEST', 'EXPIRED_PUBLIC_KEY', KEY_FINGERPRINT,
     'FORGED_UNEXPIRE_KEY', gemato.exceptions.OpenPGPExpiredKeyFailure),
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'FORGED_SUBKEY', gemato.exceptions.OpenPGPVerificationFailure),
]


@pytest.mark.parametrize(
    'manifest_var,key_var,server_key_fpr,server_key_var,expected',
    REFRESH_VARIANTS)
def test_refresh_hkp(openpgp_env, hkp_server, manifest_var, key_var,
                     server_key_fpr, server_key_var, expected):
    """Test refreshing against a HKP keyserver"""
    try:
        if key_var is not None:
            with io.BytesIO(globals()[key_var]) as f:
                openpgp_env.import_key(f)

        if server_key_var is not None:
            hkp_server.keys[server_key_fpr] = globals()[server_key_var]

        if expected is None:
            openpgp_env.refresh_keys(allow_wkd=False,
                                     keyserver=hkp_server.addr)
            with io.StringIO(globals()[manifest_var]) as f:
                openpgp_env.verify_file(f)
        else:
            with pytest.raises(expected):
                openpgp_env.refresh_keys(allow_wkd=False,
                                         keyserver=hkp_server.addr)
                with io.StringIO(globals()[manifest_var]) as f:
                        openpgp_env.verify_file(f)
    except gemato.exceptions.OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.mark.parametrize(
    'manifest_var,key_var,server_key_fpr,server_key_var,expected',
    REFRESH_VARIANTS)
def test_refresh_wkd(openpgp_env, manifest_var, key_var, server_key_fpr,
                     server_key_var, expected):
    """Test refreshing against WKD"""
    if key_var == 'EXPIRED_PUBLIC_KEY':
        pytest.skip('TODO: expired public key lacks UID with email')

    with pytest.importorskip('responses').RequestsMock() as responses:
        try:
            if key_var is not None:
                with io.BytesIO(globals()[key_var]) as f:
                    openpgp_env.import_key(f)

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
                openpgp_env.refresh_keys(allow_wkd=True,
                                         keyserver='hkps://block.invalid/')
                with io.StringIO(globals()[manifest_var]) as f:
                    openpgp_env.verify_file(f)
            else:
                with pytest.raises(expected):
                    openpgp_env.refresh_keys(allow_wkd=True,
                                             keyserver='hkps://block.invalid/')
                    with io.StringIO(globals()[manifest_var]) as f:
                            openpgp_env.verify_file(f)
        except gemato.exceptions.OpenPGPNoImplementation as e:
            pytest.skip(str(e))


def test_refresh_wkd_fallback_to_hkp(openpgp_env_valid_key, hkp_server):
    """Test whether WKD refresh failure falls back to HKP"""
    with pytest.importorskip('responses').RequestsMock() as responses:
        try:
            hkp_server.keys[KEY_FINGERPRINT] = REVOKED_PUBLIC_KEY
            responses.add(
                responses.GET,
                'https://example.com/.well-known/openpgpkey/hu/'
                '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                status=404)

            openpgp_env_valid_key.refresh_keys(allow_wkd=True,
                                               keyserver=hkp_server.addr)

            with pytest.raises(gemato.exceptions.OpenPGPRevokedKeyFailure):
                with io.StringIO(SIGNED_MANIFEST) as f:
                        openpgp_env_valid_key.verify_file(f)
        except gemato.exceptions.OpenPGPNoImplementation as e:
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
    assert (gemato.openpgp.OpenPGPEnvironment.get_wkd_url(email) ==
            expected)
