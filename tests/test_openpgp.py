# gemato: OpenPGP signature support tests
# (c) 2017-2023 Michał Górny
# SPDX-License-Identifier: GPL-2.0-or-later

import base64
import contextlib
import datetime
import io
import logging
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
    ManifestInsecureHashes,
    )
from gemato.manifest import ManifestFile
from gemato.openpgp import (
    SystemGPGEnvironment,
    IsolatedGPGEnvironment,
    PGPyEnvironment,
    get_wkd_url,
    has_advanced_wkd,
    OpenPGPSignatureList,
    OpenPGPSignatureData,
    OpenPGPSignatureStatus,
    )
from gemato.recursiveloader import ManifestRecursiveLoader

from tests.keydata import (
    PRIVATE_KEY_ID, KEY_FINGERPRINT, OTHER_KEY_FINGERPRINT, VALID_PUBLIC_KEY,
    VALID_KEY_NOEMAIL, VALID_KEY_NONUTF, COMBINED_PUBLIC_KEYS,
    VALID_KEY_SUBKEY, PRIVATE_KEY, EXPIRED_PUBLIC_KEY, REVOKED_PUBLIC_KEY,
    OTHER_VALID_PUBLIC_KEY, UNSIGNED_PUBLIC_KEY, FORGED_PUBLIC_KEY,
    UNSIGNED_SUBKEY, FORGED_SUBKEY, SUBKEY_FINGERPRINT,
    UNEXPIRE_PUBLIC_KEY, OLD_UNEXPIRE_PUBLIC_KEY,
    FORGED_UNEXPIRE_KEY, TWO_SIGNATURE_PUBLIC_KEYS, SECOND_KEY_FINGERPRINT,
    SECOND_VALID_PUBLIC_KEY, TWO_KEYS_ONE_EXPIRED,
    )
from tests.test_recursiveloader import INSECURE_HASH_TESTS
from tests.testutil import HKPServer


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

COMMON_MANIFEST_TEXT = """\
TIMESTAMP 2017-10-22T18:06:41Z
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709\
"""

SIGNED_MANIFEST = f"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

{COMMON_MANIFEST_TEXT}
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
"""

POST_EXPIRATION_SIGNED_MANIFEST = f"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

{COMMON_MANIFEST_TEXT}
-----BEGIN PGP SIGNATURE-----

iQEzBAEBCAAdFiEEgeEsFr2NzWC+GAhFE2iA5yp7E4QFAmPsj28ACgkQE2iA5yp7
E4R0xAf8CC6uh8VMmv8xlFePEoBYEuSUtDa2hWHJv1sMn90QnszHGG6oo32g2Lje
H9NRyjOltAG9t0siF/pf57EiKCs9B+Z9zLGYuWlK4gvkHjMHzsoTipUymm2/saEo
AuoeZvhqNtfU0hCIJsWENtdyMb/hsJIxIOwBjVS/JT5cZlOGjhlyxVO0CS/7FsCp
GZCeLYPdYXPw2em2DR3Q3NDuNmUY7W3WhJCL14uC+AkU64SnHc13xQ9/go6TQ2ho
783Jm2f/4ZREYpKMvCgUJvOADSqnfY89hc6B/9JCXn+Zm8a31zgENlJ8DEhN0JMN
le/JaXEH/AhO6xCOmk8tNQ3QXcNF5w==
=UGgA
-----END PGP SIGNATURE-----
"""

DASH_ESCAPED_SIGNED_MANIFEST = '''
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

MODIFIED_SIGNED_MANIFEST = '''
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

EXPIRED_SIGNED_MANIFEST = f"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

{COMMON_MANIFEST_TEXT}
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
"""

SUBKEY_SIGNED_MANIFEST = f"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

{COMMON_MANIFEST_TEXT}
-----BEGIN PGP SIGNATURE-----

iLMEAQEIAB0WIQR+nd48vkfkN0GN90A4udL3bMgzzAUCX0UGrAAKCRA4udL3bMgz
zH8MA/93/oNkXaA8+ZX7s8umhNMHiovdLJMna7Bl2C/tEdLfOoyp9o3lChhnB49v
g7VRUc//lz5sDUShdUUlTYjCPGLaYf2rBZHqd5POGJOsbzu1Tmtd8uhWFWnl8Kip
n4XmpdPvu+UdAHpQIGzKoNOEDJpZ5CzPLhYa5KgZiJhpYsDXgg==
=lpJi
-----END PGP SIGNATURE-----
"""

TWO_SIGNATURES = """
iQFHBAABCAAxFiEEgeEsFr2NzWC+GAhFE2iA5yp7E4QFAmPMHYQTHGdlbWF0b0Bl
eGFtcGxlLmNvbQAKCRATaIDnKnsThCDWB/95B9njv423M94uRdpPqSNqTpAokNhy
V0hjnhpiqnY85iFdL1Zc/rvhuxYbZezrig3dqctLseWYcx2mINBTLZqWHk5/NKEm
rd8iCdXZU1B7yo/HCfzUYR4HX5wISCiRjKimFFgkWKOg7KYGOqqrwLjAjaYJKmL5
L7R5joHpGbp87jix7c0ruSIMslQg5PbJ6/YAQWyOPTcZvqMFieJ8tqE/G2FabQcs
YRHEGu1x8wNY40rFzWd90ICR/hPjXZlCdCN2qk7hs+Coasb29n6pXjmt5L8/ICcL
zApRg8cetid6/SIzUSwiVqBt7i8noYWbgaazNt3HDlGq55v21dkOhmrXiIkEABYI
ADEWIQR1jj6cjPscaH2bJCVTcI9ps0i0zAUCY8wd6BMcc2Vjb25kQGV4YW1wbGUu
Y29tAAoJEFNwj2mzSLTMHKcA/0QbVl3PafYp45PFFo2e/knGKJKrm8D4bUH9wS5h
dchVAP0RSzkUQPP7Zs+2uHQItkqbXJyrBBHOqjGzeh39sWVuAw==
"""

TWO_SIGNATURE_MANIFEST = f"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

{COMMON_MANIFEST_TEXT}
-----BEGIN PGP SIGNATURE-----

{TWO_SIGNATURES}
=wG4b
-----END PGP SIGNATURE-----
"""


def strip_openpgp(text):
    lines = text.lstrip().splitlines()
    start = lines.index('')
    stop = lines.index('-----BEGIN PGP SIGNATURE-----')
    return '\n'.join(lines[start+1:stop-start+2]) + '\n'


# workaround pyflakes' limitations
_ = COMBINED_PUBLIC_KEYS
_ = EXPIRED_PUBLIC_KEY
_ = FORGED_PUBLIC_KEY
_ = FORGED_SUBKEY
_ = FORGED_UNEXPIRE_KEY
_ = OLD_UNEXPIRE_PUBLIC_KEY
_ = OTHER_VALID_PUBLIC_KEY
_ = SECOND_VALID_PUBLIC_KEY
_ = TWO_KEYS_ONE_EXPIRED
_ = TWO_SIGNATURE_PUBLIC_KEYS
_ = UNEXPIRE_PUBLIC_KEY
_ = UNSIGNED_PUBLIC_KEY
_ = UNSIGNED_SUBKEY
_ = VALID_KEY_NOEMAIL
_ = VALID_KEY_NONUTF
_ = VALID_KEY_SUBKEY


@pytest.mark.parametrize('manifest_var',
                         ["SIGNED_MANIFEST",
                          "DASH_ESCAPED_SIGNED_MANIFEST",
                          "SUBKEY_SIGNED_MANIFEST",
                          "MODIFIED_SIGNED_MANIFEST",
                          "EXPIRED_SIGNED_MANIFEST",
                          "TWO_SIGNATURE_MANIFEST",
                          "POST_EXPIRATION_SIGNED_MANIFEST",
                          ])
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
        with open(tmp_path / 'Manifest') as f:
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
        self._home = self._tmpdir.name
        os.environ['GNUPGHOME'] = self._tmpdir.name
        super().__init__(*args, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_cb):
        self.close()

    def close(self):
        if self._tmpdir is not None:
            IsolatedGPGEnvironment.close(self)
            # we need to recreate it to make cleanup() happy
            os.mkdir(self._tmpdir.name)
            self._tmpdir.cleanup()
            self._tmpdir = None
            os.environ.pop('GNUPGHOME', None)

    def import_key(self, keyfile, trust=True):
        IsolatedGPGEnvironment.import_key(self, keyfile, trust=trust)


@pytest.fixture(params=[IsolatedGPGEnvironment,
                        MockedSystemGPGEnvironment,
                        PGPyEnvironment,
                        ])
def openpgp_env(request):
    """OpenPGP environment fixture"""
    try:
        env = request.param()
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))
    yield env
    env.close()


@pytest.fixture(params=[IsolatedGPGEnvironment,
                        ])
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
    ('SIGNED_MANIFEST', 'VALID_KEY_NONUTF', None),
    ('SIGNED_MANIFEST', 'COMBINED_PUBLIC_KEYS', None),
    ('DASH_ESCAPED_SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', None),
    ('SUBKEY_SIGNED_MANIFEST', 'VALID_KEY_SUBKEY', None),
    ("POST_EXPIRATION_SIGNED_MANIFEST", "VALID_PUBLIC_KEY", None),
    # == Manifest signed before the key expired ==
    ("SIGNED_MANIFEST", "EXPIRED_PUBLIC_KEY", None),
    # == Manifest with two signatures ==
    ("TWO_SIGNATURE_MANIFEST", "TWO_SIGNATURE_PUBLIC_KEYS", None),
    ("TWO_SIGNATURE_MANIFEST", "VALID_PUBLIC_KEY", OpenPGPVerificationFailure),
    ("TWO_SIGNATURE_MANIFEST", "SECOND_VALID_PUBLIC_KEY",
     OpenPGPVerificationFailure),
    ("TWO_SIGNATURE_MANIFEST", "TWO_KEYS_ONE_EXPIRED",
     OpenPGPExpiredKeyFailure),
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
    ("POST_EXPIRATION_SIGNED_MANIFEST", "EXPIRED_PUBLIC_KEY",
     OpenPGPExpiredKeyFailure),
    ('SIGNED_MANIFEST', 'REVOKED_PUBLIC_KEY',
     OpenPGPRevokedKeyFailure),
    ('SIGNED_MANIFEST', 'OTHER_VALID_PUBLIC_KEY',
     OpenPGPVerificationFailure),
    ('SIGNED_MANIFEST', 'UNSIGNED_PUBLIC_KEY',
     OpenPGPKeyImportError),
    ('SIGNED_MANIFEST', 'FORGED_PUBLIC_KEY',
     OpenPGPKeyImportError),
    ('SUBKEY_SIGNED_MANIFEST', 'UNSIGNED_SUBKEY',
     OpenPGPVerificationFailure),
    ('SUBKEY_SIGNED_MANIFEST', 'FORGED_SUBKEY',
     OpenPGPVerificationFailure),
]


def assert_signature(sig: OpenPGPSignatureList,
                     manifest_var: str,
                     expect_both: bool = True,
                     ) -> None:
    """Make assertions about the signature"""
    if manifest_var == "TWO_SIGNATURE_MANIFEST":
        no_key_sig = OpenPGPSignatureData(
            sig_status=OpenPGPSignatureStatus.NO_PUBLIC_KEY)
        assert sorted(sig) == sorted([
            OpenPGPSignatureData(
                fingerprint=KEY_FINGERPRINT,
                timestamp=datetime.datetime(2023, 1, 21, 17, 14, 44),
                primary_key_fingerprint=KEY_FINGERPRINT,
                sig_status=OpenPGPSignatureStatus.GOOD,
                trusted_sig=True,
                valid_sig=True,
                ),
            OpenPGPSignatureData(
                fingerprint=SECOND_KEY_FINGERPRINT,
                timestamp=datetime.datetime(2023, 1, 21, 17, 16, 24),
                primary_key_fingerprint=SECOND_KEY_FINGERPRINT,
                sig_status=OpenPGPSignatureStatus.GOOD,
                trusted_sig=True,
                valid_sig=True,
                ) if expect_both else no_key_sig,
        ])
    elif manifest_var == 'SUBKEY_SIGNED_MANIFEST':
        assert len(sig) == 1
        assert sig.fingerprint == SUBKEY_FINGERPRINT
        assert sig.timestamp == datetime.datetime(2020, 8, 25, 12, 40, 12)
        assert sig.expire_timestamp is None
        assert sig.primary_key_fingerprint == KEY_FINGERPRINT
    elif manifest_var == "POST_EXPIRATION_SIGNED_MANIFEST":
        assert len(sig) == 1
        assert sig.fingerprint == KEY_FINGERPRINT
        assert sig.timestamp == datetime.datetime(2023, 2, 15, 7, 53, 19)
        assert sig.expire_timestamp is None
        assert sig.primary_key_fingerprint == KEY_FINGERPRINT
    else:
        assert len(sig) == 1
        assert sig.fingerprint == KEY_FINGERPRINT
        assert sig.timestamp == datetime.datetime(2017, 11, 8, 9, 1, 26)
        assert sig.expire_timestamp is None
        assert sig.primary_key_fingerprint == KEY_FINGERPRINT


@pytest.mark.parametrize('manifest_var,key_var,expected',
                         MANIFEST_VARIANTS)
def test_verify_manifest(openpgp_env, manifest_var, key_var, expected):
    """Test direct Manifest data verification"""
    if (isinstance(openpgp_env, PGPyEnvironment) and
            manifest_var == 'DASH_ESCAPED_SIGNED_MANIFEST'):
        pytest.xfail('dash escaping is known-broken in pgpy')

    try:
        with io.StringIO(globals()[manifest_var]) as f:
            if expected is None:
                if key_var is not None:
                    with io.BytesIO(globals()[key_var]) as kf:
                        openpgp_env.import_key(kf)

                sig = openpgp_env.verify_file(f)
                assert_signature(sig, manifest_var)
            else:
                with pytest.raises(expected):
                    if key_var is not None:
                        with io.BytesIO(globals()[key_var]) as kf:
                            openpgp_env.import_key(kf)

                    openpgp_env.verify_file(f)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


def test_verify_one_out_of_two():
    try:
        with MockedSystemGPGEnvironment() as openpgp_env:
            with io.BytesIO(VALID_PUBLIC_KEY) as f:
                openpgp_env.import_key(f)

            with io.StringIO(TWO_SIGNATURE_MANIFEST) as f:
                sig = openpgp_env.verify_file(f, require_all_good=False)

            assert_signature(sig, "TWO_SIGNATURE_MANIFEST", expect_both=False)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


def test_verify_untrusted_key():
    try:
        with MockedSystemGPGEnvironment() as openpgp_env:
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
    if (isinstance(openpgp_env, PGPyEnvironment) and
            manifest_var == 'DASH_ESCAPED_SIGNED_MANIFEST'):
        pytest.xfail('dash escaping is known-broken in pgpy')

    try:
        key_loaded = False
        m = ManifestFile()
        with io.StringIO(globals()[manifest_var]) as f:
            if expected is None:
                if key_var is not None:
                    with io.BytesIO(globals()[key_var]) as kf:
                        openpgp_env.import_key(kf)

                key_loaded = True
                m.load(f, openpgp_env=openpgp_env)
                assert m.openpgp_signed
                assert_signature(m.openpgp_signature, manifest_var)
            else:
                with pytest.raises(expected):
                    if key_var is not None:
                        with io.BytesIO(globals()[key_var]) as kf:
                            openpgp_env.import_key(kf)

                    key_loaded = True
                    m.load(f, openpgp_env=openpgp_env)
                assert not m.openpgp_signed
                assert m.openpgp_signature is None

        if key_loaded:
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
    if (isinstance(openpgp_env, PGPyEnvironment) and
            manifest_var == 'DASH_ESCAPED_SIGNED_MANIFEST'):
        pytest.xfail('dash escaping is known-broken in pgpy')

    try:
        with open_potentially_compressed_path(tmp_path / filename, 'w') as cf:
            cf.write(globals()[manifest_var])

        if expected is None:
            if key_var is not None:
                with io.BytesIO(globals()[key_var]) as f:
                    openpgp_env.import_key(f)

            m = ManifestRecursiveLoader(tmp_path / filename,
                                        verify_openpgp=True,
                                        openpgp_env=openpgp_env)
            assert m.openpgp_signed
            assert_signature(m.openpgp_signature, manifest_var)
        else:
            with pytest.raises(expected):
                if key_var is not None:
                    with io.BytesIO(globals()[key_var]) as f:
                        openpgp_env.import_key(f)

                ManifestRecursiveLoader(tmp_path / filename,
                                        verify_openpgp=True,
                                        openpgp_env=openpgp_env)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))


@pytest.fixture
def base_tree(tmp_path):
    os.mkdir(tmp_path / 'eclass')
    with open(tmp_path / 'eclass' / 'Manifest', 'w'):
        pass
    with open(tmp_path / 'myebuild-0.ebuild', 'wb'):
        pass
    with open(tmp_path / 'metadata.xml', 'wb'):
        pass
    return tmp_path


@pytest.mark.parametrize('manifest_var,key_var,expected',
                         [(m, k, e) for m, k, e in MANIFEST_VARIANTS
                          if k is not None])
def test_cli(base_tree, caplog, manifest_var, key_var, expected):
    """Test Manifest verification via CLI"""
    with open(base_tree / '.key.bin', 'wb') as f:
        f.write(globals()[key_var])
    with open(base_tree / 'Manifest', 'w') as f:
        f.write(globals()[manifest_var])
    if manifest_var == 'MODIFIED_SIGNED_MANIFEST':
        with open(base_tree / 'myebuild-0.ebuild', 'wb') as f:
            f.write(b'12345678901234567890123456789012')

    retval = gemato.cli.main(['gemato', 'verify',
                              '--openpgp-key',
                              str(base_tree / '.key.bin'),
                              '--no-refresh-keys',
                              '--require-signed-manifest',
                              # we verify this option separately
                              # and our test data currently sucks
                              '--no-require-secure-hashes',
                              str(base_tree)])
    if str(OpenPGPNoImplementation('install gpg')) in caplog.text:
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
     ('VALID_KEY_NONUTF', True),
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


@pytest.fixture(params=[IsolatedGPGEnvironment,
                        MockedSystemGPGEnvironment,
                        ])
def privkey_env(request):
    """Environment with private key loaded"""
    try:
        env = request.param()
        env.import_key(io.BytesIO(PRIVATE_KEY))
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))
    yield env
    env.close()


TEST_STRING = 'The quick brown fox jumps over the lazy dog'


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
    with open(tmp_path / 'eclass' / 'Manifest') as f:
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
     ('VALID_KEY_NONUTF', {KEY_FINGERPRINT: ['gemato@example.com']}),
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


REFRESH_VARIANTS = [
    # manifest, key, server key fpr, server key, expected exception
    ('SIGNED_MANIFEST', 'VALID_PUBLIC_KEY', KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', None),
    ('SIGNED_MANIFEST', 'VALID_KEY_NONUTF', KEY_FINGERPRINT,
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
    ("POST_EXPIRATION_SIGNED_MANIFEST", "EXPIRED_PUBLIC_KEY", KEY_FINGERPRINT,
     "OLD_UNEXPIRE_PUBLIC_KEY", OpenPGPExpiredKeyFailure),
    # make sure server can't malicously inject or replace key
    ('SIGNED_MANIFEST', 'OTHER_VALID_PUBLIC_KEY', OTHER_KEY_FINGERPRINT,
     'VALID_PUBLIC_KEY', OpenPGPKeyRefreshError),
    ('SIGNED_MANIFEST', 'OTHER_VALID_PUBLIC_KEY', OTHER_KEY_FINGERPRINT,
     'COMBINED_PUBLIC_KEYS', OpenPGPRuntimeError),
    # test that forged keys are rejected
    ("POST_EXPIRATION_SIGNED_MANIFEST", "EXPIRED_PUBLIC_KEY", KEY_FINGERPRINT,
     "FORGED_UNEXPIRE_KEY", OpenPGPExpiredKeyFailure),
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
                     key_var, server_key_fpr, server_key_var, expected, monkeypatch):
    """Test refreshing against a HKP keyserver"""
    monkeypatch.setattr(gemato.openpgp, 'has_advanced_wkd', lambda _: True)
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
                body_ = globals()[server_key_var]
                # The content-type changed over the development of the RFC, section 3.1.
                # https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/15/
                # 00 = The server SHOULD return "application/pgp-key" as the content-type
                # 01 = The server SHOULD return "application/octet-string" as the content-type
                content_type_ = 'application/octet-stream'
                status_ = 200
                headers_ = { 'Content-Length': len(body_) } # needed esp. for HEAD
            else:
                body_ = None
                content_type_ = None
                status_ = 404
                headers_ = None
            url1 = 'https://example.com/.well-known/openpgpkey/hu/' \
                   '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato'
            url2 = 'https://openpgpkey.example.com/.well-known/openpgpkey/example.org/hu/' \
                   '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato'
            for method_ in [responses.GET, responses.HEAD]:
                for url_ in [url1, url2]:
                    body__ = body_ if method_ == responses.HEAD else None
                    responses.add(
                        method_, url_,
                        body=body__,
                        content_type=content_type_,
                        headers=headers_,
                        status=status_)

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


@pytest.mark.parametrize('status', [401, 404, 500, ConnectionError])
def test_refresh_wkd_fallback_to_hkp(openpgp_env_with_refresh,
                                     hkp_server, caplog, status):
    """Test whether WKD refresh failure falls back to HKP"""
    with pytest.importorskip('responses').RequestsMock() as responses:
        try:
            with io.BytesIO(VALID_PUBLIC_KEY) as f:
                openpgp_env_with_refresh.import_key(f)
            hkp_server.keys[KEY_FINGERPRINT] = REVOKED_PUBLIC_KEY
            if status is not ConnectionError:
                responses.add(
                    responses.GET,
                    'https://example.com/.well-known/openpgpkey/hu/'
                    '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato',
                    status=status)

            caplog.set_level(logging.DEBUG)
            openpgp_env_with_refresh.refresh_keys(
                allow_wkd=True, keyserver=hkp_server.addr)
            assert 'failing due to failed request' in caplog.text

            with pytest.raises(OpenPGPRevokedKeyFailure):
                with io.StringIO(SIGNED_MANIFEST) as f:
                    openpgp_env_with_refresh.verify_file(f)
        except OpenPGPNoImplementation as e:
            pytest.skip(str(e))


@pytest.mark.parametrize(
    'email,has_advanced_wkd,expected',
    [('gemato@example.com',  False,
      'https://example.com/.well-known/openpgpkey/hu/'
      '5x66h616iaskmnadrm86ndo6xnxbxjxb?l=gemato'),
     ('Joe.Doe@Example.ORG', True,
      'https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/'
      'iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=Joe.Doe'),
     ])
def test_get_wkd_url(email, has_advanced_wkd, expected, monkeypatch):
    monkeypatch.setattr(gemato.openpgp, 'has_advanced_wkd', lambda _: has_advanced_wkd)
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
    if str(OpenPGPNoImplementation('install gpg')) in caplog.text:
        pytest.skip('OpenPGP implementation missing')

    assert retval == expected
    if match is not None:
        assert match in caplog.text


@pytest.mark.parametrize("hashes_arg,insecure", INSECURE_HASH_TESTS)
@pytest.mark.parametrize(
    "sign,require_secure",
    [(None, None),
     (False, None),
     (True, None),
     (None, False),
     (True, False),
     ])
def test_recursive_manifest_loader_require_secure(tmp_path, privkey_env,
                                                  hashes_arg, insecure,
                                                  sign, require_secure):
    with open(tmp_path / "Manifest", "w") as f:
        f.write(SIGNED_MANIFEST)

    ctx = (pytest.raises(ManifestInsecureHashes)
           if insecure is not None and sign is not False
           and require_secure is not False
           else contextlib.nullcontext())
    with ctx:
        m = ManifestRecursiveLoader(tmp_path / "Manifest",
                                    hashes=hashes_arg.split(),
                                    require_secure_hashes=require_secure,
                                    verify_openpgp=not sign,
                                    sign_openpgp=sign,
                                    openpgp_env=privkey_env)
        if not sign:
            assert m.openpgp_signed


@pytest.mark.parametrize("hashes_arg,insecure", INSECURE_HASH_TESTS)
@pytest.mark.parametrize(
    "sign,require_secure",
    [("", ""),
     ("--no-sign", ""),
     ("--sign", ""),
     ("", "--no-require-secure-hashes"),
     ("--sign", "--no-require-secure-hashes"),
     ])
def test_update_require_secure_cli(base_tree, caplog, hashes_arg,
                                   insecure, sign, require_secure):
    with open(base_tree / ".key.bin", "wb") as keyf:
        keyf.write(PRIVATE_KEY)
    with open(base_tree / "Manifest", "w") as f:
        f.write(SIGNED_MANIFEST)

    retval = gemato.cli.main(["gemato", "update",
                              "-K", str(base_tree / ".key.bin"),
                              "--hashes", hashes_arg,
                              str(base_tree)]
                             + f"{sign} {require_secure}".split())
    if str(OpenPGPNoImplementation('install gpg')) in caplog.text:
        pytest.skip('OpenPGP implementation missing')

    expected = (1 if insecure is not None and sign != "--no-sign"
                and require_secure != "--no-require-secure-hashes"
                else 0)
    assert retval == expected
    if expected == 1:
        assert str(ManifestInsecureHashes(insecure)) in caplog.text


@pytest.mark.parametrize(
    "require_secure", ["", "--no-require-secure-hashes"])
def test_verify_require_secure_cli(base_tree, caplog, require_secure):
    with open(base_tree / ".key.bin", "wb") as keyf:
        keyf.write(VALID_PUBLIC_KEY)
    with open(base_tree / "Manifest", "w") as f:
        f.write(SIGNED_MANIFEST)

    retval = gemato.cli.main(["gemato", "verify",
                              "--no-refresh-keys",
                              "--require-signed-manifest",
                              "-K", str(base_tree / ".key.bin"),
                              str(base_tree)]
                             + require_secure.split())
    if str(OpenPGPNoImplementation('install gpg')) in caplog.text:
        pytest.skip('OpenPGP implementation missing')

    expected = (1 if require_secure != "--no-require-secure-hashes"
                else 0)
    assert retval == expected
    if expected == 1:
        assert str(ManifestInsecureHashes(["MD5"])) in caplog.text


@pytest.mark.parametrize(
    "key_var,two_sigs",
    [("TWO_SIGNATURE_PUBLIC_KEYS", True),
     ("VALID_PUBLIC_KEY", False),
     ])
def test_verify_detached(tmp_path, key_var, two_sigs):
    try:
        with MockedSystemGPGEnvironment() as openpgp_env:
            with io.BytesIO(globals()[key_var]) as f:
                openpgp_env.import_key(f)

            with open(tmp_path / "data.bin", "wb") as f:
                f.write(b"\r\n".join(COMMON_MANIFEST_TEXT.encode("utf8")
                                     .splitlines()))
            with open(tmp_path / "sig.bin", "wb") as f:
                f.write(base64.b64decode(TWO_SIGNATURES))

            with open(tmp_path / "data.bin", "rb") as f:
                sig = openpgp_env.verify_detached(
                    tmp_path / "sig.bin", f,
                    require_all_good=two_sigs)

            assert_signature(sig, "TWO_SIGNATURE_MANIFEST",
                             expect_both=two_sigs)
    except OpenPGPNoImplementation as e:
        pytest.skip(str(e))
