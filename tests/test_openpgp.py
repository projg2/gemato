# gemato: OpenPGP signature support tests
# vim:fileencoding=utf-8
# (c) 2017-2018 Michał Górny
# Licensed under the terms of 2-clause BSD license

import base64
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


PUBLIC_KEY = b'''
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

EXPIRED_PUBLIC_KEY = b'''
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFnwXJMBCACgaTVz+d10TGL9zR920sb0GBFsitAJ5ZFzO4E0cg3SHhwI+reM
JQ6LLKmHowY/E1dl5FBbnJoRMxXP7/eScQ7HlhYj1gMPN5XiS2pkPwVkmJKBDV42
DLwoytC+ot0frRTJvSdEPCX81BNMgFiBSpkeZfXqb9XmU03bh6mFnrdd4CsHpTQG
csVXHK8QKhaxuqmHTALdpSzKCb/r0N/Z3sQExZhfLcBf/9UUVXj44Nwc6ooqZLRi
zHydxwQdxNu0aOFGEBn9WTi8Slf7MfR/pF0dI8rs9w6zMzVEq0lhDPpKFGDveoGf
g/+TpvBNXZ7DWH23GM4kID3pk4LLMc24U1PhABEBAAG0D2dlbWF0byB0ZXN0IGtl
eYkBTAQTAQoANgIbAwULCQoNBAMVCggCHgECF4AWIQSB4SwWvY3NYL4YCEUTaIDn
KnsThAUCWfEJZAUJAAH+UQAKCRATaIDnKnsThJTJB/9nXG1vgEBXHp8JsgkbmsAA
WzcSsdmuRFcr2FI3KDYJ0G7rmBpirJuAaGbWS/2+3BmQGVlOf77RjeC6CtI/DH4U
Tw3hcI7FYJrRdILV+p3HTkLhPs5fNjxH8bTyKthEE8pM0gQ3fuZxsaNnv1XbSpf0
P+d/y06ehvGCVYyEe4MHPV6f6YgCrP+ePqQvMqEpvlSizZE/HoFoKy7Ik4u2fDOH
5RRmIoNLv8j1gOKwp5+SncsuXVdQucY7jdFWSgECOAGIRvzBbGDq9+6ccCQHiOOz
ncaJWqeCHuTvNj9WfoyvKXM+hpQUdSaTURgz4a92htIGpON5wN7o32VuJz2nWXS4
=RwD3
-----END PGP PUBLIC KEY BLOCK-----
'''

REVOKED_PUBLIC_KEY = b'''
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFnwXJMBCACgaTVz+d10TGL9zR920sb0GBFsitAJ5ZFzO4E0cg3SHhwI+reM
JQ6LLKmHowY/E1dl5FBbnJoRMxXP7/eScQ7HlhYj1gMPN5XiS2pkPwVkmJKBDV42
DLwoytC+ot0frRTJvSdEPCX81BNMgFiBSpkeZfXqb9XmU03bh6mFnrdd4CsHpTQG
csVXHK8QKhaxuqmHTALdpSzKCb/r0N/Z3sQExZhfLcBf/9UUVXj44Nwc6ooqZLRi
zHydxwQdxNu0aOFGEBn9WTi8Slf7MfR/pF0dI8rs9w6zMzVEq0lhDPpKFGDveoGf
g/+TpvBNXZ7DWH23GM4kID3pk4LLMc24U1PhABEBAAGJATYEIAEIACAWIQSB4SwW
vY3NYL4YCEUTaIDnKnsThAUCWl4LpQIdAAAKCRATaIDnKnsThCvQB/9gzrXiRv7g
7UIzwRvTBMVXbKlbwjJpI0XnjdZmlYVis5y4ZWxh65z8j94lV4NmTtDtAdlMN8Xd
OyTVWPGKN5cJMRLMzMRWb+aQV1fCEfwJgngE0hQe0w2dPwuVQQVP3Kv8CC+4f2lQ
ummcgPW2LVEN3HihAwx9VWA91JSlrsX3luNSvTi2c63BM9YqGb64nJc1sAWqxzDy
x157gzt0AHKAAQ+Hmwhqt0vnR8MyKJYo60PwNUkzWlUhOLaBpb7WvHAAmva14Rw+
fCaldU4iFlC5oJrj0jE/yKvGG6SuSYZaS9O0H/UNI5vF8Y/HgGM0i8+NJxXu0hud
NRH/MmEilKxUtA9nZW1hdG8gdGVzdCBrZXmJAUYEEwEKADAWIQSB4SwWvY3NYL4Y
CEUTaIDnKnsThAUCWfBckwIbAwULCQoNBAMVCggCHgECF4AACgkQE2iA5yp7E4Qp
5Af9H4Ux9t9InYZX2YRW1YEy8a4+K6bBoNtCvB5DGlswobDjXSpKmGmLkXJtlEGd
CoOa5vY0LBmLgJ8x/+18JjpXmPecnFXwZI3vWlxegRKBonJOgvwCucO+73dZHAbS
Q60+CO78A+MEZMlHQpKVTFU+M+Gme5RyeBAq66yP5oNG/rBkch31z7yD6exdvefS
/3aW4QWQ3zDhQtAPSwUASZXShW0C4N8c1+LZ4s/wQa6eyo0zjClNLLn7HnSOdMXO
nLwmAsCRJaqPOr7+vZJWR2oRP5PZyWlADIwryTSe6VPGJyUkU0Ax9D2RLqQHcw1P
wIRkqwc+fia+zdKUCMauHbhP0A==
=Zvmi
-----END PGP PUBLIC KEY BLOCK-----
'''

PRIVATE_KEY = b'''
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQOYBFnwXJMBCACgaTVz+d10TGL9zR920sb0GBFsitAJ5ZFzO4E0cg3SHhwI+reM
JQ6LLKmHowY/E1dl5FBbnJoRMxXP7/eScQ7HlhYj1gMPN5XiS2pkPwVkmJKBDV42
DLwoytC+ot0frRTJvSdEPCX81BNMgFiBSpkeZfXqb9XmU03bh6mFnrdd4CsHpTQG
csVXHK8QKhaxuqmHTALdpSzKCb/r0N/Z3sQExZhfLcBf/9UUVXj44Nwc6ooqZLRi
zHydxwQdxNu0aOFGEBn9WTi8Slf7MfR/pF0dI8rs9w6zMzVEq0lhDPpKFGDveoGf
g/+TpvBNXZ7DWH23GM4kID3pk4LLMc24U1PhABEBAAEAB/sEgeBMIXW9ClZvvj9H
lfWcLz7yF1ZwKMC1BbOENz43LLxp7i2RJQtrErayxnxq8k6u4ML3SAe2OwK+ZIZG
2aFqL0fw+tb8KvotsSPMrE6o/HaFZMxEZYg19zj1WlsvRCxE3OlJDA2fNJBUQnj6
LQ/vYDsQOtM+VRHnfMDhLcwGObZnNPMwtmwkHLKWTgyTwAGnLObSheVutVbdyU6+
wI3UXwAoilW2e+9pKtwaODjqT7pQ2maVSCY4MPGdLQpbPy61COstdpK/hRdI3liL
uwszdlnT1QhiLsOTHPt4JjYdv2jgDjQobbe/ziKNzFp1eoMHDkbjzAh7oD2FxJcZ
EYLnBADE5oryW+9GlyYQe3x74QD5BGTZfvJctvEOgUg8BsoIfXJgBzwnEwOD0XBg
Jcl5qgt3IBH9Fn3JnYMpw12SEG2W4N8VCIBxIkDEBABVJfp1Q7HAJ8GSmzENnvt1
iaAZPUscaFVpMyuajsCDmyK92NMymGiNAb1H5MU4gaFGaEaajwQA0I7gglsehQA2
MSyJD0Uj+0b6n9KtiUzjyWEOcITXn4buf4O8Llor8gU0BWuv3hmIcvNsuJfmgXav
Vxq2UHtiGaO7T9Vk4Sr8MKS9EYrLNbK41Lyb+tjxk3jYjEyFqCDNEtWKIZR4ENdR
jo5gYKBtuqv1AYYSkflOTeaRlv/kIo8D/jVcyjmO19tNJM8lQE1xCvhp5maXOoSk
1UoUmDprsKA2Em47J83sVivrIwBySB2n9srQynnV+8I47mX7YzYtNQ6uXdL3p/5e
FRW+yfqVCShhSfyQdOmJ978UyQEwY0+0hhK372KatmaL9KEkKSuXgsqshv3XiB9y
u3Su1jw5y2IQNP20D2dlbWF0byB0ZXN0IGtleYkBRgQTAQoAMBYhBIHhLBa9jc1g
vhgIRRNogOcqexOEBQJZ8FyTAhsDBQsJCg0EAxUKCAIeAQIXgAAKCRATaIDnKnsT
hCnkB/0fhTH230idhlfZhFbVgTLxrj4rpsGg20K8HkMaWzChsONdKkqYaYuRcm2U
QZ0Kg5rm9jQsGYuAnzH/7XwmOleY95ycVfBkje9aXF6BEoGick6C/AK5w77vd1kc
BtJDrT4I7vwD4wRkyUdCkpVMVT4z4aZ7lHJ4ECrrrI/mg0b+sGRyHfXPvIPp7F29
59L/dpbhBZDfMOFC0A9LBQBJldKFbQLg3xzX4tniz/BBrp7KjTOMKU0sufsedI50
xc6cvCYCwJElqo86vv69klZHahE/k9nJaUAMjCvJNJ7pU8YnJSRTQDH0PZEupAdz
DU/AhGSrBz5+Jr7N0pQIxq4duE/Q
=wOFB
-----END PGP PRIVATE KEY BLOCK-----

'''

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


def strip_openpgp(text):
    lines = text.lstrip().splitlines()
    start = lines.index('')
    stop = lines.index('-----BEGIN PGP SIGNATURE-----')
    return '\n'.join(lines[start+1:stop-start+2]) + '\n'


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
            self.env.import_key(io.BytesIO(PUBLIC_KEY))
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
            with io.open(os.path.join(d, '.key.asc'), 'wb') as f:
                f.write(PUBLIC_KEY)
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
                        '--openpgp-key', os.path.join(d, '.key.asc'),
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
            self.env.import_key(io.BytesIO(PUBLIC_KEY))
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
                env.import_key(io.BytesIO(PUBLIC_KEY))
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

    def test_import_binary_key(self):
        with gemato.openpgp.OpenPGPEnvironment() as env:
            enc = b''.join(PUBLIC_KEY.splitlines()[2:-1])
            try:
                env.import_key(io.BytesIO(base64.b64decode(enc)))
            except gemato.exceptions.OpenPGPNoImplementation as e:
                raise unittest.SkipTest(str(e))

    def test_verify_manifest(self):
        with io.StringIO(SIGNED_MANIFEST) as f:
            with gemato.openpgp.OpenPGPEnvironment() as env:
                try:
                    try:
                        env.import_key(io.BytesIO(PUBLIC_KEY))
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
