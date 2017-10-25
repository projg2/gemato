# gemato: OpenPGP signature support tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import io
import unittest

import gemato.manifest


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
