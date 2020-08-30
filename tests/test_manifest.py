# gemato: Manifest file support tests
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import io

import pytest

from gemato.exceptions import (
    ManifestSyntaxError,
    )
from gemato.manifest import (
    ManifestFile,
    ManifestEntryTIMESTAMP,
    ManifestEntryMANIFEST,
    ManifestEntryIGNORE,
    ManifestEntryDATA,
    ManifestEntryMISC,
    ManifestEntryDIST,
    ManifestEntryEBUILD,
    ManifestEntryAUX,
    manifest_hashes_to_hashlib,
    new_manifest_entry,
    )


TEST_MANIFEST = '''
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
DATA foo.txt 0
'''

TEST_DEPRECATED_MANIFEST = '''
EBUILD myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
AUX test.patch 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
'''

EMPTY_MANIFEST = ''


@pytest.mark.parametrize('manifest_var', ['TEST_MANIFEST',
                                          'TEST_DEPRECATED_MANIFEST',
                                          'EMPTY_MANIFEST'])
def test_load(manifest_var):
    with io.StringIO(globals()[manifest_var]) as f:
        m = ManifestFile()
        m.load(f)


@pytest.mark.parametrize('manifest_var', ['TEST_MANIFEST',
                                          'TEST_DEPRECATED_MANIFEST',
                                          'EMPTY_MANIFEST'])
def test_load_via_ctor(manifest_var):
    with io.StringIO(globals()[manifest_var]) as f:
        ManifestFile(f)


@pytest.mark.parametrize('manifest_var', ['TEST_MANIFEST',
                                          'TEST_DEPRECATED_MANIFEST',
                                          'EMPTY_MANIFEST'])
def test_load_and_dump(manifest_var):
    m = ManifestFile()
    with io.StringIO(globals()[manifest_var]) as f:
        m.load(f)
    with io.StringIO() as outf:
        m.dump(outf)
        assert outf.getvalue().strip() == globals()[manifest_var].strip()


@pytest.mark.parametrize(
    'manifest_var,expected',
    [('TEST_MANIFEST', datetime.datetime(2017, 10, 22, 18, 6, 41)),
     ('TEST_DEPRECATED_MANIFEST', None),
     ('EMPTY_MANIFEST', None),
     ])
def test_find_timestamp(manifest_var, expected):
    m = ManifestFile()
    with io.StringIO(globals()[manifest_var]) as f:
        m.load(f)
    if expected is None:
        assert m.find_timestamp() is None
    else:
        assert m.find_timestamp().ts == expected


@pytest.fixture(scope='module')
def test_manifest():
    m = ManifestFile()
    with io.StringIO(TEST_MANIFEST) as f:
        m.load(f)
    yield m


@pytest.fixture(scope='module')
def deprecated_manifest():
    m = ManifestFile()
    with io.StringIO(TEST_DEPRECATED_MANIFEST) as f:
        m.load(f)
    yield m


@pytest.mark.parametrize(
    'path,expected',
    [('2017-10-22T18:06:41Z', None),
     ('eclass/Manifest', 'eclass/Manifest'),
     ('eclass', None),
     ('local', 'local'),
     ('local/foo', 'local'),
     ('locale', None),
     ('myebuild-0.ebuild', 'myebuild-0.ebuild'),
     ('metadata.xml', 'metadata.xml'),
     ('mydistfile.tar.gz', None),
     ])
def test_find_path_entry(test_manifest, path, expected):
    pe = test_manifest.find_path_entry(path)
    if expected is None:
        assert pe is None
    else:
        assert pe.path == expected


@pytest.mark.parametrize(
    'path,expected',
    [('test.patch', None),
     ('files/test.patch', 'test.patch'),
     ])
def test_find_path_entry_aux(deprecated_manifest, path, expected):
    pe = deprecated_manifest.find_path_entry(path)
    if expected is None:
        assert pe is None
    else:
        assert pe.aux_path == expected


@pytest.mark.parametrize(
    'filename,expected',
    [('myebuild-0.ebuild', None),
     ('mydistfile.tar.gz', 'mydistfile.tar.gz'),
     ])
def test_find_dist_entry(test_manifest, filename, expected):
    pe = test_manifest.find_dist_entry(filename)
    if expected is None:
        assert pe is None
    else:
        assert pe.path == expected


@pytest.mark.parametrize(
    'path,expected',
    [('foo', []),
     ('eclass', []),
     ('eclass/foo.eclass', ['eclass/Manifest']),
     ])
def test_find_manifests_for_path(test_manifest, path, expected):
    assert [x.path for x
            in test_manifest.find_manifests_for_path(path)] == expected


def test_multiple_load():
    """Test that load() overwrites previously loaded data."""
    m = ManifestFile()
    with io.StringIO(TEST_MANIFEST) as f:
        m.load(f)
    with io.StringIO(TEST_DEPRECATED_MANIFEST) as f:
        m.load(f)
    with io.StringIO() as outf:
        m.dump(outf)
        assert outf.getvalue().strip() == TEST_DEPRECATED_MANIFEST.strip()


def test_sort():
    m = ManifestFile()
    with io.StringIO(TEST_MANIFEST) as f:
        m.load(f)
    with io.StringIO() as outf:
        m.dump(outf, sort=True)
        assert outf.getvalue().strip() == '''
DATA foo.txt 0
DATA myebuild-0.ebuild 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
DIST mydistfile.tar.gz 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
IGNORE local
MANIFEST eclass/Manifest 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
MISC metadata.xml 0 MD5 d41d8cd98f00b204e9800998ecf8427e\
 SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709
TIMESTAMP 2017-10-22T18:06:41Z
'''.strip()


TEST_FILE_DATA = [('path', 'test'),
                  ('size', 0),
                  ('checksums', {'MD5': 'd41d8cd98f00b204'
                                        'e9800998ecf8427e',
                                 'SHA1': 'da39a3ee5e6b4b0d3255'
                                         'bfef95601890afd80709',
                                 }),
                  ]
TEST_FILE_LIST = ['test', '0', 'MD5', 'd41d8cd98f00b204e9800998ecf8427e',
                  'SHA1', 'da39a3ee5e6b4b0d3255bfef95601890afd80709']


ENTRY_TEST_DATA = [
    (ManifestEntryTIMESTAMP,
     ['TIMESTAMP', '2010-01-01T11:12:13Z'],
     [('ts', datetime.datetime(2010, 1, 1, 11, 12, 13)),
      ]),
    (ManifestEntryMANIFEST,
     ['MANIFEST'] + TEST_FILE_LIST,
     TEST_FILE_DATA),
    (ManifestEntryIGNORE,
     ['IGNORE', 'test'],
     [('path', 'test'),
      ]),
    (ManifestEntryDATA,
     ['DATA'] + TEST_FILE_LIST,
     TEST_FILE_DATA),
    (ManifestEntryIGNORE,
     ['IGNORE', 'test'],
     [('path', 'test'),
      ]),
    (ManifestEntryMISC,
     ['MISC'] + TEST_FILE_LIST,
     TEST_FILE_DATA),
    (ManifestEntryDIST,
     ['DIST'] + TEST_FILE_LIST,
     TEST_FILE_DATA),
    (ManifestEntryEBUILD,
     ['EBUILD'] + TEST_FILE_LIST,
     TEST_FILE_DATA),
    (ManifestEntryAUX,
     ['AUX'] + TEST_FILE_LIST,
     TEST_FILE_DATA),
]


@pytest.mark.parametrize('cls,as_list,vals', ENTRY_TEST_DATA)
def test_entry_from_list(cls, as_list, vals):
    entry = cls.from_list(as_list)
    for k, v in vals:
        if cls is ManifestEntryAUX and k == 'path':
            assert entry.aux_path == v
            v = 'files/' + v
        assert getattr(entry, k) == v


@pytest.mark.parametrize('cls,as_list,vals', ENTRY_TEST_DATA)
def test_entry_to_list(cls, as_list, vals):
    entry = cls(*(v for k, v in vals))
    assert list(entry.to_list()) == as_list


@pytest.mark.parametrize('cls,as_list,vals', ENTRY_TEST_DATA)
def test_new_manifest_entry(cls, as_list, vals):
    entry = new_manifest_entry(as_list[0], *(v for k, v in vals))
    assert isinstance(entry, cls)
    assert list(entry.to_list()) == as_list


ENTRY_INVALID_DATA = [
    (ManifestEntryTIMESTAMP, ('TIMESTAMP',)),
    (ManifestEntryTIMESTAMP, ('TIMESTAMP', '')),
    (ManifestEntryTIMESTAMP, ('TIMESTAMP', '2017-10-22T18:06:41+02:00')),
    (ManifestEntryTIMESTAMP, ('TIMESTAMP', '2017-10-22T18:06:41')),
    (ManifestEntryTIMESTAMP, ('TIMESTAMP', '2017-10-22', '18:06:41Z')),
    (ManifestEntryTIMESTAMP, ('TIMESTAMP', '20171022T180641Z')),
    (ManifestEntryMANIFEST, ('MANIFEST', '', '0')),
    (ManifestEntryMANIFEST, ('MANIFEST', '/foo', '0')),
    (ManifestEntryIGNORE, ('IGNORE', '',)),
    (ManifestEntryIGNORE, ('IGNORE', '/foo',)),
    (ManifestEntryDATA, ('DATA', '',)),
    (ManifestEntryDATA, ('DATA', '/foo',)),
    (ManifestEntryMISC, ('MISC', '',)),
    (ManifestEntryMISC, ('MISC', '/foo',)),
    (ManifestEntryDIST, ('DIST', '',)),
    (ManifestEntryDIST, ('DIST', '/foo',)),
    (ManifestEntryDIST, ('DIST', 'foo/bar.gz',)),
    (ManifestEntryEBUILD, ('EBUILD', '',)),
    (ManifestEntryEBUILD, ('EBUILD', '/foo',)),
    (ManifestEntryAUX, ('AUX', '',)),
    (ManifestEntryAUX, ('AUX', '/foo',)),
    (ManifestEntryMANIFEST, ('MANIFEST', 'foo', 'asdf')),
    (ManifestEntryMANIFEST, ('MANIFEST', 'foo', '5ds')),
    (ManifestEntryMANIFEST, ('MANIFEST', 'foo', '-5')),
    (ManifestEntryDATA, ('DATA', 'foo', 'asdf')),
    (ManifestEntryDATA, ('DATA', 'foo', '5ds')),
    (ManifestEntryDATA, ('DATA', 'foo', '-5')),
    (ManifestEntryMISC, ('MISC', 'foo', 'asdf')),
    (ManifestEntryMISC, ('MISC', 'foo', '5ds')),
    (ManifestEntryMISC, ('MISC', 'foo', '-5')),
    (ManifestEntryDIST, ('DIST', 'foo', 'asdf')),
    (ManifestEntryDIST, ('DIST', 'foo', '5ds')),
    (ManifestEntryDIST, ('DIST', 'foo', '-5')),
    (ManifestEntryEBUILD, ('EBUILD', 'foo', 'asdf')),
    (ManifestEntryEBUILD, ('EBUILD', 'foo', '5ds')),
    (ManifestEntryEBUILD, ('EBUILD', 'foo', '-5')),
    (ManifestEntryAUX, ('AUX', 'foo', 'asdf')),
    (ManifestEntryAUX, ('AUX', 'foo', '5ds')),
    (ManifestEntryAUX, ('AUX', 'foo', '-5')),
    (ManifestEntryMANIFEST, ('MANIFEST', 'foo', '0', 'md5')),
    (ManifestEntryMANIFEST, ('MANIFEST', 'foo', '0', 'md5',
                             'd41d8cd98f00b204e9800998ecf8427e', 'sha1')),
    (ManifestEntryDATA, ('DATA', 'foo', '0', 'md5')),
    (ManifestEntryDATA, ('DATA', 'foo', '0', 'md5',
                         'd41d8cd98f00b204e9800998ecf8427e', 'sha1')),
    (ManifestEntryMISC, ('MISC', 'foo', '0', 'md5')),
    (ManifestEntryMISC, ('MISC', 'foo', '0', 'md5',
                         'd41d8cd98f00b204e9800998ecf8427e', 'sha1')),
    (ManifestEntryDIST, ('DIST', 'foo', '0', 'md5')),
    (ManifestEntryDIST, ('DIST', 'foo', '0', 'md5',
                         'd41d8cd98f00b204e9800998ecf8427e', 'sha1')),
    (ManifestEntryEBUILD, ('EBUILD', 'foo', '0', 'md5')),
    (ManifestEntryEBUILD, ('EBUILD', 'foo', '0', 'md5',
                           'd41d8cd98f00b204e9800998ecf8427e', 'sha1')),
    (ManifestEntryAUX, ('AUX', 'foo', '0', 'md5')),
    (ManifestEntryAUX, ('AUX', 'foo', '0', 'md5',
                        'd41d8cd98f00b204e9800998ecf8427e', 'sha1')),
    (ManifestEntryMANIFEST, ('MANIFEST',)),
    (ManifestEntryMANIFEST, ('MANIFEST', 'foo')),
    (ManifestEntryIGNORE, ('IGNORE',)),
    (ManifestEntryIGNORE, ('IGNORE', 'foo', 'bar')),
    (ManifestEntryDATA, ('DATA',)),
    (ManifestEntryDATA, ('DATA', 'foo')),
    (ManifestEntryMISC, ('MISC',)),
    (ManifestEntryMISC, ('MISC', 'foo')),
    (ManifestEntryDIST, ('DIST',)),
    (ManifestEntryDIST, ('DIST', 'foo')),
    (ManifestEntryEBUILD, ('EBUILD',)),
    (ManifestEntryEBUILD, ('EBUILD', 'foo')),
    (ManifestEntryAUX, ('AUX',)),
    (ManifestEntryAUX, ('AUX', 'foo')),
]


@pytest.mark.parametrize('cls,as_list', ENTRY_INVALID_DATA)
def test_manifest_entry_invalid(cls, as_list):
    with pytest.raises(ManifestSyntaxError):
        cls.from_list(as_list)


@pytest.mark.parametrize('mhash,hlibhash',
                         [('MD5 SHA1', 'md5 sha1'),
                          ('RMD160', 'ripemd160'),
                          ('SHA3_256 SHA256', 'sha3_256 sha256'),
                          ])
def test_manifest_hashes_to_hashlib(mhash, hlibhash):
    assert (list(manifest_hashes_to_hashlib(mhash.split())) ==
            hlibhash.split())


PATH_ENCODING_DATA = [
    ('tes t', 'tes\\x20t'),
    ('tes\tt', 'tes\\x09t'),
    ('tes\u00a0t', 'tes\\u00A0t'),
    ('tes\u2000t', 'tes\\u2000t'),
    ('tes\x00t', 'tes\\x00t'),
    ('tes\at', 'tes\\x07t'),
    ('tes\x7ft', 'tes\\x7Ft'),
    ('tes\u0080t', 'tes\\u0080t'),
    ('tes\\t', 'tes\\x5Ct'),
]
PATH_ENCODING_NC_DATA = [
    ('tes t', 'tes\\u0020t'),
    ('tes t', 'tes\\U00000020t'),
    ('tes\u00a0t', 'tes\\u00a0t'),
    ('tes\x7ft', 'tes\\x7ft'),
    ('tes\\t', 'tes\\x5ct'),
]
PATH_ENCODING_INVALID_DATA = [
    'tes\\t',
    'tes\\\\t',
    'tes\\',
    'tes\\xt',
    'tes\\x5t',
    'tes\\ut',
    'tes\\u345t',
    'tes\\Ut',
    'tes\\U0000345t',
]


@pytest.mark.parametrize('path,enc', PATH_ENCODING_DATA)
def test_path_encode(path, enc):
    m = new_manifest_entry('DATA', path, 32, {})
    assert m.path == path
    assert m.to_list() == ['DATA', enc, '32']


@pytest.mark.parametrize('path,enc',
                         PATH_ENCODING_DATA + PATH_ENCODING_NC_DATA)
def test_path_decode(path, enc):
    m = ManifestEntryDATA.from_list(['DATA', enc, 32])
    assert m.path == path


@pytest.mark.parametrize('enc', PATH_ENCODING_INVALID_DATA)
def test_path_decode_invalid(enc):
    with pytest.raises(ManifestSyntaxError):
        ManifestEntryDATA.from_list(['DATA', enc, 32])
