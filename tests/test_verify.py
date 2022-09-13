# gemato: Verification tests
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import itertools
import os
import os.path
import socket
import stat

import pytest

from gemato.exceptions import (
    ManifestInvalidPath,
    ManifestCrossDevice,
    )
from gemato.hash import hash_path
from gemato.manifest import new_manifest_entry
from gemato.verify import (
    get_file_metadata,
    verify_path,
    update_entry_for_path,
    verify_entry_compatibility,
    )

from tests.testutil import disallow_writes


TEST_STRING = b'The quick brown fox jumps over the lazy dog'


@pytest.fixture(scope='module')
def test_tree(tmp_path_factory):
    """Test tree with different file types needed for tests"""
    tmp_path = tmp_path_factory.mktemp('verify-')
    with open(tmp_path / 'empty-file', 'w'):
        pass
    with open(tmp_path / 'regular-file', 'wb') as f:
        f.write(TEST_STRING)
    with open(tmp_path / 'unreadable-file', 'w') as f:
        os.chmod(f.fileno(), 0)
    os.mkdir(tmp_path / 'directory')
    os.symlink('regular-file', tmp_path / 'symlink-to-file')
    os.symlink('directory', tmp_path / 'symlink-to-directory')
    os.symlink('non-existing', tmp_path / 'symlink-broken')
    os.mkfifo(tmp_path / 'named-pipe')
    unix_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unix_sock.bind(str(tmp_path / 'unix-socket'))
    unix_sock.listen(1)
    disallow_writes(tmp_path)
    yield tmp_path
    unix_sock.close()


NONFILE_TEST_PATHS = [
    'directory',
    'symlink-to-directory',
    '/dev/null',  # character device
    'named-pipe',
    'unix-socket',
]
EMPTY_FILE_TEST_PATHS = [
    'empty-file',
    '/proc/version',  # special file
]
NONEMPTY_FILE_TEST_PATHS = [
    'regular-file',
    'symlink-to-file',
]
FILE_TEST_PATHS = EMPTY_FILE_TEST_PATHS + NONEMPTY_FILE_TEST_PATHS
NONEXIST_TEST_PATHS = [
    'non-existing',
    'symlink-broken',
]
ALL_TEST_PATHS = (NONFILE_TEST_PATHS + FILE_TEST_PATHS +
                  NONEXIST_TEST_PATHS)

TEST_PATH_TYPES = {
    'directory': (stat.S_IFDIR, 'directory'),
    'symlink-to-directory': (stat.S_IFDIR, 'directory'),
    '/dev/null': (stat.S_IFCHR, 'character device'),
    'named-pipe': (stat.S_IFIFO, 'named pipe'),
    'unix-socket': (stat.S_IFSOCK, 'UNIX socket'),
    'empty-file': (stat.S_IFREG, 'regular file'),
    'regular-file': (stat.S_IFREG, 'regular file'),
    'symlink-to-file': (stat.S_IFREG, 'regular file'),
    '/proc/version': (stat.S_IFREG, 'regular file'),
}


def get_checksums(path):
    """Get checksums for the specified path"""
    try:
        hashes = hash_path(path, ['md5', 'sha1', '__size__'])
    except FileNotFoundError:
        return None

    return {
        'MD5': hashes['md5'],
        'SHA1': hashes['sha1'],
        '__size__': hashes['__size__'],
    }


TEST_PATH_SIZES = {
    'empty-file': 0,
    'regular-file': 43,
    'symlink-to-file': 43,
    '/proc/version': 0,
}
TEST_PATH_CHECKSUMS = {
    'empty-file': {'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
                   'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                   '__size__': TEST_PATH_SIZES['empty-file'],
                   },
    'regular-file': {'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                     'SHA1': '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
                     '__size__': TEST_PATH_SIZES['regular-file'],
                     },
    'symlink-to-file': {'MD5': '9e107d9d372bb6826bd81d3542a419d6',
                        'SHA1': '2fd4e1c67a2d28fced84'
                                '9ee1bb76e7391b93eb12',
                        '__size__': TEST_PATH_SIZES['regular-file'],
                        },
    '/proc/version': get_checksums('/proc/version'),
}


def strip_size(checksums):
    """Strip __size__ from checksum dict"""
    d = dict(checksums)
    del d['__size__']
    return d


@pytest.mark.parametrize(
    # note: None for dynamic components, test will fill the blanks in
    'path,expected',
    [(path, [False]) for path in NONEXIST_TEST_PATHS] +
    [(path, [True, None, TEST_PATH_TYPES[path]])
     for path in NONFILE_TEST_PATHS] +
    [(path, [True, None, TEST_PATH_TYPES[path], TEST_PATH_SIZES[path],
             None, TEST_PATH_CHECKSUMS[path]])
     for path in FILE_TEST_PATHS])
def test_get_file_metadata(test_tree, path, expected):
    if path.startswith('/') and not os.path.exists(path):
        pytest.skip(f'{path} does not exist')

    try:
        st = os.stat(test_tree / path)
    except FileNotFoundError:
        pass
    else:
        # fill in the blanks
        if len(expected) > 1:
            assert expected[1] is None
            expected[1] = st.st_dev
        if len(expected) > 4:
            assert expected[4] is None
            expected[4] = st.st_mtime

    assert (
        list(get_file_metadata(test_tree / path,
                               hashes=['MD5', 'SHA1'])) ==
        expected)


EMPTY_FILE_DATA = [0, {}]
ZERO_MD5 = '00000000000000000000000000000000'
ZERO_SHA1 = '0000000000000000000000000000000000000000'


def mangle_one_checksum(checksums):
    """Returns checksums with MD5 mangled"""
    d = strip_size(checksums)
    d['MD5'] = ZERO_MD5
    if checksums['MD5'] == d['MD5']:
        pytest.skip('MD5 already was zeros, how likely is that!?')
    return d


def mangle_both_checksums(checksums):
    """Returns checksums with MD5 and SHA1 mangled"""
    d = strip_size(checksums)
    d['MD5'] = ZERO_MD5
    d['SHA1'] = ZERO_SHA1
    if checksums['MD5'] == d['MD5']:
        pytest.skip('MD5 already was zeros, how likely is that!?')
    if checksums['SHA1'] == d['SHA1']:
        pytest.skip('SHA1 already was zeros, how likely is that!?')
    return d


class FILE_MTIME:
    pass


@pytest.mark.parametrize(
    'path,entry,args,last_mtime,expected,diff',
    # IGNORE should pass for everything, even unreadable
    [(path, 'IGNORE', [], None, True, [])
     for path in ALL_TEST_PATHS + ['unreadable-file']] +
    # None means must not exist, so passes for non-existing,
    # fails for everything existing
    [(path, None, [], None, True, []) for path in NONEXIST_TEST_PATHS] +
    [(path, None, [], None, False, [('__exists__', False, True)])
     for path in ALL_TEST_PATHS if path not in NONEXIST_TEST_PATHS] +
    # test DATA on non-regular files
    [('non-existing', 'DATA', EMPTY_FILE_DATA,
      None, False, [('__exists__', True, False)])] +
    [(path, 'DATA', EMPTY_FILE_DATA,
      None, False,
      [('__type__', 'regular file', TEST_PATH_TYPES[path][1])])
     for path in NONFILE_TEST_PATHS] +
    # test DATA on regular files
    list(itertools.chain.from_iterable(
        [(path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'], {}],
          None, True, []),
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                         strip_size(TEST_PATH_CHECKSUMS[path])],
          None, True, []),
         # wrong size
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'] + 11, {}],
          None, False, [('__size__',
                         TEST_PATH_CHECKSUMS[path]['__size__'] + 11,
                         TEST_PATH_CHECKSUMS[path]['__size__'])]),
         # one wrong checksum
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                         mangle_one_checksum(TEST_PATH_CHECKSUMS[path])],
          None, False,
          [('MD5', ZERO_MD5, TEST_PATH_CHECKSUMS[path]['MD5'])]),
         # both wrong checksums
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                         mangle_both_checksums(
                             TEST_PATH_CHECKSUMS[path])],
          None, False,
          [('MD5', ZERO_MD5, TEST_PATH_CHECKSUMS[path]['MD5']),
           ('SHA1', ZERO_SHA1, TEST_PATH_CHECKSUMS[path]['SHA1'])]),
         ] for path in FILE_TEST_PATHS)) +
    # both wrong checksums + size (different for st_size == 0)
    [(path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'] + 11,
                     mangle_both_checksums(
                         TEST_PATH_CHECKSUMS[path])],
      None, False, [('__size__',
                     TEST_PATH_CHECKSUMS[path]['__size__'] + 11,
                     TEST_PATH_CHECKSUMS[path]['__size__'])])
     for path in NONEMPTY_FILE_TEST_PATHS] +
    # on empty files, mtime does not matter
    [(path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                     mangle_both_checksums(TEST_PATH_CHECKSUMS[path])],
      mtime, False,
      [('MD5', ZERO_MD5, TEST_PATH_CHECKSUMS[path]['MD5']),
       ('SHA1', ZERO_SHA1, TEST_PATH_CHECKSUMS[path]['SHA1'])])
     for path in EMPTY_FILE_TEST_PATHS
     for mtime in (0, FILE_MTIME)] +
    # on non-empty files with correct size, up-to-date mtime skips
    # checksum
    list(itertools.chain.from_iterable(
        [(path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                         mangle_both_checksums(TEST_PATH_CHECKSUMS[path])],
          0, False,
          [('MD5', ZERO_MD5, TEST_PATH_CHECKSUMS[path]['MD5']),
           ('SHA1', ZERO_SHA1, TEST_PATH_CHECKSUMS[path]['SHA1'])]),
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                         mangle_both_checksums(TEST_PATH_CHECKSUMS[path])],
          FILE_MTIME, True, []),
         # but size change invalidates it
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'] + 11,
                         mangle_both_checksums(TEST_PATH_CHECKSUMS[path])],
          FILE_MTIME, False,
          [('__size__',
            TEST_PATH_CHECKSUMS[path]['__size__'] + 11,
            TEST_PATH_CHECKSUMS[path]['__size__'])]),
         ] for path in NONEMPTY_FILE_TEST_PATHS)) +
    [(path, None, [], FILE_MTIME, False, [('__exists__', False, True)])
     for path in FILE_TEST_PATHS])
def test_verify_path(test_tree, path, entry, args, last_mtime, expected,
                     diff):
    if path.startswith('/') and not os.path.exists(path):
        pytest.skip(f'{path} does not exist')
    if entry is not None:
        entry = new_manifest_entry(entry, path, *args)
    if last_mtime is FILE_MTIME:
        st = os.stat(test_tree / path)
        last_mtime = st.st_mtime
    assert verify_path(test_tree / path,
                       entry,
                       last_mtime=last_mtime) == (expected, diff)


@pytest.mark.parametrize(
    'path,key,match',
    [(path, '__exists__', False)
     for path in NONEXIST_TEST_PATHS] +
    [(path, '__type__', TEST_PATH_TYPES[path][1])
     for path in NONFILE_TEST_PATHS])
def test_update_fail(test_tree, path, key, match):
    entry = new_manifest_entry('DATA', path, 0, {})
    with pytest.raises(ManifestInvalidPath) as exc:
        update_entry_for_path(test_tree / path, entry)
    assert exc.value.detail == (key, match)


@pytest.mark.parametrize('function', [verify_path,
                                      update_entry_for_path])
def test_cross_filesystem(test_tree, function):
    filename = 'empty-file'
    try:
        st = os.stat('/proc')
        lst = os.stat(test_tree / filename)
    except OSError:
        pytest.skip('unable to stat /proc or empty-file')
    if st.st_dev == lst.st_dev:
        pytest.skip('/proc and test tree on the same filesystem!?')

    entry = new_manifest_entry('DATA', filename, 0, {})
    with pytest.raises(ManifestCrossDevice):
        function(test_tree / filename, entry, expected_dev=st.st_dev)


@pytest.mark.parametrize(
    'path,cls,args,new_hashes,last_mtime,retval,new_data',
    list(itertools.chain.from_iterable(
        [(path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'], {}],
          None, None, False,
          [('size', TEST_PATH_CHECKSUMS[path]['__size__']),
           ]),
         (path, 'MISC', [TEST_PATH_CHECKSUMS[path]['__size__'], {}],
          None, None, False,
          [('size', TEST_PATH_CHECKSUMS[path]['__size__']),
           ]),
         # unchanged hashes
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                         strip_size(TEST_PATH_CHECKSUMS[path])],
          None, None, False,
          [('size', TEST_PATH_CHECKSUMS[path]['__size__']),
           ('checksums', strip_size(TEST_PATH_CHECKSUMS[path])),
           ]),
         # new hashes
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'], {}],
          ['MD5', 'SHA1'], None, True,
          [('size', TEST_PATH_CHECKSUMS[path]['__size__']),
           ('checksums', strip_size(TEST_PATH_CHECKSUMS[path])),
           ]),
         # fill hashes already in Manifest
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                         {'MD5': '', 'SHA1': ''}],
          None, None, True,
          [('size', TEST_PATH_CHECKSUMS[path]['__size__']),
           ('checksums', strip_size(TEST_PATH_CHECKSUMS[path])),
           ]),
         # subset of existing hashes
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                         strip_size(TEST_PATH_CHECKSUMS[path])],
          ['MD5'], None, True,
          [('size', TEST_PATH_CHECKSUMS[path]['__size__']),
           ('checksums', {'MD5': TEST_PATH_CHECKSUMS[path]['MD5']}),
           ]),
         # superset of existing hashes
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                         {'MD5': TEST_PATH_CHECKSUMS[path]['MD5']}],
          ['MD5', 'SHA1'], None, True,
          [('size', TEST_PATH_CHECKSUMS[path]['__size__']),
           ('checksums', strip_size(TEST_PATH_CHECKSUMS[path])),
           ]),
         ] for path in FILE_TEST_PATHS)) +
    # mtime does not affect empty files
    [(path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                     {'MD5': ZERO_MD5, 'SHA1': ZERO_SHA1}],
      ['MD5', 'SHA1'], mtime, True,
      [('size', TEST_PATH_CHECKSUMS[path]['__size__']),
       ('checksums', strip_size(TEST_PATH_CHECKSUMS[path])),
       ])
     for path in EMPTY_FILE_TEST_PATHS
     for mtime in (0, FILE_MTIME)] +
    # but non-empty files with recent mtime do not get rechecked
    list(itertools.chain.from_iterable(
        [(path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                         {'MD5': ZERO_MD5, 'SHA1': ZERO_SHA1}],
          ['MD5', 'SHA1'], 0, True,
          [('size', TEST_PATH_CHECKSUMS[path]['__size__']),
           ('checksums', strip_size(TEST_PATH_CHECKSUMS[path])),
           ]),
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'],
                         {'MD5': ZERO_MD5, 'SHA1': ZERO_SHA1}],
          ['MD5', 'SHA1'], FILE_MTIME, False,
          [('size', TEST_PATH_CHECKSUMS[path]['__size__']),
           ('checksums', {'MD5': ZERO_MD5, 'SHA1': ZERO_SHA1}),
           ]),
         # size invalidates recent mtime
         (path, 'DATA', [TEST_PATH_CHECKSUMS[path]['__size__'] + 11,
                         {'MD5': ZERO_MD5, 'SHA1': ZERO_SHA1}],
          ['MD5', 'SHA1'], FILE_MTIME, True,
          [('size', TEST_PATH_CHECKSUMS[path]['__size__']),
           ('checksums', strip_size(TEST_PATH_CHECKSUMS[path])),
           ]),
         ] for path in NONEMPTY_FILE_TEST_PATHS)) +
    [])
def test_update(test_tree, path, cls, args, new_hashes, last_mtime,
                retval, new_data):
    entry = new_manifest_entry(cls, path, *args)
    if last_mtime is FILE_MTIME:
        st = os.stat(test_tree / path)
        last_mtime = st.st_mtime
    assert update_entry_for_path(test_tree / path,
                                 entry,
                                 hashes=new_hashes,
                                 last_mtime=last_mtime) is retval
    assert entry.path == path
    for k, v in new_data:
        assert getattr(entry, k) == v


def test_update_IGNORE(test_tree):
    path = 'empty-file'
    entry = new_manifest_entry('IGNORE', path)
    with pytest.raises(AssertionError):
        update_entry_for_path(test_tree / path, entry)


def test_update_AUX(test_tree):
    path = 'empty-file'
    entry = new_manifest_entry('AUX', path, *EMPTY_FILE_DATA)
    assert not update_entry_for_path(test_tree / path, entry)
    assert entry.aux_path == path
    assert entry.path == f'files/{path}'
    assert entry.size == 0
    assert entry.checksums == {}


@pytest.mark.parametrize(
    'function,args',
    [(get_file_metadata, [[]]),
     (verify_path,
      [new_manifest_entry('DATA', 'unreadable-file', 0, {})]),
     (update_entry_for_path,
      [new_manifest_entry('DATA', 'unreadable-file', 0, {})]),
     ])
def test_unreadable_file(test_tree, function, args):
    with pytest.raises(PermissionError):
        for x in function(test_tree / 'unreadable-file', *args):
            pass


@pytest.mark.parametrize(
    'a_cls,a_name,a_args,b_cls,b_name,b_args,expected,diff',
    [('DATA', 'test', [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      'DATA', 'test', [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      True, []),
     ('DATA', 'test-1.ebuild',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      'EBUILD', 'test-1.ebuild',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      True, []),
     ('DATA', 'files/test.patch',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      'AUX', 'test.patch',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      True, []),
     ('DATA', 'Manifest',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      'MANIFEST', 'Manifest',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      True, []),
     ('DATA', 'metadata.xml',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      'MISC', 'metadata.xml',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      False, [('__type__', 'DATA', 'MISC')]),
     ('DATA', 'test',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      'IGNORE', 'test', [],
      False, [('__type__', 'DATA', 'IGNORE')]),
     ('DATA', 'test-1.tar.gz',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      'DIST', 'test-1.tar.gz',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      False, [('__type__', 'DATA', 'DIST')]),
     ('DATA', 'mismatched-size',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      'DATA', 'mismatched-size',
      [32, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      False, [('__size__', 0, 32)]),
     ('DATA', 'mismatched-md5',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      'DATA', 'mismatched-md5',
      [0, {'MD5': ZERO_MD5}],
      False, [('MD5', 'd41d8cd98f00b204e9800998ecf8427e', ZERO_MD5)]),
     ('DATA', 'hash-subset',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      'DATA', 'mismatched-md5',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
           'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709'}],
      True, [('SHA1', None, 'da39a3ee5e6b4b0d3255bfef95601890afd80709')]),
     ('DATA', 'mismatched-hash-sets',
      [0, {'MD5': 'd41d8cd98f00b204e9800998ecf8427e'}],
      'DATA', 'mismatched-md5',
      [0, {'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709'}],
      True, [('MD5', 'd41d8cd98f00b204e9800998ecf8427e', None),
             ('SHA1', None, 'da39a3ee5e6b4b0d3255bfef95601890afd80709')]),
     ])
def test_entry_compatibility(a_cls, a_name, a_args, b_cls, b_name,
                             b_args, expected, diff):
    e1 = new_manifest_entry(a_cls, a_name, *a_args)
    e2 = new_manifest_entry(b_cls, b_name, *b_args)
    assert verify_entry_compatibility(e1, e2) == (expected, diff)
