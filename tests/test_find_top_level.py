# gemato: Top-level Manifest finding tests
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import gzip
import os
import os.path

import pytest

from gemato.find_top_level import find_top_level_manifest

from tests.testutil import disallow_writes


@pytest.fixture(scope='module')
def plain_tree(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp('find-top-level-plain-')
    for d in ('empty-subdir',
              'manifest-subdir',
              'deep/manifest-subdir',
              'ignored-dir',
              'ignored-dir/subdir',
              'ignored-dir-not',
              'ignored-empty-dir'):
        os.makedirs(tmp_path / d)
    with open(tmp_path / 'Manifest', 'w') as f:
        f.write('''
IGNORE ignored-dir
IGNORE ignored-empty-dir
''')
    for f in ('manifest-subdir/Manifest',
              'deep/manifest-subdir/Manifest',
              'ignored-dir/Manifest'):
        with open(tmp_path / f, 'w'):
            pass
    disallow_writes(tmp_path)
    yield tmp_path


@pytest.mark.parametrize(
    'start_dir,expected',
    [('.', 'Manifest'),
     ('empty-subdir', 'Manifest'),
     ('manifest-subdir', 'Manifest'),
     ('deep/manifest-subdir', 'Manifest'),
     ('ignored-dir', 'ignored-dir/Manifest'),
     ('ignored-dir/subdir', 'ignored-dir/Manifest'),
     ('ignored-dir-not', 'Manifest'),
     ('ignored-empty-dir', None),
     ])
def test_find_top_level_manifest(plain_tree, start_dir, expected):
    """Test finding top-level Manifest from plain directory tree"""
    mpath = find_top_level_manifest(plain_tree / start_dir)
    if mpath is not None:
        mpath = os.path.relpath(mpath, plain_tree)
    assert mpath == expected


def test_unreadable_manifest(tmp_path):
    """Test failure when one of Manifest files is not readable"""
    with open(tmp_path / 'Manifest', 'w') as f:
        os.fchmod(f.fileno(), 0)
    with pytest.raises(PermissionError):
        find_top_level_manifest(tmp_path)


def test_empty_tree(tmp_path):
    """Test working on empty tree without a Manifest file"""
    assert find_top_level_manifest(tmp_path) is None


def test_root_directory(tmp_path):
    """Test that things do not explode when running on /"""
    if os.path.exists('/Manifest'):
        pytest.skip('Manifest is present in system root ("/")')
    assert find_top_level_manifest('/') is None


def test_cross_device(tmp_path):
    """Test that device boundaries are not crossed"""
    if not os.path.ismount('/proc'):
        pytest.skip('/proc is not a mount point')
    with open(tmp_path / 'Manifest', 'w'):
        pass
    os.symlink('/proc', tmp_path / 'test')
    assert find_top_level_manifest(tmp_path / 'test') is None


@pytest.fixture(scope='module')
def compressed_manifest_tree(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp('find-top-level-compressed-')
    for d in ('empty-subdir',
              'manifest-subdir',
              'deep/manifest-subdir',
              'ignored-dir',
              'ignored-dir/subdir',
              'ignored-dir-not',
              'ignored-empty-dir'):
        os.makedirs(tmp_path / d)
    with gzip.GzipFile(tmp_path / 'Manifest.gz', 'wb') as f:
        f.write(b'''
IGNORE ignored-dir
IGNORE ignored-empty-dir
''')
    with open(tmp_path / 'manifest-subdir/Manifest', 'wb'):
        pass
    for f in ('deep/manifest-subdir/Manifest.gz',
              'ignored-dir/Manifest.gz'):
        with gzip.GzipFile(tmp_path / f, 'w'):
            pass
    disallow_writes(tmp_path)
    yield tmp_path


@pytest.mark.parametrize(
    'start_dir,allow_compressed,expected',
    [('.', False, None),
     ('.', True, 'Manifest.gz'),
     ('empty-subdir', True, 'Manifest.gz'),
     ('manifest-subdir', True, 'Manifest.gz'),
     ('deep/manifest-subdir', True, 'Manifest.gz'),
     ('ignored-dir', True, 'ignored-dir/Manifest.gz'),
     ('ignored-dir/subdir', True, 'ignored-dir/Manifest.gz'),
     ('ignored-dir-not', True, 'Manifest.gz'),
     ('ignored-empty-dir', True, None),
     ])
def test_find_compressed_top_level_manifest(compressed_manifest_tree,
                                            start_dir,
                                            allow_compressed,
                                            expected):
    """Test finding compressed top-level Manifest """
    mpath = find_top_level_manifest(compressed_manifest_tree / start_dir,
                                    allow_compressed=allow_compressed)
    if mpath is not None:
        mpath = os.path.relpath(mpath, compressed_manifest_tree)
    assert mpath == expected
