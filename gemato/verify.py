# gemato: File verification routines
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import contextlib
import errno
import fcntl
import os
import stat

from gemato.exceptions import (
    ManifestCrossDevice,
    ManifestInvalidPath,
    )
from gemato.hash import hash_file
from gemato.manifest import manifest_hashes_to_hashlib


def get_file_metadata(path, hashes):
    """
    Get a generator for the metadata of the file at system path @path.

    The generator yields, in order:
    1. A boolean indicating whether the file exists.
    2. st_dev, if the file exists.
    3. Tuple of (S_IFMT(st_mode), file type as string), if the file
       exists.
    4. st_size, if the file exists and is a regular file. Note that
       it may be 0 on some filesystems, so treat the value with caution.
    5. st_mtime, if the file exists and is a regular file.
    6. A dict of @hashes and their values, if the file exists and is
       a regular file. Special __size__ member is added unconditionally.

    Note that the generator acquires resources, and does not release
    them until terminated. Always make sure to pull it until
    StopIteration, or close it explicitly.
    """

    try:
        # we want O_NONBLOCK to avoid blocking when opening pipes
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    except FileNotFoundError:
        exists = False
        opened = False
    except OSError as err:
        if err.errno in (errno.ENXIO, errno.EOPNOTSUPP):
            # ENXIO = unconnected device or socket
            # EOPNOTSUPP = opening UNIX socket on FreeBSD
            exists = True
            opened = False
        else:
            raise
    else:
        exists = True
        opened = True

    try:
        # 1. does it exist?
        yield exists

        # we can't provide any more data for a file that does not exist
        if not exists:
            return

        if opened:
            st = os.fstat(fd)
        else:
            st = os.stat(path)

        # 2. st_dev
        yield st.st_dev

        # 3. file type tuple
        if stat.S_ISREG(st.st_mode):
            ftype = 'regular file'
        elif stat.S_ISDIR(st.st_mode):
            ftype = 'directory'
        elif stat.S_ISCHR(st.st_mode):
            ftype = 'character device'
        elif stat.S_ISBLK(st.st_mode):
            ftype = 'block device'
        elif stat.S_ISFIFO(st.st_mode):
            ftype = 'named pipe'
        elif stat.S_ISSOCK(st.st_mode):
            ftype = 'UNIX socket'
        else:
            ftype = 'unknown'
        yield (stat.S_IFMT(st.st_mode), ftype)

        if not stat.S_ISREG(st.st_mode):
            if opened:
                os.close(fd)
            return

        # 4. st_size
        yield st.st_size

        # 5. st_mtime
        yield st.st_mtime

        f = open(fd, 'rb')
    except Exception:
        if opened:
            os.close(fd)
        raise

    with f:
        # open() might have left the file as O_NONBLOCK
        # make sure to fix that
        fcntl.fcntl(fd, fcntl.F_SETFL, 0)

        # 5. checksums
        e_hashes = sorted(hashes)
        hashes = list(manifest_hashes_to_hashlib(e_hashes))
        e_hashes.append('__size__')
        hashes.append('__size__')
        checksums = hash_file(f, hashes, _apparent_size=st.st_size)

        ret = {}
        for ek, k in zip(e_hashes, hashes):
            ret[ek] = checksums[k]
        yield ret


def verify_path(path, e, expected_dev=None, last_mtime=None):
    """
    Verify the file at system path @path against the data in entry @e.
    The path/filename is not matched against the entry -- the correct
    entry must be passed by the caller.

    If the path passes verification, returns (True, []). Otherwise,
    returns (False, diff) where diff is a list of differences between
    the file at path and the Manifest entry. Each list element is
    a tuple of (name, expected, got).

    If @expected_dev is not None, verifies that the file resides
    on specified device. If the device does not match, raises
    ManifestCrossDevice exception. It can be used to verify that
    the files do not cross filesystem boundaries.

    If @last_mtime is not None, it specifies the timestamp corresponding
    to the previous file verification. If the file is not newer
    than that, the checksum verification is skipped.

    Each name can be:
    - __exists__ (boolean) to indicate whether the file existed,
    - __type__ (string) as a human-readable description of file type,
    - __size__ (int) as file size,
    - any checksum name according to the entry.
    """

    if e is not None:
        assert e.tag != 'TIMESTAMP'

        # IGNORE entries cause verification to always succeed
        if e.tag == 'IGNORE':
            return (True, [])

    # None indicates we have no entry, so the file must not exist
    if e is None:
        expect_exist = False
        checksums = ()
    else:
        expect_exist = True
        checksums = e.checksums

    with contextlib.closing(get_file_metadata(path, checksums)) as g:
        # 1. verify whether the file existed in the first place
        exists = next(g)
        if exists != expect_exist:
            return (False, [('__exists__', expect_exist, exists)])
        elif not exists:
            return (True, [])

        # 2. check for xdev condition
        st_dev = next(g)
        if expected_dev is not None and st_dev != expected_dev:
            raise ManifestCrossDevice(path)

        # 3. verify whether the file is a regular file
        ifmt, ftype = next(g)
        if not stat.S_ISREG(ifmt):
            return (False, [('__type__', 'regular file', ftype)])

        # 4. verify the filesize, unless st_size == 0 (to account
        #    for weird filesystems)
        st_size = next(g)
        if st_size != 0 and st_size != e.size:
            return (False, [('__size__', e.size, st_size)])

        # 5. skip checksums if file has not changed since the last time
        #    (and st_size != 0 since we can't trust weird filesystems)
        st_mtime = next(g)
        if (last_mtime is not None and st_mtime <= last_mtime
                and st_size != 0):
            return (True, [])

        # 6. verify the real size from checksum data
        checksums = next(g)
        diff = []
        size = checksums.pop('__size__')
        if size != e.size:
            diff.append(('__size__', e.size, size))

        # 7. verify the checksums
        for h in sorted(e.checksums):
            exp = e.checksums[h]
            got = checksums[h]
            if got != exp:
                diff.append((h, exp, got))

        if diff:
            return (False, diff)

    return (True, [])


def update_entry_for_path(path, e, hashes=None, expected_dev=None,
                          last_mtime=None):
    """
    Update the data in entry @e to match the current state of file
    at path @path. Uses hashes listed in @hashes (using Manifest names),
    or the current set of hashes in @e if @hashes is None.

    Returns True if anything changed, or False if the entry did
    not change.

    The file must exist and be a regular file, and the entry must be
    of DATA, MANIFEST or a derived type. The path/filename
    is not updated nor checked.

    If @expected_dev is not None, verifies that the file resides
    on specified device. If the device does not match, raises
    ManifestCrossDevice exception. It can be used to verify that
    the files do not cross filesystem boundaries.

    If @last_mtime is not None, it specifies the timestamp corresponding
    to the previous file update. If the file is not newer than that,
    the checksum calculation is skipped.
    """

    assert e.tag not in ('IGNORE', 'TIMESTAMP')

    if hashes is None:
        hashes = list(e.checksums)

    with contextlib.closing(get_file_metadata(path, hashes)) as g:
        # 1. verify whether the file existed in the first place
        exists = next(g)
        if not exists:
            raise ManifestInvalidPath(path, ('__exists__', exists))

        # 2. check for xdev condition
        st_dev = next(g)
        if expected_dev is not None and st_dev != expected_dev:
            raise ManifestCrossDevice(path)

        # 3. verify whether the file is a regular file
        ifmt, ftype = next(g)
        if not stat.S_ISREG(ifmt):
            raise ManifestInvalidPath(path, ('__type__', ftype))

        # 4. get the apparent file size
        st_size = next(g)

        # 5. skip checksums if file has not changed since the last time
        #    (and st_size makes sense)
        st_mtime = next(g)
        if (last_mtime is not None and st_mtime <= last_mtime
                and st_size != 0 and st_size == e.size):
            return False

        # 6. get the checksums and real size
        checksums = next(g)
        size = checksums.pop('__size__')
        if st_size != 0:
            assert st_size == size, (
                f'Apparent size (st_size = {st_size}) and real size '
                f'({size}) are different!')

        if e.size != size or e.checksums != checksums:
            e.size = size
            e.checksums = checksums
            return True
        return False


def verify_entry_compatibility(e1, e2):
    """
    Verify that the two entries @e1 and @e2 are compatible.

    If the entries are compatible, returns (True, diff). Otherwise,
    returns (False, diff). Here diff is a list of differences between
    @e1 and @e2. Each list element is a tuple of (name, e1, e2).

    In case of successful comparison, the diff may contain additional
    hashes that are present only in one of the entries.
    """

    # 1. compare types
    t1 = e1.tag
    t2 = e2.tag
    assert 'TIMESTAMP' not in (t1, t2)
    if t1 != t2:
        # all those tags have compatible semantics
        COMPATIBLE_TAGS = ('MANIFEST', 'DATA', 'EBUILD', 'AUX')
        if t1 not in COMPATIBLE_TAGS or t2 not in COMPATIBLE_TAGS:
            return (False, [('__type__', t1, t2)])

    # 2. compare sizes
    if e1.size != e2.size:
        return (False, [('__size__', e1.size, e2.size)])

    # 3. compare checksums
    hashes = frozenset(e1.checksums) | frozenset(e2.checksums)
    ret = True
    diff = []
    for h in sorted(hashes):
        h1 = e1.checksums.get(h)
        h2 = e2.checksums.get(h)
        if h1 != h2:
            diff.append((h, h1, h2))
            if h1 is not None and h2 is not None:
                ret = False

    return (ret, diff)
