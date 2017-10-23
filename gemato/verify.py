# gemato: File verification routines
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import errno
import fcntl
import os
import stat

import gemato.hash
import gemato.manifest


def verify_path(path, e):
    """
    Verify the file at system path @path against the data in entry @e.
    The path/filename is not matched against the entry -- the correct
    entry must be passed by the caller.

    If the path passes verification, returns (True, []). Otherwise,
    returns (False, diff) where diff is a list of differences between
    the file at path and the Manifest entry. Each list element is
    a tuple of (name, expected, got).

    Each name can be:
    - __exists__ (boolean) to indicate whether the file existed,
    - __type__ (string) as a human-readable description of file type,
    - __size__ (int) as file size,
    - any checksum name according to the entry.
    """

    assert isinstance(e, gemato.manifest.ManifestPathEntry)

    # IGNORE entries cause verification to always succeed
    if isinstance(e, gemato.manifest.ManifestEntryIGNORE):
        return (True, [])

    try:
        # we want O_NONBLOCK to avoid blocking when opening pipes
        fd = os.open(path, os.O_RDONLY|os.O_NONBLOCK)
    except OSError as err:
        if err.errno == errno.ENOENT:
            exists = False
            opened = False
        elif err.errno == errno.ENXIO:
            # unconnected device or socket
            exists = True
            opened = False
        else:
            raise
    else:
        exists = True
        opened = True

    # 1. verify whether the file existed in the first place
    expect_exist = not isinstance(e, gemato.manifest.ManifestEntryOPTIONAL)
    if exists != expect_exist:
        if opened:
            os.close(fd)
        return (False, [('__exists__', expect_exist, exists)])
    elif not exists:
        return (True, [])

    # 2. verify whether the file is a regular file
    if opened:
        st = os.fstat(fd)
    else:
        st = os.stat(path)
    if not opened or not stat.S_ISREG(st.st_mode):
        if opened:
            os.close(fd)
        if stat.S_ISDIR(st.st_mode):
            ftype = 'directory'
        elif stat.S_ISCHR(st.st_mode):
            ftype = 'character device'
        elif stat.S_ISBLK(st.st_mode):
            ftype = 'block device'
        elif stat.S_ISREG(st.st_mode):  # can only happen w/ ENXIO
            ftype = 'unconnected regular file (?!)'
        elif stat.S_ISFIFO(st.st_mode):
            ftype = 'named pipe'
        elif stat.S_ISSOCK(st.st_mode):
            ftype = 'UNIX socket'
        else:
            ftype = 'unknown'
        return (False, [('__type__', 'regular file', ftype)])

    # grab the fd
    try:
        f = os.fdopen(fd, 'rb')
    except Exception:
        os.close(fd)
        raise

    with f:
        # open() might have left the file as O_NONBLOCK
        # make sure to fix that
        fcntl.fcntl(fd, fcntl.F_SETFL, 0)

        # ignore st_size == 0 in case of weird filesystem
        if st.st_size != 0 and st.st_size != e.size:
            return (False, [('__size__', e.size, st.st_size)])

        e_hashes = sorted(e.checksums)
        hashes = list(gemato.manifest.manifest_hashes_to_hashlib(e_hashes))
        hashes.append('__size__')
        checksums = gemato.hash.hash_file(f, hashes)

        diff = []
        size = checksums['__size__']
        if size != e.size:
            diff.append(('__size__', e.size, size))
        for ek, k in zip(e_hashes, hashes):
            exp = e.checksums[ek]
            got = checksums[k]
            if got != exp:
                diff.append((ek, exp, got))

        if diff:
            return (False, diff)

    return (True, [])


class ManifestMismatch(Exception):
    """
    An exception raised for verification failure.
    """

    def __init__(self, path, entry, diff):
        msg = "Manifest mismatch for {}".format(path)
        for k, exp, got in diff:
            msg += "\n  {}: expected: {}, have: {}".format(k, exp, got)
        super(ManifestMismatch, self).__init__(msg)
        self.path = path
        self.entry = entry
        self.diff = diff


def assert_path_verifies(path, e):
    """
    Verify the path @path against entry @e. Raises an exception if it
    does not pass the verification.
    """

    ret, diff = verify_path(path, e)
    if not ret:
        raise ManifestMismatch(path, e, diff)
