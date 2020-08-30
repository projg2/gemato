# gemato: hash support
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import hashlib
import io

from gemato.exceptions import UnsupportedHash


HASH_BUFFER_SIZE = 65536
MAX_SLURP_SIZE = 1048576


class SizeHash:
    """A cheap wrapper to count file size via hashlib-like interface"""

    __slots__ = ['size']

    def __init__(self):
        self.size = 0

    def update(self, data):
        self.size += len(data)

    def hexdigest(self):
        return self.size


def get_hash_by_name(name):
    """
    Get a hashlib-compatible hash object for hash named @name. Supports
    multiple backends.
    """
    # special case hashes
    if name == '__size__':
        return SizeHash()

    # general hash support
    if name in hashlib.algorithms_available:
        return hashlib.new(name)

    raise UnsupportedHash(name)


def hash_file(f, hash_names, _apparent_size=0):
    """
    Hash the contents of file object @f using all hashes specified
    as @hash_names. Returns a dict of (hash_name -> hex value) mappings.

    @_apparent_size can be given as a tip on how large is the file
    expected to be. This is a private API used to workaround bug in PyPy
    and should not be relied on being present long-term.
    """
    hashes = {}
    for h in hash_names:
        hashes[h] = get_hash_by_name(h)
    if _apparent_size != 0 and _apparent_size < MAX_SLURP_SIZE:
        # if the file is reasonably small, read it all into one buffer;
        # we do this since PyPy has some serious bug in dealing with
        # passing buffers to C extensions and this apparently fails
        # less; https://bitbucket.org/pypy/pypy/issues/2752
        block = f.read()
        for h in hashes.values():
            h.update(block)
    else:
        for block in iter(lambda: f.read1(HASH_BUFFER_SIZE), b''):
            for h in hashes.values():
                h.update(block)
    return dict((k, h.hexdigest()) for k, h in hashes.items())


def hash_path(path, hash_names):
    """
    Hash the contents of file at specified path @path using all hashes
    specified as @hash_names. Returns a dict of (hash_name -> hex value)
    mappings.
    """
    with open(path, 'rb') as f:
        return hash_file(f, hash_names)


def hash_bytes(buf, hash_name):
    """
    Hash the data in provided buffer @buf using the hash @hash_name.
    Returns the hex value.
    """
    return hash_file(io.BytesIO(buf), (hash_name,))[hash_name]
