# gemato: compressed file support
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import bz2
import gzip
import io
import lzma
import os.path
import sys

from gemato.exceptions import UnsupportedCompression


# NB: bz2 (and gzip in py<3.8) uses generic OSError
if sys.hexversion >= 0x03080000:
    InvalidCompressedFileExceptions = (
        gzip.BadGzipFile,
        lzma.LZMAError,
    )
else:
    InvalidCompressedFileExceptions = (
        lzma.LZMAError,
    )


def open_compressed_file(suffix, f, mode='rb'):
    """
    Get a file-like object for an open compressed file @fileobj
    of format @suffix. The file should be open in binary mode
    and positioned at the beginning. @suffix should specify a standard
    suffix for the compression format without the leading dot,
    e.g. "gz", "bz2". @mode specifies the mode to pass to
    the compressor.

    Note that independently of @mode, the returned file objects
    are always open in binary mode (i.e. expect bytestrings).
    """

    if suffix == "gz":
        return gzip.GzipFile(fileobj=f, mode=mode, filename='', mtime=0)
    elif suffix == "bz2" and bz2 is not None:
        return bz2.BZ2File(f, mode=mode)
    elif suffix == "lzma" and lzma is not None:
        return lzma.LZMAFile(f, format=lzma.FORMAT_ALONE, mode=mode)
    elif suffix == "xz" and lzma is not None:
        return lzma.LZMAFile(f, format=lzma.FORMAT_XZ, mode=mode)

    raise UnsupportedCompression(suffix)


class FileStack:
    """
    A context manager for stacked files. Maintains handles for all files
    on stack, returns the topmost (last) layer on enter and closes them
    all on exit.
    """

    __slots__ = ['files']

    def __init__(self, files=[]):
        self.files = files

    def __enter__(self):
        return self.files[-1]

    def __exit__(self, exc_type, exc_value, exc_cb):
        self.close()

    def close(self):
        for f in reversed(self.files):
            f.close()


def open_potentially_compressed_path(path, mode, **kwargs):
    """
    Open the potentially compressed file at specified path @path
    with mode @mode. If the path ends with one of the known compression
    suffixes, the file will be decompressed transparently. Otherwise,
    it will be open directly.

    @kwargs can be used to pass additional options for text files.
    Only arguments supported by io.TextIOWrapper should be used there.

    Returns an object that must be used via the context manager API.
    """

    compression = get_compressed_suffix_from_filename(path)
    if compression is None:
        return open(path, mode, **kwargs)

    bmode = mode
    if 'b' not in bmode:
        bmode += 'b'

    f = open(path, bmode)
    fs = FileStack([f])
    try:
        cf = open_compressed_file(
            compression, f, bmode if kwargs else mode)
        fs.files.append(cf)

        # add a TextIOWrapper on top whenever we do not want
        # the standard compressor file binary mode
        if 'b' not in mode:
            iow = io.TextIOWrapper(cf, **kwargs)
            fs.files.append(iow)
    except Exception:
        fs.close()
        raise

    return fs


def get_potential_compressed_names(path):
    """
    Get a list of all possible variants of @path with supported
    compressions (including the uncompressed path).
    """

    return [path + x for x in ('', '.gz', '.bz2', '.lzma', '.xz')]


def get_compressed_suffix_from_filename(path):
    """
    Get the appropriate suffix (suitable for open_compressed_file())
    for a potentially compressed filename @path. If the path
    does not seem to be compressed, returns None.
    """

    base, ext = os.path.splitext(path)
    if ext in ('.gz', '.bz2', '.lzma', '.xz'):
        return ext[1:]
    return None
