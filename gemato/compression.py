# gemato: compressed file support
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import gzip
import sys

if sys.version_info >= (3, 3):
    import bz2
else:
    # older bz2 module versions do not handle multiple streams correctly
    # so use the backport instead
    try:
        import bz2file as bz2
    except ImportError:
        bz2 = None

try:
    import lzma
except ImportError:
    try:
        import backports.lzma as lzma
    except ImportError:
        lzma = None

import gemato.exceptions


def open_compressed_file(suffix, f):
    """
    Get a file-like object for an open compressed file @fileobj
    of format @suffix. The file should be open in binary mode
    and positioned at the beginning. @suffix should specify a standard
    suffix for the compression format without the leading dot,
    e.g. "gz", "bz2".
    """

    if suffix == "gz":
        return gzip.GzipFile(fileobj=f)
    elif suffix == "bz2" and bz2 is not None:
        return bz2.BZ2File(f)
    elif suffix in ("lzma", "xz") and lzma is not None:
        return lzma.LZMAFile(f)

    raise gemato.exceptions.UnsupportedCompression(suffix)
