==================================
  gemato -- Gentoo Manifest Tool
==================================
:Author: Michał Górny
:License: 2-clause BSD license


Introduction
============
gemato provides a reference implementation of the full-tree Manifest
checks as specified in GLEP 74 [#GLEP74]_. Originally focused
on verifying the integrity and authenticity of the Gentoo ebuild
repository, the tool can be used as a generic checksumming tool
for any directory trees.


Usage
=====

Verification
------------
The basic purpose of gemato is to verify a directory tree against
Manifest files. In order to do that, run the ``gemato verify`` tool
against the requested directory::

    gemato verify /var/db/repos/gentoo

The tool will automatically locate the top-level Manifest (if any)
and check the specified directory recursively. If a subdirectory
of the Manifest tree is specified, only the specified leaf is checked.


Requirements
============
gemato is written in Python and meant to be compatible with CPython 2.7,
CPython 3.4+, PyPy and PyPy3. It uses only the standard library modules,
or backports of those modules to older Python versions.

The exact runtime dependencies depend on Python standard library version
used. Those are:

Python 3.6+
  none -- only standard modules are used

Python 3.4, 3.5
  - pyblake2 -- for BLAKE2 family of hashes [#pyblake2]_
  - pysha3 -- for SHA3 (Keccak) family of hashes [#pysha3]_

Python 2.7
  the above, plus:

  - bz2file -- for BZip2 compression support [#bz2file]_ [#bz2py2]_
  - backports.lzma -- for LZMA/XZ compressed file support [#lzma]_


References and footnotes
========================
.. [#GLEP74] GLEP 74: Full-tree verification using Manifest files
   (https://www.gentoo.org/glep/glep-0074.html)

.. [#pyblake2] BLAKE2 hash function extension module
   (https://pypi.python.org/pypi/pyblake2)
   (https://github.com/dchest/pyblake2)

.. [#pysha3] SHA-3 (Keccak) for Python 2.7 - 3.5
   (https://pypi.python.org/pypi/pysha3)
   (https://github.com/tiran/pysha3)

.. [#bz2file] Read and write bzip2-compressed files
   (https://pypi.python.org/pypi/bz2file)
   (https://github.com/nvawda/bz2file)

.. [#bz2py2] Strictly speaking, Python 2.7 has a ``bz2`` module.
   However, this old module version does not support working on open
   files nor multiple streams inside a single file. For this reason,
   the external module is unconditionally required.

.. [#lzma] Backport of Python 3.3's 'lzma' module for XZ/LZMA compressed
   files
   (https://pypi.python.org/pypi/backports.lzma)
   (https://github.com/peterjc/backports.lzma)
