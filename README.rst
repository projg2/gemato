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


Creating new Manifest tree
--------------------------
Creating a new Manifest tree can be accomplished using the ``gemato
create`` command against the top directory of the new Manifest tree::

    gemato create -p ebuild /var/db/repos/gentoo

Note that for the ``create`` command you always need to specify either
a profile (via ``-p``) or at least a hash set (via ``-H``).


Updating existing Manifests
---------------------------
The ``gemato update`` command is provided to update an existing Manifest
tree::

    gemato update -p ebuild /var/db/repos/gentoo

Alike ``create``, ``update`` also requires specifying a profile (``-p``)
or a hash set (``-H``). The command locates the appropriate top-level
Manifest and updates the specified directory recursively.
If a subdirectory of the Manifest tree is specified, the entries
for the specified leaf and respective Manifest files are updated.


Utility commands
----------------
gemato provides a few other commands that could help debugging its
behavior. Those are:

``gemato hash -H <hashes> [<path>...]``
  Print hashes of the specified files in Manifest-like format.
  Used to verify that the hash backend works correctly.

``gemato openpgp-verify [-K <key>] [<path>...]``
  Check OpenPGP signatures embedded in the specified files. Detached
  signatures are not supported. Used to verify that the OpenPGP backend
  works correctly.


Requirements
============
gemato is written in Python and compatible with implementations
of Python 2.7 and Python 3.4+. However, the support for Python 2
is considered 'best effort' and has some known limitations. For example,
non-ASCII paths on command-line do not work.

gemato is currently tested against CPython 2.7, CPython 3.4 through 3.6,
PyPy and PyPy3.

gemato depends only on standard Python library modules and their
backports. The exact runtime dependencies depend on the standard library
version used. Those are:

Python 3.6+
  none -- only standard modules are used

Python 3.4, 3.5
  - pyblake2 -- for BLAKE2 family of hashes [#pyblake2]_
  - pysha3 -- for SHA3 (Keccak) family of hashes [#pysha3]_

Python 2.7
  the above, plus:

  - bz2file -- for BZip2 compression support [#bz2file]_ [#bz2py2]_
  - backports.lzma -- for LZMA/XZ compressed file support [#lzma]_

Additionally, gemato calls the GnuPG executable to work with OpenPGP
signatures. Both GnuPG 1.4.21 and 2.2+ are tested.


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
