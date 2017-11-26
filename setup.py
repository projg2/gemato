#!/usr/bin/python
# vim:fileencoding=utf-8
# (C) 2017 Michał Górny <mgorny@gentoo.org>
# Licensed under the terms of 2-clause BSD license

from setuptools import setup


setup(
    name='gemato',
    version='8',
    description='Gentoo Manifest Tool -- a stand-alone utility to verify and update Gentoo Manifest files',

    author='Michał Górny',
    author_email='mgorny@gentoo.org',
    license='BSD',
    url='http://github.com/mgorny/gemato',

    extras_require={
        'blake2': ['pyblake2;python_version<"3.6"'],
        'bz2': ['bz2file;python_version<"3.0"'],
        'lzma': ['backports.lzma;python_version<"3.0"'],
        'sha3': ['pysha3;python_version<"3.6"'],
    },

    packages=['gemato'],
    scripts=['bin/gemato'],

    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Topic :: Security :: Cryptography',
    ]
)
