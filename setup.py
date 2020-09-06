#!/usr/bin/env python
# vim:fileencoding=utf-8
# (C) 2017-2020 Michał Górny <mgorny@gentoo.org>
# Licensed under the terms of 2-clause BSD license

from setuptools import setup


setup(
    name='gemato',
    version='16.0',
    description='Gentoo Manifest Tool -- a stand-alone utility to verify and update Gentoo Manifest files',

    author='Michał Górny',
    author_email='mgorny@gentoo.org',
    license='BSD',
    url='http://github.com/mgorny/gemato',

    packages=['gemato'],
    entry_points={
        'console_scripts': [
            'gemato=gemato.cli:setuptools_main',
        ],
    },

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Security :: Cryptography',
    ]
)
