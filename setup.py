#!/usr/bin/python
# vim:fileencoding=utf-8
# (C) 2017 Michał Górny <mgorny@gentoo.org>
# Licensed under the terms of 2-clause BSD license

from distutils.core import setup


setup(
    name='gemato',
    version=0,
    author='Michał Górny',
    author_email='mgorny@gentoo.org',
    url='http://github.com/mgorny/gemato',

    packages=['gemato'],
    scripts=['bin/gemato'],

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Topic :: Security :: Cryptography',
    ]
)
