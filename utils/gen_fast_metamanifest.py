#!/usr/bin/env python
# Ultra-optimized Meta-Manifest writing.
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import glob
import io
import os
import os.path
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))

import gen_fast_manifest


def manifest_dir_generator():
    with io.open('profiles/categories', 'r') as f:
        categories = [x.strip() for x in f]

    for c in categories:
        # all package directories
        for d in glob.glob(os.path.join(c, '*/')):
            yield d
        # category directory
        yield c
        # md5-cache for the category
        yield os.path.join('metadata/md5-cache', c)

    # few special metadata directories
    yield 'metadata/glsa'
    yield 'metadata/md5-cache'
    yield 'metadata/news'

    # top-level dirs
    yield 'metadata'
    yield 'eclass'
    yield 'licenses'
    yield 'profiles'

    # finally, the whole repo
    yield '.'


def gen_metamanifest(top_dir):
    os.chdir(top_dir)
    alldirs = manifest_dir_generator()

    # pre-populate IGNORE entries
    with io.open('metadata/Manifest', 'wb') as f:
        f.write(b'''IGNORE timestamp
IGNORE timestamp.chk
IGNORE timestamp.commit
IGNORE timestamp.x
''')
    with io.open('Manifest', 'wb') as f:
        f.write(b'''IGNORE distfiles
IGNORE local
IGNORE packages
''')

    # call the fast-gen routine
    for path in alldirs:
        gen_fast_manifest.gen_manifest(path)

    # write timestamp
    with io.open('Manifest', 'ab') as f:
        f.write(datetime.datetime.utcnow().strftime('TIMESTAMP %Y-%m-%dT%H:%M:%SZ\n').encode('ascii'))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: {} <top-directory>'.format(sys.argv[0]))
        sys.exit(1)

    gen_metamanifest(sys.argv[1])
