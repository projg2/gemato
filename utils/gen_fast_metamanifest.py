#!/usr/bin/env python
# vim:fileencoding=utf-8
# Ultra-optimized Meta-Manifest writing.
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import glob
import io
import multiprocessing
import os
import os.path
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))

import gen_fast_manifest


def manifest_dir_generator(iter_n):
    with io.open('profiles/categories', 'r') as f:
        categories = [x.strip() for x in f]

    for c in categories:
        if iter_n == 1:
            # all package directories
            for d in glob.glob(os.path.join(c, '*/')):
                yield d
            # md5-cache for the category
            yield os.path.join('metadata/md5-cache', c)
        elif iter_n == 2:
            # category directory
            yield c

    if iter_n == 1:
        # few special metadata subdirectories
        yield 'metadata/dtd'
        yield 'metadata/glsa'
        yield 'metadata/md5-cache'
        yield 'metadata/news'
        yield 'metadata/xml-schema'

        # independent top-level dirs
        yield 'eclass'
        yield 'licenses'
        yield 'profiles'
    elif iter_n == 2:
        # top-level dirs
        yield 'metadata'


def gen_metamanifest(top_dir):
    os.chdir(top_dir)

    # pre-populate IGNORE entries
    with io.open('metadata/Manifest', 'wb') as f:
        f.write(b'''IGNORE timestamp
IGNORE timestamp.chk
IGNORE timestamp.commit
IGNORE timestamp.x
''')
    for mdir in ('dtd', 'glsa', 'news', 'xml-schema'):
        with io.open(os.path.join('metadata', mdir, 'Manifest'), 'wb') as f:
            f.write(b'''IGNORE timestamp.chk
IGNORE timestamp.commit
''')
    with io.open('Manifest', 'wb') as f:
        f.write(b'''IGNORE distfiles
IGNORE local
IGNORE lost+found
IGNORE packages
''')

    p = multiprocessing.Pool()

    # generate 1st batch of sub-Manifests
    # expecting 20000+ items, so use iterator with a reasonably large
    # chunksize
    p.map(gen_fast_manifest.gen_manifest, manifest_dir_generator(1), chunksize=64)

    # timestamp into tier 1 directories
    ts = datetime.datetime.utcnow().strftime(
            'TIMESTAMP %Y-%m-%dT%H:%M:%SZ\n').encode('ascii')
    with io.open('metadata/glsa/Manifest', 'ab') as f:
        f.write(ts)
    with io.open('metadata/news/Manifest', 'ab') as f:
        f.write(ts)

    # 2nd batch (files depending on results of 1st batch)
    # this one is fast to generate, so let's pass a list and let map()
    # choose optimal chunksize
    p.map(gen_fast_manifest.gen_manifest, list(manifest_dir_generator(2)))

    # finally, generate the top-level Manifest
    gen_fast_manifest.gen_manifest('.')

    # final timestamp
    ts = datetime.datetime.utcnow().strftime(
            'TIMESTAMP %Y-%m-%dT%H:%M:%SZ\n').encode('ascii')
    with io.open('Manifest', 'ab') as f:
        f.write(ts)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: {} <top-directory>'.format(sys.argv[0]))
        sys.exit(1)

    gen_metamanifest(sys.argv[1])
