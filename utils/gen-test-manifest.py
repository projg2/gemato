#!/usr/bin/env python

import glob
import os
import os.path
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import gemato.hash


def write_manifest_entry(manifest_file, t, path, relpath, hashes):
    checksums = gemato.hash.hash_path(path,
            [x.lower() for x in hashes] + ['__size__'])
    hashvals = []
    for h in hashes:
        hashvals += [h, checksums[h.lower()]]
    manifest_file.write('{} {} {} {}\n'.format(t, relpath,
        checksums['__size__'], ' '.join(hashvals)))


def write_manifest_entries_for_dir(manifest_file, topdir, hashes):
    for dirpath, dirs, files in os.walk(topdir):
        if dirpath != topdir:
            for f in files:
                if f.startswith('Manifest'):
                    fp = os.path.join(dirpath, f)
                    write_manifest_entry(manifest_file, 'MANIFEST',
                            fp, os.path.relpath(fp, topdir), hashes)
                    # do not descend
                    dirs.clear()
                    skip = True
                    break
            else:
                skip = False
            if skip:
                continue

        for f in files:
            if f.startswith('Manifest'):
                continue
            fp = os.path.join(dirpath, f)
            write_manifest_entry(manifest_file, 'DATA',
                    fp, os.path.relpath(fp, topdir), hashes)


def gen_metamanifests(top_dir, hashes):
    with open(os.path.join(top_dir, 'profiles/categories'), 'r') as f:
        categories = [x.strip() for x in f]

    alldirs = []

    # we assume every package has thick Manifests already, so we just
    # need to Manifest the Manifests
    for c in categories:
        alldirs.append(c)
        alldirs.append(os.path.join('metadata/md5-cache', c))

    # Manifest a few big dirs separately
    alldirs.extend(['eclass', 'licenses', 'metadata/md5-cache', 'metadata/glsa',
            'metadata/news', 'metadata', 'profiles'])

    for bm in alldirs:
        bmdir = os.path.join(top_dir, bm)
        if not list(glob.glob(os.path.join(bmdir, 'Manifest*'))):
            with open(os.path.join(bmdir, 'Manifest'), 'w') as f:
                write_manifest_entries_for_dir(f, bmdir, hashes)

    with open(os.path.join(top_dir, 'Manifest'), 'w') as f:
        write_manifest_entries_for_dir(f, top_dir, hashes)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: {} <rsync-path> <hashes>'.format(sys.argv[0]))
        sys.exit(1)

    gen_metamanifests(sys.argv[1], sys.argv[2].split())
