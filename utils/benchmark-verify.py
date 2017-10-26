#!/usr/bin/env python

import os.path
import sys
import timeit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import gemato.recursiveloader


def benchmark(path):
    m = gemato.recursiveloader.ManifestRecursiveLoader(path)
    print('load-dict: {}'.format(timeit.timeit(m.get_file_entry_dict, number=1)))
    print('verify: {}'.format(timeit.timeit(m.assert_directory_verifies, number=1)))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: {} <top-level-manifest>'.format(sys.argv[0]))
        sys.exit(1)

    benchmark(sys.argv[1])
