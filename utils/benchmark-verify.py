#!/usr/bin/env python

import os.path
import sys
import timeit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import gemato.recursiveloader


def benchmark(path):
    m = gemato.recursiveloader.ManifestRecursiveLoader(path)
    print(f'load-dict: {timeit.timeit(m.get_file_entry_dict, number=1)}')
    print(f'verify: {timeit.timeit(m.assert_directory_verifies, number=1)}')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <top-level-manifest>')
        sys.exit(1)

    benchmark(sys.argv[1])
