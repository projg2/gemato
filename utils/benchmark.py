#!/usr/bin/env python

import os.path
import sys
import timeit

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import gemato.hash


def benchmark_one(path, hashes):
	f = lambda: gemato.hash.hash_path(path, hashes)
	t = timeit.repeat(f, number=1)
	print("{} -> {}".format(hashes, t))


def benchmark(path, hash_sets):
	if not hash_sets:
		hash_sets = [
			["sha256"],
			["sha256", "blake2b"],
			["sha256", "blake2b", "sha512"],
		]
	else:
		hash_sets = [x.split() for x in hash_sets]

	for hashes in hash_sets:
		benchmark_one(path, hashes)


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print('Usage: {} <test-file> [<hash-set>...]'.format(sys.argv[0]))
		sys.exit(1)

	benchmark(sys.argv[1], sys.argv[2:])
