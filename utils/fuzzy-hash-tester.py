#!/usr/bin/env python
# dumb utility to randomly test different hash implementations
# for compliance

import base64
import functools
import hashlib
import random
import subprocess
import sys

import pyblake2


class ExternalToolHash:
    def __init__(self, argv):
        self.subp = subprocess.Popen(argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)

    def update(self, data):
        self.subp.stdin.write(data)

    def hexdigest(self):
        stdo, stde = self.subp.communicate()
        return stdo.decode('ASCII').split()[0]


ALGORITHMS = {
    'md5': [hashlib.md5,
            functools.partial(ExternalToolHash, 'md5sum')],
    'sha1': [hashlib.sha1,
             functools.partial(ExternalToolHash, 'sha1sum')],
    'sha224': [hashlib.sha224,
               functools.partial(ExternalToolHash, 'sha224sum')],
    'sha256': [hashlib.sha256,
               functools.partial(ExternalToolHash, 'sha256sum')],
    'sha384': [hashlib.sha384,
               functools.partial(ExternalToolHash, 'sha384sum')],
    'sha512': [hashlib.sha512,
               functools.partial(ExternalToolHash, 'sha512sum')],
    'blake2b': [hashlib.blake2b, hashlib.blake2b,
                functools.partial(ExternalToolHash, 'b2sum')],
}


def main(algo_name, min_size, max_size=None):
    impls = ALGORITHMS[algo_name]
    if max_size is None:
        max_size = min_size
    min_size = int(min_size)
    max_size = int(max_size)

    with open('/dev/urandom', 'rb') as urandom:
        i = 0
        while True:
            size = random.randint(min_size, max_size)
            data = urandom.read(size)
            digests = {}
            for a in impls:
                h = a()
                h.update(data)
                digests[a] = h.hexdigest()

            if len(set(digests.values())) != 1:
                print('Inconsistent hash values found!')
                print('Hash values:')
                for a, v in digests.items():
                    print('  {}: {}'.format(a, v))
                print('Data block as base64:')
                print(base64.encodebytes(data).decode())
                sys.exit(1)

            i += 1
            if i % 1000 == 0:
                print('{} blocks tested.'.format(i))


if __name__ == '__main__':
    main(*sys.argv[1:])
