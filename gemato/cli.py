# gemato: CLI routines
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

from __future__ import print_function

import argparse
import logging
import timeit

import gemato.find_top_level
import gemato.recursiveloader


def do_verify(args):
    for p in args.paths:
        tlm = gemato.find_top_level.find_top_level_manifest(p)
        if tlm is None:
            logging.error('Top-level Manifest not found in {}'.format(p))
            return 1

        start = timeit.default_timer()
        m = gemato.recursiveloader.ManifestRecursiveLoader(tlm)
        try:
            m.assert_directory_verifies()
        except gemato.exceptions.ManifestMismatch as e:
            logging.error(str(e))
            return 1

        stop = timeit.default_timer()
        logging.info('{} validated in {:.2f} seconds'.format(p, stop - start))


def main(argv):
    argp = argparse.ArgumentParser(
            prog=argv[0],
            description='Gentoo Manifest Tool')
    subp = argp.add_subparsers()

    verify = subp.add_parser('verify')
    verify.add_argument('paths', nargs='*', default=['.'],
            help='Paths to verify (defaults to "." if none specified)')
    verify.set_defaults(func=do_verify)

    vals = argp.parse_args(argv[1:])
    return vals.func(vals)
