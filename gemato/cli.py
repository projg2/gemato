# gemato: CLI routines
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

from __future__ import print_function

import argparse
import datetime
import io
import logging
import os.path
import timeit

import gemato.find_top_level
import gemato.profile
import gemato.recursiveloader


def verify_failure(e):
    logging.error(str(e))
    return False


def do_verify(args, argp):
    ret = True

    for p in args.paths:
        tlm = gemato.find_top_level.find_top_level_manifest(p)
        if tlm is None:
            logging.error('Top-level Manifest not found in {}'.format(p))
            return 1

        init_kwargs = {}
        kwargs = {}
        if args.keep_going:
            kwargs['fail_handler'] = verify_failure
        if not args.openpgp_verify:
            init_kwargs['verify_openpgp'] = False
        with gemato.openpgp.OpenPGPEnvironment() as env:
            if args.openpgp_key is not None:
                with io.open(args.openpgp_key, 'rb') as f:
                    env.import_key(f)
                init_kwargs['openpgp_env'] = env

            start = timeit.default_timer()
            try:
                m = gemato.recursiveloader.ManifestRecursiveLoader(tlm, **init_kwargs)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                logging.error(str(e))
                return 1
            except gemato.exceptions.OpenPGPVerificationFailure as e:
                logging.error(str(e))
                return 1
            if args.require_signed_manifest and not m.openpgp_signed:
                logging.error('Top-level Manifest {} is not OpenPGP signed'.format(tlm))
                return 1

            relpath = os.path.relpath(p, os.path.dirname(tlm))
            if relpath == '.':
                relpath = ''
            try:
                ret &= m.assert_directory_verifies(relpath, **kwargs)
            except gemato.exceptions.ManifestCrossDevice as e:
                logging.error(str(e))
                return 1
            except gemato.exceptions.ManifestIncompatibleEntry as e:
                logging.error(str(e))
                return 1
            except gemato.exceptions.ManifestMismatch as e:
                logging.error(str(e))
                return 1

            stop = timeit.default_timer()
            logging.info('{} validated in {:.2f} seconds'.format(p, stop - start))
    return 0 if ret else 1


def do_update(args, argp):
    for p in args.paths:
        tlm = gemato.find_top_level.find_top_level_manifest(p)
        if tlm is None:
            logging.error('Top-level Manifest not found in {}'.format(p))
            return 1

        init_kwargs = {}
        save_kwargs = {}
        update_kwargs = {}
        if args.hashes is not None:
            init_kwargs['hashes'] = args.hashes.split()
        if args.compress_watermark is not None:
            if args.compress_watermark < 0:
                argp.error('--compress-watermark must not be negative!')
            init_kwargs['compress_watermark'] = args.compress_watermark
        if args.compress_format is not None:
            init_kwargs['compress_format'] = args.compress_format
        if args.force_rewrite:
            save_kwargs['force'] = True
        if args.openpgp_id is not None:
            init_kwargs['openpgp_keyid'] = args.openpgp_id
        if args.profile is not None:
            init_kwargs['profile'] = gemato.profile.get_profile_by_name(
                    args.profile)
        if args.sign is not None:
            init_kwargs['sign_openpgp'] = args.sign
        with gemato.openpgp.OpenPGPEnvironment() as env:
            if args.openpgp_key is not None:
                with io.open(args.openpgp_key, 'rb') as f:
                    env.import_key(f)
                init_kwargs['openpgp_env'] = env

            start = timeit.default_timer()
            try:
                m = gemato.recursiveloader.ManifestRecursiveLoader(tlm,
                        **init_kwargs)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                logging.error(str(e))
                return 1
            except gemato.exceptions.OpenPGPVerificationFailure as e:
                logging.error(str(e))
                return 1

            # if not specified by user, profile must set it
            if m.hashes is None:
                argp.error('--hashes must be specified if not implied by --profile')

            relpath = os.path.relpath(p, os.path.dirname(tlm))
            if relpath == '.':
                relpath = ''
            if args.timestamp and relpath != '':
                argp.error('Timestamp can only be updated if doing full-tree update')
            if args.incremental:
                if relpath != '':
                    argp.error('Incremental works only for full-tree update')
                last_ts = m.find_timestamp()
                if last_ts is None:
                    argp.error('Incremental specified but no timestamp in Manifest')
                update_kwargs['last_mtime'] = last_ts.ts.timestamp()

            try:
                start_ts = datetime.datetime.utcnow()
                m.update_entries_for_directory(relpath, **update_kwargs)

                # write TIMESTAMP if requested, or if already there
                if relpath != '':
                    # skip timestamp if not doing full update
                    pass
                elif args.timestamp:
                    m.set_timestamp(start_ts)
                else:
                    ts = m.find_timestamp()
                    if ts is not None:
                        ts.ts = start_ts

                m.save_manifests(**save_kwargs)
            except gemato.exceptions.ManifestCrossDevice as e:
                logging.error(str(e))
                return 1
            except gemato.exceptions.ManifestInvalidPath as e:
                logging.error(str(e))
                return 1
            except gemato.exceptions.ManifestInvalidFilename as e:
                logging.error(str(e))
                return 1

            stop = timeit.default_timer()
            logging.info('{} updated in {:.2f} seconds'.format(p, stop - start))
    return 0


def do_create(args, argp):
    for p in args.paths:
        init_kwargs = {}
        save_kwargs = {}
        init_kwargs['allow_create'] = True
        if args.hashes is not None:
            init_kwargs['hashes'] = args.hashes.split()
        if args.compress_watermark is not None:
            if args.compress_watermark < 0:
                argp.error('--compress-watermark must not be negative!')
            init_kwargs['compress_watermark'] = args.compress_watermark
        if args.compress_format is not None:
            init_kwargs['compress_format'] = args.compress_format
        if args.force_rewrite:
            save_kwargs['force'] = True
        if args.openpgp_id is not None:
            init_kwargs['openpgp_keyid'] = args.openpgp_id
        if args.profile is not None:
            init_kwargs['profile'] = gemato.profile.get_profile_by_name(
                    args.profile)
        if args.sign is not None:
            init_kwargs['sign_openpgp'] = args.sign
        with gemato.openpgp.OpenPGPEnvironment() as env:
            if args.openpgp_key is not None:
                with io.open(args.openpgp_key, 'rb') as f:
                    env.import_key(f)
                init_kwargs['openpgp_env'] = env

            start = timeit.default_timer()
            try:
                m = gemato.recursiveloader.ManifestRecursiveLoader(
                        os.path.join(p, 'Manifest'), **init_kwargs)
            except gemato.exceptions.OpenPGPNoImplementation as e:
                logging.error(str(e))
                return 1
            except gemato.exceptions.OpenPGPVerificationFailure as e:
                logging.error(str(e))
                return 1

            # if not specified by user, profile must set it
            if m.hashes is None:
                argp.error('--hashes must be specified if not implied by --profile')

            try:
                start_ts = datetime.datetime.utcnow()
                m.update_entries_for_directory()

                # write TIMESTAMP if requested, or if already there
                if args.timestamp:
                    m.set_timestamp(start_ts)

                m.save_manifests(**save_kwargs)
            except gemato.exceptions.ManifestCrossDevice as e:
                logging.error(str(e))
                return 1
            except gemato.exceptions.ManifestInvalidPath as e:
                logging.error(str(e))
                return 1
            except gemato.exceptions.ManifestInvalidFilename as e:
                logging.error(str(e))
                return 1

            stop = timeit.default_timer()
            logging.info('{} updated in {:.2f} seconds'.format(p, stop - start))
    return 0


def main(argv):
    argp = argparse.ArgumentParser(
            prog=argv[0],
            description='Gentoo Manifest Tool')
    subp = argp.add_subparsers()

    verify = subp.add_parser('verify',
            help='Verify one or more directories against Manifests')
    verify.add_argument('paths', nargs='*', default=['.'],
            help='Paths to verify (defaults to "." if none specified)')
    verify.add_argument('-k', '--keep-going', action='store_true',
            help='Continue reporting errors rather than terminating on the first failure')
    verify.add_argument('-K', '--openpgp-key',
            help='Use only the OpenPGP key(s) from a specific file')
    verify.add_argument('-P', '--no-openpgp-verify', action='store_false',
            dest='openpgp_verify',
            help='Disable OpenPGP verification of signed Manifests')
    verify.add_argument('-s', '--require-signed-manifest', action='store_true',
            help='Require that the top-level Manifest is OpenPGP signed')
    verify.set_defaults(func=do_verify)

    update = subp.add_parser('update',
            help='Update the Manifest entries for one or more directory trees')
    update.add_argument('paths', nargs='*', default=['.'],
            help='Paths to update (defaults to "." if none specified)')
    update.add_argument('-c', '--compress-watermark', type=int,
            help='Minimum Manifest size for files to be compressed')
    update.add_argument('-C', '--compress-format',
            help='Format for compressed files (e.g. "gz", "bz2"...)')
    update.add_argument('-f', '--force-rewrite', action='store_true',
            help='Force rewriting all the Manifests, even if they did not change')
    update.add_argument('-H', '--hashes',
            help='Whitespace-separated list of hashes to use')
    update.add_argument('-i', '--incremental', action='store_true',
            help='Perform incremental update by comparing mtimes against TIMESTAMP')
    update.add_argument('-k', '--openpgp-id',
            help='Use the specified OpenPGP key (by ID or user)')
    update.add_argument('-K', '--openpgp-key',
            help='Use only the OpenPGP key(s) from a specific file')
    update.add_argument('-p', '--profile',
            help='Use the specified profile ("default", "ebuild", "old-ebuild"...)')
    signgroup = update.add_mutually_exclusive_group()
    signgroup.add_argument('-s', '--sign', action='store_true',
            default=None,
            help='Force signing the top-level Manifest')
    signgroup.add_argument('-S', '--no-sign', action='store_false',
            dest='sign',
            help='Disable signing the top-level Manifest')
    update.add_argument('-t', '--timestamp', action='store_true',
            help='Include TIMESTAMP entry in Manifest')
    update.set_defaults(func=do_update)

    create = subp.add_parser('create',
            help='Create a Manifest tree starting at the specified file')
    create.add_argument('paths', nargs='*', default=['.'],
            help='Paths to create (defaults to "Manifest" if none specified)')
    create.add_argument('-c', '--compress-watermark', type=int,
            help='Minimum Manifest size for files to be compressed')
    create.add_argument('-C', '--compress-format',
            help='Format for compressed files (e.g. "gz", "bz2"...)')
    create.add_argument('-f', '--force-rewrite', action='store_true',
            help='Force rewriting all the Manifests, even if they did not change')
    create.add_argument('-H', '--hashes',
            help='Whitespace-separated list of hashes to use')
    create.add_argument('-k', '--openpgp-id',
            help='Use the specified OpenPGP key (by ID or user)')
    create.add_argument('-K', '--openpgp-key',
            help='Use only the OpenPGP key(s) from a specific file')
    create.add_argument('-p', '--profile',
            help='Use the specified profile ("default", "ebuild", "old-ebuild"...)')
    signgroup = create.add_mutually_exclusive_group()
    signgroup.add_argument('-s', '--sign', action='store_true',
            default=None,
            help='Force signing the top-level Manifest')
    signgroup.add_argument('-S', '--no-sign', action='store_false',
            dest='sign',
            help='Disable signing the top-level Manifest')
    create.add_argument('-t', '--timestamp', action='store_true',
            help='Include TIMESTAMP entry in Manifest')
    create.set_defaults(func=do_create)

    vals = argp.parse_args(argv[1:])
    if not hasattr(vals, 'func'):
        argp.error('No function specified')
    return vals.func(vals, argp)
