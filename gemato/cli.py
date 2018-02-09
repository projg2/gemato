# gemato: CLI routines
# vim:fileencoding=utf-8
# (c) 2017-2018 Michał Górny
# Licensed under the terms of 2-clause BSD license

from __future__ import print_function

import argparse
import datetime
import io
import logging
import multiprocessing
import os.path
import sys
import timeit

import gemato.exceptions
import gemato.find_top_level
import gemato.openpgp
import gemato.profile
import gemato.recursiveloader


def verify_failure(e):
    logging.error(str(e))
    return False


class GematoCommand(object):
    """
    Base class for commands supported by gemato.
    """

    @property
    def name(self):
        """
        Command name. Used on the command-line
        """
        pass

    @property
    def help(self):
        """
        Command description for --help.
        """
        pass

    def add_options(self, subp):
        """
        Add options specific to the command to subparser @subp.
        """
        pass

    def parse_args(self, args, argp):
        """
        Process command-line arguments @args. @argp is the argparse
        instance provided for error reporting.
        """
        pass

    def __call__(self):
        """
        Perform the command. Returns the exit status.
        """
        pass

    def cleanup(self):
        """
        Perform any cleanups necessary. Called on program termination.
        """
        pass


class VerifyCommand(GematoCommand):
    name = 'verify'
    help = 'Verify one or more directories against Manifests'

    def __init__(self):
        self.openpgp_env = None

    def add_options(self, verify):
        verify.add_argument('paths', nargs='*', default=['.'],
                help='Paths to verify (defaults to "." if none specified)')
        verify.add_argument('-j', '--jobs', type=int,
                help='Specify the maximum number of parallel jobs to use (default: {})'
                    .format(multiprocessing.cpu_count()))
        verify.add_argument('-k', '--keep-going', action='store_true',
                help='Continue reporting errors rather than terminating on the first failure')
        verify.add_argument('-K', '--openpgp-key',
                help='Use only the OpenPGP key(s) from a specific file')
        verify.add_argument('-P', '--no-openpgp-verify', action='store_false',
                dest='openpgp_verify',
                help='Disable OpenPGP verification of signed Manifests')
        verify.add_argument('-R', '--no-refresh-keys', action='store_false',
                dest='refresh_keys',
                help='Disable refreshing OpenPGP key (prevents network access, applicable '
                    +'when using -K only)')
        verify.add_argument('-s', '--require-signed-manifest', action='store_true',
                help='Require that the top-level Manifest is OpenPGP signed')

    def parse_args(self, args, argp):
        self.paths = args.paths
        self.require_signed_manifest = args.require_signed_manifest
        self.init_kwargs = {}
        self.kwargs = {}

        if args.jobs is not None:
            if args.jobs < 1:
                argp.error('--jobs must be positive')
            self.init_kwargs['max_jobs'] = args.jobs
        if args.keep_going:
            self.kwargs['fail_handler'] = verify_failure
        if not args.openpgp_verify:
            self.init_kwargs['verify_openpgp'] = False

        # use isolated environment if key is specified;
        # system environment otherwise
        if args.openpgp_key is not None:
            env_class = gemato.openpgp.OpenPGPEnvironment
        else:
            env_class = gemato.openpgp.OpenPGPSystemEnvironment
        self.openpgp_env = env_class()

        if args.openpgp_key is not None:
            with io.open(args.openpgp_key, 'rb') as f:
                self.openpgp_env.import_key(f)
            # always refresh keys to check for revocation
            # (unless user specifically asked us not to)
            if args.refresh_keys:
                logging.info('Refreshing keys from keyserver...')
                self.openpgp_env.refresh_keys()
                logging.info('Keys refreshed.')
        self.init_kwargs['openpgp_env'] = self.openpgp_env

    def __call__(self):
        ret = True

        for p in self.paths:
            tlm = gemato.find_top_level.find_top_level_manifest(p)
            if tlm is None:
                logging.error('Top-level Manifest not found in {}'.format(p))
                return 1

            start = timeit.default_timer()
            m = gemato.recursiveloader.ManifestRecursiveLoader(tlm,
                    **self.init_kwargs)
            if self.require_signed_manifest and not m.openpgp_signed:
                logging.error('Top-level Manifest {} is not OpenPGP signed'.format(tlm))
                return 1

            ts = m.find_timestamp()
            if ts:
                logging.info('Manifest timestamp: {} UTC'.format(ts.ts))

            if m.openpgp_signed:
                logging.info('Valid OpenPGP signature found:')
                logging.info('- primary key: {}'.format(
                    m.openpgp_signature.primary_key_fingerprint))
                logging.info('- subkey: {}'.format(
                    m.openpgp_signature.fingerprint))
                logging.info('- timestamp: {} UTC'.format(
                    m.openpgp_signature.timestamp))

            logging.info('Verifying {}...'.format(p))

            relpath = os.path.relpath(p, os.path.dirname(tlm))
            if relpath == '.':
                relpath = ''
            ret &= m.assert_directory_verifies(relpath, **self.kwargs)

            stop = timeit.default_timer()
            logging.info('{} verified in {:.2f} seconds'.format(p, stop - start))

        return 0 if ret else 1

    def cleanup(self):
        if self.openpgp_env is not None:
            self.openpgp_env.close()


class UpdateCommand(GematoCommand):
    name = 'update'
    help = 'Update the Manifest entries for one or more directory trees'

    def add_options(self, update):
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
        update.add_argument('-j', '--jobs', type=int,
                help='Specify the maximum number of parallel jobs to use (default: {})'
                    .format(multiprocessing.cpu_count()))
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

    def parse_args(self, args, argp):
        self.paths = args.paths
        self.timestamp = args.timestamp
        self.incremental = args.incremental

        self.init_kwargs = {}
        self.save_kwargs = {}
        self.update_kwargs = {}

        if args.hashes is not None:
            self.init_kwargs['hashes'] = args.hashes.split()
        if args.compress_watermark is not None:
            if args.compress_watermark < 0:
                argp.error('--compress-watermark must not be negative!')
            self.init_kwargs['compress_watermark'] = args.compress_watermark
        if args.compress_format is not None:
            self.init_kwargs['compress_format'] = args.compress_format
        if args.force_rewrite:
            self.save_kwargs['force'] = True
        if args.jobs is not None:
            if args.jobs < 1:
                argp.error('--jobs must be positive')
            self.init_kwargs['max_jobs'] = args.jobs
        if args.openpgp_id is not None:
            self.init_kwargs['openpgp_keyid'] = args.openpgp_id
        if args.profile is not None:
            self.init_kwargs['profile'] = gemato.profile.get_profile_by_name(
                    args.profile)
        if args.sign is not None:
            self.init_kwargs['sign_openpgp'] = args.sign

        # use isolated environment if key is specified;
        # system environment otherwise
        if args.openpgp_key is not None:
            env_class = gemato.openpgp.OpenPGPEnvironment
        else:
            env_class = gemato.openpgp.OpenPGPSystemEnvironment
        self.openpgp_env = env_class()

        if args.openpgp_key is not None:
            with io.open(args.openpgp_key, 'rb') as f:
                self.openpgp_env.import_key(f)
        self.init_kwargs['openpgp_env'] = self.openpgp_env

    def __call__(self):
        for p in self.paths:
            tlm = gemato.find_top_level.find_top_level_manifest(p)
            if tlm is None:
                logging.error('Top-level Manifest not found in {}'.format(p))
                return 1

            start = timeit.default_timer()
            m = gemato.recursiveloader.ManifestRecursiveLoader(tlm,
                    **self.init_kwargs)

            # if not specified by user, profile must set it
            if m.hashes is None:
                logging.error('--hashes must be specified if not implied by --profile')
                return 1

            relpath = os.path.relpath(p, os.path.dirname(tlm))
            if relpath == '.':
                relpath = ''
            if self.timestamp and relpath != '':
                logging.error('Timestamp can only be updated if doing full-tree update')
                return 1
            if self.incremental:
                if relpath != '':
                    logging.error('Incremental works only for full-tree update')
                    return 1
                last_ts = m.find_timestamp()
                if last_ts is None:
                    loggng.error('Incremental specified but no timestamp in Manifest')
                    return 1
                self.update_kwargs['last_mtime'] = last_ts.ts.timestamp()

            logging.info('Updating Manifests in {}...'.format(p))

            start_ts = datetime.datetime.utcnow()
            m.update_entries_for_directory(relpath, **self.update_kwargs)

            # write TIMESTAMP if requested, or if already there
            if relpath != '':
                # skip timestamp if not doing full update
                pass
            elif self.timestamp:
                m.set_timestamp(start_ts)
            else:
                ts = m.find_timestamp()
                if ts is not None:
                    ts.ts = start_ts

            m.save_manifests(**self.save_kwargs)

            stop = timeit.default_timer()
            logging.info('{} updated in {:.2f} seconds'.format(p, stop - start))

        return 0

    def cleanup(self):
        if self.openpgp_env is not None:
            self.openpgp_env.close()


class CreateCommand(GematoCommand):
    name = 'create'
    help = 'Create a Manifest tree starting at the specified file'

    def add_options(self, create):
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
        create.add_argument('-j', '--jobs', type=int,
                help='Specify the maximum number of parallel jobs to use (default: {})'
                    .format(multiprocessing.cpu_count()))
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

    def parse_args(self, args, argp):
        self.paths = args.paths
        self.timestamp = args.timestamp

        self.init_kwargs = {}
        self.save_kwargs = {}
        self.init_kwargs['allow_create'] = True

        if args.hashes is not None:
            self.init_kwargs['hashes'] = args.hashes.split()
        if args.compress_watermark is not None:
            if args.compress_watermark < 0:
                argp.error('--compress-watermark must not be negative!')
            self.init_kwargs['compress_watermark'] = args.compress_watermark
        if args.compress_format is not None:
            self.init_kwargs['compress_format'] = args.compress_format
        if args.force_rewrite:
            self.save_kwargs['force'] = True
        if args.jobs is not None:
            if args.jobs < 1:
                argp.error('--jobs must be positive')
            self.init_kwargs['max_jobs'] = args.jobs
        if args.openpgp_id is not None:
            self.init_kwargs['openpgp_keyid'] = args.openpgp_id
        if args.profile is not None:
            self.init_kwargs['profile'] = gemato.profile.get_profile_by_name(
                    args.profile)
        if args.sign is not None:
            self.init_kwargs['sign_openpgp'] = args.sign

        # use isolated environment if key is specified;
        # system environment otherwise
        if args.openpgp_key is not None:
            env_class = gemato.openpgp.OpenPGPEnvironment
        else:
            env_class = gemato.openpgp.OpenPGPSystemEnvironment
        self.openpgp_env = env_class()

        if args.openpgp_key is not None:
            with io.open(args.openpgp_key, 'rb') as f:
                self.openpgp_env.import_key(f)
        self.init_kwargs['openpgp_env'] = self.openpgp_env

    def __call__(self):
        for p in self.paths:
            start = timeit.default_timer()
            m = gemato.recursiveloader.ManifestRecursiveLoader(
                    os.path.join(p, 'Manifest'), **self.init_kwargs)

            # if not specified by user, profile must set it
            if m.hashes is None:
                logging.error('--hashes must be specified if not implied by --profile')
                return 1

            logging.info('Creating Manifests in {}...'.format(p))

            start_ts = datetime.datetime.utcnow()
            m.update_entries_for_directory()

            # write TIMESTAMP if requested
            if self.timestamp:
                m.set_timestamp(start_ts)

            m.save_manifests(**self.save_kwargs)

            stop = timeit.default_timer()
            logging.info('{} updated in {:.2f} seconds'.format(p, stop - start))

        return 0

    def cleanup(self):
        if self.openpgp_env is not None:
            self.openpgp_env.close()


def main(argv):
    argp = argparse.ArgumentParser(
            prog=argv[0],
            description='Gentoo Manifest Tool')
    subp = argp.add_subparsers()

    commands = [VerifyCommand, UpdateCommand, CreateCommand]
    for cmdclass in commands:
        cmd = cmdclass()
        cmdp = subp.add_parser(cmd.name, help=cmd.help)
        cmd.add_options(cmdp)
        cmdp.set_defaults(cmd=cmd)

    vals = argp.parse_args(argv[1:])
    if not hasattr(vals, 'cmd'):
        argp.error('No function specified')
    try:
        try:
            vals.cmd.parse_args(vals, argp)
            return vals.cmd()
        finally:
            vals.cmd.cleanup()
    except gemato.exceptions.GematoException as e:
        logging.error(str(e))
        return 1


def setuptools_main():
    logging.getLogger().setLevel(logging.INFO)
    sys.exit(main(sys.argv))
