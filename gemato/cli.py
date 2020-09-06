# gemato: CLI routines
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

from __future__ import print_function

import argparse
import datetime
import logging
import multiprocessing
import os.path
import signal
import subprocess
import sys
import timeit

from gemato.exceptions import GematoException
from gemato.find_top_level import find_top_level_manifest
from gemato.hash import hash_file, hash_path
from gemato.manifest import (
    ManifestFileEntry,
    manifest_hashes_to_hashlib,
    )
from gemato.openpgp import (
    OpenPGPEnvironment,
    OpenPGPSystemEnvironment,
    IsolatedGPGEnvironment,
    )
from gemato.profile import get_profile_by_name
from gemato.recursiveloader import ManifestRecursiveLoader


def verify_failure(e):
    logging.error(e)
    return False


class GematoCommand:
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
        subp.add_argument('--debug', action='store_true',
                          help='Enable debugging output')

    def parse_args(self, args, argp):
        """
        Process command-line arguments @args. @argp is the argparse
        instance provided for error reporting.
        """
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

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


class BaseOpenPGPMixin:
    """
    A base mixin that adds logic to load and use OpenPGP keys.
    """

    def __init__(self):
        super().__init__()
        self.openpgp_env = None

    def add_options(self, subp):
        super().add_options(subp)

        subp.add_argument(
            '-K', '--openpgp-key',
            help='Use only the OpenPGP key(s) from a specific file')
        subp.add_argument(
            '--proxy',
            help='Use HTTP proxy')

    def parse_args(self, args, argp):
        super().parse_args(args, argp)

        # use isolated environment if key is specified;
        # system environment otherwise
        if args.openpgp_key is not None:
            env_class = OpenPGPEnvironment
        else:
            env_class = OpenPGPSystemEnvironment
        self.openpgp_env = env_class(debug=args.debug,
                                     proxy=args.proxy)

        if args.openpgp_key is not None:
            with open(args.openpgp_key, 'rb') as f:
                self.openpgp_env.import_key(f)

    def cleanup(self):
        super().cleanup()

        if self.openpgp_env is not None:
            self.openpgp_env.close()


class VerifyingOpenPGPMixin(BaseOpenPGPMixin):
    """
    Verification-class OpenPGP mixin. Additionally refreshes keys.
    """

    def add_options(self, subp):
        super().add_options(subp)

        subp.add_argument(
            '-R', '--no-refresh-keys', action='store_false',
            dest='refresh_keys',
            help='Disable refreshing OpenPGP key (prevents network '
                 'access, applicable when using -K only)')
        subp.add_argument(
            '-W', '--no-wkd', action='store_false',
            dest='allow_wkd',
            help='Do not attempt to use WKD to refetch keys (use '
                 'keyservers only)')
        subp.add_argument(
            '--keyserver',
            help='Force custom keyserver URL')

    def parse_args(self, args, argp):
        super().parse_args(args, argp)

        if args.openpgp_key is not None:
            # always refresh keys to check for revocation
            # (unless user specifically asked us not to)
            if args.refresh_keys:
                logging.info('Refreshing keys...')
                self.openpgp_env.refresh_keys(allow_wkd=args.allow_wkd,
                                              keyserver=args.keyserver)
                logging.info('Keys refreshed.')


class BaseManifestLoaderMixin:
    """
    Mixin for commands using RecursiveManifestLoader class.
    """

    def add_options(self, subp):
        super().add_options(subp)

        subp.add_argument(
            '-j', '--jobs', type=int,
            help=f'Specify the maximum number of parallel jobs to use '
                 f'(default: {multiprocessing.cpu_count()})')
        subp.add_argument(
            '-x', '--one-file-system', action='store_true',
            help='Do not cross filesystem boundaries (report an error '
                 'instead)')

    def parse_args(self, args, argp):
        super().parse_args(args, argp)

        self.init_kwargs = {}
        if args.jobs is not None:
            if args.jobs < 1:
                argp.error('--jobs must be positive')
            self.init_kwargs['max_jobs'] = args.jobs
        if args.one_file_system:
            self.init_kwargs['allow_xdev'] = False


class VerifyCommand(BaseManifestLoaderMixin, VerifyingOpenPGPMixin,
                    GematoCommand):
    name = 'verify'
    help = 'Verify one or more directories against Manifests'

    def add_options(self, verify):
        super().add_options(verify)

        verify.add_argument(
            'paths', nargs='*', default=['.'],
            help='Paths to verify (defaults to "." if none specified)')
        verify.add_argument(
            '-k', '--keep-going', action='store_true',
            help='Continue reporting errors rather than terminating '
                 'on the first failure')
        verify.add_argument(
            '-P', '--no-openpgp-verify', action='store_false',
            dest='openpgp_verify',
            help='Disable OpenPGP verification of signed Manifests')
        verify.add_argument(
            '-s', '--require-signed-manifest', action='store_true',
            help='Require that the top-level Manifest is OpenPGP signed')

    def parse_args(self, args, argp):
        super().parse_args(args, argp)

        self.paths = args.paths
        self.require_signed_manifest = args.require_signed_manifest
        self.kwargs = {}
        self.init_kwargs['openpgp_env'] = self.openpgp_env

        if args.keep_going:
            self.kwargs['fail_handler'] = verify_failure
        if not args.openpgp_verify:
            self.init_kwargs['verify_openpgp'] = False

    def __call__(self):
        super().__call__()

        ret = True

        for p in self.paths:
            tlm = find_top_level_manifest(p)
            if tlm is None:
                logging.error(f'Top-level Manifest not found in {p}')
                return 1

            start = timeit.default_timer()
            m = ManifestRecursiveLoader(tlm, **self.init_kwargs)
            if self.require_signed_manifest and not m.openpgp_signed:
                logging.error(f'Top-level Manifest {tlm} is not '
                              f'OpenPGP signed')
                return 1

            ts = m.find_timestamp()
            if ts:
                logging.info(f'Manifest timestamp: {ts.ts} UTC')

            if m.openpgp_signed:
                logging.info('Valid OpenPGP signature found:')
                logging.info(
                    f'- primary key: '
                    f'{m.openpgp_signature.primary_key_fingerprint}')
                logging.info(
                    f'- subkey: '
                    f'{m.openpgp_signature.fingerprint}')
                logging.info(
                    f'- timestamp: '
                    f'{m.openpgp_signature.timestamp} UTC')

            logging.info(f'Verifying {p}...')

            relpath = os.path.relpath(p, os.path.dirname(tlm))
            if relpath == '.':
                relpath = ''
            ret &= m.assert_directory_verifies(relpath, **self.kwargs)

            stop = timeit.default_timer()
            logging.info(f'{p} verified in {stop - start:.2f} seconds')

        return 0 if ret else 1


class BaseUpdateMixin(BaseManifestLoaderMixin, BaseOpenPGPMixin):
    """
    A mixin that adds common bits for update-class commands.
    """

    def add_options(self, update):
        super().add_options(update)

        update.add_argument(
            '-c', '--compress-watermark', type=int,
            help='Minimum Manifest size for files to be compressed')
        update.add_argument(
            '-C', '--compress-format',
            help='Format for compressed files (e.g. "gz", "bz2"...)')
        update.add_argument(
            '-f', '--force-rewrite', action='store_true',
            help='Force rewriting all the Manifests, even if they did '
                 'not change')
        update.add_argument(
            '-H', '--hashes',
            help='Whitespace-separated list of hashes to use')
        update.add_argument(
            '-k', '--openpgp-id',
            help='Use the specified OpenPGP key (by ID or user)')
        update.add_argument(
            '-p', '--profile',
            help='Use the specified profile ("default", "ebuild", '
                 '"old-ebuild"...)')
        signgroup = update.add_mutually_exclusive_group()
        signgroup.add_argument(
            '-s', '--sign', action='store_true',
            default=None,
            help='Force signing the top-level Manifest')
        signgroup.add_argument(
            '-S', '--no-sign', action='store_false',
            dest='sign',
            help='Disable signing the top-level Manifest')
        update.add_argument(
            '-t', '--timestamp', action='store_true',
            help='Include TIMESTAMP entry in Manifest')

    def parse_args(self, args, argp):
        super().parse_args(args, argp)

        self.timestamp = args.timestamp

        self.save_kwargs = {}
        self.init_kwargs['openpgp_env'] = self.openpgp_env

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
        if args.openpgp_id is not None:
            self.init_kwargs['openpgp_keyid'] = args.openpgp_id
        if args.profile is not None:
            self.init_kwargs['profile'] = (
                get_profile_by_name(args.profile))
        if args.sign is not None:
            self.init_kwargs['sign_openpgp'] = args.sign


class UpdateCommand(BaseUpdateMixin, GematoCommand):
    name = 'update'
    help = 'Update the Manifest entries for one or more directory trees'

    def add_options(self, update):
        super().add_options(update)

        update.add_argument(
            'paths', nargs='*', default=['.'],
            help='Paths to update (defaults to "." if none specified)')
        update.add_argument(
            '-i', '--incremental', action='store_true',
            help='Perform incremental update by comparing mtimes '
                 'against TIMESTAMP')

    def parse_args(self, args, argp):
        super().parse_args(args, argp)

        self.paths = args.paths
        self.incremental = args.incremental

    def __call__(self):
        super().__call__()

        for p in self.paths:
            tlm = find_top_level_manifest(p)
            if tlm is None:
                logging.error(f'Top-level Manifest not found in {p}')
                return 1

            start = timeit.default_timer()
            m = ManifestRecursiveLoader(tlm, **self.init_kwargs)

            # if not specified by user, profile must set it
            if m.hashes is None:
                logging.error('--hashes must be specified if not '
                              'implied by --profile')
                return 1

            relpath = os.path.relpath(p, os.path.dirname(tlm))
            if relpath == '.':
                relpath = ''
            if self.timestamp and relpath != '':
                logging.error('Timestamp can only be updated if doing '
                              'full-tree update')
                return 1

            update_kwargs = {}
            if self.incremental:
                if relpath != '':
                    logging.error('Incremental works only for '
                                  'full-tree update')
                    return 1
                last_ts = m.find_timestamp()
                if last_ts is None:
                    logging.error('Incremental specified but no '
                                  'timestamp in Manifest')
                    return 1
                update_kwargs['last_mtime'] = last_ts.ts.timestamp()

            logging.info(f'Updating Manifests in {p}...')

            start_ts = datetime.datetime.utcnow()
            m.update_entries_for_directory(relpath, **update_kwargs)

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
            logging.info(f'{p} updated in {stop - start:.2f} seconds')

        return 0


class CreateCommand(BaseUpdateMixin, GematoCommand):
    name = 'create'
    help = 'Create a Manifest tree starting at the specified file'

    def add_options(self, create):
        super().add_options(create)

        create.add_argument(
            'paths', nargs='*', default=['.'],
            help='Paths to create Manifest in (defaults to "." '
                 'if none specified)')

    def parse_args(self, args, argp):
        super().parse_args(args, argp)

        self.init_kwargs['allow_create'] = True
        self.paths = args.paths

    def __call__(self):
        super().__call__()

        for p in self.paths:
            start = timeit.default_timer()
            m = ManifestRecursiveLoader(
                os.path.join(p, 'Manifest'), **self.init_kwargs)

            # if not specified by user, profile must set it
            if m.hashes is None:
                logging.error('--hashes must be specified if not '
                              'implied by --profile')
                return 1

            logging.info(f'Creating Manifests in {p}...')

            start_ts = datetime.datetime.utcnow()
            m.update_entries_for_directory()

            # write TIMESTAMP if requested
            if self.timestamp:
                m.set_timestamp(start_ts)

            m.save_manifests(**self.save_kwargs)

            stop = timeit.default_timer()
            logging.info(f'{p} updated in {stop - start:.2f} seconds')

        return 0


class HashCommand(GematoCommand):
    name = 'hash'
    help = 'Generate hashes for specified file(s) and/or stdin'

    def add_options(self, subp):
        super().add_options(subp)

        subp.add_argument(
            'paths', nargs='*', default=['-'],
            help='Paths to hash (defaults to "-" (stdin) if not '
                 'specified)')
        subp.add_argument(
            '-H', '--hashes', required=True,
            help='Whitespace-separated list of hashes to use')

    def parse_args(self, args, argp):
        super().parse_args(args, argp)

        self.hashes = sorted(args.hashes.split())
        self.paths = args.paths

    def __call__(self):
        super().__call__()

        hashlib_hashes = list(manifest_hashes_to_hashlib(self.hashes))
        hashlib_hashes.append('__size__')

        for p in self.paths:
            if p == '-':
                h = hash_file(sys.stdin.buffer, hashlib_hashes)
            else:
                h = hash_path(p, hashlib_hashes)

            sz = h.pop('__size__')
            e = ManifestFileEntry(
                p, sz,
                dict((mh, h[hh]) for mh, hh
                     in zip(self.hashes, hashlib_hashes)))
            print(' '.join(e.to_list('DATA' if p != '-' else 'STDIN')))


class OpenPGPVerifyCommand(VerifyingOpenPGPMixin, GematoCommand):
    name = 'openpgp-verify'
    help = ('Verify OpenPGP signatures embedded in specified file(s) '
            'and/or stdin')

    def add_options(self, subp):
        super().add_options(subp)

        subp.add_argument(
            'paths', nargs='*', default=['-'],
            help='Paths to hash (defaults to "-" (stdin) if not '
                 'specified)')

    def parse_args(self, args, argp):
        super().parse_args(args, argp)

        self.paths = args.paths

    def __call__(self):
        super().__call__()

        ret = True

        for p in self.paths:
            if p == '-':
                f = sys.stdin
            else:
                f = open(p, 'r')

            try:
                try:
                    sig = self.openpgp_env.verify_file(f)
                except GematoException as e:
                    logging.error(
                        f'OpenPGP verification failed for {p}:\n{e}')
                    ret = False
                else:
                    logging.info(
                        f'Valid OpenPGP signature found in {p}:')
                    logging.info(
                        f'- primary key: {sig.primary_key_fingerprint}')
                    logging.info(f'- subkey: {sig.fingerprint}')
                    logging.info(f'- timestamp: {sig.timestamp} UTC')
            finally:
                if p != '-':
                    f.close()

        return 0 if ret else 1


class GnuPGWrapCommand(VerifyingOpenPGPMixin, GematoCommand):
    name = 'gpg-wrap'
    help = ('Run specified command with GNUPGHOME set to OpenPGP '
            'verification environment (with keys loaded)')

    def add_options(self, subp):
        super().add_options(subp)

        subp.add_argument(
            'argv', nargs='+',
            help='Command to execute')

    def parse_args(self, args, argp):
        super().parse_args(args, argp)

        if args.openpgp_key is None:
            argp.error('gpg-wrap requires --openpgp-key to be specified')
        self.argv = args.argv

    def __call__(self):
        super().__call__()
        assert isinstance(self.openpgp_env, IsolatedGPGEnvironment)
        os.environ['GNUPGHOME'] = self.openpgp_env._home
        p = subprocess.Popen(self.argv)
        ret = p.wait()
        if ret < 0:
            if hasattr(signal, 'strsignal'):
                sig = signal.strsignal(-ret)
            else:
                sig = -ret
            logging.error(
                f'Child process terminated due to signal: {sig}')
        return ret


def main(argv):
    argp = argparse.ArgumentParser(
            prog=argv[0],
            description='Gentoo Manifest Tool')
    subp = argp.add_subparsers()

    commands = [VerifyCommand,
                UpdateCommand,
                CreateCommand,
                HashCommand,
                OpenPGPVerifyCommand,
                GnuPGWrapCommand,
                ]
    for cmdclass in commands:
        cmd = cmdclass()
        cmdp = subp.add_parser(cmd.name, help=cmd.help)
        cmd.add_options(cmdp)
        cmdp.set_defaults(cmd=cmd)

    vals = argp.parse_args(argv[1:])
    if not hasattr(vals, 'cmd'):
        argp.error('No function specified')
    try:
        assert isinstance(vals.cmd, GematoCommand)

        try:
            vals.cmd.parse_args(vals, argp)
            return vals.cmd()
        finally:
            vals.cmd.cleanup()
    except GematoException as e:
        logging.error(e)
        return 1


def setuptools_main():
    logging.getLogger().setLevel(logging.INFO)
    sys.exit(main(sys.argv))
