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
import gemato.hash
import gemato.manifest
import gemato.openpgp
import gemato.profile
import gemato.recursiveloader


def verify_failure(e):
    logging.error(e)
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


class BaseOpenPGPMixin(object):
    """
    A base mixin that adds logic to load and use OpenPGP keys.
    """

    def __init__(self):
        super(BaseOpenPGPMixin, self).__init__()
        self.openpgp_env = None

    def add_options(self, subp):
        super(BaseOpenPGPMixin, self).add_options(subp)

        subp.add_argument('-K', '--openpgp-key',
                help='Use only the OpenPGP key(s) from a specific file')

    def parse_args(self, args, argp):
        super(BaseOpenPGPMixin, self).parse_args(args, argp)

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

    def cleanup(self):
        super(BaseOpenPGPMixin, self).cleanup()

        if self.openpgp_env is not None:
            self.openpgp_env.close()


class VerifyingOpenPGPMixin(BaseOpenPGPMixin):
    """
    Verification-class OpenPGP mixin. Additionally refreshes keys.
    """

    def add_options(self, subp):
        super(VerifyingOpenPGPMixin, self).add_options(subp)

        subp.add_argument('-R', '--no-refresh-keys', action='store_false',
                dest='refresh_keys',
                help='Disable refreshing OpenPGP key (prevents network access, '
                    +'applicable when using -K only)')

    def parse_args(self, args, argp):
        super(VerifyingOpenPGPMixin, self).parse_args(args, argp)

        if args.openpgp_key is not None:
            # always refresh keys to check for revocation
            # (unless user specifically asked us not to)
            if args.refresh_keys:
                logging.info('Refreshing keys from keyserver...')
                self.openpgp_env.refresh_keys()
                logging.info('Keys refreshed.')


class BaseManifestLoaderMixin(object):
    """
    Mixin for commands using RecursiveManifestLoader class.
    """

    def add_options(self, subp):
        super(BaseManifestLoaderMixin, self).add_options(subp)

        subp.add_argument('-j', '--jobs', type=int,
                help='Specify the maximum number of parallel jobs to use (default: {})'
                    .format(multiprocessing.cpu_count()))
        subp.add_argument('-x', '--one-file-system', action='store_true',
                help='Do not cross filesystem boundaries (report an error instead)')

    def parse_args(self, args, argp):
        super(BaseManifestLoaderMixin, self).parse_args(args, argp)

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
        super(VerifyCommand, self).add_options(verify)

        verify.add_argument('paths', nargs='*', default=['.'],
                help='Paths to verify (defaults to "." if none specified)')
        verify.add_argument('-k', '--keep-going', action='store_true',
                help='Continue reporting errors rather than terminating on the first failure')
        verify.add_argument('-P', '--no-openpgp-verify', action='store_false',
                dest='openpgp_verify',
                help='Disable OpenPGP verification of signed Manifests')
        verify.add_argument('-s', '--require-signed-manifest', action='store_true',
                help='Require that the top-level Manifest is OpenPGP signed')

    def parse_args(self, args, argp):
        super(VerifyCommand, self).parse_args(args, argp)

        self.paths = args.paths
        self.require_signed_manifest = args.require_signed_manifest
        self.kwargs = {}
        self.init_kwargs['openpgp_env'] = self.openpgp_env

        if args.keep_going:
            self.kwargs['fail_handler'] = verify_failure
        if not args.openpgp_verify:
            self.init_kwargs['verify_openpgp'] = False

    def __call__(self):
        super(VerifyCommand, self).__call__()

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


class BaseUpdateMixin(BaseManifestLoaderMixin, BaseOpenPGPMixin):
    """
    A mixin that adds common bits for update-class commands.
    """

    def add_options(self, update):
        super(BaseUpdateMixin, self).add_options(update)

        update.add_argument('-c', '--compress-watermark', type=int,
                help='Minimum Manifest size for files to be compressed')
        update.add_argument('-C', '--compress-format',
                help='Format for compressed files (e.g. "gz", "bz2"...)')
        update.add_argument('-f', '--force-rewrite', action='store_true',
                help='Force rewriting all the Manifests, even if they did not change')
        update.add_argument('-H', '--hashes',
                help='Whitespace-separated list of hashes to use')
        update.add_argument('-k', '--openpgp-id',
                help='Use the specified OpenPGP key (by ID or user)')
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
        super(BaseUpdateMixin, self).parse_args(args, argp)

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
            self.init_kwargs['profile'] = gemato.profile.get_profile_by_name(
                    args.profile)
        if args.sign is not None:
            self.init_kwargs['sign_openpgp'] = args.sign


class UpdateCommand(BaseUpdateMixin, GematoCommand):
    name = 'update'
    help = 'Update the Manifest entries for one or more directory trees'

    def add_options(self, update):
        super(UpdateCommand, self).add_options(update)

        update.add_argument('paths', nargs='*', default=['.'],
                help='Paths to update (defaults to "." if none specified)')
        update.add_argument('-i', '--incremental', action='store_true',
                help='Perform incremental update by comparing mtimes against TIMESTAMP')

    def parse_args(self, args, argp):
        super(UpdateCommand, self).parse_args(args, argp)

        self.paths = args.paths
        self.incremental = args.incremental

    def __call__(self):
        super(UpdateCommand, self).__call__()

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

            update_kwargs = {}
            if self.incremental:
                if relpath != '':
                    logging.error('Incremental works only for full-tree update')
                    return 1
                last_ts = m.find_timestamp()
                if last_ts is None:
                    logging.error('Incremental specified but no timestamp in Manifest')
                    return 1
                update_kwargs['last_mtime'] = last_ts.ts.timestamp()

            logging.info('Updating Manifests in {}...'.format(p))

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
            logging.info('{} updated in {:.2f} seconds'.format(p, stop - start))

        return 0


class CreateCommand(BaseUpdateMixin, GematoCommand):
    name = 'create'
    help = 'Create a Manifest tree starting at the specified file'

    def add_options(self, create):
        super(CreateCommand, self).add_options(create)

        create.add_argument('paths', nargs='*', default=['.'],
                help='Paths to create Manifest in (defaults to "." if none specified)')

    def parse_args(self, args, argp):
        super(CreateCommand, self).parse_args(args, argp)

        self.init_kwargs['allow_create'] = True
        self.paths = args.paths

    def __call__(self):
        super(CreateCommand, self).__call__()

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


class HashCommand(GematoCommand):
    name = 'hash'
    help = 'Generate hashes for specified file(s) and/or stdin'

    def add_options(self, subp):
        super(HashCommand, self).add_options(subp)

        subp.add_argument('paths', nargs='*', default=['-'],
                help='Paths to hash (defaults to "-" (stdin) if not specified)')
        subp.add_argument('-H', '--hashes', required=True,
                help='Whitespace-separated list of hashes to use')

    def parse_args(self, args, argp):
        super(HashCommand, self).parse_args(args, argp)

        self.hashes = sorted(args.hashes.split())
        self.paths = args.paths

    def __call__(self):
        super(HashCommand, self).__call__()

        hashlib_hashes = list(
                gemato.manifest.manifest_hashes_to_hashlib(self.hashes))
        hashlib_hashes.append('__size__')

        for p in self.paths:
            if p == '-':
                if sys.hexversion >= 0x03000000:
                    f = sys.stdin.buffer
                else:
                    f = sys.stdin
                h = gemato.hash.hash_file(f, hashlib_hashes)
            else:
                h = gemato.hash.hash_path(p, hashlib_hashes)

            sz = h.pop('__size__')
            e = gemato.manifest.ManifestFileEntry(p, sz,
                    dict((mh, h[hh]) for mh, hh in zip(self.hashes, hashlib_hashes)))
            print(' '.join(e.to_list('DATA' if p != '-' else 'STDIN')))


class OpenPGPVerifyCommand(VerifyingOpenPGPMixin, GematoCommand):
    name = 'openpgp-verify'
    help = 'Verify OpenPGP signatures embedded in specified file(s) and/or stdin'

    def add_options(self, subp):
        super(OpenPGPVerifyCommand, self).add_options(subp)

        subp.add_argument('paths', nargs='*', default=['-'],
                help='Paths to hash (defaults to "-" (stdin) if not specified)')

    def parse_args(self, args, argp):
        super(OpenPGPVerifyCommand, self).parse_args(args, argp)

        self.paths = args.paths

    def __call__(self):
        super(OpenPGPVerifyCommand, self).__call__()

        ret = True

        for p in self.paths:
            if p == '-':
                if sys.hexversion >= 0x03000000:
                    f = sys.stdin
                else:
                    f = io.open(sys.stdin.fileno(), 'r')
            else:
                f = io.open(p, 'r')

            try:
                try:
                    sig = self.openpgp_env.verify_file(f)
                except gemato.exceptions.GematoException as e:
                    logging.error(u'OpenPGP verification failed for {}:\n{}'
                            .format(p, e))
                    ret = False
                else:
                    logging.info('Valid OpenPGP signature found in {}:'
                            .format(p))
                    logging.info('- primary key: {}'.format(
                        sig.primary_key_fingerprint))
                    logging.info('- subkey: {}'.format(
                        sig.fingerprint))
                    logging.info('- timestamp: {} UTC'.format(
                        sig.timestamp))
            finally:
                if p != '-':
                    f.close()

        return 0 if ret else 1


def main(argv):
    argp = argparse.ArgumentParser(
            prog=argv[0],
            description='Gentoo Manifest Tool')
    subp = argp.add_subparsers()

    commands = [VerifyCommand, UpdateCommand, CreateCommand,
                HashCommand, OpenPGPVerifyCommand]
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
    except gemato.exceptions.GematoException as e:
        logging.error(e)
        return 1


def setuptools_main():
    logging.getLogger().setLevel(logging.INFO)
    if sys.hexversion < 0x03000000:
        argv = [x.decode(sys.getfilesystemencoding()) for x in sys.argv]
    else:
        argv = sys.argv
    sys.exit(main(argv))
