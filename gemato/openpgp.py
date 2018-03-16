# gemato: OpenPGP verification support
# vim:fileencoding=utf-8
# (c) 2017-2018 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import errno
import os
import os.path
import shutil
import subprocess
import tempfile

import gemato.exceptions


class OpenPGPSignatureData(object):
    __slots__ = ['fingerprint', 'timestamp', 'expire_timestamp',
                 'primary_key_fingerprint']

    def __init__(self, fingerprint, timestamp, expire_timestamp,
                 primary_key_fingerprint):
        self.fingerprint = fingerprint
        self.timestamp = timestamp
        self.expire_timestamp = expire_timestamp
        self.primary_key_fingerprint = primary_key_fingerprint


class OpenPGPSystemEnvironment(object):
    """
    OpenPGP environment class that uses the global OpenPGP environment
    (user's home directory or GNUPGHOME).
    """

    __slots__ = ['_impl']

    def __init__(self):
        self._impl = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_cb):
        pass

    def close(self):
        pass

    def import_key(self, keyfile):
        """
        Import a public key from open file @keyfile. The file should
        be open for reading in binary mode, and oriented
        at the beginning.
        """

        raise NotImplementedError('import_key() is not implemented by this OpenPGP provider')

    def refresh_keys(self):
        """
        Update the keys from their assigned keyservers. This should be called
        at start of every execution in order to ensure that revocations
        are respected. This action requires network access.
        """

        raise NotImplementedError('refresh_keys() is not implemented by this OpenPGP provider')

    def _parse_gpg_ts(self, ts):
        """
        Parse GnuPG status timestamp that can either be time_t value
        or ISO 8601 timestamp.
        """
        # that's how upstream tells us to detect this
        if 'T' in ts:
            # TODO: is this correct for all cases? is it localtime?
            return datetime.datetime.strptime(ts, '%Y%m%dT%H%M%S')
        elif ts == '0':
            # no timestamp
            return None
        else:
            return datetime.datetime.utcfromtimestamp(int(ts))

    def verify_file(self, f):
        """
        Perform an OpenPGP verification of Manifest data in open file @f.
        The file should be open in text mode and set at the beginning
        (or start of signed part). Raises an exception if the verification
        fails.
        """

        exitst, out, err = self._spawn_gpg(['--status-fd', '1', '--verify'],
                                           f.read().encode('utf8'))
        if exitst != 0:
            raise gemato.exceptions.OpenPGPVerificationFailure(err.decode('utf8'))

        is_good = False
        sig_data = None

        # process the output of gpg to find the exact result
        for l in out.splitlines():
            if l.startswith(b'[GNUPG:] GOODSIG'):
                is_good = True
            elif l.startswith(b'[GNUPG:] EXPKEYSIG'):
                raise gemato.exceptions.OpenPGPExpiredKeyFailure(err.decode('utf8'))
            elif l.startswith(b'[GNUPG:] REVKEYSIG'):
                raise gemato.exceptions.OpenPGPRevokedKeyFailure(err.decode('utf8'))
            elif l.startswith(b'[GNUPG:] VALIDSIG'):
                spl = l.split(b' ')
                assert len(spl) >= 12
                fp = spl[2].decode('utf8')
                ts = self._parse_gpg_ts(spl[4].decode('utf8'))
                expts = self._parse_gpg_ts(spl[5].decode('utf8'))
                pkfp = spl[11].decode('utf8')

                sig_data = OpenPGPSignatureData(fp, ts, expts, pkfp)

        # require both GOODSIG and VALIDSIG
        if not is_good or sig_data is None:
            raise gemato.exceptions.OpenPGPUnknownSigFailure(err.decode('utf8'))
        return sig_data

    def clear_sign_file(self, f, outf, keyid=None):
        """
        Create an OpenPGP cleartext signed message containing the data
        from open file @f, and writing it into open file @outf.
        Both files should be open in text mode and set at the appropriate
        position. Raises an exception if signing fails.

        Pass @keyid to specify the key to use. If not specified,
        the implementation will use the default key.
        """

        args = []
        if keyid is not None:
            args += ['--local-user', keyid]
        exitst, out, err = self._spawn_gpg(['--clearsign'] + args,
                                           f.read().encode('utf8'))
        if exitst != 0:
            raise gemato.exceptions.OpenPGPSigningFailure(err.decode('utf8'))

        outf.write(out.decode('utf8'))

    def _spawn_gpg(self, options, stdin, env_override={}):
        env = os.environ.copy()
        env['TZ'] = 'UTC'
        env.update(env_override)

        impls = ['gpg2', 'gpg']
        if self._impl is not None:
            impls = [self._impl]

        for impl in impls:
            try:
                p = subprocess.Popen([impl, '--batch'] + options,
                                     stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     env=env)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise
            else:
                break
        else:
            raise gemato.exceptions.OpenPGPNoImplementation()

        self._impl = impl

        out, err = p.communicate(stdin)
        return (p.wait(), out, err)


class OpenPGPEnvironment(OpenPGPSystemEnvironment):
    """
    An isolated environment for OpenPGP routines. Used to get reliable
    verification results independently of user configuration.

    Remember to close() in order to clean up the temporary directory,
    or use as a context manager (via 'with').
    """

    __slots__ = ['_home']

    def __init__(self):
        super(OpenPGPEnvironment, self).__init__()
        self._home = tempfile.mkdtemp()

        with open(os.path.join(self._home, 'dirmngr.conf'), 'w') as f:
            f.write('''# autogenerated by gemato

# honor user's http_proxy setting
honor-http-proxy
''')
        with open(os.path.join(self._home, 'gpg.conf'), 'w') as f:
            f.write('''# autogenerated by gemato

# we are using an isolated keyring, so always trust our keys
trust-model always
''')
        with open(os.path.join(self._home, 'gpg-agent.conf'), 'w') as f:
            f.write('''# autogenerated by gemato

# avoid any smartcard operations, we are running in isolation
disable-scdaemon
''')

    def __exit__(self, exc_type, exc_value, exc_cb):
        if self._home is not None:
            self.close()

    @staticmethod
    def _rmtree_error_handler(func, path, exc_info):
        # ignore ENOENT -- it probably means a race condition between
        # us and gpg-agent cleaning up after itself
        if (not isinstance(exc_info[1], OSError)
                or exc_info[1].errno != errno.ENOENT):
            raise exc_info[1]

    def close(self):
        if self._home is not None:
            shutil.rmtree(self._home, onerror=self._rmtree_error_handler)
            self._home = None

    def import_key(self, keyfile):
        exitst, out, err = self._spawn_gpg(['--import'], keyfile.read())
        if exitst != 0:
            raise gemato.exceptions.OpenPGPKeyImportError(err.decode('utf8'))

    def refresh_keys(self):
        exitst, out, err = self._spawn_gpg(['--refresh-keys'], '')
        if exitst != 0:
            raise gemato.exceptions.OpenPGPKeyRefreshError(err.decode('utf8'))

    @property
    def home(self):
        assert self._home is not None
        return self._home

    def _spawn_gpg(self, options, stdin):
        env_override = {'GNUPGHOME': self.home}
        return (super(OpenPGPEnvironment, self)
                ._spawn_gpg(options, stdin, env_override))
