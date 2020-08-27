# gemato: OpenPGP verification support
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import base64
import datetime
import email.utils
import errno
import hashlib
import logging
import os
import os.path
import shutil
import subprocess
import tempfile
import urllib.parse

import gemato.exceptions

try:
    import requests
except ImportError:
    requests = None


GNUPG = os.environ.get('GNUPG', 'gpg')
GNUPGCONF = os.environ.get('GNUPGCONF', 'gpgconf')


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

    __slots__ = ['debug']

    def __init__(self, debug=False, proxy=None):
        self.debug = debug

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

    def refresh_keys(self, allow_wkd=True, keyserver=None):
        """
        Update the keys from their assigned keyservers. This should be called
        at start of every execution in order to ensure that revocations
        are respected. This action requires network access.

        @allow_wkd specifies whether WKD can be used to fetch keys. This is
        experimental but usually is more reliable than keyservers.  If WKD
        fails to fetch *all* keys, gemato falls back to keyservers.

        @keyserver may be used to force an alternate keyserver. If its present,
        it should specify a keyserver URL.
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

        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--status-fd', '1', '--verify'],
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
        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--clearsign'] + args,
            f.read().encode('utf8'))
        if exitst != 0:
            raise gemato.exceptions.OpenPGPSigningFailure(err.decode('utf8'))

        outf.write(out.decode('utf8'))

    def _spawn_gpg(self, argv, stdin='', env_override={}):
        env = os.environ.copy()
        env['TZ'] = 'UTC'
        env.update(env_override)

        try:
            p = subprocess.Popen(argv,
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 env=env)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
            raise gemato.exceptions.OpenPGPNoImplementation()

        out, err = p.communicate(stdin)
        return (p.wait(), out, err)


class OpenPGPEnvironment(OpenPGPSystemEnvironment):
    """
    An isolated environment for OpenPGP routines. Used to get reliable
    verification results independently of user configuration.

    Remember to close() in order to clean up the temporary directory,
    or use as a context manager (via 'with').
    """

    __slots__ = ['_home', 'proxy']

    def __init__(self, debug=False, proxy=None):
        super(OpenPGPEnvironment, self).__init__(debug=debug)
        self.proxy = proxy
        self._home = tempfile.mkdtemp(prefix='gemato.')

        with open(os.path.join(self._home, 'dirmngr.conf'), 'w') as f:
            f.write('''# autogenerated by gemato

# honor user's http_proxy setting
honor-http-proxy

# enable debugging, in case we needed it
log-file {debug_file}
debug-level guru
'''.format(debug_file=os.path.join(self._home, 'dirmngr.log')))
        with open(os.path.join(self._home, 'gpg.conf'), 'w') as f:
            f.write('''# autogenerated by gemato

# we are using an isolated keyring, so always trust our keys
trust-model always
''')
        with open(os.path.join(self._home, 'gpg-agent.conf'), 'w') as f:
            f.write('''# autogenerated by gemato

# avoid any smartcard operations, we are running in isolation
disable-scdaemon

# enable debugging, in case we needed it
log-file {debug_file}
debug-level guru
'''.format(debug_file=os.path.join(self._home, 'gpg-agent.log')))

    def __exit__(self, exc_type, exc_value, exc_cb):
        if self._home is not None:
            self.close()

    def clone(self):
        return OpenPGPEnvironment(debug=self.debug, proxy=self.proxy)

    @staticmethod
    def _rmtree_error_handler(func, path, exc_info):
        # ignore ENOENT -- it probably means a race condition between
        # us and gpg-agent cleaning up after itself
        # also non-empty directory due to races, and EBUSY for NFS:
        # https://bugs.gentoo.org/684172
        if (not isinstance(exc_info[1], OSError)
                or exc_info[1].errno not in (errno.ENOENT,
                                             errno.ENOTEMPTY,
                                             errno.EEXIST,
                                             errno.EBUSY)):
            raise exc_info[1]

    def close(self):
        if self._home is not None:
            ret, sout, serr = self._spawn_gpg(
                [GNUPGCONF, '--kill', 'all'])
            if ret != 0:
                logging.warning('{} --kill failed: {}'
                                .format(GNUPGCONF, serr))
            if not self.debug:
                # we need to loop due to ENOTEMPTY potential
                while os.path.isdir(self._home):
                    shutil.rmtree(self._home,
                                  onerror=self._rmtree_error_handler)
            else:
                logging.debug('GNUPGHOME left for debug purposes: {}'
                              .format(self._home))
            self._home = None

    def import_key(self, keyfile):
        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--import'], keyfile.read())
        if exitst != 0:
            raise gemato.exceptions.OpenPGPKeyImportError(err.decode('utf8'))

    zbase32_translate = bytes.maketrans(
        b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
        b'ybndrfg8ejkmcpqxot1uwisza345h769')

    @classmethod
    def get_wkd_url(cls, email):
        localname, domain = email.encode('utf8').split(b'@', 1)
        b32 = (base64.b32encode(
                hashlib.sha1(localname.lower()).digest())
            .translate(cls.zbase32_translate).decode())
        uenc = urllib.parse.quote(localname)
        ldomain = domain.lower().decode('utf8')
        return (f'https://{ldomain}/.well-known/openpgpkey/hu/'
                f'{b32}?l={uenc}')

    def refresh_keys_wkd(self):
        """
        Attempt to fetch updated keys using WKD.  Returns true if *all*
        keys were successfully found.  Otherwise, returns false.
        """
        if requests is None:
            logging.debug('refresh_keys_wkd(): failing because requests'
                          'module is missing')
            return False

        # list all keys in the keyring
        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--with-colons', '--list-keys'])
        if exitst != 0:
            raise gemato.exceptions.OpenPGPKeyRefreshError(err.decode('utf8'))

        # find keys and UIDs
        addrs = set()
        addrs_key = set()
        keys = set()
        prev_pub = None
        for l in out.splitlines():
            # were we expecting a fingerprint?
            if prev_pub is not None:
                if l.startswith(b'fpr:'):
                    fpr = l.split(b':')[9].decode('ASCII')
                    assert fpr.endswith(prev_pub)
                    logging.debug('refresh_keys_wkd(): fingerprint: {}'
                                  .format(fpr))
                    keys.add(fpr)
                    prev_pub = None
                else:
                    # old GnuPG doesn't give fingerprints by default
                    # (but it doesn't support WKD either)
                    logging.debug('refresh_keys_wkd(): failing due to old gpg')
                    return False
            elif l.startswith(b'pub:'):
                if keys:
                    # every key must have at least one UID
                    if not addrs_key:
                        logging.debug('refresh_keys_wkd(): failing due to no UIDs')
                        return False
                    addrs.update(addrs_key)
                    addrs_key = set()

                # wait for the fingerprint
                prev_pub = l.split(b':')[4].decode('ASCII')
                logging.debug('refresh_keys_wkd(): keyid: {}'
                              .format(prev_pub))
            elif l.startswith(b'uid:'):
                uid = l.split(b':')[9]
                name, addr = email.utils.parseaddr(uid.decode('utf8'))
                if '@' in addr:
                    logging.debug('refresh_keys_wkd(): UID: {}'
                                  .format(addr))
                    addrs_key.add(addr)
                else:
                    logging.debug('refresh_keys_wkd(): ignoring UID without mail: {}'
                                  .format(uid.decode('utf8')))

        # grab the final set (also aborts when there are no keys)
        if not addrs_key:
            logging.debug('refresh_keys_wkd(): failing due to no UIDs')
            return False
        addrs.update(addrs_key)

        data = b''
        proxies = {}
        if self.proxy is not None:
            proxies = {
                'http': self.proxy,
                'https': self.proxy,
            }
        for a in addrs:
            url = self.get_wkd_url(a)
            resp = requests.get(url, proxies=proxies)
            if resp.status_code != 200:
                logging.debug(f'refresh_keys_wkd(): failing due to failed'
                              f'request for {url}: {resp}')
                return False
            data += resp.content

        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--import', '--status-fd', '1'], data)
        if exitst != 0:
            # there's no valid reason for import to fail here
            raise gemato.exceptions.OpenPGPKeyRefreshError(err.decode('utf8'))

        # we need to explicitly ensure all keys were fetched
        for l in out.splitlines():
            if l.startswith(b'[GNUPG:] IMPORT_OK'):
                fpr = l.split(b' ')[3].decode('ASCII')
                logging.debug('refresh_keys_wkd(): import successful for key: {}'
                              .format(fpr))
                if fpr in keys:
                    keys.remove(fpr)
                else:
                    # we need to delete unexpected keys
                    exitst, out, err = self._spawn_gpg(
                        [GNUPG, '--batch', '--delete-keys', fpr])
                    if exitst != 0:
                        raise gemato.exceptions.OpenPGPKeyRefreshError(
                            err.decode('utf8'))
        if keys:
            logging.debug('refresh_keys_wkd(): failing due to non-updated keys: {}'
                          .format(keys))
            return False

        return True

    def refresh_keys_keyserver(self, keyserver=None):
        ks_args = []
        if keyserver is not None:
            ks_args = ['--keyserver', keyserver]

        exitst, out, err = self._spawn_gpg(
            [GNUPG, '--batch', '--refresh-keys'] + ks_args)
        if exitst != 0:
            raise gemato.exceptions.OpenPGPKeyRefreshError(err.decode('utf8'))

    def refresh_keys(self, allow_wkd=True, keyserver=None):
        logging.debug('refresh_keys(allow_wkd={}, keyserver={}) called'
                      .format(allow_wkd, keyserver))

        if allow_wkd and self.refresh_keys_wkd():
            return

        self.refresh_keys_keyserver(keyserver=keyserver)

    @property
    def home(self):
        assert self._home is not None
        return self._home

    def _spawn_gpg(self, options, stdin=''):
        env_override = {'GNUPGHOME': self.home}
        if self.proxy is not None:
            env_override['http_proxy'] = self.proxy
        return (super(OpenPGPEnvironment, self)
                ._spawn_gpg(options, stdin, env_override))
