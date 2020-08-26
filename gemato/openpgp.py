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
    import pgpy
except ImportError:
    pgpy = None

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
            raise gemato.exceptions.OpenPGPNoImplementation('install gnupg')

        out, err = p.communicate(stdin)
        return (p.wait(), out, err)


class OpenPGPEnvironment(object):
    """
    An isolated environment for OpenPGP routines. Used to get reliable
    verification results independently of user configuration.
    """

    __slots__ = ['debug', 'keyring', 'proxy']

    def __init__(self, debug=False, proxy=None):
        if pgpy is None:
            raise gemato.exceptions.OpenPGPNoImplementation('install PGPy')
        self.debug = debug
        self.keyring = pgpy.PGPKeyring()
        self.proxy = proxy

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_cb):
        pass

    def close(self):
        pass

    def clone(self):
        return OpenPGPEnvironment(debug=self.debug, proxy=self.proxy)

    def import_key(self, keyfile):
        try:
            fprs = self.keyring.load(keyfile.read())
        except ValueError as e:
            raise gemato.exceptions.OpenPGPKeyImportError(
                f'OpenPGP key import failed: {e}')

        for fpr in fprs:
            with self.keyring.key(fpr) as k:
                if k.parent is not None:
                    if not k.parent.verify(k):
                        self.keyring.unload(k)
                for uid in k.userids:
                    if uid.selfsig is None:
                        raise gemato.exceptions.OpenPGPKeyImportError(
                            f'Self-signature on {uid} missing')
                    if not k.verify(uid):
                        raise gemato.exceptions.OpenPGPKeyImportError(
                            f'Self-signature on {uid} does not verify')

    def verify_file(self, f):
        """
        Perform an OpenPGP verification of Manifest data in open file @f.
        The file should be open in text mode and set at the beginning
        (or start of signed part). Raises an exception if the verification
        fails.
        """

        msg = pgpy.PGPMessage.from_blob(f.read())
        assert msg.is_signed
        assert len(msg.signatures) == 1
        assert len(msg.signers) == 1

        signer, = msg.signers
        try:
            with self.keyring.key(signer) as k:
                pk = k
                if k.parent is not None:
                    pk = k.parent
                assert pk.parent is None

                vr = k.verify(msg)
                if not vr:
                    raise gemato.exceptions.OpenPGPVerificationFailure(
                        f'Bad signature made by key {k.fingerprint}')
                now = datetime.datetime.utcnow()
                sig_expire = msg.signatures[0].expires_at
                if sig_expire is not None and sig_expire < now:
                    raise gemato.exceptions.OpenPGPVerificationFailure(
                        f'Signature expired at {msg.signatures[0].expires_at}')
                if k.expires_at is not None and k.expires_at < now:
                    raise gemato.exceptions.OpenPGPExpiredKeyFailure(
                        f'Key {k.fingerprint} expired at {k.expires_at}')
                if pk.expires_at is not None and pk.expires_at < now:
                    raise gemato.exceptions.OpenPGPExpiredKeyFailure(
                        f'Primary key {pk.fingerprint} expired '
                        f'at {k.expires_at}')
                if list(k.revocation_signatures):
                    raise gemato.exceptions.OpenPGPRevokedKeyFailure(
                        f'Key {pk.fingerprint} was revoked')
                if list(pk.revocation_signatures):
                    raise gemato.exceptions.OpenPGPRevokedKeyFailure(
                        f'Primary key {pk.fingerprint} was revoked')
                return OpenPGPSignatureData(
                    k.fingerprint,
                    msg.signatures[0].created,
                    msg.signatures[0].expires_at,
                    pk.fingerprint)
        except KeyError:
            raise gemato.exceptions.OpenPGPVerificationFailure(
                f'Key {signer} not in keyring')

    def clear_sign_file(self, f, outf, keyid=None):
        raise NotImplementedError(
            'clear_sign_file() is not implemented by this OpenPGP provider')

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

        keys = set()
        addrs = set()
        for fpr in self.keyring.fingerprints():
            with self.keyring.key(fpr) as k:
                if not k.userids:
                    logging.debug(f'refresh_keys_wkd(): failing due to no UIDs'
                                  f'on key {fpr}')
                    return False
                for uid in k.userids:
                    addrs.add(uid.email)

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

        new_keys = pgpy.PGPKeyring()
        new_keys.load(data)
        for fpr in self.keyring.fingerprints():
            try:
                with new_keys.key(fpr) as k:
                    self.keyring.load(k)
            except KeyError:
                logging.debug(f'refresh_keys_wkd(): failing due to '
                              f'non-updated keys: {keys}')
                return False

        return True

    def refresh_keys_keyserver(self, keyserver=None):
        import pytest
        pytest.skip('need to reinvent this')
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
