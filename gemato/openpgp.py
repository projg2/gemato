# gemato: OpenPGP verification support
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import errno
import shutil
import subprocess
import tempfile

import gemato.exceptions


def _spawn_gpg(options, home, stdin):
    env = None
    if home is not None:
        env={'HOME': home}

    try:
        p = subprocess.Popen(['gpg', '--batch'] + options,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env)
    except OSError as e:
        if e.errno == errno.ENOENT:
            raise gemato.exceptions.OpenPGPNoImplementation()
        else:
            raise

    out, err = p.communicate(stdin)
    return (p.wait(), out, err)


class OpenPGPEnvironment(object):
    """
    An isolated environment for OpenPGP routines. Used to get reliable
    verification results independently of user configuration.

    Remember to close() in order to clean up the temporary directory,
    or use as a context manager (via 'with').
    """

    __slots__ = ['_home']

    def __init__(self):
        self._home = tempfile.mkdtemp()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_cb):
        if self._home is not None:
            self.close()

    def close(self):
        if self._home is not None:
            shutil.rmtree(self._home)
            self._home = None

    def import_key(self, keyfile):
        """
        Import a public key from open file @keyfile. The file should
        be open for reading in binary mode, and oriented
        at the beginning.
        """

        exitst, out, err = _spawn_gpg(['--import'], self.home,
                keyfile.read())
        if exitst != 0:
            raise RuntimeError('Unable to import key: {}'.format(err.decode('utf8')))

    def verify_file(self, f):
        """
        A convenience wrapper for verify_file(), using this environment.
        """

        verify_file(f, env=self)

    def clear_sign_file(self, f, outf, keyid=None):
        """
        A convenience wrapper for clear_sign_file(), using this
        environment.
        """

        clear_sign_file(f, outf, keyid=keyid, env=self)

    @property
    def home(self):
        if self._home is None:
            raise RuntimeError(
                    'OpenPGPEnvironment has been closed')
        return self._home


def verify_file(f, env=None):
    """
    Perform an OpenPGP verification of Manifest data in open file @f.
    The file should be open in text mode and set at the beginning
    (or start of signed part). Raises an exception if the verification
    fails.

    Note that this function does not distinguish whether the key
    is trusted, and is subject to user configuration. To get reliable
    results, prepare a dedicated OpenPGPEnvironment and pass it as @env.
    """

    exitst, out, err = _spawn_gpg(['--verify'],
            env.home if env is not None else None,
            f.read().encode('utf8'))
    if exitst != 0:
        raise gemato.exceptions.OpenPGPVerificationFailure(err.decode('utf8'))


def clear_sign_file(f, outf, keyid=None, env=None):
    """
    Create an OpenPGP cleartext signed message containing the data
    from open file @f, and writing it into open file @outf.
    Both files should be open in text mode and set at the appropriate
    position. Raises an exception if signing fails.

    Pass @keyid to specify the key to use. If not specified,
    the implementation will use the default key. Pass @env to use
    a dedicated OpenPGPEnvironment.
    """

    args = []
    if keyid is not None:
        args += ['--local-user', keyid]
    exitst, out, err = _spawn_gpg(['--clearsign'] + args,
            env.home if env is not None else None,
            f.read().encode('utf8'))
    if exitst != 0:
        raise gemato.exceptions.OpenPGPSigningFailure(err.decode('utf8'))

    outf.write(out.decode('utf8'))
