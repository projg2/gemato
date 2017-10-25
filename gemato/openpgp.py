# gemato: OpenPGP verification support
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import shutil
import subprocess
import tempfile

import gemato.exceptions


class OpenPGPEnvironment(object):
    """
    An isolated environment for OpenPGP routines. Used to get reliable
    verification results independently of user configuration.

    Remember to close() in order to clean up the temporary directory,
    or use as a context manager (via 'with').
    """

    def __init__(self):
        self._home = tempfile.mkdtemp()

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_value, exc_cb):
        if self._home is not None:
            self.close()
            self._home = None

    def close(self):
        shutil.rmtree(self._home)

    def import_key(self, keyfile):
        """
        Import a public key from open file @keyfile. The file should
        be open for reading in binary mode, and oriented
        at the beginning.
        """

        p = subprocess.Popen(['gpg', '--import', '--batch'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={'HOME': self.home})
        out, err = p.communicate(keyfile.read())

        if p.wait() != 0:
            raise RuntimeError('Unable to import key: {}'.format(err.decode('utf8')))

    def verify_file(self, f):
        """
        A convenience wrapper for verify_file(), using this environment.
        """

        verify_file(f, env=self)

    @property
    def home(self):
        if self._home is None:
            raise RuntimeError(
                    'OpenPGPEnvironment must be used via context manager')
        return self._home


def verify_file(f, env=None):
    """
    Perform an OpenPGP verification of Manifest data in open file @f.
    The file should be open in binary mode and set at the beginning
    (or start of signed part). Raises an exception if the verification
    fails.

    Note that this function does not distinguish whether the key
    is trusted, and is subject to user configuration. To get reliable
    results, prepare a dedicated OpenPGPEnvironment and pass it as @env.
    """

    penv = None
    if env is not None:
        penv = {'HOME': env.home}

    p = subprocess.Popen(['gpg', '--verify', '--batch'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=penv)
    out, err = p.communicate(f.read())

    if p.wait() != 0:
        raise gemato.exceptions.OpenPGPVerificationFailure(err.decode('utf8'))
