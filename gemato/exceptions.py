# gemato: exceptions
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

class GematoException(Exception):
    """
    Base class for gemato exceptions. Makes it easier to catch them all.
    """
    pass


class UnsupportedCompression(GematoException):
    __slots__ = ['suffix']

    def __init__(self, suffix):
        super().__init__(suffix)
        self.suffix = suffix

    def __str__(self):
        return f'Unsupported compression suffix: {self.suffix}'


class UnsupportedHash(GematoException):
    __slots__ = ['hash_name']

    def __init__(self, hash_name):
        super().__init__(hash_name)
        self.hash_name = hash_name

    def __str__(self):
        return f'Unsupported hash name: {self.hash_name}'


class ManifestSyntaxError(GematoException):
    def __init__(self, message):
        super().__init__(message)


class ManifestIncompatibleEntry(GematoException):
    __slots__ = ['e1', 'e2', 'diff']

    def __init__(self, e1, e2, diff):
        super().__init__(e1, e2, diff)
        self.e1 = e1
        self.e2 = e2
        self.diff = diff

    def __str__(self):
        msg = f'Incompatible Manifest entries for {self.e1.path}'
        for k, d1, d2 in self.diff:
            msg += f'\n  {k}: e1: {d1}, e2: {d2}'
        return msg


class ManifestMismatch(GematoException):
    """
    An exception raised for verification failure.
    """

    __slots__ = ['path', 'entry', 'diff']

    def __init__(self, path, entry, diff):
        super().__init__(path, entry, diff)
        self.path = path
        self.entry = entry
        self.diff = diff

    def __str__(self):
        msg = f'Manifest mismatch for {self.path}'
        for k, exp, got in self.diff:
            msg += f'\n  {k}: expected: {exp}, have: {got}'
        return msg


class ManifestCrossDevice(GematoException):
    """
    An exception caused by attempting to cross filesystem boundaries.
    """

    __slots__ = ['path']

    def __init__(self, path):
        super().__init__(path)
        self.path = path

    def __str__(self):
        return (f'Path {self.path} crosses filesystem boundaries, it '
                f'must be IGNORE-d explicitly')


class ManifestSymlinkLoop(GematoException):
    """
    An exception caused by hitting a symlink loop (symlink to itself
    or a parent directory).
    """

    __slots__ = ['path']

    def __init__(self, path):
        super().__init__(path)
        self.path = path

    def __str__(self):
        return (f'Path {self.path} is a symlink to one of its parent '
                f'directories, it must be IGNORE-d explicitly')


class ManifestUnsignedData(GematoException):
    """
    An exception caused by a Manifest file containing non-whitespace
    outside the OpenPGP-signed part.
    """

    def __str__(self):
        return 'Unsigned data found in an OpenPGP signed Manifest'


class OpenPGPRuntimeError(GematoException):
    """
    Base exception class for OpenPGP runtime errors.
    """

    __slots__ = ['output']

    def __init__(self, output):
        super().__init__(output)
        self.output = output


class OpenPGPKeyImportError(OpenPGPRuntimeError):
    """
    An exception raised when key import fails.
    """

    def __str__(self):
        return f'OpenPGP key import failed:\n{self.output}'


class OpenPGPKeyListingError(OpenPGPRuntimeError):
    """
    An exception raised when key listing fails.
    """

    def __str__(self):
        return f'OpenPGP key listing failed:\n{self.output}'


class OpenPGPKeyRefreshError(OpenPGPRuntimeError):
    """
    An exception raised when keyring refresh (update) fails.
    """

    def __str__(self):
        return f'OpenPGP keyring refresh failed:\n{self.output}'


class OpenPGPVerificationFailure(OpenPGPRuntimeError):
    """
    An exception raised when OpenPGP verification fails.
    """

    def __str__(self):
        return f'OpenPGP verification failed:\n{self.output}'


class OpenPGPExpiredKeyFailure(OpenPGPRuntimeError):
    """
    OpenPGP verification rejected because of expired key.
    """

    def __str__(self):
        return (f'OpenPGP signature rejected because of expired key:\n'
                f'{self.output}')


class OpenPGPRevokedKeyFailure(OpenPGPRuntimeError):
    """
    OpenPGP verification rejected because of revoked key.
    """

    def __str__(self):
        return (f'OpenPGP signature rejected because of revoked key:\n'
                f'{self.output}')


class OpenPGPUnknownSigFailure(OpenPGPRuntimeError):
    """
    OpenPGP verification rejected for unknown reason (i.e. unrecognized
    GPG status).
    """

    def __str__(self):
        return (f'OpenPGP signature rejected for unknown reason:\n'
                f'{self.output}')


class OpenPGPUntrustedSigFailure(OpenPGPRuntimeError):
    """OpenPGP verification failed due to untrusted signing key"""

    def __str__(self):
        return (f'Good OpenPGP signature made using untrusted key:\n'
                f'{self.output}')


class OpenPGPSigningFailure(OpenPGPRuntimeError):
    """
    An exception raised when OpenPGP signing fails.
    """

    def __str__(self):
        return f'OpenPGP signing failed:\n{self.output}'


class OpenPGPNoImplementation(GematoException):
    """
    An exception raised when no supported OpenPGP implementation
    is available.
    """

    def __str__(self):
        return ('No supported OpenPGP implementation found (install '
                'gnupg)')


class ManifestInvalidPath(GematoException):
    """
    An exception raised when an invalid path tries to be added to
    Manifest.
    """

    __slots__ = ['path', 'detail']

    def __init__(self, path, detail):
        super().__init__(path, detail)
        self.path = path
        self.detail = detail

    def __str__(self):
        return (f'Attempting to add invalid path {self.path} to '
                f'Manifest: {self.detail[0]} must not be '
                f'{self.detail[1]}')


class ManifestInvalidFilename(GematoException):
    """
    An exception raised when an entry for invalid filename is created.
    """

    __slots__ = ['filename', 'pos']

    def __init__(self, filename, pos):
        super().__init__(filename, pos)
        self.filename = filename
        self.pos = pos

    def __str__(self):
        return (f'Attempting to add invalid filename {self.filename!r} '
                f'to Manifest: disallowed character '
                f'U+{ord(self.filename[self.pos]):04X} at position '
                f'{self.pos}')
