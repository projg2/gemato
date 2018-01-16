# gemato: exceptions
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

class UnsupportedCompression(Exception):
    __slots__ = ['suffix']

    def __init__(self, suffix):
        super(UnsupportedCompression, self).__init__(suffix)
        self.suffix = suffix

    def __str__(self):
        return 'Unsupported compression suffix: {}'.format(self.suffix)


class UnsupportedHash(Exception):
    __slots__ = ['hash_name']

    def __init__(self, hash_name):
        super(UnsupportedHash, self).__init__(hash_name)
        self.hash_name = hash_name

    def __str__(self):
        return 'Unsupported hash name: {}'.format(self.hash_name)


class ManifestSyntaxError(Exception):
    def __init__(self, message):
        super(ManifestSyntaxError, self).__init__(message)


class ManifestIncompatibleEntry(Exception):
    __slots__ = ['e1', 'e2', 'diff']

    def __init__(self, e1, e2, diff):
        super(ManifestIncompatibleEntry, self).__init__(e1, e2, diff)
        self.e1 = e1
        self.e2 = e2
        self.diff = diff

    def __str__(self):
        msg = "Incompatible Manifest entries for {}".format(self.e1.path)
        for k, d1, d2 in self.diff:
            msg += "\n  {}: e1: {}, e2: {}".format(k, d1, d2)
        return msg


class ManifestMismatch(Exception):
    """
    An exception raised for verification failure.
    """

    __slots__ = ['path', 'entry', 'diff']

    def __init__(self, path, entry, diff):
        super(ManifestMismatch, self).__init__(path, entry, diff)
        self.path = path
        self.entry = entry
        self.diff = diff

    def __str__(self):
        msg = "Manifest mismatch for {}".format(self.path)
        for k, exp, got in self.diff:
            msg += "\n  {}: expected: {}, have: {}".format(k, exp, got)
        return msg


class ManifestCrossDevice(Exception):
    """
    An exception caused by attempting to cross filesystem boundaries.
    """

    __slots__ = ['path']

    def __init__(self, path):
        super(ManifestCrossDevice, self).__init__(path)
        self.path = path

    def __str__(self):
        return ("Path {} crosses filesystem boundaries, it must be IGNORE-d explicitly"
            .format(self.path))


class ManifestUnsignedData(Exception):
    """
    An exception caused by a Manifest file containing non-whitespace
    outside the OpenPGP-signed part.
    """

    def __str__(self):
        return "Unsigned data found in an OpenPGP signed Manifest"


class OpenPGPVerificationFailure(Exception):
    """
    An exception raised when OpenPGP verification fails.
    """

    __slots__ = ['output']

    def __init__(self, output):
        super(OpenPGPVerificationFailure, self).__init__(output)
        self.output = output

    def __str__(self):
        return "OpenPGP verification failed:\n{}".format(self.output)


class OpenPGPExpiredKeyFailure(OpenPGPVerificationFailure):
    """
    OpenPGP verification rejected because of expired key.
    """

    def __str__(self):
        return "OpenPGP signature rejected because of expired key:\n{}".format(self.output)


class OpenPGPRevokedKeyFailure(OpenPGPVerificationFailure):
    """
    OpenPGP verification rejected because of revoked key.
    """

    def __str__(self):
        return "OpenPGP signature rejected because of revoked key:\n{}".format(self.output)


class OpenPGPUnknownSigFailure(OpenPGPVerificationFailure):
    """
    OpenPGP verification rejected for unknown reason (i.e. unrecognized
    GPG status).
    """

    def __str__(self):
        return "OpenPGP signature rejected for unknown reason:\n{}".format(self.output)


class OpenPGPSigningFailure(Exception):
    """
    An exception raised when OpenPGP signing fails.
    """

    __slots__ = ['output']

    def __init__(self, output):
        super(OpenPGPSigningFailure, self).__init__(output)
        self.output = output

    def __str__(self):
        return "OpenPGP signing failed:\n{}".format(self.output)


class OpenPGPNoImplementation(Exception):
    """
    An exception raised when no supported OpenPGP implementation
    is available.
    """

    def __str__(self):
        return "No supported OpenPGP implementation found (install gnupg)"


class ManifestInvalidPath(Exception):
    """
    An exception raised when an invalid path tries to be added to
    Manifest.
    """

    __slots__ = ['path', 'detail']

    def __init__(self, path, detail):
        super(ManifestInvalidPath, self).__init__(path, detail)
        self.path = path
        self.detail = detail

    def __str__(self):
        return ("Attempting to add invalid path {} to Manifest: {} must not be {}"
                .format(self.path, self.detail[0], self.detail[1]))


class ManifestInvalidFilename(Exception):
    """
    An exception raised when an entry for invalid filename is created.
    """

    __slots__ = ['filename', 'pos']

    def __init__(self, filename, pos):
        super(ManifestInvalidFilename, self).__init__(filename, pos)
        self.filename = filename
        self.pos = pos

    def __str__(self):
        return ("Attempting to add invalid filename {!r} to Manifest: disallowed character U+{:04X} at position {}"
                .format(self.filename, ord(self.filename[self.pos]), self.pos))
