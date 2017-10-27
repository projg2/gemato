# gemato: exceptions
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

class UnsupportedCompression(Exception):
    def __init__(self, suffix):
        super(UnsupportedCompression, self).__init__(
                'Unsupported compression suffix: {}'.format(suffix))


class UnsupportedHash(Exception):
    def __init__(self, hash_name):
        super(UnsupportedHash, self).__init__(
                'Unsupported hash name: {}'.format(hash_name))


class ManifestSyntaxError(Exception):
    def __init__(self, message):
        super(ManifestSyntaxError, self).__init__(message)


class ManifestIncompatibleEntry(Exception):
    def __init__(self, e1, e2, diff):
        msg = "Incompatible Manifest entries for {}".format(e1.path)
        for k, d1, d2 in diff:
            msg += "\n  {}: e1: {}, e2: {}".format(k, e1, e2)
        super(ManifestIncompatibleEntry, self).__init__(msg)
        self.e1 = e1
        self.e2 = e2
        self.diff = diff


class ManifestMismatch(Exception):
    """
    An exception raised for verification failure.
    """

    def __init__(self, path, entry, diff):
        msg = "Manifest mismatch for {}".format(path)
        for k, exp, got in diff:
            msg += "\n  {}: expected: {}, have: {}".format(k, exp, got)
        super(ManifestMismatch, self).__init__(msg)
        self.path = path
        self.entry = entry
        self.diff = diff


class ManifestCrossDevice(Exception):
    """
    An exception caused by attempting to cross filesystem boundaries.
    """

    def __init__(self, path):
        self.path = path
        super(ManifestCrossDevice, self).__init__(
            "Path {} crosses filesystem boundaries, it must be IGNORE-d explicitly"
            .format(path))


class ManifestUnsignedData(Exception):
    """
    An exception caused by a Manifest file containing non-whitespace
    outside the OpenPGP-signed part.
    """

    def __init__(self):
        super(ManifestUnsignedData, self).__init__(
                "Unsigned data found in an OpenPGP signed Manifest")


class OpenPGPVerificationFailure(Exception):
    """
    An exception raised when OpenPGP verification fails.
    """

    def __init__(self, output):
        super(OpenPGPVerificationFailure, self).__init__(
                "OpenPGP verification failed:\n{}".format(output))


class OpenPGPNoImplementation(Exception):
    """
    An exception raised when no supported OpenPGP implementation
    is available.
    """

    def __init__(self):
        super(OpenPGPNoImplementation, self).__init__(
                "No supported OpenPGP implementation found (install gnupg)")


class ManifestInvalidPath(Exception):
    """
    An exception raised when an invalid path tries to be added to
    Manifest.
    """

    def __init__(self, path, detail):
        super(ManifestInvalidPath, self).__init__(
                "Attempting to add invalid path {} to Manifest: {} must not be {}"
                .format(path, detail[0], detail[1]))
