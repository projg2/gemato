# gemato: exceptions
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

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
