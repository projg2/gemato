# gemato: Manifest file objects
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import os.path


class ManifestSyntaxError(Exception):
    def __init__(self, message):
        super(ManifestSyntaxError, self).__init__(message)


class ManifestEntryTIMESTAMP(object):
    """
    ISO-8601 timestamp.
    """

    def __init__(self, ts):
        assert isinstance(ts, datetime.datetime)
        self.ts = ts

    @classmethod
    def from_list(cls, l):
        if len(l) != 1:
            raise ManifestSyntaxError(
                    'TIMESTAMP line: expects 1 value, got: {}'.format(l))
        try:
            ts = datetime.datetime.strptime(l[0], '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            raise ManifestSyntaxError(
                    'TIMESTAMP line: expected ISO8601 timestamp, got: {}'.format(l[0]))
        return cls(ts)


class ManifestPathEntry(object):
    """
    Base class for entries using a path.
    """

    def __init__(self, path):
        assert path[0] != '/'
        self.path = path

    @staticmethod
    def process_path(tag, l):
        if len(l) != 1:
            raise ManifestSyntaxError(
                    '{} line: expects 1 value, got: {}'.format(tag, l))
        if not l[0] or l[0][0] == '/':
            raise ManifestSyntaxError(
                    '{} line: expected relative path, got: {}'.format(tag, l[0]))
        return l[0]


class ManifestEntryIGNORE(ManifestPathEntry):
    """
    Ignored path.
    """

    @classmethod
    def from_list(cls, l):
        return cls(cls.process_path('IGNORE', l))


class ManifestEntryOPTIONAL(ManifestPathEntry):
    """
    Optional path.
    """

    def __init__(self, path):
        super(ManifestEntryOPTIONAL, self).__init__(path)
        self.size = None
        self.checksums = {}

    @classmethod
    def from_list(cls, l):
        return cls(cls.process_path('OPTIONAL', l))


class ManifestFileEntry(ManifestPathEntry):
    """
    Base class for entries providing checksums for a path.
    """

    def __init__(self, path, size, checksums):
        super(ManifestFileEntry, self).__init__(path)
        self.size = size
        self.checksums = checksums

    @staticmethod
    def process_checksums(tag, l):
        if len(l) < 2:
            raise ManifestSyntaxError(
                    '{} line: expects at least 2 values, got: {}'.format(tag, l))

        try:
            size = int(l[1])
            if size < 0:
                raise ValueError()
        except ValueError:
            raise ManifestSyntaxError(
                    '{} line: size must be a non-negative integer, got: {}'.format(tag, l[1]))

        checksums = {}
        it = iter(l[2:])
        while True:
            try:
                ckname = next(it)
            except StopIteration:
                break
            try:
                ckval = next(it)
            except StopIteration:
                raise ManifestSyntaxError(
                        '{} line: checksum {} has no value'.format(tag, ckname))
            checksums[ckname] = ckval

        return size, checksums


class ManifestEntryMANIFEST(ManifestFileEntry):
    """
    Sub-Manifest file reference.
    """

    @classmethod
    def from_list(cls, l):
        path = cls.process_path('MANIFEST', l[:1])
        size, checksums = cls.process_checksums('MANIFEST', l)
        return cls(path, size, checksums)


class ManifestEntryDATA(ManifestFileEntry):
    """
    Regular file reference.
    """

    @classmethod
    def from_list(cls, l):
        path = cls.process_path('DATA', l[:1])
        size, checksums = cls.process_checksums('DATA', l)
        return cls(path, size, checksums)


class ManifestEntryMISC(ManifestFileEntry):
    """
    Non-obligatory file reference.
    """

    @classmethod
    def from_list(cls, l):
        path = cls.process_path('MISC', l[:1])
        size, checksums = cls.process_checksums('MISC', l)
        return cls(path, size, checksums)


class ManifestEntryDIST(ManifestFileEntry):
    """
    Distfile reference.
    """

    @classmethod
    def from_list(cls, l):
        path = cls.process_path('DIST', l[:1])
        if '/' in path:
            raise ManifestSyntaxError(
                    'DIST line: file name expected, got directory path: {}'.format(path))
        size, checksums = cls.process_checksums('DIST', l)
        return cls(path, size, checksums)


class ManifestEntryEBUILD(ManifestFileEntry):
    """
    Deprecated ebuild file reference (equivalent to DATA).
    """

    @classmethod
    def from_list(cls, l):
        path = cls.process_path('EBUILD', l[:1])
        size, checksums = cls.process_checksums('EBUILD', l)
        return cls(path, size, checksums)


class ManifestEntryAUX(ManifestFileEntry):
    """
    Deprecated AUX file reference (DATA with 'files/' prepended).
    """

    def __init__(self, aux_path, size, checksums):
        self.aux_path = aux_path
        super(ManifestEntryAUX, self).__init__(
                os.path.join('files', aux_path), size, checksums)

    @classmethod
    def from_list(cls, l):
        path = cls.process_path('AUX', l[:1])
        size, checksums = cls.process_checksums('AUX', l)
        return cls(path, size, checksums)


MANIFEST_TAG_MAPPING = {
    'TIMESTAMP': ManifestEntryTIMESTAMP,
    'MANIFEST': ManifestEntryMANIFEST,
    'IGNORE': ManifestEntryIGNORE,
    'DATA': ManifestEntryDATA,
    'MISC': ManifestEntryMISC,
    'OPTIONAL': ManifestEntryOPTIONAL,
    'DIST': ManifestEntryDIST,
    'EBUILD': ManifestEntryEBUILD,
    'AUX': ManifestEntryAUX,
}


class ManifestFile(object):
    """
    A class encapsulating a single Manifest file. It supports reading
    from files and writing to them.
    """

    def __init__(self, f=None):
        """
        Create a new instance. If @f is provided, reads the entries
        from open Manifest file @f (see load()).
        """
        if f is not None:
            self.load(f)

    def load(self, f):
        """
        Load data from file @f. The file should be open for reading
        in text mode, and oriented at the beginning.
        """

        for l in f:
            sl = l.strip().split()
            # skip empty lines
            if not sl:
                continue
            tag = sl.pop(0)
            MANIFEST_TAG_MAPPING[tag].from_list(sl)


    def dump(self, f):
        """
        Dump data into file @f. The file should be open for writing
        in text mode, and truncated to zero length.
        """
        pass
