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

    tag = 'TIMESTAMP'

    def __init__(self, ts):
        assert isinstance(ts, datetime.datetime)
        self.ts = ts

    @classmethod
    def from_list(cls, l):
        assert l[0] == cls.tag
        if len(l) != 2:
            raise ManifestSyntaxError(
                    '{} line: expects 1 value, got: {}'.format(l[0], l[1:]))
        try:
            ts = datetime.datetime.strptime(l[1], '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            raise ManifestSyntaxError(
                    '{} line: expected ISO8601 timestamp, got: {}'.format(l[0], l[1:]))
        return cls(ts)

    def to_list(self):
        return (self.tag, self.ts.strftime('%Y-%m-%dT%H:%M:%SZ'))


class ManifestPathEntry(object):
    """
    Base class for entries using a path.
    """

    def __init__(self, path):
        assert path[0] != '/'
        self.path = path

    @staticmethod
    def process_path(l):
        if len(l) != 2:
            raise ManifestSyntaxError(
                    '{} line: expects 1 value, got: {}'.format(l[0], l[1:]))
        if not l[1] or l[1][0] == '/':
            raise ManifestSyntaxError(
                    '{} line: expected relative path, got: {}'.format(l[0], l[1:]))
        return l[1]


class ManifestEntryIGNORE(ManifestPathEntry):
    """
    Ignored path.
    """

    tag = 'IGNORE'

    @classmethod
    def from_list(cls, l):
        assert l[0] == cls.tag
        return cls(cls.process_path(l))

    def to_list(self):
        return (self.tag, self.path)


class ManifestEntryOPTIONAL(ManifestPathEntry):
    """
    Optional path.
    """

    tag = 'OPTIONAL'

    def __init__(self, path):
        super(ManifestEntryOPTIONAL, self).__init__(path)
        self.size = None
        self.checksums = {}

    @classmethod
    def from_list(cls, l):
        assert l[0] == cls.tag
        return cls(cls.process_path(l))

    def to_list(self):
        return (self.tag, self.path)


class ManifestFileEntry(ManifestPathEntry):
    """
    Base class for entries providing checksums for a path.
    """

    def __init__(self, path, size, checksums):
        super(ManifestFileEntry, self).__init__(path)
        self.size = size
        self.checksums = checksums

    @staticmethod
    def process_checksums(l):
        if len(l) < 3:
            raise ManifestSyntaxError(
                    '{} line: expects at least 2 values, got: {}'.format(l[0], l[1:]))

        try:
            size = int(l[2])
            if size < 0:
                raise ValueError()
        except ValueError:
            raise ManifestSyntaxError(
                    '{} line: size must be a non-negative integer, got: {}'.format(l[0], l[2]))

        checksums = {}
        it = iter(l[3:])
        while True:
            try:
                ckname = next(it)
            except StopIteration:
                break
            try:
                ckval = next(it)
            except StopIteration:
                raise ManifestSyntaxError(
                        '{} line: checksum {} has no value'.format(l[0], ckname))
            checksums[ckname] = ckval

        return size, checksums

    def to_list(self, tag):
        ret = [tag, self.path, str(self.size)]
        for k, v in sorted(self.checksums.items()):
            ret += [k, v]
        return ret


class ManifestEntryMANIFEST(ManifestFileEntry):
    """
    Sub-Manifest file reference.
    """

    tag = 'MANIFEST'

    @classmethod
    def from_list(cls, l):
        assert l[0] == cls.tag
        path = cls.process_path(l[:2])
        size, checksums = cls.process_checksums(l)
        return cls(path, size, checksums)

    def to_list(self):
        return super(ManifestEntryMANIFEST, self).to_list(self.tag)


class ManifestEntryDATA(ManifestFileEntry):
    """
    Regular file reference.
    """

    tag = 'DATA'

    @classmethod
    def from_list(cls, l):
        assert l[0] == cls.tag
        path = cls.process_path(l[:2])
        size, checksums = cls.process_checksums(l)
        return cls(path, size, checksums)

    def to_list(self):
        return super(ManifestEntryDATA, self).to_list(self.tag)


class ManifestEntryMISC(ManifestFileEntry):
    """
    Non-obligatory file reference.
    """

    tag = 'MISC'

    @classmethod
    def from_list(cls, l):
        assert l[0] == cls.tag
        path = cls.process_path(l[:2])
        size, checksums = cls.process_checksums(l)
        return cls(path, size, checksums)

    def to_list(self):
        return super(ManifestEntryMISC, self).to_list(self.tag)


class ManifestEntryDIST(ManifestFileEntry):
    """
    Distfile reference.
    """

    tag = 'DIST'

    @classmethod
    def from_list(cls, l):
        path = cls.process_path(l[:2])
        if '/' in path:
            raise ManifestSyntaxError(
                    'DIST line: file name expected, got directory path: {}'.format(path))
        size, checksums = cls.process_checksums(l)
        return cls(path, size, checksums)

    def to_list(self):
        return super(ManifestEntryDIST, self).to_list(self.tag)


class ManifestEntryEBUILD(ManifestFileEntry):
    """
    Deprecated ebuild file reference (equivalent to DATA).
    """

    tag = 'EBUILD'

    @classmethod
    def from_list(cls, l):
        assert l[0] == cls.tag
        path = cls.process_path(l[:2])
        size, checksums = cls.process_checksums(l)
        return cls(path, size, checksums)

    def to_list(self):
        return super(ManifestEntryEBUILD, self).to_list(self.tag)


class ManifestEntryAUX(ManifestFileEntry):
    """
    Deprecated AUX file reference (DATA with 'files/' prepended).
    """

    tag = 'AUX'

    def __init__(self, aux_path, size, checksums):
        self.aux_path = aux_path
        super(ManifestEntryAUX, self).__init__(
                os.path.join('files', aux_path), size, checksums)

    @classmethod
    def from_list(cls, l):
        assert l[0] == cls.tag
        path = cls.process_path(l[:2])
        size, checksums = cls.process_checksums(l)
        return cls(path, size, checksums)

    def to_list(self):
        ret = super(ManifestEntryAUX, self).to_list(self.tag)
        assert ret[1].startswith('files/')
        ret[1] = ret[1][6:]
        return ret


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
        self.entries = []

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
            tag = sl[0]
            self.entries.append(MANIFEST_TAG_MAPPING[tag].from_list(sl))

    def dump(self, f):
        """
        Dump data into file @f. The file should be open for writing
        in text mode, and truncated to zero length.
        """
        
        for e in self.entries:
            f.write(u' '.join(e.to_list()) + '\n')

    def find_timestamp(self):
        """
        Find a timestamp entry and return it. Returns None if there
        is no timestamp.
        """

        for e in self.entries:
            if isinstance(e, ManifestEntryTIMESTAMP):
                return e
        return None

    def find_path_entry(self, path):
        """
        Find a matching entry for path @path and return it. Returns
        None when no path matches. DIST entries are not included.
        """

        for e in self.entries:
            if isinstance(e, ManifestEntryIGNORE):
                # ignore matches recursively, so we process it separately
                # py<3.5 does not have os.path.commonpath()
                if (path + '/').startswith(e.path + '/'):
                    return e
            elif isinstance(e, ManifestEntryDIST):
                # distfiles are not local files, so skip them
                pass
            elif isinstance(e, ManifestPathEntry):
                if e.path == path:
                    return e
        return None

    def find_dist_entry(self, filename):
        """
        Find a matching entry for distfile @filename and return it.
        Returns None when no DIST entry matches.
        """

        for e in self.entries:
            if isinstance(e, ManifestEntryDIST):
                if e.path == filename:
                    return e
        return None

    def find_manifests_for_path(self, path):
        """
        Find all MANIFEST entries that could affect the path @path
        and return an iterator over them. Yield an empty list when
        there are no matching MANIFEST entries.
        """

        for e in self.entries:
            if isinstance(e, ManifestEntryMANIFEST):
                mdir = os.path.dirname(e.path)
                if path.startswith(mdir + '/'):
                    yield e


MANIFEST_HASH_MAPPING = {
    'MD5': 'md5',
    'SHA1': 'sha1',
    'SHA256': 'sha256',
    'SHA512': 'sha512',
    'RMD160': 'ripemd160',
    'WHIRLPOOL': 'whirlpool',
    'BLAKE2B': 'blake2b',
    'BLAKE2S': 'blake2s',
    'SHA3_256': 'sha3_256',
    'SHA3_512': 'sha3_512',
}


def manifest_hashes_to_hashlib(hashes):
    """
    Return the hashlib hash names corresponding to the Manifest names
    in @hashes. Returns an iterable.
    """
    for h in hashes:
        yield MANIFEST_HASH_MAPPING[h]
