# gemato: Manifest file objects
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import io
import os.path

import gemato.exceptions
import gemato.openpgp
import gemato.util


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
            raise gemato.exceptions.ManifestSyntaxError(
                    '{} line: expects 1 value, got: {}'.format(l[0], l[1:]))
        try:
            ts = datetime.datetime.strptime(l[1], '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            raise gemato.exceptions.ManifestSyntaxError(
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
            raise gemato.exceptions.ManifestSyntaxError(
                    '{} line: expects 1 value, got: {}'.format(l[0], l[1:]))
        if not l[1] or l[1][0] == '/':
            raise gemato.exceptions.ManifestSyntaxError(
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
            raise gemato.exceptions.ManifestSyntaxError(
                    '{} line: expects at least 2 values, got: {}'.format(l[0], l[1:]))

        try:
            size = int(l[2])
            if size < 0:
                raise ValueError()
        except ValueError:
            raise gemato.exceptions.ManifestSyntaxError(
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
                raise gemato.exceptions.ManifestSyntaxError(
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
            raise gemato.exceptions.ManifestSyntaxError(
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
        assert gemato.util.path_inside_dir(ret[1], 'files')
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


class ManifestState(object):
    """
    FSM constants for loading Manifest.
    """

    DATA = 0
    SIGNED_PREAMBLE = 1
    SIGNED_DATA = 2
    SIGNATURE = 3
    POST_SIGNED_DATA = 4


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
        self.openpgp_signed = None
        if f is not None:
            self.load(f)

    def load(self, f, verify_openpgp=True, openpgp_env=None):
        """
        Load data from file @f. The file should be open for reading
        in text mode, and oriented at the beginning.

        If @verify_openpgp is True and the Manifest contains an OpenPGP
        signature, the signature will be verified. Provide @openpgp_env
        to perform the verification in specific environment.

        If the verification succeeds, the openpgp_signed property will
        be set to True. If it fails or OpenPGP is not available,
        an exception will be raised. If the exception is caught,
        the caller can continue using the ManifestFile instance
        -- it will be loaded completely.
        """

        self.entries = []
        self.openpgp_signed = False
        state = ManifestState.DATA
        openpgp_data = ''

        for l in f:
            if state == ManifestState.DATA:
                if l == '-----BEGIN PGP SIGNED MESSAGE-----\n':
                    if self.entries:
                        raise gemato.exceptions.ManifestUnsignedData()
                    if verify_openpgp:
                        openpgp_data += l
                    state = ManifestState.SIGNED_PREAMBLE
                    continue
            elif state == ManifestState.SIGNED_PREAMBLE:
                if verify_openpgp:
                    openpgp_data += l
                # skip header lines up to the empty line
                if l.strip():
                    continue
                state = ManifestState.SIGNED_DATA
            elif state == ManifestState.SIGNED_DATA:
                if verify_openpgp:
                    openpgp_data += l
                if l == '-----BEGIN PGP SIGNATURE-----\n':
                    state = ManifestState.SIGNATURE
                    continue
                # dash-escaping, RFC 4880 says any line can suffer from it
                if l.startswith('- '):
                    l = l[2:]
            elif state == ManifestState.SIGNATURE:
                if verify_openpgp:
                    openpgp_data += l
                if l == '-----END PGP SIGNATURE-----\n':
                    state = ManifestState.POST_SIGNED_DATA
                    continue

            if l.startswith('-----') and l.rstrip().endswith('-----'):
                raise gemato.exceptions.ManifestSyntaxError(
                        "Unexpected OpenPGP header: {}".format(l))
            if state in (ManifestState.SIGNED_PREAMBLE, ManifestState.SIGNATURE):
                continue

            sl = l.strip().split()
            # skip empty lines
            if not sl:
                continue
            if state == ManifestState.POST_SIGNED_DATA:
                raise gemato.exceptions.ManifestUnsignedData()
            tag = sl[0]
            self.entries.append(MANIFEST_TAG_MAPPING[tag].from_list(sl))

        if state == ManifestState.SIGNED_PREAMBLE:
            raise gemato.exceptions.ManifestSyntaxError(
                    "Manifest terminated early, in OpenPGP headers")
        elif state == ManifestState.SIGNED_DATA:
            raise gemato.exceptions.ManifestSyntaxError(
                    "Manifest terminated early, before signature")
        elif state == ManifestState.SIGNATURE:
            raise gemato.exceptions.ManifestSyntaxError(
                    "Manifest terminated early, inside signature")

        if verify_openpgp and state == ManifestState.POST_SIGNED_DATA:
            with io.BytesIO(openpgp_data.encode('utf8')) as f:
                gemato.openpgp.verify_file(f, env=openpgp_env)
            self.openpgp_signed = True

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
                if gemato.util.path_starts_with(path, e.path):
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
                if gemato.util.path_inside_dir(path, mdir):
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
