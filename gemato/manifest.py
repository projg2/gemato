# gemato: Manifest file objects
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import datetime
import io
import os.path
import re

from gemato.exceptions import (
    ManifestSyntaxError,
    ManifestUnsignedData,
    )
from gemato.util import (
    path_starts_with,
    path_inside_dir,
    )


class ManifestEntryTIMESTAMP:
    """ISO-8601 timestamp"""

    __slots__ = ['ts']
    tag = 'TIMESTAMP'

    def __init__(self, ts):
        assert isinstance(ts, datetime.datetime)
        self.ts = ts

    @classmethod
    def from_list(cls, data):
        assert data[0] == cls.tag
        if len(data) != 2:
            raise ManifestSyntaxError(
                f'{data[0]} line: expects 1 value, got: {data[1:]}')
        try:
            ts = datetime.datetime.strptime(data[1],
                                            '%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            raise ManifestSyntaxError(
                f'{data[0]} line: expected ISO8601 timestamp, '
                f'got: {data[1:]}')
        return cls(ts)

    def to_list(self):
        return (self.tag, self.ts.strftime('%Y-%m-%dT%H:%M:%SZ'))

    def __eq__(self, other):
        return self.tag == other.tag and self.ts == other.ts

    def __lt__(self, other):
        return (self.tag < other.tag
                or (self.tag == other.tag and self.ts < other.ts))


class ManifestPathEntry:
    """Base class for entries using a path"""

    __slots__ = ['path']
    disallowed_path_re = re.compile(r'[\x00-\x1F\x7F-\x9F\s\\]', re.U)
    escape_seq_re = re.compile(
        r'\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})?')

    def __init__(self, path):
        self.path = path

    @staticmethod
    def decode_char(m):
        val = m.group(1)
        if val is None:
            raise ManifestSyntaxError(
                f'Invalid escape sequence at pos {m.start()} '
                f'of: {m.string}')
        return chr(int(val[1:], base=16))

    @classmethod
    def process_path(cls, data):
        if len(data) != 2:
            raise ManifestSyntaxError(
                f'{data[0]} line: expects 1 value, got: {data[1:]}')
        if not data[1] or data[1][0] == '/':
            raise ManifestSyntaxError(
                f'{data[0]} line: expected relative path, '
                f'got: {data[1:]}')
        return cls.escape_seq_re.sub(cls.decode_char, data[1])

    @staticmethod
    def encode_char(m):
        assert len(m.group(0)) == 1
        cp = ord(m.group(0))
        if cp <= 0x7F:
            return f'\\x{cp:02X}'
        elif cp <= 0xFFFF:
            return f'\\u{cp:04X}'
        else:
            return f'\\U{cp:08X}'

    @property
    def encoded_path(self):
        return self.disallowed_path_re.sub(self.encode_char, self.path)

    def __eq__(self, other):
        return self.tag == other.tag and self.path == other.path

    def __lt__(self, other):
        return (self.tag < other.tag
                or (self.tag == other.tag and self.path < other.path))


class ManifestEntryIGNORE(ManifestPathEntry):
    """Ignored path"""

    tag = 'IGNORE'

    @classmethod
    def from_list(cls, data):
        assert data[0] == cls.tag
        return cls(cls.process_path(data))

    def to_list(self):
        return (self.tag, self.encoded_path)


class ManifestFileEntry(ManifestPathEntry):
    """
    Base class for entries providing checksums for a path.
    """

    __slots__ = ['checksums', 'size']

    def __init__(self, path, size, checksums):
        super().__init__(path)
        self.size = size
        self.checksums = checksums

    @staticmethod
    def process_checksums(data):
        if len(data) < 3:
            raise ManifestSyntaxError(
                f'{data[0]} line: expects at least 2 values, '
                f'got: {data[1:]}')

        try:
            size = int(data[2])
            if size < 0:
                raise ValueError()
        except ValueError:
            raise ManifestSyntaxError(
                f'{data[0]} line: size must be a non-negative integer, '
                f'got: {data[2]}')

        checksums = {}
        it = iter(data[3:])
        while True:
            try:
                ckname = next(it)
            except StopIteration:
                break
            try:
                ckval = next(it)
            except StopIteration:
                raise ManifestSyntaxError(
                    f'{data[0]} line: checksum {ckname} has no value')
            checksums[ckname] = ckval

        return size, checksums

    def to_list(self, tag):
        ret = [tag, self.encoded_path, str(self.size)]
        for k, v in sorted(self.checksums.items()):
            ret += [k, v]
        return ret

    def __eq__(self, other):
        return (super().__eq__(other)
                and self.size == other.size
                and self.checksums == other.checksums)

    # for the purpose of __lt__, the path is good enough for sorting


class ManifestEntryMANIFEST(ManifestFileEntry):
    """
    Sub-Manifest file reference.
    """

    tag = 'MANIFEST'

    @classmethod
    def from_list(cls, data):
        assert data[0] == cls.tag
        path = cls.process_path(data[:2])
        size, checksums = cls.process_checksums(data)
        return cls(path, size, checksums)

    def to_list(self):
        return super().to_list(self.tag)


class ManifestEntryDATA(ManifestFileEntry):
    """
    Regular file reference.
    """

    tag = 'DATA'

    @classmethod
    def from_list(cls, data):
        assert data[0] == cls.tag
        path = cls.process_path(data[:2])
        size, checksums = cls.process_checksums(data)
        return cls(path, size, checksums)

    def to_list(self):
        return super().to_list(self.tag)


class ManifestEntryDIST(ManifestFileEntry):
    """
    Distfile reference.
    """

    tag = 'DIST'

    @classmethod
    def from_list(cls, data):
        path = cls.process_path(data[:2])
        if '/' in path:
            raise ManifestSyntaxError(
                f'{data[0]} line: file name expected, got directory '
                f'path: {path}')
        size, checksums = cls.process_checksums(data)
        return cls(path, size, checksums)

    def to_list(self):
        return super().to_list(self.tag)


class ManifestEntryEBUILD(ManifestFileEntry):
    """
    Deprecated ebuild file reference (equivalent to DATA).
    """

    tag = 'EBUILD'

    @classmethod
    def from_list(cls, data):
        assert data[0] == cls.tag
        path = cls.process_path(data[:2])
        size, checksums = cls.process_checksums(data)
        return cls(path, size, checksums)

    def to_list(self):
        return super().to_list(self.tag)


class ManifestEntryMISC(ManifestFileEntry):
    """
    Deprecated 'non-strict' checksum (now equivalent to DATA).
    """

    tag = 'MISC'

    @classmethod
    def from_list(cls, data):
        assert data[0] == cls.tag
        path = cls.process_path(data[:2])
        size, checksums = cls.process_checksums(data)
        return cls(path, size, checksums)

    def to_list(self):
        return super().to_list(self.tag)


class ManifestEntryAUX(ManifestFileEntry):
    """
    Deprecated AUX file reference (DATA with 'files/' prepended).
    """

    __slots__ = ['aux_path']
    tag = 'AUX'

    def __init__(self, aux_path, size, checksums):
        self.aux_path = aux_path
        super().__init__(
                os.path.join('files', aux_path), size, checksums)

    @classmethod
    def from_list(cls, data):
        assert data[0] == cls.tag
        path = cls.process_path(data[:2])
        size, checksums = cls.process_checksums(data)
        return cls(path, size, checksums)

    def to_list(self):
        ret = super().to_list(self.tag)
        assert path_inside_dir(ret[1], 'files')
        ret[1] = ret[1][6:]
        return ret


MANIFEST_TAG_MAPPING = {
    'TIMESTAMP': ManifestEntryTIMESTAMP,
    'MANIFEST': ManifestEntryMANIFEST,
    'IGNORE': ManifestEntryIGNORE,
    'DATA': ManifestEntryDATA,
    'DIST': ManifestEntryDIST,
    'EBUILD': ManifestEntryEBUILD,
    'MISC': ManifestEntryMISC,
    'AUX': ManifestEntryAUX,
}


def new_manifest_entry(tag, *args):
    """
    Construct a Manifest entry for given @tag. @args are passed
    to the constructor.
    """
    return MANIFEST_TAG_MAPPING[tag](*args)


class ManifestState:
    """
    FSM constants for loading Manifest.
    """

    DATA = 0
    SIGNED_PREAMBLE = 1
    SIGNED_DATA = 2
    SIGNATURE = 3
    POST_SIGNED_DATA = 4


class ManifestFile:
    """
    A class encapsulating a single Manifest file. It supports reading
    from files and writing to them.
    """

    __slots__ = ['entries', 'openpgp_signed', 'openpgp_signature']

    def __init__(self, f=None):
        """
        Create a new instance. If @f is provided, reads the entries
        from open Manifest file @f (see load()).
        """

        self.entries = []
        self.openpgp_signed = None
        self.openpgp_signature = None
        if f is not None:
            self.load(f)

    def load(self, f, verify_openpgp=True, openpgp_env=None):
        """
        Load data from file @f. The file should be open for reading
        in text mode, and oriented at the beginning.

        If @verify_openpgp is True and the Manifest contains an OpenPGP
        signature, the signature will be verified. In that case,
        @openpgp_env needs to be provided.

        If the verification succeeds, the openpgp_signed property will
        be set to True and openpgp_signature will contain the signature
        data. If it fails or OpenPGP is not available, an exception
        will be raised. If the exception is caught, the caller
        can continue using the ManifestFile instance -- it will
        be loaded completely.
        """

        self.entries = []
        self.openpgp_signed = False
        self.openpgp_signature = None
        state = ManifestState.DATA
        openpgp_data = ''

        for line in f:
            if state == ManifestState.DATA:
                if line == '-----BEGIN PGP SIGNED MESSAGE-----\n':
                    if self.entries:
                        raise ManifestUnsignedData()
                    if verify_openpgp:
                        openpgp_data += line
                    state = ManifestState.SIGNED_PREAMBLE
                    continue
            elif state == ManifestState.SIGNED_PREAMBLE:
                if verify_openpgp:
                    openpgp_data += line
                # skip header lines up to the empty line
                if line.strip():
                    continue
                state = ManifestState.SIGNED_DATA
            elif state == ManifestState.SIGNED_DATA:
                if verify_openpgp:
                    openpgp_data += line
                if line == '-----BEGIN PGP SIGNATURE-----\n':
                    state = ManifestState.SIGNATURE
                    continue
                # dash-escaping, RFC 4880 says any line can suffer from it
                if line.startswith('- '):
                    line = line[2:]
            elif state == ManifestState.SIGNATURE:
                if verify_openpgp:
                    openpgp_data += line
                if line == '-----END PGP SIGNATURE-----\n':
                    state = ManifestState.POST_SIGNED_DATA
                    continue

            if line.startswith('-----') and line.rstrip().endswith('-----'):
                raise ManifestSyntaxError(
                    f'Unexpected OpenPGP header: {line}')
            if state in (ManifestState.SIGNED_PREAMBLE,
                         ManifestState.SIGNATURE):
                continue

            sl = line.strip().split()
            # skip empty lines
            if not sl:
                continue
            if state == ManifestState.POST_SIGNED_DATA:
                raise ManifestUnsignedData()
            tag = sl[0]
            try:
                self.entries.append(
                    MANIFEST_TAG_MAPPING[tag].from_list(sl))
            except KeyError:
                raise ManifestSyntaxError(
                    f'Invalid Manifest line: {line}')

        if state == ManifestState.SIGNED_PREAMBLE:
            raise ManifestSyntaxError(
                    "Manifest terminated early, in OpenPGP headers")
        elif state == ManifestState.SIGNED_DATA:
            raise ManifestSyntaxError(
                    "Manifest terminated early, before signature")
        elif state == ManifestState.SIGNATURE:
            raise ManifestSyntaxError(
                    "Manifest terminated early, inside signature")

        if verify_openpgp and state == ManifestState.POST_SIGNED_DATA:
            assert openpgp_env
            with io.StringIO(openpgp_data) as f:
                self.openpgp_signature = openpgp_env.verify_file(f)
            self.openpgp_signed = True

    def dump(self, f, sign_openpgp=None, openpgp_keyid=None,
             openpgp_env=None, sort=False):
        """
        Dump data into file @f. The file should be open for writing
        in text mode, and truncated to zero length.

        If @sign_openpgp is True, the file will include an OpenPGP
        cleartext signature. If it False, the signature will be omitted.
        If it is None (the default), the file will be signed if it
        was originally signed with a valid signature.

        If @openpgp_keyid is not None, it specifies the key to use
        for signing. If @sign_openpgp is not False, @openpgp_env must
        provide an OpenPGP environment for signing.

        If @sort is True, the entries are sorted prior to dumping.
        """

        if sign_openpgp is None:
            sign_openpgp = self.openpgp_signed

        if sort:
            self.entries = sorted(self.entries)

        if sign_openpgp:
            assert openpgp_env
            with io.StringIO() as data:
                # get the plain data into a stream
                self.dump(data, sign_openpgp=False)
                data.seek(0)
                openpgp_env.clear_sign_file(data, f, keyid=openpgp_keyid)
        else:
            for e in self.entries:
                f.write(' '.join(e.to_list()) + '\n')

    def find_timestamp(self):
        """
        Find a timestamp entry and return it. Returns None if there
        is no timestamp.
        """

        for e in self.entries:
            if e.tag == 'TIMESTAMP':
                return e
        return None

    def find_path_entry(self, path):
        """
        Find a matching entry for path @path and return it. Returns
        None when no path matches. DIST entries are not included.
        """

        for e in self.entries:
            if e.tag == 'IGNORE':
                # ignore matches recursively, so we process it separately
                # py<3.5 does not have os.path.commonpath()
                if path_starts_with(path, e.path):
                    return e
            elif e.tag in ('DIST', 'TIMESTAMP'):
                # distfiles are not local files, so skip them
                # timestamp is not a file ;-)
                pass
            else:
                if e.path == path:
                    return e
        return None

    def find_dist_entry(self, filename):
        """
        Find a matching entry for distfile @filename and return it.
        Returns None when no DIST entry matches.
        """

        for e in self.entries:
            if e.tag == 'DIST' and e.path == filename:
                return e
        return None

    def find_manifests_for_path(self, path):
        """
        Find all MANIFEST entries that could affect the path @path
        and return an iterator over them. Yield an empty list when
        there are no matching MANIFEST entries.
        """

        for e in self.entries:
            if e.tag == 'MANIFEST':
                mdir = os.path.dirname(e.path)
                if path_inside_dir(path, mdir):
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
