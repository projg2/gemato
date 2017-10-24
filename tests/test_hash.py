# gemato: hash support tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import io
import tempfile
import unittest

import gemato.exceptions
import gemato.hash


TEST_STRING = b'The quick brown fox jumps over the lazy dog'


class HashAPITest(unittest.TestCase):
    """
    Test basic aspects of the hash function API.
    """

    def test_get_valid(self):
        gemato.hash.get_hash_by_name('md5')
        gemato.hash.get_hash_by_name('sha1')

    def test_get_invalid(self):
        self.assertRaises(gemato.exceptions.UnsupportedHash,
                gemato.hash.get_hash_by_name, '_invalid_name_')

    def test_get_invalid_pyblake2(self):
        self.assertRaises(gemato.exceptions.UnsupportedHash,
                gemato.hash.get_hash_by_name, 'blake2zzz')

    def test_get_invalid_pysha3(self):
        self.assertRaises(gemato.exceptions.UnsupportedHash,
                gemato.hash.get_hash_by_name, 'sha3_987')

    def test_hash_file(self):
        f = io.BytesIO(TEST_STRING)
        self.assertDictEqual(gemato.hash.hash_file(f, ('md5', 'sha1', 'sha256')),
                {
                    'md5': '9e107d9d372bb6826bd81d3542a419d6',
                    'sha1': '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
                    'sha256': 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
                })

    def test_hash_empty_file(self):
        f = io.BytesIO(b'')
        self.assertDictEqual(gemato.hash.hash_file(f, ('md5', 'sha1', 'sha256')),
                {
                    'md5': 'd41d8cd98f00b204e9800998ecf8427e',
                    'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                    'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                })

    def test_hash_path(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write(TEST_STRING)
            f.flush()
            self.assertDictEqual(gemato.hash.hash_path(f.name, ('md5', 'sha1', 'sha256')),
                    {
                        'md5': '9e107d9d372bb6826bd81d3542a419d6',
                        'sha1': '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
                        'sha256': 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592',
                    })

    def test_hash_empty_path(self):
        with tempfile.NamedTemporaryFile() as f:
            self.assertDictEqual(gemato.hash.hash_path(f.name, ('md5', 'sha1', 'sha256')),
                    {
                        'md5': 'd41d8cd98f00b204e9800998ecf8427e',
                        'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                        'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                    })


class GuaranteedHashTest(unittest.TestCase):
    """
    Test basic operation of various hash functions. This test aims
    mostly to make sure that we can load and run the various backend
    routines, and that they run the correct version of the hash.
    This set covers hash functions that are guaranteed to be provided.
    """

    def test_md5(self):
        self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'md5'),
                '9e107d9d372bb6826bd81d3542a419d6')

    def test_md5_empty(self):
        self.assertEqual(gemato.hash.hash_bytes(b'', 'md5'),
                'd41d8cd98f00b204e9800998ecf8427e')

    def test_sha1(self):
        self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'sha1'),
                '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')

    def test_sha1_empty(self):
        self.assertEqual(gemato.hash.hash_bytes(b'', 'sha1'),
                'da39a3ee5e6b4b0d3255bfef95601890afd80709')

    def test_sha224(self):
        self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'sha224'),
                '730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525')

    def test_sha224_empty(self):
        self.assertEqual(gemato.hash.hash_bytes(b'', 'sha224'),
                'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f')

    def test_sha256(self):
        self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'sha256'),
                'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592')

    def test_sha256_empty(self):
        self.assertEqual(gemato.hash.hash_bytes(b'', 'sha256'),
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    def test_sha384(self):
        self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'sha384'),
                'ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1')

    def test_sha384_empty(self):
        self.assertEqual(gemato.hash.hash_bytes(b'', 'sha384'),
                '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b')

    def test_sha512(self):
        self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'sha512'),
                '07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6')

    def test_sha512_empty(self):
        self.assertEqual(gemato.hash.hash_bytes(b'', 'sha512'),
                'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')


class OptionalHashTest(unittest.TestCase):
    """
    Test basic operation of various hash functions. This test aims
    mostly to make sure that we can load and run the various backend
    routines, and that they run the correct version of the hash.
    This set covers hash functions that are optional.
    """

    def test_md4(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'md4'),
                    '1bee69a46ba811185c194762abaeae90')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_md4_empty(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(b'', 'md4'),
                    '31d6cfe0d16ae931b73c59d7e0c089c0')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_ripemd160(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'ripemd160'),
                    '37f332f68db77bd9d7edd4969571ad671cf9dd3b')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_ripemd160_empty(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(b'', 'ripemd160'),
                    '9c1185a5c5e9fc54612808977ee8f548b2258d31')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_blake2b(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'blake2b'),
                    'a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_blake2b_empty(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(b'', 'blake2b'),
                    '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_blake2s(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'blake2s'),
                    '606beeec743ccbeff6cbcdf5d5302aa855c256c29b88c8ed331ea1a6bf3c8812')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_blake2s_empty(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(b'', 'blake2s'),
                    '69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_sha3_224(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'sha3_224'),
                    'd15dadceaa4d5d7bb3b48f446421d542e08ad8887305e28d58335795')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_sha3_224_empty(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(b'', 'sha3_224'),
                    '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_sha3_256(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'sha3_256'),
                    '69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_sha3_256_empty(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(b'', 'sha3_256'),
                    'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_sha3_384(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'sha3_384'),
                    '7063465e08a93bce31cd89d2e3ca8f602498696e253592ed26f07bf7e703cf328581e1471a7ba7ab119b1a9ebdf8be41')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_sha3_384_empty(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(b'', 'sha3_384'),
                    '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_sha3_512(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'sha3_512'),
                    '01dedd5de4ef14642445ba5f5b97c15e47b9ad931326e4b0727cd94cefc44fff23f07bf543139939b49128caf436dc1bdee54fcb24023a08d9403f9b4bf0d450')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_sha3_512_empty(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(b'', 'sha3_512'),
                    'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_whirlpool(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, 'whirlpool'),
                    'b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725fd2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_whirlpool_empty(self):
        try:
            self.assertEqual(gemato.hash.hash_bytes(b'', 'whirlpool'),
                    '19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3')
        except gemato.exceptions.UnsupportedHash:
            raise unittest.SkipTest('hash not supported')


class SizeHashTest(unittest.TestCase):
    """
    Test __size__ special function.
    """

    def test_size(self):
        self.assertEqual(gemato.hash.hash_bytes(TEST_STRING, '__size__'), 43)

    def test_size_empty(self):
        self.assertEqual(gemato.hash.hash_bytes(b'', '__size__'), 0)
