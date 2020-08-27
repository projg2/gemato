# gemato: hash support tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import io

import pytest

from gemato.exceptions import (
    UnsupportedHash,
    )
from gemato.hash import (
    get_hash_by_name,
    hash_bytes,
    hash_file,
    hash_path,
    )


EMPTY_STRING = b''
TEST_STRING = b'The quick brown fox jumps over the lazy dog'


@pytest.mark.parametrize('name', ['_invalid_name_',
                                  'blake2zzzz',
                                  'sha3_987'])
def test_get_invalid(name):
    with pytest.raises(UnsupportedHash):
        get_hash_by_name(name)


REQUIRED_TEST_HASHES = {
    'TEST_STRING': {
        'md5': '9e107d9d372bb6826bd81d3542a419d6',
        'sha1': '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
        'sha256': 'd7a8fbb307d7809469ca9abcb0082e4f'
                  '8d5651e46d3cdb762d02d0bf37c9e592',
    },
    'EMPTY_STRING': {
        'md5': 'd41d8cd98f00b204e9800998ecf8427e',
        'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        'sha256': 'e3b0c44298fc1c149afbf4c8996fb924'
                  '27ae41e4649b934ca495991b7852b855',
    },
}


HASH_VARIANTS = [
    # name, required, test hashes
    ('md5', True,
     {'TEST_STRING': REQUIRED_TEST_HASHES['TEST_STRING']['md5'],
      'EMPTY_STRING': REQUIRED_TEST_HASHES['EMPTY_STRING']['md5'],
      }),
    ('sha1', True,
     {'TEST_STRING': REQUIRED_TEST_HASHES['TEST_STRING']['sha1'],
      'EMPTY_STRING': REQUIRED_TEST_HASHES['EMPTY_STRING']['sha1'],
      }),
    ('sha224', True,
     {'TEST_STRING': '730e109bd7a8a32b1cb9d9a09aa2'
                     '325d2430587ddbc0c38bad911525',
      'EMPTY_STRING': 'd14a028c2a3a2bc9476102bb2882'
                      '34c415a2b01f828ea62ac5b3e42f',
      }),
    ('sha256', True,
     {'TEST_STRING': REQUIRED_TEST_HASHES['TEST_STRING']['sha256'],
      'EMPTY_STRING': REQUIRED_TEST_HASHES['EMPTY_STRING']['sha256'],
      }),
    ('sha384', True,
     {'TEST_STRING': 'ca737f1014a48f4c0b6dd43cb177b0af'
                     'd9e5169367544c494011e3317dbf9a50'
                     '9cb1e5dc1e85a941bbee3d7f2afbc9b1',
      'EMPTY_STRING': '38b060a751ac96384cd9327eb1b1e36a'
                      '21fdb71114be07434c0cc7bf63f6e1da'
                      '274edebfe76f65fbd51ad2f14898b95b',
      }),
    ('sha512', True,
     {'TEST_STRING': '07e547d9586f6a73f73fbac0435ed769'
                     '51218fb7d0c8d788a309d785436bbb64'
                     '2e93a252a954f23912547d1e8a3b5ed6'
                     'e1bfd7097821233fa0538f3db854fee6',
      'EMPTY_STRING': 'cf83e1357eefb8bdf1542850d66d8007'
                      'd620e4050b5715dc83f4a921d36ce9ce'
                      '47d0d13c5d85f2b0ff8318d2877eec2f'
                      '63b931bd47417a81a538327af927da3e',
      }),
    ('md4', False,
     {'TEST_STRING': '1bee69a46ba811185c194762abaeae90',
      'EMPTY_STRING': '31d6cfe0d16ae931b73c59d7e0c089c0',
      }),
    ('ripemd160', False,
     {'TEST_STRING': '37f332f68db77bd9d7edd4969571ad671cf9dd3b',
      'EMPTY_STRING': '9c1185a5c5e9fc54612808977ee8f548b2258d31',
      }),
    ('blake2b', False,
     {'TEST_STRING': 'a8add4bdddfd93e4877d2746e62817b1'
                     '16364a1fa7bc148d95090bc7333b3673'
                     'f82401cf7aa2e4cb1ecd90296e3f14cb'
                     '5413f8ed77be73045b13914cdcd6a918',
      'EMPTY_STRING': '786a02f742015903c6c6fd852552d272'
                      '912f4740e15847618a86e217f71f5419'
                      'd25e1031afee585313896444934eb04b'
                      '903a685b1448b755d56f701afe9be2ce',
      }),
    ('blake2s', False,
     {'TEST_STRING': '606beeec743ccbeff6cbcdf5d5302aa8'
                     '55c256c29b88c8ed331ea1a6bf3c8812',
      'EMPTY_STRING': '69217a3079908094e11121d042354a7c'
                      '1f55b6482ca1a51e1b250dfd1ed0eef9',
      }),
    ('sha3_224', False,
     {'TEST_STRING': 'd15dadceaa4d5d7bb3b48f446421'
                     'd542e08ad8887305e28d58335795',
      'EMPTY_STRING': '6b4e03423667dbb73b6e15454f0e'
                      'b1abd4597f9a1b078e3f5b5a6bc7',
      }),
    ('sha3_256', False,
     {'TEST_STRING': '69070dda01975c8c120c3aada1b28239'
                     '4e7f032fa9cf32f4cb2259a0897dfc04',
      'EMPTY_STRING': 'a7ffc6f8bf1ed76651c14756a061d662'
                      'f580ff4de43b49fa82d80a4b80f8434a',
      }),
    ('sha3_384', False,
     {'TEST_STRING': '7063465e08a93bce31cd89d2e3ca8f60'
                     '2498696e253592ed26f07bf7e703cf32'
                     '8581e1471a7ba7ab119b1a9ebdf8be41',
      'EMPTY_STRING': '0c63a75b845e4f7d01107d852e4c2485'
                      'c51a50aaaa94fc61995e71bbee983a2a'
                      'c3713831264adb47fb6bd1e058d5f004',
      }),
    ('sha3_512', False,
     {'TEST_STRING': '01dedd5de4ef14642445ba5f5b97c15e'
                     '47b9ad931326e4b0727cd94cefc44fff'
                     '23f07bf543139939b49128caf436dc1b'
                     'dee54fcb24023a08d9403f9b4bf0d450',
      'EMPTY_STRING': 'a69f73cca23a9ac5c8b567dc185a756e'
                      '97c982164fe25859e0d1dcc1475c80a6'
                      '15b2123af1f5f94c11e3e9402c3ac558'
                      'f500199d95b6d3e301758586281dcd26',
      }),
    ('whirlpool', False,
     {'TEST_STRING': 'b97de512e91e3828b40d2b0fdce9ceb3'
                     'c4a71f9bea8d88e75c4fa854df36725f'
                     'd2b52eb6544edcacd6f8beddfea403cb'
                     '55ae31f03ad62a5ef54e42ee82c3fb35',
      'EMPTY_STRING': '19fa61d75522a4669b44e39c1d2e1726'
                      'c530232130d407f89afee0964997f7a7'
                      '3e83be698b288febcf88e3e03c4f0757'
                      'ea8964e59b63d93708b138cc42a66eb3',
      }),
    ('__size__', True,
     {'TEST_STRING': 43,
      'EMPTY_STRING': 0,
      }),
]


@pytest.mark.parametrize('name,required,test_hashes',
                         HASH_VARIANTS)
@pytest.mark.parametrize('test_var', ['TEST_STRING', 'EMPTY_STRING'])
def test_hash_bytes(name, required, test_hashes, test_var):
    try:
        assert hash_bytes(globals()[test_var], name) == test_hashes[test_var]
    except UnsupportedHash:
        if not required:
            pytest.skip(f'Hash {name} not supported')
        raise


@pytest.mark.parametrize('test_var', ['TEST_STRING', 'EMPTY_STRING'])
def test_hash_file(test_var):
    with io.BytesIO(globals()[test_var]) as f:
        assert (hash_file(f, REQUIRED_TEST_HASHES[test_var].keys()) ==
                REQUIRED_TEST_HASHES[test_var])


@pytest.mark.parametrize('test_var', ['TEST_STRING', 'EMPTY_STRING'])
def test_hash_path(tmp_path, test_var):
    with open(tmp_path / 'test.txt', 'wb') as f:
        f.write(globals()[test_var])
    assert (hash_path(tmp_path / 'test.txt',
                      REQUIRED_TEST_HASHES[test_var].keys()) ==
            REQUIRED_TEST_HASHES[test_var])
