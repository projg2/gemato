# gemato: compressed file tests
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import base64
import io

import pytest

from gemato.compression import (
    open_compressed_file,
    open_potentially_compressed_path,
    get_potential_compressed_names,
    get_compressed_suffix_from_filename,
    )


TEST_STRING = b'The quick brown fox jumps over the lazy dog'
# we need to be specific on endianness to avoid unreliably writing BOM
UTF16_TEST_STRING = TEST_STRING.decode('utf8').encode('utf_16_be')


COMPRESSION_ALGOS = ['gz', 'bz2', 'lzma', 'xz']

COMPRESSION_DATA = {
    'baseline': {
        None: TEST_STRING,
        'gz': b'''
H4sIACbJ8FkAAwvJSFUoLM1MzlZIKsovz1NIy69QyCrNLShWyC9LLVIoAUrnJFZVKqTkpwMA
OaNPQSsAAAA=
''',
        'bz2': b'''
QlpoOTFBWSZTWUWd7mEAAAQTgEAABAA////wIAEABTQAAAGigAAAAEBoLtBqVm1CpOmzyfUX
Aw5PHXD0304jMvvfF3JFOFCQRZ3uYQ==
''',
        'lzma': b'''
XQAAAAT//////////wAqGgiiAyVm8Ut4xaIF/y7m2dIgGq00+OId6EE2+twGabs85BA0Jwnr
s2bsGhcv//zOkAA=
''',
        'xz': b'''
/Td6WFoAAATm1rRGAgAhARwAAAAQz1jMAQAqVGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBv
dmVyIHRoZSBsYXp5IGRvZwAAxKFK5cK4XlsAAUMrrVBuVx+2830BAAAAAARZWg==
''',
    },
    'empty': {
        None: b'',
        'gz': b'H4sIACbJ8FkAAwMAAAAAAAAAAAA=',
        'bz2': b'QlpoORdyRThQkAAAAAA=',
        'lzma': b'XQAAAAT//////////wCD//v//8AAAAA=',
        'xz': b'/Td6WFoAAATm1rRGAAAAABzfRCEftvN9AQAAAAAEWVo=',
    },
    'split': {
        None: TEST_STRING,
        'gz': b'''
H4sIACbJ8FkAAwvJSFUoLM1MzlZIKsovz1NIy69QAADidbCIFAAAAB+LCAAmyfBZAAPLKs0t
KFbIL0stUijJSFXISayqVEjJTwcAlGd4GBcAAAA=
''',
        'bz2': '''
QlpoOTFBWSZTWQgcCrAAAAITgEAABAAbabLAIABBEaDR6jT9UoAAAbUXZJ48gnMg3xdyRThQ
kAgcCrBCWmg5MUFZJlNZOxleaAAABRGAQAAm1t8wIACAUaNDRtTaSgAAAcAcViIdSEhzctM/
F3JFOFCQOxleaA==
''',
        'lzma': '''
XQAAAAT//////////wAqGgiiAyVm8Ut4xaIF/y7m2dIgGq1EvQql//X0QABdAAAABP//////
////ADUdSd6zBOkOpekGFH46zix9wE9VT65OVeV479//7uUAAA==
''',
        'xz': '''
/Td6WFoAAATm1rRGAgAhARwAAAAQz1jMAQATVGhlIHF1aWNrIGJyb3duIGZveCAAIEFC5aca
LXcAASwU+AptAx+2830BAAAAAARZWv03elhaAAAE5ta0RgIAIQEcAAAAEM9YzAEAFmp1bXBz
IG92ZXIgdGhlIGxhenkgZG9nAADjZCTmHjHqggABLxeBCEmxH7bzfQEAAAAABFla
''',
    },
}


@pytest.mark.parametrize('suffix', COMPRESSION_ALGOS)
@pytest.mark.parametrize('data_group', COMPRESSION_DATA.keys())
def test_decompress(suffix, data_group):
    data = COMPRESSION_DATA[data_group]
    with io.BytesIO(base64.b64decode(data[suffix])) as f:
        with open_compressed_file(suffix, f, "rb") as z:
            assert z.read() == data[None]


@pytest.mark.parametrize('suffix', COMPRESSION_ALGOS)
def test_round_trip(suffix):
    with io.BytesIO() as f:
        with open_compressed_file(suffix, f, 'wb') as z:
            z.write(TEST_STRING)

        f.seek(0)

        with open_compressed_file(suffix, f, 'rb') as z:
            assert z.read() == TEST_STRING


@pytest.fixture(params=COMPRESSION_ALGOS)
def test_file(tmp_path, request):
    yield tmp_path / f'test.{request.param}'


@pytest.mark.parametrize('data_group', COMPRESSION_DATA.keys())
def test_open_potentially_compressed_path(test_file, data_group):
    suffix = test_file.suffix.lstrip('.')
    with open(test_file, 'wb') as wf:
        wf.write(base64.b64decode(COMPRESSION_DATA[data_group][suffix]))

    with open_potentially_compressed_path(test_file, 'rb') as cf:
        assert cf.read() == COMPRESSION_DATA[data_group][None]


def test_open_potentially_compressed_path_write(test_file):
    with open_potentially_compressed_path(test_file, 'wb') as cf:
        cf.write(TEST_STRING)

    suffix = test_file.suffix.lstrip('.')
    with open(test_file, 'rb') as rf:
        with open_compressed_file(suffix, rf, 'rb') as z:
            assert z.read() == TEST_STRING


def test_open_potentially_compressed_path_with_encoding(test_file):
    suffix = test_file.suffix.lstrip('.')
    with open(test_file, 'wb') as wf:
        with open_compressed_file(suffix, wf, 'wb') as z:
            z.write(UTF16_TEST_STRING)

    with open_potentially_compressed_path(test_file, 'r',
                                          encoding='utf_16_be') as cf:
        assert cf.read() == TEST_STRING.decode('utf8')


@pytest.mark.parametrize('encoding,out_var', [(None, 'TEST_STRING'),
                                              ('utf_16_be',
                                               'UTF16_TEST_STRING'),
                                              ])
def test_open_potentially_compressed_path_write_with_unicode(
        test_file, encoding, out_var):
    kwargs = {}
    if encoding is not None:
        kwargs['encoding'] = encoding
    with open_potentially_compressed_path(test_file, 'w', **kwargs) as cf:
        cf.write(TEST_STRING.decode('utf8'))

    suffix = test_file.suffix.lstrip('.')
    with open(test_file, 'rb') as rf:
        with open_compressed_file(suffix, rf, 'rb') as z:
            assert z.read() == globals()[out_var]


def test_open_potentially_compressed_path_with_encoding_line_api(test_file):
    suffix = test_file.suffix.lstrip('.')
    with open(test_file, 'wb') as wf:
        with open_compressed_file(suffix, wf, 'wb') as z:
            z.write(UTF16_TEST_STRING)

    with open_potentially_compressed_path(test_file, 'r',
                                          encoding='utf_16_be') as cf:
        assert [x for x in cf] == [TEST_STRING.decode('utf8')]


def test_open_potentially_compressed_path_fileno_passthrough(test_file):
    fs1 = open_potentially_compressed_path(test_file, 'w',
                                           encoding='utf_16_be')
    with fs1 as cf:
        assert ([f.fileno() for f in fs1.files] ==
                [cf.fileno() for f in fs1.files])

    fs2 = open_potentially_compressed_path(test_file, 'r',
                                           encoding='utf_16_be')
    with fs2 as cf:
        assert ([f.fileno() for f in fs2.files] ==
                [cf.fileno() for f in fs2.files])


def test_get_potential_compressed_names():
    assert (
        frozenset(get_potential_compressed_names('test')) ==
        frozenset(['test'] + [f'test.{sfx}' for sfx in COMPRESSION_ALGOS]))


@pytest.mark.parametrize('suffix', COMPRESSION_ALGOS)
def test_get_compressed_suffix_from_filename(suffix):
    assert (
        get_compressed_suffix_from_filename(f'test.{suffix}') == suffix)
