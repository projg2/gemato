#!/bin/bash
test_string='The quick brown fox jumps over the lazy dog'

if [[ ${#} -lt 1 ]]; then
    echo "Usage: ${0} <hashlib-name> [<program-to-use>]"
    exit 1
fi

algo=${1}
algo_sum=${2:-${algo}sum}

empty=$(printf '' | ${algo_sum} | cut -d' ' -f1)
str=$(printf '%s' "${test_string}" | ${algo_sum} | cut -d' ' -f1)

cat <<_EOF_

    def test_${algo}(self):
        try:
            self.assertEqual(hash_bytes(TEST_STRING, '${algo}'),
                    '${str}')
        except UnsupportedHash:
            raise unittest.SkipTest('hash not supported')

    def test_${algo}_empty(self):
        try:
            self.assertEqual(hash_bytes(b'', '${algo}'),
                    '${empty}')
        except UnsupportedHash:
            raise unittest.SkipTest('hash not supported')
_EOF_
