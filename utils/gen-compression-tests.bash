#!/bin/bash
test_string='The quick brown fox jumps over the lazy dog'

if [[ ${#} -lt 1 ]]; then
    echo "Usage: ${0} <program-to-use>"
    exit 1
fi

program=${1}

empty=$(printf '' | ${program} | base64)
str=$(printf '%s' "${test_string}" | ${program} | base64)
split=$(
    ( printf '%s' "${test_string::20}" | ${program}
    printf '%s' "${test_string:20}" | ${program} ) | base64)

cat <<_EOF_

    BASE64 = b'''
${str}
'''

    EMPTY_BASE64 = b'''
${empty}
'''

    SPLIT_BASE64 = b'''
${split}
'''

_EOF_
