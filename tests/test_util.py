# gemato: Utility function tests
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import pytest

from gemato.util import (
    path_starts_with,
    path_inside_dir,
    )


@pytest.mark.parametrize(
    'p1,p2,expected',
    [("", "", True),
     ("foo", "", True),
     ("foo/", "", True),
     ("foo/bar", "", True),
     ("bar", "", True),
     ("bar/", "", True),
     ("bar/bar", "", True),
     ("foo", "foo", True),
     ("foo/", "foo", True),
     ("foo/bar", "foo", True),
     ("bar", "foo", False),
     ("fooo", "foo", False),
     ("foo.", "foo", False),
     ("foo", "foo/", True),
     ("foo/", "foo/", True),
     ("foo/bar", "foo/bar/", True),
     ])
def test_path_starts_with(p1, p2, expected):
    assert path_starts_with(p1, p2) is expected


@pytest.mark.parametrize(
    'p1,p2,expected',
    [("", "", False),
     ("foo", "", True),
     ("foo/", "", True),
     ("foo/bar", "", True),
     ("bar", "", True),
     ("bar/", "", True),
     ("bar/bar", "", True),
     ("foo", "foo", False),
     ("foo/", "foo", False),
     ("foo/bar", "foo", True),
     ("bar", "foo", False),
     ("fooo", "foo", False),
     ("foo.", "foo", False),
     ("foo", "foo/", False),
     ("foo/", "foo/", False),
     ("foo/bar", "foo/bar/", False),
     ])
def test_path_inside_dir(p1, p2, expected):
    assert path_inside_dir(p1, p2) is expected
