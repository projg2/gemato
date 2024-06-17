# gemato: Utility function tests
# (c) 2017-2022 Michał Górny
# SPDX-License-Identifier: GPL-2.0-or-later

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
