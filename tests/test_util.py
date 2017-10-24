# gemato: Utility function tests
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import unittest

import gemato.util


class UtilityTestCase(unittest.TestCase):
    def test_path_starts_with(self):
        self.assertTrue(gemato.util.path_starts_with("", ""))
        self.assertTrue(gemato.util.path_starts_with("foo", ""))
        self.assertTrue(gemato.util.path_starts_with("foo/", ""))
        self.assertTrue(gemato.util.path_starts_with("foo/bar", ""))
        self.assertTrue(gemato.util.path_starts_with("bar", ""))
        self.assertTrue(gemato.util.path_starts_with("bar/", ""))
        self.assertTrue(gemato.util.path_starts_with("bar/bar", ""))
        self.assertTrue(gemato.util.path_starts_with("foo", "foo"))
        self.assertTrue(gemato.util.path_starts_with("foo/", "foo"))
        self.assertTrue(gemato.util.path_starts_with("foo/bar", "foo"))
        self.assertFalse(gemato.util.path_starts_with("bar", "foo"))
        self.assertFalse(gemato.util.path_starts_with("fooo", "foo"))
        self.assertFalse(gemato.util.path_starts_with("foo.", "foo"))
        self.assertTrue(gemato.util.path_starts_with("foo", "foo/"))
        self.assertTrue(gemato.util.path_starts_with("foo/", "foo/"))
        self.assertTrue(gemato.util.path_starts_with("foo/bar", "foo/bar/"))

    def test_path_inside_dir(self):
        self.assertFalse(gemato.util.path_inside_dir("", ""))
        self.assertTrue(gemato.util.path_inside_dir("foo", ""))
        self.assertTrue(gemato.util.path_inside_dir("foo/", ""))
        self.assertTrue(gemato.util.path_inside_dir("foo/bar", ""))
        self.assertTrue(gemato.util.path_inside_dir("bar", ""))
        self.assertTrue(gemato.util.path_inside_dir("bar/", ""))
        self.assertTrue(gemato.util.path_inside_dir("bar/bar", ""))
        self.assertFalse(gemato.util.path_inside_dir("foo", "foo"))
        self.assertFalse(gemato.util.path_inside_dir("foo/", "foo"))
        self.assertTrue(gemato.util.path_inside_dir("foo/bar", "foo"))
        self.assertFalse(gemato.util.path_inside_dir("bar", "foo"))
        self.assertFalse(gemato.util.path_inside_dir("fooo", "foo"))
        self.assertFalse(gemato.util.path_inside_dir("foo.", "foo"))
        self.assertFalse(gemato.util.path_inside_dir("foo", "foo/"))
        self.assertFalse(gemato.util.path_inside_dir("foo/", "foo/"))
        self.assertFalse(gemato.util.path_inside_dir("foo/bar", "foo/bar/"))
