# gemato: Test utility functions
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import io
import os
import os.path
import tempfile
import unittest


class TempDirTestCase(unittest.TestCase):
    DIRS = []
    FILES = {}

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        for k in self.DIRS:
            os.mkdir(os.path.join(self.dir, k))
        for k, v in self.FILES.items():
            with io.open(os.path.join(self.dir, k), 'w', encoding='utf8') as f:
                f.write(v)

    def tearDown(self):
        for k in self.FILES:
            os.unlink(os.path.join(self.dir, k))
        for k in reversed(self.DIRS):
            os.rmdir(os.path.join(self.dir, k))
        os.rmdir(self.dir)
