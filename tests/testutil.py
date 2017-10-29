# gemato: Test utility functions
# vim:fileencoding=utf-8
# (c) 2017 Michał Górny
# Licensed under the terms of 2-clause BSD license

import io
import logging
import os
import os.path
import shutil
import sys
import tempfile
import unittest


class LoggingTestCase(unittest.TestCase):
    def setUp(self):
        if sys.hexversion < 0x03000000:
            self.log = io.BytesIO()
        else:
            self.log = io.StringIO()
        self.log_handler = logging.getLogger().addHandler(
                logging.StreamHandler(self.log))

    def tearDown(self):
        # TODO: make some use of the log output?
        logging.getLogger().removeHandler(self.log_handler)


class TempDirTestCase(LoggingTestCase):
    DIRS = []
    FILES = {}

    def setUp(self):
        super(TempDirTestCase, self).setUp()
        self.dir = tempfile.mkdtemp()
        for k in self.DIRS:
            os.mkdir(os.path.join(self.dir, k))
        for k, v in self.FILES.items():
            with io.open(os.path.join(self.dir, k), 'w', encoding='utf8') as f:
                f.write(v)

    def tearDown(self):
        shutil.rmtree(self.dir)
        super(TempDirTestCase, self).tearDown()
