# gemato: Test utility functions
# vim:fileencoding=utf-8
# (c) 2017-2020 Michał Górny
# Licensed under the terms of 2-clause BSD license

import errno
import functools
import io
import logging
import os
import os.path
import random
import shutil
import stat
import tempfile
import threading
import unittest

import pytest

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


def disallow_writes(path):
    """Mark path non-writable, recursively"""
    for dirpath, dirs, files in os.walk(path, topdown=False):
        for f in files + dirs:
            st = os.lstat(os.path.join(dirpath, f))
            if not stat.S_ISLNK(st.st_mode):
                os.chmod(os.path.join(dirpath, f),
                         st.st_mode & ~0o222)
    os.chmod(path, 0o555)


class LoggingTestCase(unittest.TestCase):
    def setUp(self):
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


class HKPServerRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, keys, *args, **kwargs):
        self.keys = keys
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_message(self, *args, **kwargs):
        pass

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            assert parsed.path == '/pks/lookup'

            qs = parse_qs(parsed.query)
            assert qs.get('op') == ['get']
            assert len(qs.get('search', [])) == 1

            key = qs['search'][0]
            assert key.startswith('0x')
            key = key[2:]
        except AssertionError:
            self.send_error(400, "Bad request")
            return

        if key not in self.keys:
            self.send_error(404, "Not found")
            return

        self.send_response(200, "OK")
        self.send_header("Content-type", "application/pgp-keys")
        self.end_headers()
        # note: technically we should be using ASCII armor here
        # but GnuPG seems happy with the binary form too
        self.wfile.write(self.keys[key])
        self.wfile.flush()


class HKPServer:
    def __init__(self):
        self.keys = {}
        self.addr = None

    def start(self):
        # try 10 randomly selected ports before giving up
        for port in random.sample(range(1024, 32768), 10):
            try:
                self.server = HTTPServer(
                    ('127.0.0.1', port),
                    functools.partial(HKPServerRequestHandler, self.keys))
            except OSError as e:
                if e.errno != errno.EADDRINUSE:
                    pytest.skip(
                        f'Unable to bind the HKP server: {e}')
            else:
                break
        else:
            pytest.skip('Unable to find a free port for HKP server')

        self.addr = f'hkp://127.0.0.1:{port}'
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def stop(self):
        assert self.addr is not None
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.addr = None
