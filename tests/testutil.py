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
import sys
import tempfile
import threading
import unittest

if sys.hexversion >= 0x03000000:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from urllib.parse import urlparse, parse_qs
else:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
    from urlparse import urlparse, parse_qs

import gemato.openpgp


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
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(self.keys[key])
        self.wfile.flush()


class HKPServerTestCase(unittest.TestCase):
    """
    A test case deploying HKP server for OpenPGP client to use.
    """

    SERVER_KEYS = {}

    def setUp(self):
        # try 10 randomly selected ports before giving up
        for port in random.sample(range(1024, 32768), 10):
            try:
                self.server = HTTPServer(('127.0.0.1', port),
                        functools.partial(HKPServerRequestHandler,
                                          self.SERVER_KEYS))
            except OSError as e:
                if e.errno != errno.EADDRINUSE:
                    raise unittest.SkipTest('Unable to bind the HKP server: {}'
                            .format(e))
            else:
                break
        else:
            raise unittest.SkipTest('Unable to find a free port for HKP server')

        self.server_addr = 'hkp://127.0.0.1:{}'.format(port)
        self.server_thread = threading.Thread(
                target=self.server.serve_forever)
        self.server_thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()


class MockedWKDOpenPGPEnvironment(gemato.openpgp.OpenPGPEnvironment):
    """
    A subclass of OpenPGPEnvironment that partially mocks spawning
    OpenPGP in order to inject keys without having to implement
    full HTTPS server with domain satisfactory to GnuPG.
    """

    def __init__(self, keys={}):
        self.keys = keys
        super(MockedWKDOpenPGPEnvironment, self).__init__()

    def clone(self):
        return MockedWKDOpenPGPEnvironment(self.keys)

    def _spawn_gpg(self, argv, stdin=''):
        if '--locate-keys' in argv:
            argv.remove('--locate-keys')
            assert len(argv) == 3
            assert argv[:2] == ['gpg', '--batch']
            if argv[2] in self.keys:
                ret, sout, serr = super(MockedWKDOpenPGPEnvironment,
                    self)._spawn_gpg(
                        ['gpg', '--batch', '--import'],
                        self.keys[argv[2]])
            else:
                ret = 2
            return (ret, b'', b'')

        return super(MockedWKDOpenPGPEnvironment, self)._spawn_gpg(
                argv, stdin)
