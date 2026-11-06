import http.client
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import mini_burp as mb


class Shop(BaseHTTPRequestHandler):
    """A pretend lab shop: one page, one cookie without flags."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Set-Cookie", "token=abc; Path=/")
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, *args):
        pass


def start(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class TestRules(unittest.TestCase):
    def test_lab_addresses_are_allowed(self):
        self.assertTrue(mb.lab_only("192.168.230.129"))
        self.assertTrue(mb.lab_only("127.0.0.1"))

    def test_internet_is_refused(self):
        self.assertFalse(mb.lab_only("8.8.8.8"))

    def test_json_secrets_are_hidden(self):
        body = b'{"email":"student@juice.lab","password":"Practice-123!"}'
        shown = mb.mask(body)
        self.assertIn("student@juice.lab", shown)
        self.assertNotIn("Practice-123!", shown)

    def test_form_secrets_are_hidden(self):
        self.assertEqual(mb.mask(b"user=admin&password=pw"),
                         "user=admin&password=***")

    def test_login_cookie_is_named_not_shown(self):
        headers = http.client.HTTPMessage()
        headers["Cookie"] = "language=en; token=secret123"
        headers["Authorization"] = "Bearer secret123"
        notes = mb.request_notes(headers)
        self.assertEqual(len(notes), 2)
        self.assertNotIn("secret123", " ".join(notes))

    def test_background_requests_are_quiet(self):
        mb.history.clear()
        mb.findings.clear()
        with mock.patch("builtins.print") as out:
            mb.record("GET", "http://127.0.0.1/main.js", 200, b"", [], 9)
        self.assertTrue(mb.history[0]["quiet"])
        out.assert_not_called()

    def test_summary_counts_findings(self):
        mb.history.clear()
        mb.findings.clear()
        mb.findings["missing Content-Security-Policy"] = 3
        self.assertIn("x3", mb.summary())

    def test_audit_finds_missing_headers_and_flags(self):
        headers = http.client.HTTPMessage()
        headers["X-Frame-Options"] = "SAMEORIGIN"
        headers["Set-Cookie"] = "token=abc; Path=/"
        notes = mb.audit(headers)
        self.assertIn("missing Content-Security-Policy", notes)
        self.assertIn("cookie token without HttpOnly", notes)


class TestProxy(unittest.TestCase):
    def setUp(self):
        mb.history.clear()
        mb.findings.clear()
        mb.hosts.clear()
        self.shop = start(Shop)
        self.proxy = start(mb.Proxy)

    def tearDown(self):
        for server in (self.shop, self.proxy):
            server.shutdown()
            server.server_close()

    def ask(self, method, url):
        conn = http.client.HTTPConnection("127.0.0.1",
                                          self.proxy.server_port)
        with mock.patch("builtins.print"):
            conn.request(method, url)
            reply = conn.getresponse()
            result = reply.status, reply.read()
        conn.close()
        return result

    def test_forwards_and_records(self):
        url = f"http://127.0.0.1:{self.shop.server_port}/"
        status, body = self.ask("GET", url)
        self.assertEqual((status, body), (200, b"hello"))
        self.assertEqual(mb.history[0]["url"], url)

    def test_refuses_the_internet(self):
        status, _ = self.ask("GET", "http://8.8.8.8/")
        self.assertEqual(status, 403)
        self.assertEqual(mb.history, [])

    def test_https_is_not_intercepted(self):
        status, _ = self.ask("CONNECT", "192.168.230.129:443")
        self.assertEqual(status, 501)


if __name__ == "__main__":
    unittest.main()
