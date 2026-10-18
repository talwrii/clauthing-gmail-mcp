import contextlib
import io
import unittest
from unittest.mock import Mock

from clauthing_gmail_mcp.oauth_callback import callback_parameters, run_browser_login


class Connection:
    def __init__(self, data):
        self.data = data
        self.sent = []

    def settimeout(self, value):
        pass

    def makefile(self, *args):
        return io.BytesIO(self.data)

    def sendall(self, data):
        self.sent.append(data)


class FakeServer:
    server_port = 12345

    def __init__(self, requests):
        self.requests = iter(requests)
        self.count = 0

    def factory(self, address, handler):
        self.handler = handler
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def handle_request(self):
        self.count += 1
        self.handler(Connection(next(self.requests)), ('127.0.0.1', 123), self)


def request(path, host='127.0.0.1:12345'):
    return f'GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n'.encode()


class BrowserCallback(unittest.TestCase):
    def flow(self):
        flow = Mock()
        flow.authorization_url.return_value = ('https://accounts.google.com/example', 'expected')
        return flow

    def test_empty_probe_and_unrelated_requests_do_not_end_login(self):
        server = FakeServer([b'', request('/favicon.ico'), request('/?code=bad&state=wrong'),
                             request('/?code=good&state=expected', 'evil.example'),
                             request('/?code=good&state=expected')])
        flow = self.flow()
        with contextlib.redirect_stdout(io.StringIO()):
            result = run_browser_login(flow, server_factory=server.factory, open_browser=Mock())
        self.assertEqual(server.count, 5)
        self.assertEqual(result, flow.credentials)
        self.assertEqual(flow.redirect_uri, 'http://127.0.0.1:12345/')
        flow.fetch_token.assert_called_once_with(code='good')

    def test_oauth_denial_does_not_exchange_token(self):
        server = FakeServer([request('/?error=access_denied&state=expected')])
        flow = self.flow()
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'declined'):
            run_browser_login(flow, server_factory=server.factory, open_browser=Mock())
        flow.fetch_token.assert_not_called()

    def test_real_timeout_has_readable_error(self):
        server = FakeServer([])
        flow = self.flow()
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, 'timed out'):
            run_browser_login(flow, timeout=0, server_factory=server.factory, open_browser=Mock())
        flow.fetch_token.assert_not_called()

    def test_rejects_missing_or_duplicate_state_and_ambiguous_result(self):
        for path in ['/', '/?code=x', '/?code=x&state=expected&state=expected',
                     '/?code=x&code=y&state=expected', '/?code=x&error=denied&state=expected']:
            self.assertIsNone(callback_parameters(path, 'expected'))
