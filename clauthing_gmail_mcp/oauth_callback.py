"""Wait for a genuine OAuth callback, tolerating browser connection probes."""
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


def callback_parameters(path, state):
    parsed = urlsplit(path)
    if parsed.path != '/' or len(path) > 8192:
        return None
    parameters = parse_qs(parsed.query)
    received = parameters.get('state', [])
    if len(received) != 1 or not secrets.compare_digest(received[0], state):
        return None
    for field in ('code', 'error'):
        if len(parameters.get(field, [])) == 1 and not parameters.get('error' if field == 'code' else 'code'):
            return field, parameters[field][0]
    return None


def run_browser_login(flow, *, timeout=300, server_factory=ThreadingHTTPServer, open_browser=None):
    completed = threading.Event()
    result = []
    result_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(2)
            super().setup()

        def log_message(self, *args):
            pass  # Callback URLs contain authorization codes: never log them.

        def do_GET(self):
            if self.headers.get('Host') != f'127.0.0.1:{server.server_port}':
                self.send_error(400, 'Invalid host')
                return
            parameters = callback_parameters(self.path, state)
            if parameters is None:
                self.send_error(400, 'Waiting for the Google login callback')
                return
            with result_lock:
                if not result:
                    result.append(parameters)
                    completed.set()
            body = b'Login response received. You may return to the terminal.'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

    with server_factory(('127.0.0.1', 0), Handler) as server:
        server.daemon_threads = True
        flow.redirect_uri = f'http://127.0.0.1:{server.server_port}/'
        url, state = flow.authorization_url(access_type='offline', prompt='consent')
        print(f'Please visit this URL to authorize this application: {url}', flush=True)
        (open_browser or webbrowser.open)(url, new=1, autoraise=True)
        deadline = time.monotonic() + timeout
        while not completed.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('Google login timed out waiting for the local callback. '
                                   'Allow the browser to access localhost, then run auth again.')
            server.timeout = min(0.2, remaining)
            server.handle_request()
    field, value = result[0]
    if field == 'error':
        raise RuntimeError('Google login was declined or failed; no login was saved')
    # State was checked above. The library supplies its PKCE verifier during exchange.
    flow.fetch_token(code=value)
    return flow.credentials
