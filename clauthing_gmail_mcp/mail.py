"""Gmail transport: list/get only. OAuth token refresh is the only POST."""
import base64
import email
import email.policy
import json
import os
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

SCOPE = 'https://www.googleapis.com/auth/gmail.readonly'


def configure_client(directory, client_id=None, client_secret=None, credentials_file=None):
    """Save a dedicated OAuth registration, or reuse this application's saved one."""
    path = Path(directory) / 'oauth-client.json'
    if credentials_file is not None and (client_id is not None or client_secret is not None):
        raise ValueError('Use either --credentials or --client-id with --client-secret')
    if credentials_file is not None:
        source = json.loads(Path(credentials_file).read_text())
        installed = source.get('installed')
        if not isinstance(installed, dict):
            raise ValueError('Use credentials for a Google Desktop app OAuth client')
        client_id, client_secret = installed.get('client_id'), installed.get('client_secret')
        if not client_id or not client_secret:
            raise ValueError('Desktop OAuth JSON must contain client_id and client_secret')
    if client_id is None and client_secret is None:
        if not path.is_file():
            raise ValueError('No saved Gmail client credentials. Supply --client-id and --client-secret.')
        # Validate saved credentials too; never print their contents.
        saved = json.loads(path.read_text())
        installed = saved.get('installed', {})
        client_id, client_secret = installed.get('client_id'), installed.get('client_secret')
    if (not isinstance(client_id, str) or not client_id.strip()
            or not isinstance(client_secret, str) or not client_secret.strip()):
        raise ValueError('Both --client-id and --client-secret are required together and must be nonempty')
    config = {'installed': {
        'client_id': client_id.strip(), 'client_secret': client_secret.strip(),
        'auth_uri': 'https://accounts.google.com/o/oauth2/auth',
        'token_uri': 'https://oauth2.googleapis.com/token',
        'redirect_uris': ['http://localhost'],
    }}
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    private_json(path, config)
    return path


def private_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as target:
            json.dump(value, target)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def cached_login(directory, config, credentials_class, request_factory):
    """Reuse/refresh only a readonly token issued to the configured OAuth client."""
    path = Path(directory) / 'google-token.json'
    if not path.exists():
        return False
    saved = json.loads(path.read_text())
    installed = config['installed']
    if (saved.get('client_id') != installed['client_id']
            or saved.get('client_secret') != installed['client_secret']
            or set(saved.get('scopes', [])) != {SCOPE}
            or not saved.get('refresh_token')):
        return False
    credentials = credentials_class.from_authorized_user_info(saved, [SCOPE])
    if not credentials.valid:
        credentials.refresh(request_factory())
    if set(credentials.granted_scopes or credentials.scopes or []) != {SCOPE}:
        raise ValueError('Unexpected scopes in cached Google login')
    private_json(path, json.loads(credentials.to_json()))
    return True


def login(directory, credentials_file, reauth=False):
    config = json.loads(Path(credentials_file).read_text())
    if 'installed' not in config:
        raise ValueError('Use credentials for a Google Desktop app OAuth client')
    if not reauth and (Path(directory) / 'google-token.json').exists():
        from google.auth.exceptions import RefreshError, TransportError
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        try:
            if cached_login(directory, config, Credentials, Request):
                return {'status': 'authenticated', 'scope': SCOPE, 'login': 'cached'}
        except TransportError:
            raise RuntimeError('Unable to refresh saved login due to a network error; retry without signing in again') from None
        except RefreshError as error:
            if error.retryable:
                raise RuntimeError('Google temporarily rejected refresh; retry without signing in again') from None
            # Revoked/expired refresh tokens require a fresh browser consent.
    from google_auth_oauthlib.flow import InstalledAppFlow
    # PKCE and browser consent are handled by Google's installed-app library.
    flow = InstalledAppFlow.from_client_config(config, [SCOPE], autogenerate_code_verifier=True)
    from .oauth_callback import run_browser_login
    credentials = run_browser_login(flow)
    granted = set(credentials.granted_scopes or credentials.scopes or [])
    if granted != {SCOPE}:
        raise ValueError('Google returned unexpected scopes; no credentials were saved')
    if not credentials.refresh_token:
        raise ValueError('Google did not issue a refresh token; no credentials were saved')
    private_json(Path(directory) / 'google-token.json', json.loads(credentials.to_json()))
    return {'status': 'authenticated', 'scope': SCOPE, 'login': 'browser'}


class Gmail:
    def __init__(self, directory):
        self.path = Path(directory) / 'google-token.json'
        self.credentials = None

    def get(self, path, **params):
        from google.auth.transport.requests import AuthorizedSession, Request
        from google.oauth2.credentials import Credentials
        if self.credentials is None:
            if not self.path.is_file():
                raise ValueError('No saved Google login. Run clauthing-gmail-mcp auth first.')
            saved = json.loads(self.path.read_text())
            if set(saved.get('scopes', [])) != {SCOPE}:
                raise ValueError('Refusing credentials with scopes other than gmail.readonly')
            self.credentials = Credentials.from_authorized_user_info(saved, [SCOPE])
        if not self.credentials.valid:
            self.credentials.refresh(Request())
            if set(self.credentials.granted_scopes or self.credentials.scopes or []) != {SCOPE}:
                raise ValueError('Unexpected scopes after token refresh')
            private_json(self.path, json.loads(self.credentials.to_json()))
        with AuthorizedSession(self.credentials) as session:
            response = session.get('https://gmail.googleapis.com/gmail/v1/users/me/' + path,
                                   params=params, timeout=30, allow_redirects=False)
            if response.status_code != 200:
                raise RuntimeError(f'Gmail returned HTTP {response.status_code}; check access/API setup')
            return response.json()

    def ids(self, query, limit=None):
        result, page = [], None
        while True:
            params = {'q': query, 'maxResults': min(limit or 500, 500)}
            if page:
                params['pageToken'] = page
            data = self.get('messages', **params)
            result.extend(item['id'] for item in data.get('messages', []))
            if limit is not None and len(result) >= limit:
                return result[:limit]
            page = data.get('nextPageToken')
            if not page:
                return result

    def contains(self, query, message_id):
        # Evaluate the approved query itself: never concatenate untrusted Gmail syntax.
        return message_id in self.ids(query)

    def metadata(self, message_id):
        data = self.get('messages/' + quote(message_id, safe=''), format='metadata',
                        metadataHeaders=['From', 'To', 'Subject', 'Date'])
        headers = {h['name'].lower(): h['value'] for h in data.get('payload', {}).get('headers', [])}
        return {'id': data['id'], 'headers': {k: v for k, v in headers.items() if k in ('from', 'subject', 'date')},
                'received_at': int(data['internalDate']) / 1000}

    def read(self, message_id):
        data = self.get('messages/' + quote(message_id, safe=''), format='raw')
        encoded = data['raw']
        raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
        message = email.message_from_bytes(raw, policy=email.policy.default)
        body = message.get_body(preferencelist=('plain', 'html'))
        content = body.get_content() if body else ''
        return {'id': data['id'],
                'headers': {name: str(message.get(name, '')) for name in ['From', 'To', 'Subject', 'Date']},
                'body': content[:20000], 'body_truncated': len(content) > 20000,
                'content_type': body.get_content_type() if body else 'text/plain',
                'untrusted_content': True}


class FixtureMail:
    """Offline backend supporting only the broker's generated after: queries."""
    def __init__(self, path):
        self.data = json.loads(Path(path).read_text())
        for message in self.data['messages'].values():
            message['received_at'] = time.time() - message.get('age_seconds', 0)

    def ids(self, query, limit=None):
        since = int(query.removeprefix('after:')) if query else 0
        return [key for key, value in self.data['messages'].items()
                if value['received_at'] > since][:limit]

    def contains(self, query, message_id):
        return message_id in self.ids(query)

    def metadata(self, message_id):
        data = self.data['messages'][message_id]
        return {'id': message_id, 'headers': data['headers'], 'received_at': data['received_at']}

    def read(self, message_id):
        return dict(self.data['messages'][message_id], id=message_id, untrusted_content=True)
