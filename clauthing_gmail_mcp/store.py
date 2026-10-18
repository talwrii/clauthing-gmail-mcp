"""Owner-managed policy; client tokens are hashed and list/read grants are separate."""
import fnmatch
import hashlib
import secrets
import sqlite3
import time
from email.utils import getaddresses
from pathlib import Path


class Denied(PermissionError):
    pass


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def validate_rule(operation, sender, max_age_seconds):
    if operation not in ('list', 'read'):
        raise ValueError('Operation must be list or read')
    if not isinstance(sender, str) or not sender or len(sender) > 256 or any(c.isspace() for c in sender):
        raise ValueError('Sender must be an address glob, such as *@anthropic.com')
    if max_age_seconds is not None and (type(max_age_seconds) is not int or max_age_seconds <= 0):
        raise ValueError('Message age must be a positive integer number of seconds')


def matches(rule, message, now=None):
    now = time.time() if now is None else now
    headers = {k.lower(): v for k, v in message.get('headers', {}).items()}
    addresses = getaddresses([headers.get('from', '')])
    if len(addresses) != 1 or not addresses[0][1] or '@' not in addresses[0][1]:
        return False
    if not fnmatch.fnmatchcase(addresses[0][1].lower(), rule['sender'].lower()):
        return False
    age = rule['max_age_seconds']
    received = message.get('received_at')
    if age is not None and (not isinstance(received, (int, float)) or not now-age <= received <= now+60):
        return False
    return True


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        self.db = sqlite3.connect(self.directory / 'policy.sqlite', timeout=30)
        self.db.row_factory = sqlite3.Row
        (self.directory / 'policy.sqlite').chmod(0o600)
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS grants (
            id TEXT PRIMARY KEY, client_id TEXT NOT NULL, operation TEXT NOT NULL,
            sender TEXT NOT NULL, max_age_seconds INTEGER, expires REAL,
            revoked INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS requests (
            id TEXT PRIMARY KEY, client_id TEXT NOT NULL, operation TEXT NOT NULL,
            sender TEXT NOT NULL, max_age_seconds INTEGER,
            created REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending');
          CREATE TABLE IF NOT EXISTS audit (
            at REAL NOT NULL, client_id TEXT NOT NULL, operation TEXT NOT NULL,
            detail TEXT NOT NULL);
        ''')
        for table, columns in {
            'grants': {'mode': "TEXT NOT NULL DEFAULT 'auto'", 'name': 'TEXT',
                       'consumed': 'INTEGER NOT NULL DEFAULT 0'},
            'requests': {'name': 'TEXT'},
        }.items():
            existing = {row['name'] for row in self.db.execute(f'PRAGMA table_info({table})')}
            for column, definition in columns.items():
                if column not in existing:
                    self.db.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
        self.db.commit()

    def close(self):
        self.db.close()

    def client_add(self, name):
        token = secrets.token_urlsafe(32)
        identifier = secrets.token_hex(8)
        with self.db:
            self.db.execute('INSERT INTO clients(id,name,token_hash) VALUES(?,?,?)',
                            (identifier, name, token_hash(token)))
        return {'client_id': identifier, 'name': name, 'token': token}

    def authenticate(self, token):
        row = self.db.execute('SELECT id FROM clients WHERE token_hash=? AND revoked=0',
                              (token_hash(token),)).fetchone()
        if not row:
            raise Denied('Invalid or revoked client token')
        return row['id']

    def grant(self, client_id, operation, sender, max_age_seconds, seconds, *, mode="auto", name=None):
        with self.db:
            return self._grant(client_id, operation, sender, max_age_seconds, seconds, mode=mode, name=name)

    def _grant(self, client_id, operation, sender, max_age_seconds, seconds, *, mode, name):
        validate_rule(operation, sender, max_age_seconds)
        if mode not in ('auto', 'ask', 'once'):
            raise ValueError('Unknown access mode')
        if name is not None and (not isinstance(name, str) or not name.strip() or len(name) > 120):
            raise ValueError('Access name must be 1–120 characters')
        if mode == 'once':
            seconds, name = 600, None
        if seconds is not None and seconds <= 0:
            raise ValueError('Grant duration must be positive')
        if not self.db.execute('SELECT 1 FROM clients WHERE id=? AND revoked=0',
                               (client_id,)).fetchone():
            raise ValueError('Unknown or revoked client')
        identifier = secrets.token_hex(8)
        self.db.execute('''INSERT INTO grants
                (id,client_id,operation,sender,max_age_seconds,expires,mode,name) VALUES(?,?,?,?,?,?,?,?)''',
                (identifier, client_id, operation, sender, max_age_seconds,
                 None if seconds is None else time.time() + seconds, mode, name))
        return {'grant_id': identifier, 'client_id': client_id, 'operation': operation,
                'sender': sender, 'max_age_seconds': max_age_seconds, 'duration_seconds': seconds, 'mode': mode, 'name': name, 'access': identifier}

    def rules(self, client_id, operation, *, include_consumed=False):
        return [dict(row) for row in self.db.execute('''SELECT * FROM grants WHERE client_id=?
          AND operation=? AND revoked=0 AND (consumed=0 OR ?) AND (expires IS NULL OR expires>?)
          AND EXISTS(SELECT 1 FROM clients WHERE id=? AND revoked=0)''',
          (client_id, operation, include_consumed, time.time(), client_id))]

    def allowed(self, client_id, operation, message):
        return any(rule['mode'] == 'auto' and matches(rule, message) for rule in self.rules(client_id, operation))

    def request(self, client_id, operation, sender, max_age_seconds, name=None):
        validate_rule(operation, sender, max_age_seconds)
        if name is not None and (not isinstance(name, str) or not name.strip() or len(name) > 120):
            raise ValueError('Access name must be 1–120 characters')
        row = self.db.execute('''SELECT id FROM requests WHERE client_id=? AND operation=?
          AND sender=? AND max_age_seconds IS ? AND name IS ? AND status='pending' ''',
          (client_id, operation, sender, max_age_seconds, name)).fetchone()
        identifier = row['id'] if row else secrets.token_hex(8)
        if not row:
            with self.db:
                self.db.execute('''INSERT INTO requests
                  (id,client_id,operation,sender,max_age_seconds,created,name) VALUES(?,?,?,?,?,?,?)''',
                  (identifier, client_id, operation, sender, max_age_seconds, time.time(), name))
        return {'status': 'approval_required', 'request_id': identifier, 'operation': operation,
                'sender': sender, 'max_age_seconds': max_age_seconds, 'name': name}

    def approve(self, request_id, seconds, expected_client=None, *, mode="auto", name=None):
        # Serialize claiming a pending request and inserting its grant across MCP processes.
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute("SELECT * FROM requests WHERE id=? AND status='pending'",
                                  (request_id,)).fetchone()
            if not row or (expected_client is not None and row['client_id'] != expected_client):
                raise ValueError('Unknown, foreign, or already handled request')
            result = self._grant(row['client_id'], row['operation'], row['sender'], row['max_age_seconds'],
                                 seconds, mode=mode, name=name or row['name'])
            self.db.execute("UPDATE requests SET status='approved' WHERE id=?", (request_id,))
        return result

    def consume_once(self, grant_id, client_id):
        with self.db:
            cursor = self.db.execute("""UPDATE grants SET consumed=1 WHERE id=? AND client_id=?
                AND mode='once' AND consumed=0 AND revoked=0 AND expires>?
                AND EXISTS(SELECT 1 FROM clients WHERE id=? AND revoked=0)""",
                (grant_id, client_id, time.time(), client_id))
            if cursor.rowcount != 1:
                raise Denied('One-use approval expired or was already used')

    def deny(self, request_id, expected_client):
        with self.db:
            cursor = self.db.execute(
                "UPDATE requests SET status='denied' WHERE id=? AND client_id=? AND status='pending'",
                (request_id, expected_client))
            if not cursor.rowcount:
                raise ValueError('Unknown, foreign, or already handled request')

    def revoke(self, kind, identifier):
        table = {'client': 'clients', 'grant': 'grants'}[kind]
        with self.db:
            cursor = self.db.execute(f'UPDATE {table} SET revoked=1 WHERE id=?', (identifier,))
        if not cursor.rowcount:
            raise ValueError('Unknown identifier')
        return {'revoked': identifier, 'kind': kind}

    def list(self, kind):
        queries = {
            'clients': 'SELECT id,name,revoked FROM clients',
            'grants': 'SELECT * FROM grants',
            'requests': "SELECT * FROM requests WHERE status='pending'",
            'audit': 'SELECT * FROM audit ORDER BY at DESC LIMIT 100',
        }
        return [dict(row) for row in self.db.execute(queries[kind])]

    def audit(self, client_id, operation, detail):
        with self.db:
            self.db.execute('INSERT INTO audit VALUES(?,?,?,?)',
                            (time.time(), client_id, operation, detail))
