"""HTTP broker. No owner/approval operations are exposed over the client interface."""
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from .store import Denied, Store, matches, validate_rule


class Broker:
    def __init__(self, store, mail):
        self.store, self.mail = store, mail

    def call(self, token, operation, args, *, confirm=None):
        client = self.store.authenticate(token)
        if operation == 'request_access':
            return self.store.request(client, args['operation'], args['sender'], args.get('max_age_seconds'), args.get('name'))
        if operation not in ('list', 'read'):
            raise ValueError('Unknown operation')
        rules = self.store.rules(client, operation)
        access = args.get('access')
        if access is not None:
            rules = [r for r in rules if r['id'] == access]
        else:
            automatic = [r for r in rules if r['mode'] == 'auto']
            rules = automatic or [r for r in rules if r['mode'] == 'once'][:1]
        if not rules:
            raise Denied(f'No active {operation} permission. Request access first.')
        approved_ids = {r['id'] for r in rules}
        reserved = set()
        def allowed(message):
            return any(r['id'] in approved_ids and (not r['consumed'] or r['id'] in reserved)
                       and matches(r, message)
                       for r in self.store.rules(client, operation, include_consumed=True))
        # Validate arguments before consuming an approval or opening a prompt.
        if operation == 'read' and not isinstance(args.get('message_id'), str):
            raise ValueError('message_id must be a string')
        if operation == 'list':
            if type(args.get('limit', 20)) is not int or not 1 <= args.get('limit', 20) <= 100:
                raise ValueError('Limit must be an integer from 1 to 100')
            validate_rule('list', args.get('sender', '*'), args.get('max_age_seconds'))
        for rule in rules:
            if rule['mode'] == 'ask':
                if confirm is None:
                    raise Denied('This access requires confirmation through MCP')
                decision = confirm(rule, operation, dict(args))
                if decision.get('status') != 'approved':
                    return decision
            if rule['mode'] == 'once':
                self.store.consume_once(rule['id'], client)
                reserved.add(rule['id'])
        # Owner may revoke while the confirmation is open.
        live_ids = {r['id'] for r in self.store.rules(client, operation, include_consumed=True)}
        if not approved_ids <= live_ids:
            raise Denied('Permission expired or was revoked')
        if operation == 'list':
            limit = args.get('limit', 20)
            if type(limit) is not int or not 1 <= limit <= 100:
                raise ValueError('Limit must be an integer from 1 to 100')
            sender = args.get('sender', '*')
            age = args.get('max_age_seconds')
            validate_rule('list', sender, age)
            ages = [rule['max_age_seconds'] for rule in rules]
            rule_age = None if None in ages else max(ages)
            effective_age = age if rule_age is None else rule_age if age is None else min(age, rule_age)
            query = '' if effective_age is None else f'after:{int(time.time()-effective_age)}'
            identifiers = self.mail.ids(query, 1000)
            messages = []
            narrowed = {'sender': sender, 'max_age_seconds': age}
            for identifier in identifiers:
                metadata = self.mail.metadata(identifier)
                if allowed(metadata) and matches(narrowed, metadata):
                    messages.append(metadata)
                    if len(messages) == limit:
                        break
            # Recheck grants after all provider I/O, including possible owner revocation.
            result = {'messages': [m for m in messages if allowed(m) and matches(narrowed, m)],
                      'scan_limit_reached': len(identifiers) == 1000,
                      'untrusted_content': True}
        else:
            identifier = args['message_id']
            metadata = self.mail.metadata(identifier)
            if not allowed(metadata):
                raise Denied('No read permission for this sender/message age')
            result = self.mail.read(identifier)
            if not allowed(metadata):
                raise Denied('Read permission expired or was revoked')
        self.store.audit(client, operation, sender if operation == 'list' else args['message_id'])
        return result


def serve(directory, mail, port=8767):
    store = Store(directory)
    broker = Broker(store, mail)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log Authorization headers or message contents.

        def reply(self, status, value):
            payload = json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):
            if self.path != '/rpc' or self.headers.get('Origin'):
                return self.reply(403, {'error': 'Not permitted'})
            # Prevent browser DNS-rebinding access; the service binds only loopback.
            if self.headers.get('Host') != f'127.0.0.1:{self.server.server_port}':
                return self.reply(403, {'error': 'Invalid host'})
            authorization = self.headers.get('Authorization', '')
            if not authorization.startswith('Bearer '):
                return self.reply(401, {'error': 'Client token required'})
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 16384:
                    raise ValueError('Invalid request size')
                request = json.loads(self.rfile.read(length))
                if not isinstance(request, dict) or not isinstance(request.get('arguments', {}), dict):
                    raise ValueError('Expected an object request and arguments')
                result = broker.call(authorization[7:], request['operation'], request.get('arguments', {}))
                self.reply(200, result)
            except Denied as error:
                self.reply(403, {'error': str(error)})
            except (ValueError, KeyError, TypeError) as error:
                self.reply(400, {'error': str(error)})
            except Exception:
                self.reply(502, {'error': 'Mail backend failed; check broker setup and Google credentials'})

    server = HTTPServer(('127.0.0.1', port), Handler)
    server.timeout = 1
    print(f'Broker listening on http://127.0.0.1:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        store.close()
