import argparse
import json
import os
import sys
from pathlib import Path

from .client import call, serve_stdio
from .mail import FixtureMail, Gmail, configure_client, login
from .paths import config_directory, data_directory, project_directory
from .store import Denied, Store


def duration(value):
    if value == 'saved':
        return None
    try:
        factors = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
        result = int(value[:-1]) * factors[value[-1]]
        if result <= 0:
            raise ValueError()
        return result
    except (ValueError, KeyError, IndexError):
        raise argparse.ArgumentTypeError('Use 15m, 1h, 1d, or saved') from None


def parser():
    p = argparse.ArgumentParser(description='Clauthing Gmail MCP — Selective Access')
    p.add_argument('--state', type=Path, default=project_directory(),
                   help='Private project policy directory (default: home data directory indexed by current directory)')
    p.add_argument('--auth-state', type=Path, default=data_directory(),
                   help='Private Google login directory, shared across project directories')
    p.add_argument('--url', default='http://127.0.0.1:8767')
    p.add_argument('--token-file', type=Path, help='Client token file (never Google credentials)')
    sub = p.add_subparsers(dest='command', required=True)
    auth = sub.add_parser('auth', help='Owner: browser sign-in for gmail.readonly')
    auth.add_argument('--client-id', help='Dedicated Google Desktop OAuth client ID; saved for future logins')
    auth.add_argument('--client-secret', help='Matching OAuth client secret; saved for future logins')
    auth.add_argument('--credentials', type=Path, help='Alternatively import downloaded Desktop OAuth JSON')
    auth.add_argument('--reauth', action='store_true', help='Force browser sign-in instead of reusing the saved login')
    auth.add_argument('--config-dir', type=Path,
                      default=config_directory(),
                      help='Credential directory (default: ~/.config/clauthing-gmail-mcp)')
    server = sub.add_parser('serve', help='Owner: run local broker')
    server.add_argument('--port', type=int, default=8767)
    server.add_argument('--fixture', type=Path, help='Fake mail for offline development')
    add = sub.add_parser('client-add', help='Owner: create revocable client identity')
    add.add_argument('name')
    add.add_argument('--out', type=Path, help='Client token file (default: client.token in this project policy directory)')
    for name in ['clients', 'grants', 'requests', 'audit']:
        sub.add_parser(name, help='Owner: list ' + name)
    grant = sub.add_parser('grant', help='Owner: grant separate list or read permission')
    grant.add_argument('client_id')
    grant.add_argument('operation', choices=['list', 'read'])
    grant.add_argument('--sender', required=True)
    grant.add_argument('--last', type=duration, help='Rolling message age, e.g. 10m; omit for any age')
    grant.add_argument('--for', dest='seconds', required=True, type=duration)
    approve = sub.add_parser('approve', help='Owner: approve a pending access request')
    approve.add_argument('request_id')
    approve.add_argument('--for', dest='seconds', required=True, type=duration)
    revoke = sub.add_parser('revoke', help='Owner: revoke a grant or entire client')
    revoke.add_argument('kind', choices=['grant', 'client'])
    revoke.add_argument('id')
    request = sub.add_parser('request', help='Client: request access without revealing mail')
    request.add_argument('operation', choices=['list', 'read'])
    request.add_argument('--sender', required=True)
    request.add_argument('--last', type=duration)
    request.add_argument('--name', help='Suggested name for reusable access')
    listing = sub.add_parser('list', help='Client: list permitted message headers only')
    listing.add_argument('--sender', default='*')
    listing.add_argument('--last', type=duration)
    listing.add_argument('--limit', type=int, default=20)
    read = sub.add_parser('read', help='Client: read an in-scope message')
    read.add_argument('message_id')
    for command in (listing, read):
        command.add_argument('--access', help='Use the exact access ID returned by request_access')
    mcp = sub.add_parser('mcp', help='Serve MCP over stdio with automatic identity and embedded broker')
    mcp.add_argument('--external-broker', action='store_true',
                     help='Use a separately started HTTP broker instead of the embedded broker')
    mcp.add_argument('--approval-state', type=Path,
                     help='Owner policy directory (default: current directory indexed private project state)')
    mcp.add_argument('--no-elicitation', action='store_true',
                     help='Leave requests pending for manual owner CLI approval')
    top = sub.add_parser('top', help='Owner: show the newest email directly using the saved Google login')
    top.add_argument('--json', action='store_true', help='Output the message as JSON')
    sub.add_parser('paths', help='Show resolved project policy, token, and Google login paths without creating files')
    return p


def main():
    args = parser().parse_args()
    try:
        if args.command == 'paths':
            result = {'cwd': str(Path.cwd().resolve()), 'policy_directory': str(args.state),
                      'token_file': str(args.token_file or args.state/'client.token'),
                      'google_login_directory': str(args.auth_state),
                      'config_directory': str(config_directory())}
        elif args.command == 'top':
            mail = Gmail(args.auth_state)
            identifiers = mail.ids('', limit=1)
            result = mail.read(identifiers[0]) if identifiers else None
            if not args.json:
                if result is None:
                    print('No emails found.')
                else:
                    headers = {key.lower(): value for key, value in result['headers'].items()}
                    for key in ('from', 'to', 'date', 'subject'):
                        print(f'{key.title()}: {headers.get(key, "")}')
                    print()
                    print(result['body'])
                    if result.get('body_truncated'):
                        print('\n[Message body truncated]')
                return
        elif args.command in ('request', 'list', 'read', 'mcp'):
            if args.token_file:
                token = args.token_file.read_text().strip()
            else:
                token = os.environ.get('CLAUTHING_GMAIL_TOKEN')
                if not token:
                    token_path = args.state/'client.token'
                    if not token_path.is_file() and args.command == 'mcp' and not args.external_broker:
                        from .identity import ensure_identity
                        ensure_identity(args.state)
                    if not token_path.is_file():
                        raise ValueError('No client token for this directory. Run client-add NAME here first.')
                    token = token_path.read_text().strip()
            if args.command == 'mcp':
                if not token:
                    raise ValueError('Client token required')
                approval_state = None if args.no_elicitation else (args.approval_state or args.state)
                if args.external_broker:
                    return serve_stdio(args.url, token, approval_state)
                from .broker import Broker
                store = Store(args.state)
                try:
                    store.authenticate(token)
                    broker = Broker(store, Gmail(args.auth_state))
                    return serve_stdio(args.url, token, approval_state,
                                       broker=broker)
                finally:
                    store.close()
            parameters = {}
            if args.command in ('request', 'list'):
                parameters.update(sender=args.sender, max_age_seconds=args.last)
            if args.command == 'request':
                parameters['operation'] = args.operation
                parameters['name'] = args.name
            if args.command == 'list':
                parameters['limit'] = args.limit
            if args.command == 'read':
                parameters['message_id'] = args.message_id
            if args.command in ('list', 'read') and args.access:
                parameters['access'] = args.access
            result = call(args.url, token,
                          'request_access' if args.command == 'request' else args.command, parameters)
        elif args.command == 'serve':
            from .broker import serve
            return serve(args.state, FixtureMail(args.fixture) if args.fixture else Gmail(args.auth_state), args.port)
        elif args.command == 'auth':
            path = configure_client(args.config_dir, args.client_id, args.client_secret, args.credentials)
            result = login(args.auth_state, path, reauth=args.reauth)
            result['credentials_file'] = str(path)
        else:
            store = Store(args.state)
            try:
                if args.command == 'client-add':
                    args.out = args.out or args.state/'client.token'
                    # Avoid overwriting a credential file the owner may still use.
                    args.out.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'w') as target:
                        result = store.client_add(args.name)
                        target.write(result.pop('token') + '\n')
                    result['token_file'] = str(args.out)
                elif args.command in ('clients', 'grants', 'requests', 'audit'):
                    result = store.list(args.command)
                elif args.command == 'grant':
                    result = store.grant(args.client_id, args.operation, args.sender, args.last, args.seconds)
                elif args.command == 'approve':
                    result = store.approve(args.request_id, args.seconds)
                elif args.command == 'revoke':
                    result = store.revoke(args.kind, args.id)
            finally:
                store.close()
        print(json.dumps(result, indent=2))
    except (Denied, ValueError, RuntimeError, OSError, KeyError, ImportError) as error:
        print(json.dumps({'error': str(error)}), file=sys.stderr)
        return sys.exit(1)


if __name__ == '__main__':
    main()
