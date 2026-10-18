import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from clauthing_gmail_mcp.store import Store


class AutomaticStartup(unittest.TestCase):
    def test_fresh_mcp_starts_without_login_or_broker_and_reuses_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root/'policy'
            env = dict(os.environ, CLAUTHING_GMAIL_TOKEN='', XDG_DATA_HOME=str(root/'data'))
            requests = [
                {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}},
                {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
                {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                 'params': {'name': 'list_messages', 'arguments': {}}},
                {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call',
                 'params': {'name': 'request_access', 'arguments': {
                     'operation': 'list', 'sender': '*@anthropic.com', 'max_age_seconds': 600}}},
            ]
            command = [sys.executable, '-m', 'clauthing_gmail_mcp', '--state', str(state), 'mcp']
            def launch():
                result = subprocess.run(command, input=''.join(json.dumps(r)+'\n' for r in requests),
                                        text=True, capture_output=True, env=env, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                return [json.loads(line) for line in result.stdout.splitlines()]
            responses = launch()
            self.assertIn('serverInfo', responses[0]['result'])
            self.assertEqual(len(responses[1]['result']['tools']), 3)
            self.assertTrue(responses[2]['result']['isError'])
            self.assertFalse(responses[3]['result']['isError'])
            token = (state/'client.token').read_bytes()
            launch()
            self.assertEqual((state/'client.token').read_bytes(), token)
            store = Store(state)
            try:
                self.assertEqual(len(store.list('clients')), 1)
                self.assertEqual(store.list('grants'), [])
                self.assertEqual(len(store.list('requests')), 1)
            finally:
                store.close()
            self.assertFalse((root/'data').exists())
