import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from clauthing_gmail_mcp.cli import main


class OwnerTop(unittest.TestCase):
    def run_top(self, extra=(), empty=False):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'policy'
            auth = Path(directory)/'auth'
            output = io.StringIO()
            with patch('sys.argv', ['gmail', '--state', str(state), '--auth-state', str(auth), 'top', *extra]), \
                 patch('clauthing_gmail_mcp.cli.Gmail') as gmail, \
                 patch('clauthing_gmail_mcp.cli.Store') as store, \
                 patch('clauthing_gmail_mcp.cli.call') as broker, \
                 contextlib.redirect_stdout(output):
                mail = gmail.return_value
                mail.ids.return_value = [] if empty else ['newest']
                mail.read.return_value = {'id': 'newest', 'headers': {'From': 'sender@example.com',
                    'Subject': 'A message'}, 'body': 'Hello there', 'body_truncated': False}
                main()
            gmail.assert_called_once_with(auth)
            mail.ids.assert_called_once_with('', limit=1)
            if empty:
                mail.read.assert_not_called()
            else:
                mail.read.assert_called_once_with('newest')
            store.assert_not_called()
            broker.assert_not_called()
            self.assertFalse(state.exists())
            return output.getvalue()

    def test_plain_output_needs_no_agent_permission_setup(self):
        output = self.run_top()
        self.assertIn('From: sender@example.com', output)
        self.assertIn('Subject: A message', output)
        self.assertIn('Hello there', output)

    def test_json_and_empty_mailbox(self):
        self.assertEqual(json.loads(self.run_top(['--json']))['id'], 'newest')
        self.assertEqual(self.run_top(empty=True).strip(), 'No emails found.')
        self.assertIsNone(json.loads(self.run_top(['--json'], empty=True)))
