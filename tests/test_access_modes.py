import json
import os
import select
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from clauthing_gmail_mcp.broker import Broker
from clauthing_gmail_mcp.intervals import interval_seconds
from clauthing_gmail_mcp.mail import FixtureMail
from clauthing_gmail_mcp.store import Denied, Store

FIXTURE = Path(__file__).resolve().parents[1]/'demo-mail.json'


class AccessModes(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(self.temp.name)
        self.addCleanup(self.store.close)
        identity = self.store.client_add('test')
        self.token, self.client = identity['token'], identity['client_id']
        self.broker = Broker(self.store, FixtureMail(FIXTURE))

    def grant(self, mode, operation='list', **kwargs):
        return self.store.grant(self.client, operation, '*@anthropic.example', 600,
                                None, mode=mode, name='Login emails', **kwargs)['access']

    def test_once_consumed_and_separate_read_not_permitted(self):
        access = self.grant('once')
        with self.assertRaises(Denied):
            self.broker.call(self.token, 'read', {'access': access, 'message_id': 'demo-1'})
        result = self.broker.call(self.token, 'list', {'access': access})
        self.assertEqual([m['id'] for m in result['messages']], ['demo-1'])
        with self.assertRaises(Denied):
            self.broker.call(self.token, 'list', {'access': access})
        row = self.store.list('grants')[0]
        self.assertIsNone(row['name'])
        self.assertAlmostEqual(row['expires'], time.time()+600, delta=5)

    def test_once_expired_or_invalid_arguments(self):
        access = self.grant('once')
        with self.assertRaises(ValueError):
            self.broker.call(self.token, 'list', {'access': access, 'limit': 0})
        self.assertEqual(self.store.list('grants')[0]['consumed'], 0)
        with self.store.db:
            self.store.db.execute('UPDATE grants SET expires=?', (time.time()-1,))
        with self.assertRaises(Denied):
            self.broker.call(self.token, 'list', {'access': access})

    def test_once_consumption_is_atomic_across_connections(self):
        access = self.grant('once')
        def consume(_):
            store = Store(self.temp.name)
            try:
                try:
                    store.consume_once(access, self.client)
                    return True
                except Denied:
                    return False
            finally:
                store.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(consume, range(2))), 1)

    def test_ask_cannot_be_bypassed_using_args_or_omitting_access(self):
        access = self.grant('ask')
        for args in [{}, {'access': access, 'confirmed': True}]:
            with self.assertRaises(Denied):
                self.broker.call(self.token, 'list', args)
        approvals = []
        def confirm(rule, operation, arguments):
            approvals.append(rule['name'])
            return {'status': 'approved'}
        for _ in range(2):
            self.broker.call(self.token, 'list', {'access': access}, confirm=confirm)
        self.assertEqual(approvals, ['Login emails', 'Login emails'])
        denied = self.broker.call(self.token, 'list', {'access': access},
                                 confirm=lambda *args: {'status': 'denied', 'reason': 'Narrower, please'})
        self.assertEqual(denied['reason'], 'Narrower, please')
        self.assertFalse(self.store.allowed(self.client, 'list', {'headers': {'From': 'a@anthropic.example'},
                                                               'received_at': time.time()}))

    def test_scope_and_revocation_still_apply_after_confirmation(self):
        access = self.grant('ask', 'read')
        with self.assertRaises(Denied):
            self.broker.call(self.token, 'read', {'access': access, 'message_id': 'demo-2'},
                             confirm=lambda *args: {'status': 'approved'})
        def revoke(*args):
            self.store.revoke('grant', access)
            return {'status': 'approved'}
        with self.assertRaises(Denied):
            self.broker.call(self.token, 'read', {'access': access, 'message_id': 'demo-1'}, confirm=revoke)

    def test_pending_once_request_can_only_be_approved_once_concurrently(self):
        pending = self.store.request(self.client, 'list', '*@anthropic.example', 600)
        def approve(_):
            store = Store(self.temp.name)
            try:
                try:
                    store.approve(pending['request_id'], None, expected_client=self.client, mode='once')
                    return True
                except ValueError:
                    return False
            finally:
                store.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(approve, range(2))), 1)
        self.assertEqual(len(self.store.list('grants')), 1)

    def test_failed_provider_call_still_consumes_once(self):
        access = self.grant('once')
        def failed(*args):
            raise RuntimeError('offline')
        self.broker.mail.ids = failed
        with self.assertRaises(RuntimeError):
            self.broker.call(self.token, 'list', {'access': access})
        self.assertEqual(self.store.list('grants')[0]['consumed'], 1)
        with self.assertRaises(Denied):
            self.broker.call(self.token, 'list', {'access': access})

    def test_existing_policy_migrates_without_changing_access(self):
        with tempfile.TemporaryDirectory() as directory:
            db = sqlite3.connect(Path(directory)/'policy.sqlite')
            db.executescript("""
                CREATE TABLE grants (id TEXT PRIMARY KEY, client_id TEXT NOT NULL,
                    operation TEXT NOT NULL, sender TEXT NOT NULL, max_age_seconds INTEGER,
                    expires REAL, revoked INTEGER NOT NULL DEFAULT 0);
                INSERT INTO grants VALUES ('old', 'client', 'list', '*@example.com', 600, NULL, 0);
            """)
            db.close()
            migrated = Store(directory)
            try:
                grant = migrated.list('grants')[0]
                self.assertEqual(grant['id'], 'old')
                self.assertEqual(grant['mode'], 'auto')
                self.assertIsNone(grant['expires'])
                self.assertEqual(grant['consumed'], 0)
            finally:
                migrated.close()

    def test_intervals(self):
        for text, seconds in [('30m', 1800), ('2h', 7200), ('7d', 604800), ('1 hour', 3600),
                              ('15 minutes', 900), ('2 weeks', 1209600)]:
            self.assertEqual(interval_seconds(text), seconds)
        for text in ['', '0h', '-1h', 'forever', 'saved', None, '1h garbage']:
            with self.assertRaises(ValueError):
                interval_seconds(text)


class ElicitationModes(unittest.TestCase):
    def setUp(self):
        AccessModes.setUp(self)
        code = '''
import os
from clauthing_gmail_mcp.client import serve_stdio
from clauthing_gmail_mcp.broker import Broker
from clauthing_gmail_mcp.mail import FixtureMail
from clauthing_gmail_mcp.store import Store
store = Store(os.environ['TEST_STATE'])
serve_stdio('', os.environ['TEST_TOKEN'], os.environ['TEST_STATE'],
            broker=Broker(store, FixtureMail(os.environ['TEST_FIXTURE'])))
'''
        self.process = subprocess.Popen([sys.executable, '-c', code], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=dict(os.environ, TEST_STATE=self.temp.name, TEST_TOKEN=self.token, TEST_FIXTURE=str(FIXTURE)))
        self.addCleanup(self.stop)
        self.sequence = 0
        self.send({'jsonrpc': '2.0', 'id': 0, 'method': 'initialize',
                   'params': {'capabilities': {'elicitation': {}}}})
        self.receive()

    def stop(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.process.stdout.close()
        self.process.stderr.close()

    def send(self, value):
        self.process.stdin.write(json.dumps(value)+'\n')
        self.process.stdin.flush()

    def receive(self):
        self.assertTrue(select.select([self.process.stdout], [], [], 5)[0], 'Response timed out')
        return json.loads(self.process.stdout.readline())

    def tool(self, tool_name, **arguments):
        self.sequence += 1
        self.send({'jsonrpc': '2.0', 'id': self.sequence, 'method': 'tools/call',
                   'params': {'name': tool_name, 'arguments': arguments}})
        return self.receive()

    def reply(self, prompt, content=None, action='accept'):
        self.send({'jsonrpc': '2.0', 'id': prompt['id'], 'result': {'action': action, 'content': content}})
        return self.receive()

    def request(self, choice):
        prompt = self.tool('request_access', operation='list', sender='*@anthropic.example',
                           max_age_seconds=600, name='Anthropic logins')
        fields = prompt['params']['requestedSchema']['properties']
        self.assertEqual(fields['duration']['enum'], ['once', 'ask', 'auto', 'deny'])
        self.assertNotIn('reason', fields)
        self.assertNotIn('name', fields)
        self.assertIn('Anthropic logins', prompt['params']['message'])
        return self.reply(prompt, {'duration': choice})

    def result(self, response):
        self.assertFalse(response['result']['isError'], response)
        return json.loads(response['result']['content'][0]['text'])

    def test_auto_opens_duration_form_and_saves_custom_interval(self):
        prompt = self.request('auto')
        self.assertEqual(prompt['params']['requestedSchema']['properties']['interval']['default'], '1h')
        result = self.result(self.reply(prompt, {'interval': '2 hours'}))
        self.assertEqual(result['mode'], 'auto')
        self.assertEqual(result['duration_seconds'], 7200)
        self.assertEqual(result['name'], 'Anthropic logins')
        listing = self.result(self.tool('list_messages', access=result['access']))
        self.assertEqual(len(listing['messages']), 1)

    def test_auto_default_and_cancelling_or_invalid_duration_grants_nothing(self):
        prompt = self.request('auto')
        self.assertEqual(self.result(self.reply(prompt, {}, action='cancel'))['status'], 'cancel')
        self.assertEqual(self.store.list('grants'), [])
        prompt = self.request('auto')
        response = self.reply(prompt, {'interval': 'forever'})
        self.assertTrue(response['result']['isError'])
        self.assertEqual(self.store.list('grants'), [])
        prompt = self.request('auto')
        self.assertEqual(self.result(self.reply(prompt, {}))['duration_seconds'], 3600)

    def test_ask_use_prompts_with_name_each_time_and_can_deny_with_reason(self):
        access = self.result(self.request('ask'))['access']
        for _ in range(2):
            prompt = self.tool('list_messages', access=access)
            self.assertEqual(prompt['params']['requestedSchema']['properties']['allow']['enum'], ['Yes', 'No'])
            self.assertIn('Anthropic logins', prompt['params']['message'])
            self.assertNotIn('*@anthropic.example', prompt['params']['message'])
            self.assertEqual(len(self.result(self.reply(prompt, {'allow': 'Yes'}))['messages']), 1)
        prompt = self.tool('list_messages', access=access)
        feedback = self.reply(prompt, {'allow': 'No'})
        denial = self.result(self.reply(feedback, {'reason': 'Not now'}))
        self.assertEqual(denial, {'status': 'denied', 'reason': 'Not now'})

    def test_once_needs_no_followup_and_is_not_reusable(self):
        access = self.result(self.request('once'))['access']
        self.result(self.tool('list_messages', access=access))
        response = self.tool('list_messages', access=access)
        self.assertTrue(response['result']['isError'])
