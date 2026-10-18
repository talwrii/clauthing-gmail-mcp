import json
import tempfile
import os
import select
import subprocess
import sys
import time
import unittest
from pathlib import Path

from clauthing_gmail_mcp.broker import Broker
from clauthing_gmail_mcp.client import approval_from_response, mcp_dispatch
from clauthing_gmail_mcp.store import Denied, Store, matches


class Mail:
    def __init__(self):
        now = time.time()
        self.messages = {
            'recent': {'id': 'recent', 'headers': {'From': 'Login <login@anthropic.example>',
                         'Subject': 'Login'}, 'received_at': now-60},
            'old': {'id': 'old', 'headers': {'From': 'login@anthropic.example'}, 'received_at': now-3600},
            'other': {'id': 'other', 'headers': {'From': 'bob@example.com'}, 'received_at': now-60},
        }
        self.body_reads = []
        self.after_read = None

    def ids(self, query, limit=None):
        return list(self.messages)[:limit]

    def metadata(self, identifier):
        return self.messages[identifier]

    def read(self, identifier):
        self.body_reads.append(identifier)
        if self.after_read:
            self.after_read()
        return {'id': identifier, 'body': 'Secret synthetic body', 'untrusted_content': True}


class Permissions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(self.temp.name)
        self.client = self.store.client_add('agent')
        self.token = self.client['token']
        self.identifier = self.client['client_id']
        self.mail = Mail()
        self.broker = Broker(self.store, self.mail)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def grant(self, operation='list', age=600, seconds=900):
        return self.store.grant(self.identifier, operation, '*@anthropic.example', age, seconds)

    def invoke(self, method, **args):
        return self.broker.call(self.token, method, args)

    def test_default_deny(self):
        for operation, args in [('list', {}), ('read', {'message_id': 'recent'})]:
            with self.assertRaises(Denied):
                self.invoke(operation, **args)
        self.assertEqual(self.mail.body_reads, [])

    def test_list_recent_matching_sender_only_and_no_body(self):
        self.grant()
        result = self.invoke('list')
        self.assertEqual([m['id'] for m in result['messages']], ['recent'])
        self.assertNotIn('Secret synthetic body', json.dumps(result))
        self.assertEqual(self.mail.body_reads, [])

    def test_list_does_not_grant_read(self):
        self.grant()
        with self.assertRaises(Denied):
            self.invoke('read', message_id='recent')

    def test_read_grant_can_be_broader_in_age_without_list(self):
        self.grant('read', age=None)
        self.assertIn('body', self.invoke('read', message_id='old'))
        with self.assertRaises(Denied):
            self.invoke('list')

    def test_read_wrong_sender_or_old_message_denied_before_body(self):
        self.grant('read')
        for identifier in ['old', 'other']:
            with self.assertRaises(Denied):
                self.invoke('read', message_id=identifier)
        self.assertEqual(self.mail.body_reads, [])

    def test_expired_grant(self):
        grant = self.grant()
        with self.store.db:
            self.store.db.execute('UPDATE grants SET expires=0 WHERE id=?', (grant['grant_id'],))
        with self.assertRaises(Denied):
            self.invoke('list')

    def test_rolling_age_not_just_age_at_approval(self):
        self.grant('read')
        self.mail.messages['recent']['received_at'] = time.time()-601
        with self.assertRaises(Denied):
            self.invoke('read', message_id='recent')

    def test_revoked_client(self):
        self.grant()
        self.store.revoke('client', self.identifier)
        with self.assertRaises(Denied):
            self.invoke('list')

    def test_revocation_during_provider_call_blocks_disclosure(self):
        grant = self.grant('read')
        self.mail.after_read = lambda: self.store.revoke('grant', grant['grant_id'])
        with self.assertRaises(Denied):
            self.invoke('read', message_id='recent')

    def test_other_client_does_not_inherit_permission(self):
        self.grant()
        other = self.store.client_add('other')
        with self.assertRaises(Denied):
            self.broker.call(other['token'], 'list', {})

    def test_saved_grant_survives_reopen_and_no_raw_token_stored(self):
        self.grant(seconds=None)
        second = Store(self.temp.name)
        try:
            self.assertTrue(second.allowed(self.identifier, 'list', self.mail.messages['recent']))
        finally:
            second.close()
        self.assertNotIn(self.token.encode(), (Path(self.temp.name)/'policy.sqlite').read_bytes())

    def test_sender_display_name_cannot_match(self):
        rule = {'sender': '*@anthropic.example', 'max_age_seconds': None}
        self.assertFalse(matches(rule, {'headers': {'From': 'login@anthropic.example <bob@example.com>'}}))
        self.assertFalse(matches(rule, {'headers': {'From': 'a@anthropic.example, bob@example.com'}}))

    def test_recent_rule_rejects_missing_date(self):
        self.assertFalse(matches({'sender': '*', 'max_age_seconds': 600},
                                 {'headers': {'From': 'a@example.com'}}))

    def test_client_filters_cannot_widen_permissions(self):
        self.grant()
        self.assertEqual(self.invoke('list', sender='*', max_age_seconds=999999)['messages'][0]['id'], 'recent')
        self.assertEqual(self.invoke('list', sender='bob@example.com')['messages'], [])

    def request(self, operation='list'):
        return self.invoke('request_access', operation=operation,
                           sender='*@anthropic.example', max_age_seconds=600)

    def test_requests_are_pending_not_grants_and_duplicate_is_stable(self):
        first = self.request()
        self.assertEqual(first['request_id'], self.request()['request_id'])
        with self.assertRaises(Denied):
            self.invoke('list')

    def test_accept_approves_only_requested_operation(self):
        pending = self.request()
        approval_from_response(self.store, self.token, pending['request_id'],
                               {'action': 'accept', 'content': {'duration': '15m'}})
        self.assertEqual(len(self.invoke('list')['messages']), 1)
        with self.assertRaises(Denied):
            self.invoke('read', message_id='recent')

    def test_decline_cancel_or_invalid_response_never_grants(self):
        pending = self.request()
        for action in ['decline', 'cancel']:
            approval_from_response(self.store, self.token, pending['request_id'], {'action': action})
        with self.assertRaises(ValueError):
            approval_from_response(self.store, self.token, pending['request_id'],
                                   {'action': 'accept', 'content': {'duration': 'forever'}})
        self.assertEqual(self.store.rules(self.identifier, 'list'), [])

    def test_denial_feedback_grants_nothing_and_cannot_be_approved_later(self):
        pending = self.request()
        reason = 'Only login emails from the last ten minutes, please.'
        result = approval_from_response(self.store, self.token, pending['request_id'],
            {'action': 'accept', 'content': {'duration': 'deny', 'reason': reason}})
        self.assertEqual(result, {'status': 'denied', 'request_id': pending['request_id'], 'reason': reason})
        self.assertEqual(self.store.rules(self.identifier, 'list'), [])
        self.assertEqual(self.store.list('requests'), [])
        with self.assertRaises(ValueError):
            self.store.approve(pending['request_id'], 900)
        self.assertNotEqual(self.request()['request_id'], pending['request_id'])

    def test_invalid_denial_feedback_or_foreign_request_is_rejected(self):
        pending = self.request()
        for reason in [None, {}, 1, 'x'*2001]:
            with self.assertRaises(ValueError):
                approval_from_response(self.store, self.token, pending['request_id'],
                    {'action': 'accept', 'content': {'duration': 'deny', 'reason': reason}})
        other = self.store.client_add('other')
        with self.assertRaises(ValueError):
            approval_from_response(self.store, other['token'], pending['request_id'],
                {'action': 'accept', 'content': {'duration': 'deny', 'reason': 'No'}})
        self.assertEqual(len(self.store.list('requests')), 1)
        self.assertEqual(self.store.list('grants'), [])

    def test_adapter_cannot_approve_another_clients_request(self):
        pending = self.request()
        other = self.store.client_add('other')
        with self.assertRaises(ValueError):
            approval_from_response(self.store, other['token'], pending['request_id'],
                                   {'action': 'accept', 'content': {'duration': 'saved'}})

    def test_admin_or_send_not_exposed_via_broker_or_mcp(self):
        for name in ['approve', 'grant', 'send', 'delete']:
            with self.assertRaises(ValueError):
                self.invoke(name)
        tools = mcp_dispatch({'method': 'tools/list'}, lambda *args: None)['tools']
        self.assertEqual({t['name'] for t in tools}, {'request_access', 'list_messages', 'read_message'})

    def test_mcp_denial_is_tool_error_not_content(self):
        result = mcp_dispatch({'method': 'tools/call', 'params': {'name': 'read_message',
                               'arguments': {'message_id': 'other'}}},
                              lambda operation, args: (_ for _ in ()).throw(RuntimeError('denied')))
        self.assertTrue(result['isError'])
        self.assertNotIn('body', json.dumps(result))

    def test_real_stdio_elicitation_roundtrip(self):
        fixture = Path(__file__).resolve().parents[1]/'demo-mail.json'
        code = '''
import os
from clauthing_gmail_mcp import client
from clauthing_gmail_mcp.broker import Broker
from clauthing_gmail_mcp.mail import FixtureMail
from clauthing_gmail_mcp.store import Store
broker = Broker(Store(os.environ['TEST_STATE']), FixtureMail(os.environ['TEST_FIXTURE']))
client.call = lambda url, token, operation, arguments: broker.call(token, operation, arguments)
client.serve_stdio('http://127.0.0.1:8767', os.environ['TEST_TOKEN'], os.environ['TEST_STATE'])
'''
        process = subprocess.Popen([sys.executable, '-c', code], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    env=dict(os.environ, TEST_STATE=self.temp.name, TEST_FIXTURE=str(fixture),
                             TEST_TOKEN=self.token))

        def send(value):
            process.stdin.write(json.dumps(value)+'\n')
            process.stdin.flush()

        def receive():
            self.assertTrue(select.select([process.stdout], [], [], 5)[0], 'MCP response timed out')
            return json.loads(process.stdout.readline())

        try:
            send({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                'protocolVersion': '2025-06-18', 'capabilities': {'elicitation': {}},
                'clientInfo': {'name': 'test', 'version': '1'}}})
            self.assertEqual(receive()['result']['protocolVersion'], '2025-06-18')
            send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
            send({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {
                'name': 'request_access', 'arguments': {'operation': 'list',
                'sender': '*@anthropic.example', 'max_age_seconds': 600}}})
            elicitation = receive()
            self.assertEqual(elicitation['method'], 'elicitation/create')
            self.assertIn('not bodies', elicitation['params']['message'])
            fields = elicitation['params']['requestedSchema']['properties']
            self.assertIn('deny', fields['duration']['enum'])
            self.assertNotIn('reason', fields)
            reason = 'Ask only for login emails.'
            send({'jsonrpc': '2.0', 'id': elicitation['id'], 'result': {'action': 'accept',
                  'content': {'duration': 'deny'}}})
            feedback = receive()
            self.assertEqual(feedback['method'], 'elicitation/create')
            self.assertEqual(set(feedback['params']['requestedSchema']['properties']), {'reason'})
            self.assertEqual(self.store.list('grants'), [])
            self.assertEqual(self.store.list('requests'), [])
            send({'jsonrpc': '2.0', 'id': feedback['id'], 'result': {
                'action': 'accept', 'content': {'reason': reason}}})
            denial = json.loads(receive()['result']['content'][0]['text'])
            self.assertEqual(denial['status'], 'denied')
            self.assertEqual(denial['reason'], reason)
            self.assertEqual(self.store.rules(self.identifier, 'list'), [])
            send({'jsonrpc': '2.0', 'id': 20, 'method': 'tools/call', 'params': {
                'name': 'request_access', 'arguments': {'operation': 'list',
                'sender': '*@anthropic.example', 'max_age_seconds': 600}}})
            elicitation = receive()
            send({'jsonrpc': '2.0', 'id': elicitation['id'], 'result': {'action': 'decline'}})
            feedback = receive()
            send({'jsonrpc': '2.0', 'id': feedback['id'], 'result': {'action': 'cancel'}})
            denial = json.loads(receive()['result']['content'][0]['text'])
            self.assertEqual(denial['status'], 'denied')
            self.assertEqual(denial['reason'], '')
            self.assertEqual(self.store.list('grants'), [])
            send({'jsonrpc': '2.0', 'id': 21, 'method': 'tools/call', 'params': {
                'name': 'request_access', 'arguments': {'operation': 'list',
                'sender': '*@anthropic.example', 'max_age_seconds': 600}}})
            elicitation = receive()
            send({'jsonrpc': '2.0', 'id': elicitation['id'], 'result': {'action': 'accept',
                  'content': {'duration': '15m', 'operation': 'read'}}})
            result = receive()
            self.assertFalse(result['result']['isError'])
            self.assertTrue(self.store.allowed(self.identifier, 'list', self.mail.messages['recent']))
            self.assertFalse(self.store.allowed(self.identifier, 'read', self.mail.messages['recent']))
            send({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {
                'name': 'list_messages', 'arguments': {}}})
            result = json.loads(receive()['result']['content'][0]['text'])
            self.assertEqual([m['id'] for m in result['messages']], ['demo-1'])
        finally:
            process.stdin.close()
            process.wait(timeout=5)
            stderr = process.stderr.read()
            process.stdout.close()
            process.stderr.close()
        self.assertEqual(process.returncode, 0, stderr)


if __name__ == '__main__':
    unittest.main()
