import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from clauthing_gmail_mcp.cli import main, parser
from clauthing_gmail_mcp.mail import SCOPE, cached_login, configure_client, private_json


class AuthConfiguration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)/'config'/'clauthing-gmail-mcp'

    def test_saves_pair_privately_and_reuses_it(self):
        path = configure_client(self.directory, 'test-client', 'test-secret')
        self.assertEqual(path.name, 'oauth-client.json')
        self.assertEqual(json.loads(path.read_text())['installed']['client_secret'], 'test-secret')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(configure_client(self.directory), path)

    def test_partial_pair_does_not_replace_existing_credentials(self):
        path = configure_client(self.directory, 'old-client', 'old-secret')
        original = path.read_bytes()
        for pair in [('new-client', None), (None, 'new-secret'), ('', 'secret'), ('id', ' ')]:
            with self.assertRaises(ValueError):
                configure_client(self.directory, *pair)
            self.assertEqual(path.read_bytes(), original)

    def test_no_saved_credentials_has_actionable_error(self):
        with self.assertRaisesRegex(ValueError, '--client-id and --client-secret'):
            configure_client(self.directory)
        self.assertFalse(self.directory.exists())

    def test_json_import_is_copied_to_config_and_requires_desktop_client(self):
        source = Path(self.temp.name)/'download.json'
        source.write_text(json.dumps({'installed': {'client_id': 'id', 'client_secret': 'secret'}}))
        path = configure_client(self.directory, credentials_file=source)
        source.unlink()
        self.assertEqual(configure_client(self.directory), path)
        source.write_text(json.dumps({'web': {'client_id': 'wrong-type'}}))
        with self.assertRaisesRegex(ValueError, 'Desktop'):
            configure_client(self.directory, credentials_file=source)

    def test_explicit_pair_and_json_cannot_be_mixed(self):
        with self.assertRaises(ValueError):
            configure_client(self.directory, 'id', 'secret', Path('not-read.json'))

    def test_default_path_honors_config_home(self):
        with patch.dict(os.environ, {'XDG_CONFIG_HOME': str(Path(self.temp.name)/'xdg')}):
            args = parser().parse_args(['auth', '--client-id', 'id', '--client-secret', 'secret'])
        self.assertEqual(args.config_dir, Path(self.temp.name)/'xdg'/'clauthing-gmail-mcp')

    def test_cli_passes_saved_pair_to_login_without_printing_secret(self):
        arguments = ['clauthing-gmail-mcp', '--auth-state', str(Path(self.temp.name)/'state'),
                     'auth', '--client-id', 'id', '--client-secret', 'do-not-print-this',
                     '--config-dir', str(self.directory)]
        output = io.StringIO()
        with patch('sys.argv', arguments), patch('clauthing_gmail_mcp.cli.login') as login:
            login.return_value = {'status': 'authenticated'}
            with contextlib.redirect_stdout(output):
                main()
            saved_path = login.call_args.args[1]
        self.assertEqual(json.loads(saved_path.read_text())['installed']['client_id'], 'id')
        self.assertNotIn('do-not-print-this', output.getvalue())
        # A subsequent bare auth command reuses the persisted registration.
        with patch('sys.argv', ['cmd', 'auth', '--config-dir', str(self.directory)]), \
             patch('clauthing_gmail_mcp.cli.login', return_value={}) as login, \
             contextlib.redirect_stdout(io.StringIO()):
            main()
        self.assertEqual(login.call_args.args[1], saved_path)

    def test_browser_failure_still_keeps_registration_for_retry(self):
        with patch('sys.argv', ['cmd', 'auth', '--config-dir', str(self.directory),
                               '--client-id', 'id', '--client-secret', 'secret']), \
             patch('clauthing_gmail_mcp.cli.login', side_effect=RuntimeError('Consent cancelled')), \
             contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                main()
        self.assertTrue((self.directory/'oauth-client.json').is_file())

    def cached_setup(self, valid=True):
        state = Path(self.temp.name)/'state'
        value = {'client_id': 'id', 'client_secret': 'secret', 'scopes': [SCOPE],
                 'refresh_token': 'synthetic-refresh', 'token': 'synthetic-access'}
        private_json(state/'google-token.json', value)
        credentials = Mock(valid=valid, scopes=[SCOPE], granted_scopes=None)
        credentials.to_json.return_value = json.dumps(value)
        credentials_class = Mock()
        credentials_class.from_authorized_user_info.return_value = credentials
        request = Mock()
        config = {'installed': {'client_id': 'id', 'client_secret': 'secret'}}
        return state, value, config, credentials, credentials_class, request

    def test_valid_login_reused_without_refresh(self):
        state, value, config, credentials, factory, request = self.cached_setup()
        self.assertTrue(cached_login(state, config, factory, request))
        credentials.refresh.assert_not_called()
        request.assert_not_called()

    def test_expired_access_token_refreshed_and_saved(self):
        state, value, config, credentials, factory, request = self.cached_setup(valid=False)
        value['token'] = 'new-access-token'
        credentials.to_json.return_value = json.dumps(value)
        self.assertTrue(cached_login(state, config, factory, request))
        credentials.refresh.assert_called_once_with(request.return_value)
        self.assertEqual(json.loads((state/'google-token.json').read_text())['token'], 'new-access-token')

    def test_different_client_or_broad_scopes_not_reused(self):
        state, value, config, credentials, factory, request = self.cached_setup()
        for overrides in [{'client_id': 'different'}, {'client_secret': 'different'},
                          {'scopes': [SCOPE, 'https://mail.google.com/']}, {'refresh_token': None}]:
            private_json(state/'google-token.json', dict(value, **overrides))
            self.assertFalse(cached_login(state, config, factory, request))
        factory.from_authorized_user_info.assert_not_called()

    def test_failed_refresh_preserves_cached_credentials(self):
        state, value, config, credentials, factory, request = self.cached_setup(valid=False)
        before = (state/'google-token.json').read_bytes()
        credentials.refresh.side_effect = RuntimeError('offline')
        with self.assertRaises(RuntimeError):
            cached_login(state, config, factory, request)
        self.assertEqual((state/'google-token.json').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
