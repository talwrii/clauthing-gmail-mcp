import contextlib
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from clauthing_gmail_mcp.cli import main, parser
from clauthing_gmail_mcp.paths import config_directory, data_directory, project_directory, project_key


class ProjectStorage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env = patch.dict(os.environ, {'XDG_DATA_HOME': str(self.root/'data'),
                                     'XDG_CONFIG_HOME': str(self.root/'config')})
        env.start()
        self.addCleanup(env.stop)

    def test_names_disambiguate_paths_and_resolve_symlinks(self):
        self.assertNotEqual(project_key(self.root/'a/b'), project_key(self.root/'a-b'))
        actual = self.root/'actual'
        actual.mkdir()
        alias = self.root/'alias'
        alias.symlink_to(actual, target_is_directory=True)
        self.assertEqual(project_key(actual), project_key(alias))
        self.assertLessEqual(len(project_key(self.root/('x'*200))), 97)

    def test_paths_respect_xdg_without_creating_files(self):
        self.assertEqual(config_directory(), self.root/'config/clauthing-gmail-mcp')
        self.assertEqual(data_directory(), self.root/'data/clauthing-gmail-mcp')
        with patch('sys.argv', ['gmail', 'paths']), contextlib.redirect_stdout(io.StringIO()):
            main()
        self.assertFalse((self.root/'data').exists())
        self.assertFalse((self.root/'config').exists())

    def test_project_changes_leave_google_login_shared(self):
        with patch('pathlib.Path.cwd', return_value=self.root/'first'):
            first = parser().parse_args(['mcp'])
        with patch('pathlib.Path.cwd', return_value=self.root/'second'):
            second = parser().parse_args(['serve'])
        self.assertNotEqual(first.state, second.state)
        self.assertEqual(first.auth_state, second.auth_state)

    def test_default_token_and_owner_policy_match_and_can_disable_elicitation(self):
        state = project_directory()
        with patch('sys.argv', ['gmail', 'client-add', 'codex']), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            main()
        token_path = state/'client.token'
        token = token_path.read_text().strip()
        self.assertNotIn(token, output.getvalue())
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(token_path.stat().st_mode), 0o600)
        with patch.dict(os.environ, {'CLAUTHING_GMAIL_TOKEN': ''}), \
             patch('clauthing_gmail_mcp.cli.serve_stdio', return_value=None) as serve:
            for extra, expected in [([], state), (['--no-elicitation'], None)]:
                with patch('sys.argv', ['gmail', 'mcp', '--external-broker', *extra]):
                    main()
                self.assertEqual(serve.call_args.args, ('http://127.0.0.1:8767', token, expected))

    def test_explicit_state_controls_both_token_and_approval_defaults(self):
        state = self.root/'override'
        state.mkdir()
        (state/'client.token').write_text('test-token')
        with patch.dict(os.environ, {'CLAUTHING_GMAIL_TOKEN': ''}), \
             patch('sys.argv', ['gmail', '--state', str(state), 'mcp', '--external-broker']), \
             patch('clauthing_gmail_mcp.cli.serve_stdio', return_value=None) as serve:
            main()
        self.assertEqual(serve.call_args.args[1:], ('test-token', state))
