import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, ROOT / source)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tunnel = load('token_controls_tunnel', 'src/starfive_tunnel.py')
vpn = load('token_controls_vpn', 'src/vpnctl.py')
TOKEN = 'EVN1-' + 'a' * 43
OTHER = 'EVN1-' + 'b' * 43


class TokenControlTests(unittest.TestCase):
    def test_confirmation_persists_without_starting_tunnel_and_status_masks_secret(self):
        with tempfile.TemporaryDirectory() as td, patch.object(tunnel, 'ROOT', Path(td)), \
                patch.object(tunnel, 'STATE', Path(td) / 'state.json'), \
                patch.object(tunnel, 'command', return_value=subprocess.CompletedProcess([], 3, '', '')) as command:
            tunnel.save_token('  ' + TOKEN + '\n')
            self.assertEqual((Path(td) / 'token').read_text(), TOKEN)
            self.assertEqual((Path(td) / 'token').stat().st_mode & 0o777, 0o600)
            public = tunnel.status()
            self.assertTrue(public['has_token'])
            self.assertIn('ID ', public['token_hint'])
            self.assertNotIn(TOKEN, str(public))
            self.assertFalse(public['running'])
            self.assertEqual(public['phase'], 'off')
            for call in command.call_args_list:
                self.assertEqual(call.args[0][:2], ['systemctl', 'is-active'])

    def test_invalid_or_running_replacement_preserves_existing_credentials(self):
        with tempfile.TemporaryDirectory() as td, patch.object(tunnel, 'ROOT', Path(td)), \
                patch.object(tunnel, 'command', return_value=subprocess.CompletedProcess([], 0, '', '')):
            (Path(td) / 'token').write_text(TOKEN)
            cert = Path(td) / 'client.pem'; cert.write_text('old cert')
            with self.assertRaises(ValueError):
                tunnel.save_token('invalid')
            with self.assertRaises(RuntimeError):
                tunnel.save_token(OTHER)
            tunnel.save_token(TOKEN)  # Same-account confirmation is idempotent.
            self.assertEqual(cert.read_text(), 'old cert')
            self.assertEqual((Path(td) / 'token').read_text(), TOKEN)

    def test_replacement_discards_previous_accounts_cached_certificate_and_key(self):
        with tempfile.TemporaryDirectory() as td, patch.object(tunnel, 'ROOT', Path(td)), \
                patch.object(tunnel, 'STATE', Path(td) / 'state.json'), \
                patch.object(tunnel, 'command', return_value=subprocess.CompletedProcess([], 3, '', '')):
            tunnel.save_token(TOKEN)
            before = tunnel.token_status()['token_hint']
            for name in ('device', 'client-key.pem', 'client.pem', 'profile.json', 'request.pem',
                         'private/client-key.pem', 'x509/client.pem'):
                tunnel.write(Path(td) / name, 'old')
            tunnel.save_token(OTHER)
            self.assertNotEqual(before, tunnel.token_status()['token_hint'])
            self.assertFalse((Path(td) / 'private/client-key.pem').exists())
            self.assertFalse((Path(td) / 'profile.json').exists())

    def test_update_removes_only_firefox_codex_and_keeps_backup_and_future_choices(self):
        with tempfile.TemporaryDirectory() as td, patch.object(vpn, '_owner_ids', return_value=(os.getuid(), os.getgid())), \
                patch.object(vpn, 'save_settings') as save:
            path = Path(td) / 'DIRECT apps.txt'
            original = '# personal rules\nfirefox\n/usr/lib/firefox/\n/opt/Codex/codex\nCodex\nsteam\n/opt/mycodex/helper\n'
            path.write_text(original)
            settings = {'direct_apps': str(path)}
            vpn.migrate_firefox_codex_exceptions(settings)
            self.assertEqual(path.read_text(), '# personal rules\nsteam\n/opt/mycodex/helper\n')
            self.assertEqual(path.with_name(path.name + '.before-0.3.0-ru.2').read_text(), original)
            path.write_text('firefox\n')
            vpn.migrate_firefox_codex_exceptions(settings)
            self.assertEqual(path.read_text(), 'firefox\n')
            save.assert_called_once_with(settings)
