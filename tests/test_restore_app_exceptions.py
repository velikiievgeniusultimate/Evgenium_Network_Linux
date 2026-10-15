import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('restore_vpn', ROOT/'src/vpnctl.py')
vpn = importlib.util.module_from_spec(spec); spec.loader.exec_module(vpn)


class RestoreExceptionsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'DIRECT apps.txt'
        self.backup = self.path.with_name(self.path.name+'.before-0.3.0-ru.2')
        self.settings = {'direct_apps': str(self.path), 'firefox_codex_exceptions_migrated': True}
        self.original = '# original rules\nfirefox\n/usr/lib/firefox/\n/opt/Codex/codex\nCodex\nsteam\n'
        self.backup.write_text(self.original)
        self.path.write_text('# original rules\nsteam\n')
        ids = patch.object(vpn, '_owner_ids', return_value=(os.getuid(), os.getgid()))
        ids.start(); self.addCleanup(ids.stop)
        saver = patch.object(vpn, 'save_settings')
        self.save = saver.start(); self.addCleanup(saver.stop)

    def test_restore_exact_original_and_keep_backup(self):
        vpn.restore_firefox_codex_exceptions(self.settings)
        self.assertEqual(self.path.read_bytes(), self.backup.read_bytes())
        self.assertNotIn('firefox_codex_exceptions_migrated', self.settings)
        self.save.assert_called_once_with(self.settings)

    def test_keep_later_edits_and_do_not_duplicate_readded_rule(self):
        self.path.write_text('# changed\nsteam\ncustom-app\nfirefox\n')
        vpn.restore_firefox_codex_exceptions(self.settings)
        restored = self.path.read_text()
        self.assertTrue(restored.startswith('# changed\nsteam\ncustom-app\nfirefox\n'))
        self.assertEqual(restored.splitlines().count('firefox'), 1)
        self.assertIn('/opt/Codex/codex\n', restored)
        self.assertEqual(self.backup.read_text(), self.original)

    def test_unaffected_installations_and_later_user_choices_are_untouched(self):
        self.settings.pop('firefox_codex_exceptions_migrated')
        before = self.path.read_bytes()
        vpn.restore_firefox_codex_exceptions(self.settings)
        self.assertEqual(self.path.read_bytes(), before)
        self.save.assert_not_called()

    def test_second_update_does_not_restore_rules_user_removed_after_repair(self):
        vpn.restore_firefox_codex_exceptions(self.settings)
        self.path.write_text('custom-app\n')
        vpn.restore_firefox_codex_exceptions(self.settings)
        self.assertEqual(self.path.read_text(), 'custom-app\n')
        self.assertEqual(self.save.call_count, 1)

    def test_no_backup_leaves_existing_rules_untouched(self):
        self.backup.unlink()
        before = self.path.read_bytes()
        vpn.restore_firefox_codex_exceptions(self.settings)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertNotIn('firefox_codex_exceptions_migrated', self.settings)

    def test_symlink_backup_is_rejected(self):
        self.backup.unlink(); self.backup.symlink_to(self.path)
        before = self.path.read_bytes()
        with self.assertRaises(vpn.VPNError):
            vpn.restore_firefox_codex_exceptions(self.settings)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(self.settings['firefox_codex_exceptions_migrated'])
