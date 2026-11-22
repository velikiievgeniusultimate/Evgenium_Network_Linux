"""Exercise update and explicit install with a real private home and a fake KDE runner."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location('desktop_cache_manager', ROOT / 'src/vpnctl.py')
manager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manager)


class DesktopCacheTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.user = pwd.getpwuid(os.getuid())
        self.settings = {'owner_home': str(self.home), 'owner_user': self.user.pw_name}
        self.desktop = manager._gui_desktop_path(self.settings)
        self.widget = manager._widget_package_dir(self.settings)
        self.cache_command = '/fixture/kbuildsycoca6'
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.enterContext(contextlib.redirect_stderr(io.StringIO()))
        self.enterContext(patch.object(manager, 'INSTALL_PENDING', self.home / 'pending'))
        self.enterContext(patch.object(manager, 'INSTALL_COMPLETE', self.home / 'complete'))
        self.enterContext(patch.object(manager.vpn_tunnel, 'finish_name_transition'))
        self.enterContext(patch.object(manager.vpn_tunnel, 'layout_in_use', return_value=True))
        self.enterContext(patch.object(manager, 'sync_system_files'))
        self.enterContext(patch.object(manager.vpn_tunnel, 'token_status', return_value={'has_token': True}))
        self.which = self.enterContext(patch.object(manager.shutil, 'which', return_value=self.cache_command))
        self.runner = self.enterContext(patch.object(manager, 'run', side_effect=self.fake_run))

    def fake_run(self, args, **kwargs):
        self.assertEqual(args, [self.cache_command])
        self.assertEqual(kwargs, {'user': self.user.pw_name, 'check': False, 'capture': True})
        return subprocess.CompletedProcess(args, 0, '', '')

    def update(self):
        manager.finish_installation(self.settings, reconnect=False)

    def test_first_update_repeat_then_new_or_damaged_desktop(self):
        self.update()
        self.runner.assert_called_once()
        self.assertEqual(self.desktop.read_text(), manager.GUI_DESKTOP_ENTRY)
        first = self.desktop.stat()
        self.assertEqual((first.st_uid, first.st_gid, stat.S_IMODE(first.st_mode)),
                         (self.user.pw_uid, self.user.pw_gid, 0o644))
        self.assertFalse(self.widget.exists())
        self.runner.reset_mock()
        gui = manager._gui_package_dir(self.settings) / 'evgenium_gui.py'
        gui.write_text('broken payload')
        self.update()
        self.runner.assert_not_called()
        again = self.desktop.stat()
        self.assertEqual((again.st_ino, again.st_mtime_ns), (first.st_ino, first.st_mtime_ns))
        self.assertNotEqual(gui.read_text(), 'broken payload')
        self.assertEqual(stat.S_IMODE(gui.stat().st_mode), 0o755)
        replacement = manager.GUI_DESKTOP_ENTRY.replace('StartupNotify=true', 'StartupNotify=false')
        with patch.object(manager, 'GUI_DESKTOP_ENTRY', replacement):
            self.update()
            self.runner.assert_called_once()
            self.assertEqual(self.desktop.read_text(), replacement)
            self.runner.reset_mock()
            self.desktop.write_bytes(b'?' * len(replacement.encode()))
            self.update()
            self.runner.assert_called_once()
            self.assertEqual(self.desktop.read_text(), replacement)

    def test_widget_is_refreshed_together_with_first_install_and_metadata_changes(self):
        self.widget.mkdir(parents=True)
        self.update()
        self.runner.assert_called_once()
        metadata = self.widget / 'metadata.json'
        stamp = metadata.stat().st_mtime_ns
        self.runner.reset_mock()
        (self.widget / 'contents/ui/main.qml').write_text('old widget implementation')
        self.update()
        self.runner.assert_not_called()
        self.assertEqual(metadata.stat().st_mtime_ns, stamp)
        self.assertEqual((self.widget / 'contents/ui/main.qml').read_text(), manager.PLASMOID_MAIN_QML)
        with patch.object(manager, 'PLASMOID_METADATA', manager.PLASMOID_METADATA + '\n'):
            self.update()
            self.runner.assert_called_once()
            self.runner.reset_mock()
            self.update()
            self.runner.assert_not_called()
            self.desktop.unlink()
            metadata.unlink()
            self.update()
            self.runner.assert_called_once()

    def test_manual_install_force_rebuild_and_cache_tool_optional(self):
        manager.cmd_gui_install(self.settings)
        self.runner.assert_called_once()
        self.runner.reset_mock()
        manager.cmd_gui_install(self.settings)
        self.runner.assert_called_once()
        self.runner.reset_mock()
        manager.cmd_widget_install(self.settings)
        self.runner.assert_called_once()
        self.runner.reset_mock()
        manager.cmd_widget_install(self.settings)
        self.runner.assert_called_once()
        self.runner.reset_mock()
        self.which.return_value = None
        self.desktop.unlink()
        self.update()
        self.runner.assert_not_called()
        self.assertEqual(self.desktop.read_text(), manager.GUI_DESKTOP_ENTRY)

    def test_replace_untrusted_metadata_without_reading_it(self):
        self.widget.mkdir(parents=True)
        self.update()
        metadata = self.widget / 'metadata.json'
        protected = self.home / 'unrelated'
        protected.write_bytes(b'x' * len(manager.PLASMOID_METADATA.encode()))
        with patch('builtins.open', side_effect=AssertionError('unexpected content read')):
            for kind in ('symlink', 'fifo', 'large', 'hardlink', 'mode'):
                with self.subTest(kind=kind):
                    metadata.unlink()
                    if kind == 'symlink':
                        metadata.symlink_to(protected)
                    elif kind == 'fifo':
                        os.mkfifo(metadata)
                    elif kind == 'large':
                        metadata.touch()
                        os.truncate(metadata, 1 << 30)
                    elif kind == 'hardlink':
                        os.link(protected, metadata)
                    else:
                        metadata.write_bytes(manager.PLASMOID_METADATA.encode())
                        metadata.chmod(0o600)
                    self.assertTrue(manager._install_registration(
                        self.settings, metadata, manager.PLASMOID_METADATA,
                        self.user.pw_uid, self.user.pw_gid))
                    self.assertEqual(metadata.read_text(), manager.PLASMOID_METADATA)
                    self.assertEqual(stat.S_IMODE(metadata.stat().st_mode), 0o644)
                    self.assertFalse(metadata.is_symlink())
        self.assertEqual(protected.read_bytes(), b'x' * len(manager.PLASMOID_METADATA.encode()))

    def test_widget_failure_updates_published_desktop_and_retry_completes_widget(self):
        self.widget.mkdir(parents=True)
        with patch.object(manager, '_install_widget_files', side_effect=OSError('full disk')):
            with self.assertRaisesRegex(OSError, 'full disk'):
                self.update()
        self.assertTrue(self.desktop.is_file())
        self.runner.assert_called_once()
        self.runner.reset_mock()
        self.update()
        self.runner.assert_called_once()
        self.assertEqual((self.widget / 'metadata.json').read_text(), manager.PLASMOID_METADATA)

    def test_failed_comparison_refreshes_and_failed_replace_preserves_registration(self):
        self.update()
        self.runner.reset_mock()
        with patch('builtins.open', side_effect=PermissionError('proc fd unavailable')):
            self.update()
        self.runner.assert_called_once()
        old = self.desktop.read_bytes()
        with patch.object(manager.os, 'replace', side_effect=OSError('full disk')):
            with self.assertRaisesRegex(OSError, 'full disk'):
                manager._install_registration(self.settings, self.desktop, 'new registration',
                                              self.user.pw_uid, self.user.pw_gid)
        self.assertEqual(self.desktop.read_bytes(), old)
        self.assertEqual(list(self.desktop.parent.glob('*.tmp')), [])

    def test_regular_desktop_symlink_keeps_original_refusal(self):
        self.update()
        self.runner.reset_mock()
        original = self.home / 'preserved'
        self.desktop.rename(original)
        self.desktop.symlink_to(original)
        with self.assertRaises((RuntimeError, SystemExit)):
            self.update()
        self.runner.assert_not_called()
        self.assertEqual(original.read_text(), manager.GUI_DESKTOP_ENTRY)
