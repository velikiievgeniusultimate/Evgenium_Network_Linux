import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vpn_lock', Path(__file__).parents[1] / 'src/vpnctl.py')
vpn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vpn)

class OperationLockTests(unittest.TestCase):
    def test_release_after_success_and_error_and_keep_inode(self):
        with tempfile.TemporaryDirectory() as td, patch.object(vpn, 'RUNTIME_DIR', Path(td)), patch.object(vpn, 'ensure_runtime'):
            args = SimpleNamespace(cmd='off')
            path = Path(td) / 'operation.lock'
            for fail in (False, True):
                try:
                    with vpn.operation_guard(args, {}):
                        self.assertEqual(json.loads(path.read_text())['pid'], os.getpid())
                        inode = path.stat().st_ino
                        with path.open('a') as contender:
                            with self.assertRaises(BlockingIOError):
                                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        if fail:
                            raise RuntimeError('transaction failed')
                except RuntimeError:
                    self.assertTrue(fail)
                with path.open('a') as contender:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(path.stat().st_ino, inode)
                self.assertEqual(signal.alarm(0), 0)

    def test_busy_lock_reports_owner_without_breaking_lock(self):
        with tempfile.TemporaryDirectory() as td, patch.object(vpn, 'RUNTIME_DIR', Path(td)), patch.object(vpn, 'ensure_runtime'):
            path = Path(td) / 'operation.lock'
            with path.open('w+') as owner:
                owner.write('{"pid": 123, "command": "on"}')
                owner.flush()
                fcntl.flock(owner, fcntl.LOCK_EX)
                with self.assertRaisesRegex(vpn.VPNError, '123'):
                    with vpn.operation_guard(SimpleNamespace(cmd='update'), {}, wait_seconds=0):
                        self.fail('entered busy transaction')
                self.assertIn('123', path.read_text())

    def test_deadline_releases_lock(self):
        with tempfile.TemporaryDirectory() as td, patch.object(vpn, 'RUNTIME_DIR', Path(td)), patch.object(vpn, 'ensure_runtime'):
            with self.assertRaisesRegex(vpn.VPNError, '10 минут'):
                with vpn.operation_guard(SimpleNamespace(cmd='on'), {}):
                    signal.raise_signal(signal.SIGALRM)
            with (Path(td) / 'operation.lock').open('a') as contender:
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_read_only_does_not_need_runtime(self):
        with patch.object(vpn, 'ensure_runtime') as runtime:
            with vpn.operation_guard(SimpleNamespace(cmd='status'), {}):
                pass
            runtime.assert_not_called()

    def test_real_stalled_subprocess_is_killed(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            vpn.run([sys.executable, '-c', 'import time; time.sleep(60)'], timeout=0.05)

    def test_default_timeout_and_existing_explicit_timeout_semantics(self):
        with patch.object(vpn.subprocess, 'run', side_effect=subprocess.TimeoutExpired('systemctl', 60)) as runner:
            with self.assertRaises(vpn.VPNError):
                vpn.run(['/usr/bin/systemctl', 'stop', 'xray'])
            self.assertEqual(runner.call_args.kwargs['timeout'], 60)
            with self.assertRaises(subprocess.TimeoutExpired):
                vpn.run(['curl'], timeout=4)

    def test_post_update_is_serialized(self):
        for command in ('internal-after-update', 'internal-sync'):
            self.assertTrue(vpn.operation_requires_lock(SimpleNamespace(cmd=command)))

if __name__ == '__main__':
    unittest.main()
