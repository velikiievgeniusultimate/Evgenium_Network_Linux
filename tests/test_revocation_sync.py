import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'scripts/direct-ingress/revocation-sync.py'
spec = importlib.util.spec_from_file_location('revocation_sync', SOURCE)
sync = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync)


class RevocationDelivery(unittest.TestCase):
    def test_public_success_does_not_use_fallback(self):
        with patch.object(sync.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'accepted\n')) as run:
            self.assertEqual(sync.send_snapshot({'issued': 1}), 'public')
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][0], 'ssh')

    def test_timeout_uses_same_pinned_identity_over_namespace(self):
        with patch.object(sync.subprocess, 'run', side_effect=[subprocess.TimeoutExpired('ssh', 18), subprocess.CompletedProcess([], 0, 'accepted\n')]) as run:
            self.assertEqual(sync.send_snapshot({'issued': 1}), 'wireguard')
        first, second = run.call_args_list
        cmd = second.args[0]
        self.assertEqual(cmd[:4], ['ip', 'netns', 'exec', 'evg-link'])
        self.assertEqual(cmd[-1], 'root@10.203.81.1')
        for required in ['HostKeyAlias=38.180.164.67', 'StrictHostKeyChecking=yes', 'IdentitiesOnly=yes', 'UserKnownHostsFile=/etc/evgenium-direct-sync/known_hosts']:
            self.assertIn(required, cmd)
        self.assertEqual(first.kwargs['input'], second.kwargs['input'])
        self.assertEqual(second.kwargs['timeout'], 18)

    def test_rejected_snapshot_never_reports_success(self):
        for result in [subprocess.CompletedProcess([], 1, 'accepted\n'), subprocess.CompletedProcess([], 0, 'rejected\n')]:
            with self.subTest(result=result), patch.object(sync.subprocess, 'run', return_value=result) as run:
                with self.assertRaisesRegex(RuntimeError, '^revocation_sync_failed$'):
                    sync.send_snapshot({'issued': 1})
                self.assertEqual(run.call_count, 2)

    def test_missing_namespace_or_ssh_fails_closed(self):
        with patch.object(sync.subprocess, 'run', side_effect=OSError('unavailable')):
            with self.assertRaises(RuntimeError):
                sync.send_snapshot({'issued': 1})

    def test_wireguard_revocations_never_poison_certificate_snapshot(self):
        data={'a':{'enabled':True,'devices':{'first':{'identity':'device-first','disabled':True},
                 'second':{'identity':'wg:public-key','type':'wireguard','disabled':True}}}}
        def read(path):
            return json.dumps(data) if path.name=='accounts.json' else 'test-crl'
        with patch.object(sync.Path,'read_text',autospec=True,side_effect=read),patch.object(sync,'send_snapshot',return_value='wireguard') as send:
            self.assertEqual(sync.sync(),'wireguard')
        self.assertEqual(send.call_args.args[0]['disabled'],['device-first'])


if __name__ == '__main__':
    unittest.main()
