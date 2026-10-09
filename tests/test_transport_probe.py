import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('vpn', Path(__file__).parents[1] / 'src/vpnctl.py')
vpn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vpn)
NODE = {'name': 'node', 'server_ip': '192.0.2.7', 'outbound': {'tag': 'proxy', 'protocol': 'vless', 'settings': {'address': '192.0.2.7', 'port': 21814}}}

class TransportTests(unittest.TestCase):
    def test_successful_transport_uses_parsed_profile_format(self):
        with tempfile.TemporaryDirectory() as td:
            profile = Path(td) / 'Estonia'
            profile.write_text('vless://00000000-0000-0000-0000-000000000001@192.0.2.7:21814?security=none&type=tcp')
            nodes = vpn.load_profile(profile)
        sock = MagicMock()
        with patch.object(vpn, 'default_physical_iface', return_value='eth0'), patch.object(vpn, 'run', return_value=SimpleNamespace(stdout='[{"dev":"eth0"}]')), patch.object(vpn.socket, 'socket', return_value=sock):
            vpn.startup_preflight(nodes)
        sock.connect.assert_called_once_with(('192.0.2.7', 21814))
        sock.close.assert_called_once()

    def test_foreign_route_never_opens_direct_socket(self):
        with patch.object(vpn, 'default_physical_iface', return_value='eth0'), patch.object(vpn, 'run', return_value=SimpleNamespace(stdout='[{"dev":"tun2"}]')), patch.object(vpn.socket, 'socket') as sock:
            with self.assertRaisesRegex(vpn.VPNError, 'другой VPN'):
                vpn.startup_preflight([NODE])
            sock.assert_not_called()

    def test_unreachable_server_closes_bounded_sockets(self):
        sock = MagicMock()
        sock.connect.side_effect = TimeoutError('timeout')
        with patch.object(vpn, 'default_physical_iface', return_value='eth0'), patch.object(vpn, 'run', return_value=SimpleNamespace(stdout='[{"dev":"eth0"}]')), patch.object(vpn.socket, 'socket', return_value=sock):
            with self.assertRaisesRegex(vpn.VPNError, 'до запуска TUN'):
                vpn.startup_preflight([NODE])
        self.assertEqual(sock.close.call_count, 2)
        sock.settimeout.assert_called_with(3)
        sock.setsockopt.assert_called_with(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'eth0\0')

    def test_failed_preflight_preserves_network(self):
        with patch.object(vpn, 'load_state', return_value={}), patch.object(vpn, 'RUNTIME_CONFIG') as runtime, patch.object(vpn, 'service_active', return_value=False), patch.object(vpn, 'load_profile', return_value=[NODE]), patch.object(vpn, 'build_config', return_value={}), patch.object(vpn, 'validate_candidate'), patch.object(vpn, 'validate_dns_guard'), patch.object(vpn, 'startup_preflight', side_effect=vpn.VPNError('transport down')), patch.object(vpn, 'install_guard') as guard, patch.object(vpn, 'start_config') as start, patch.object(vpn, 'stop_core') as stop, patch.object(vpn, 'save_state') as save:
            runtime.exists.return_value = False
            with self.assertRaisesRegex(vpn.VPNError, 'transport down'):
                vpn.activate({}, Path('Estonia'))
            guard.assert_not_called(); start.assert_not_called(); stop.assert_not_called(); save.assert_not_called()

    def test_failed_diagnostic_start_is_recorded_without_starting_monitor(self):
        with patch.object(vpn, 'stop_diagnostic'), patch.object(vpn, 'choose_config', return_value=Path('Estonia')), patch.object(vpn, 'activate', side_effect=vpn.VPNError('TCP timeout')), patch.object(vpn, '_diagnostic_write') as write, patch.object(vpn, '_diagnostic_network_fingerprint', return_value={}), patch.object(vpn, 'run') as run:
            with self.assertRaisesRegex(vpn.VPNError, 'TCP timeout'):
                vpn.cmd_diagnostic_on({}, 'Estonia')
            self.assertEqual(write.call_args.args[0]['event'], 'startup_failed')
            run.assert_not_called()

    def test_proxy_requires_two_valid_ipv4_providers_and_no_env_bypass(self):
        replies = [subprocess.CompletedProcess([], 0, '192.0.2.5', ''), subprocess.CompletedProcess([], 0, 'HTML', '')]
        with patch.object(vpn, 'run', side_effect=replies) as run:
            self.assertFalse(vpn._proxy_health_check(1234, 'secret')[0])
            for call in run.call_args_list:
                args = call.args[0]
                self.assertEqual(args[args.index('--noproxy') + 1], '')
                self.assertIn('socks5h://127.0.0.1:1234', args)

    def test_isolated_probe_cleanup_and_no_system_mutations(self):
        with tempfile.TemporaryDirectory() as td:
            proc = MagicMock(); proc.poll.return_value = None
            configs = []
            with patch.object(vpn, 'RUNTIME_DIR', Path(td)), patch.object(vpn, 'ensure_runtime'), patch.object(vpn, 'choose_config', return_value=Path('Estonia')), patch.object(vpn, 'load_profile', return_value=[NODE]), patch.object(vpn, 'test_config', side_effect=lambda p: configs.append(json.loads(p.read_text()))), patch.object(vpn.subprocess, 'Popen', return_value=proc), patch.object(vpn.socket, 'create_connection'), patch.object(vpn, '_proxy_health_check', side_effect=RuntimeError('interrupted')), patch.object(vpn, 'activate') as activate, patch.object(vpn, 'install_guard') as guard, patch.object(vpn, 'stop_core') as stop:
                with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                    vpn.cmd_diagnostic_probe({}, 'Estonia')
                activate.assert_not_called(); guard.assert_not_called(); stop.assert_not_called()
            proc.terminate.assert_called_once(); proc.wait.assert_called_once()
            self.assertEqual(list(Path(td).iterdir()), [])
            config = configs[0]
            self.assertEqual(len(config['inbounds']), 1)
            self.assertEqual(config['inbounds'][0]['protocol'], 'socks')
            self.assertEqual(config['inbounds'][0]['settings']['auth'], 'password')
            self.assertEqual(config['outbounds'], [NODE['outbound']])

    def test_probe_does_not_wait_for_mutating_operation_lock(self):
        self.assertFalse(vpn.operation_requires_lock(SimpleNamespace(cmd='diagnostic', diagnostic_cmd='probe')))
        self.assertTrue(vpn.operation_requires_lock(SimpleNamespace(cmd='diagnostic', diagnostic_cmd='on')))

if __name__ == '__main__':
    unittest.main()
