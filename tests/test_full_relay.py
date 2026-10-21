import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('full_tunnel',ROOT/'src/starfive_tunnel.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)

class FullRelayTests(unittest.TestCase):
    def test_failure_cleanup_retains_guard_dns_and_policy(self):
        with tempfile.TemporaryDirectory() as d,patch.object(t,'ROOT',Path(d)),patch.object(t,'command') as cmd:
            t.write(t.full_state(),json.dumps({'active':True,'dns_backup':'old'}))
            t.cleanup_full()
            calls=[c.args[0] for c in cmd.call_args_list]
            self.assertTrue(t.full_state().exists())
            self.assertFalse(any('nft' in x or 'rule' in x or 'disable' in x for x in calls))
            self.assertIn(['ip','route','del','default','metric','10','table',t.FULL_TABLE],calls)

    def test_unowned_cleanup_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d,patch.object(t,'ROOT',Path(d)),patch.object(t,'command') as cmd:
            t.cleanup_full(release=True)
            cmd.assert_not_called()

    @patch.object(t, "ensure_evgt_binary")
    def test_dependency_install_is_skipped_when_complete(self, binary):
        with patch.object(t,'charon_binary',return_value='/usr/bin/charon-systemd'),patch.object(t.shutil,'which',return_value='/usr/bin/tool'),patch.object(t,'command') as cmd:
            t.ensure_dependencies()
            cmd.assert_not_called()

    @patch.object(t, "ensure_evgt_binary")
    def test_arch_missing_dependency_installs_native_packages(self, binary):
        with patch.object(t,'charon_binary',side_effect=[None,'/usr/bin/charon-systemd']),patch.object(t.shutil,'which',return_value='/usr/bin/tool'),patch.object(t,'command') as cmd,patch.object(t,'stage'):
            t.ensure_dependencies()
            args=cmd.call_args.args[0]
            self.assertEqual(args[:4],['pacman','-S','--needed','--noconfirm'])
            self.assertIn('strongswan',args)
            self.assertFalse(any('systemctl' in x for x in args))

    def test_guard_has_no_direct_or_established_output_bypass(self):
        text=t.full_firewall()
        output=text.split(' chain output {')[1].split(' chain forward {')[0]
        self.assertIn('policy drop',output)
        self.assertNotIn('ct state established',output)
        self.assertNotIn('meta skuid',output)
        self.assertNotIn('ip6 daddr',output)
        self.assertIn('dnat ip to 1.1.1.1',text)
        self.assertNotIn('tcp dport 22',text)
        self.assertIn('snat ip to 172.29.247.1',text)
        self.assertIn('ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept',text)

    def test_ingress_migration_replaces_retained_guard_atomically(self):
        with tempfile.TemporaryDirectory() as d,patch.object(t,'ROOT',Path(d)),patch.object(t,'full_guard_active',return_value=True),patch.object(t,'command') as cmd:
            t.refresh_retained_guard()
            rules=(Path(d)/'full-guard.nft').read_text()
            self.assertIn('195.209.211.163',rules)
            self.assertIn('udp dport 24550',rules)
            self.assertNotIn('udp dport {500,4500}',rules)
            self.assertNotIn('109.194.67.159',rules)
            self.assertNotIn('192.168.0.163',rules)
            self.assertIn('policy drop',rules)
            self.assertEqual([c.args[0] for c in cmd.call_args_list],[['nft','-c','-f','-'],['nft','-f','-']])
            self.assertTrue(cmd.call_args.kwargs['data'].startswith('delete table inet '+t.FULL_GUARD+'\n'))

    def test_switch_does_not_destroy_exempt_sockets(self):
        with patch.object(t,'command') as cmd:
            t.retire_previous_connections(['192.168.0.163','172.31.255.1'])
            cmd.assert_not_called()

    def test_cleanup_is_idempotent_without_new_objects(self):
        with tempfile.TemporaryDirectory() as d,patch.object(t,'ROOT',Path(d)),patch.object(t,'command') as cmd:
            t.cleanup();t.cleanup()
            cmd.assert_not_called()

spec=importlib.util.spec_from_file_location('server_relay',ROOT/'scripts/server-link/relay-star.py')
server=importlib.util.module_from_spec(spec);spec.loader.exec_module(server)

class ServerRelayTests(unittest.TestCase):
    def test_iproute2_split_prefix_is_accepted_on_restart(self):
        result=subprocess.CompletedProcess([],0,json.dumps([{'priority':210,'src':'10.77.0.0','srclen':24,'table':'51827'}]),'')
        with patch.object(server,'run',return_value=result) as run:
            server.policy()
            self.assertFalse(any(c.args[:3]==('ip','rule','add') for c in run.call_args_list))

    def test_stop_removes_egress_before_validation_failure(self):
        with tempfile.TemporaryDirectory() as d,patch.object(server,'BASE',Path(d)),patch.object(server,'run') as run,patch.object(server,'guard'),patch.object(server,'policy',side_effect=RuntimeError('collision')):
            with self.assertRaises(RuntimeError):server.stop()
            self.assertEqual(run.call_args.args[:5],('ip','route','del','default','metric'))
