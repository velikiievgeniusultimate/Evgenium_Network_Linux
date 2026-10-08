import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vpn_dns', Path(__file__).parents[1] / 'src/vpnctl.py')
vpn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vpn)

class DnsTests(unittest.TestCase):
    def config(self, ipv6):
        settings = {key: '/nonexistent/dns-test' for key in ('direct_apps', 'direct_sites', 'direct_networks')}
        with patch.object(vpn, 'read_direct_apps', return_value=['chrome']), patch.object(vpn, 'read_direct_networks', return_value=[]):
            return vpn.build_config(settings, [{'outbound': {'tag': 'proxy', 'protocol': 'freedom'}}], ipv6_enabled=ipv6)

    def test_dns_cannot_match_direct_application_or_lan_rules(self):
        for ipv6 in (False, True):
            cfg = self.config(ipv6)
            listeners = [i for i in cfg['inbounds'] if i['tag'].startswith('dns-in-')]
            self.assertEqual({i['listen'] for i in listeners}, {'127.0.0.1', '::1'})
            for inbound in listeners:
                self.assertEqual(inbound['settings']['address'], '195.80.119.99')
                self.assertEqual(inbound['settings']['network'], 'tcp,udp')
                matches = [r for r in cfg['routing']['rules'] if inbound['tag'] in r.get('inboundTag', [])]
                self.assertEqual(matches[0]['outboundTag'], 'proxy')
            rules = cfg['routing']['rules']
            tags = [r['ruleTag'] for r in rules]
            self.assertLess(tags.index('estonia-dns-always-vpn'), tags.index('user-direct-applications'))

    def test_capture_both_transports_and_families_before_lan_exceptions(self):
        rules = vpn.render_guard_rules(999, set(), set(), dns_redirect=True)
        self.assertIn('type nat hook output priority dstnat', rules)
        self.assertIn('meta skuid != 999 meta l4proto { tcp, udp } th dport 53 redirect to :18553', rules)
        reject = rules.index('th dport 53 reject')
        self.assertLess(reject, rules.index('ip daddr 192.168.0.0/16 accept'))
        self.assertLess(reject, rules.index('ip6 daddr fe80::/10 accept'))
        self.assertNotIn('dns_output', vpn.render_guard_rules(999, set(), set()))

    def test_legacy_rollback_does_not_keep_capture_without_listener(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            with patch.object(vpn, 'RUNTIME_CONFIG', path):
                self.assertFalse(vpn.runtime_has_dns_proxy())
                path.write_text(json.dumps(self.config(False)))
                self.assertTrue(vpn.runtime_has_dns_proxy())
                path.write_text('{"inbounds": []}')
                self.assertFalse(vpn.runtime_has_dns_proxy())

    def test_failed_start_never_installs_dns_capture(self):
        with patch.object(vpn, 'write_runtime_config'), patch.object(vpn, 'run'), patch.object(vpn, 'wait_service', return_value=False), patch.object(vpn, 'install_guard') as guard:
            self.assertFalse(vpn.start_config({}, {}))
            guard.assert_not_called()

    def test_successful_start_installs_capture_and_flushes_poisoned_cache(self):
        events = []
        with patch.object(vpn, 'write_runtime_config'), patch.object(vpn, 'run'), patch.object(vpn, 'wait_service', return_value=True), patch.object(vpn, 'install_guard', side_effect=lambda _: events.append('guard')), patch.object(vpn, 'flush_dns_cache', side_effect=lambda: events.append('flush')):
            self.assertTrue(vpn.start_config({}, {}))
            self.assertEqual(events, ['guard', 'flush'])

    def test_pinned_xray_accepts_dns_listeners(self):
        binary = Path('/opt/vpn-manager/bin/xray')
        if not binary.exists():
            self.skipTest('Xray not installed')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            path.write_text(json.dumps(self.config(False)))
            subprocess.run([str(binary), 'run', '-test', '-config', str(path)], check=True, capture_output=True)
