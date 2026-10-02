import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('vpnctl', Path(__file__).parents[1] / 'src/vpnctl.py')
vpn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vpn)

class StartupTests(unittest.TestCase):
    def test_temporary_failure_does_not_restart_core(self):
        with patch.object(vpn, '_health_check_v4_once', side_effect=[(False,'timeout'), (True,'1.1.1.1'), (True,'1.1.1.1')]), patch.object(vpn, 'stop_core') as stop:
            self.assertTrue(vpn.health_check_v4()[0])
            stop.assert_not_called()

    def test_one_provider_not_sufficient(self):
        with patch.object(vpn, '_health_check_v4_once', side_effect=[(False,'down'), (True,'1.1.1.1')]*3):
            self.assertFalse(vpn.health_check_v4()[0])

    def test_malformed_and_ipv6_rejected(self):
        for output in ('HTML', '::1'):
            with patch.object(vpn, 'run', return_value=subprocess.CompletedProcess([],0,output,'')):
                self.assertFalse(vpn._health_check_v4_once('https://api.ipify.org')[0])

    def test_timeout_is_not_uncaught_transaction_exception(self):
        with patch.object(vpn, 'run', side_effect=subprocess.TimeoutExpired('curl',15)):
            self.assertFalse(vpn._health_check_v4_once('https://api.ipify.org')[0])

    def test_same_actual_config_reuses_known_mode(self):
        st = {'active':'Estonia','ipv6_mode':'blocked','since':1000}
        with patch.object(vpn.time, 'time', return_value=1100):
            self.assertTrue(vpn.reuse_ipv4_mode(st,Path('Estonia'),b'{"a":1}',{'a':1}))
            self.assertFalse(vpn.reuse_ipv4_mode(st,Path('Estonia'),b'{"a":2}',{'a':1}))
            self.assertFalse(vpn.reuse_ipv4_mode(st,Path('Other'),b'{"a":1}',{'a':1}))
            self.assertFalse(vpn.reuse_ipv4_mode(st,Path('Estonia'),b'invalid',{'a':1}))
        with patch.object(vpn.time, 'time', return_value=90000):
            self.assertFalse(vpn.reuse_ipv4_mode(st,Path('Estonia'),b'{"a":1}',{'a':1}))

    def test_healthy_same_config_is_idempotent(self):
        st = {'active':'Estonia','ipv6_mode':'blocked','since':1000}
        with patch.object(vpn.time,'time',return_value=1100), \
             patch.object(vpn,'load_state',return_value=st), \
             patch.object(vpn,'RUNTIME_CONFIG') as runtime, \
             patch.object(vpn,'service_active',return_value=True), \
             patch.object(vpn,'load_profile',return_value=[{}]), \
             patch.object(vpn,'build_config',return_value={'a':1}), \
             patch.object(vpn,'validate_candidate'), \
             patch.object(vpn,'save_state'), \
             patch.object(vpn,'health_check_v4',return_value=(True,'1.1.1.1')), \
             patch.object(vpn,'stop_core') as stop, \
             patch.object(vpn,'start_config') as start:
            runtime.exists.return_value=True
            runtime.read_bytes.return_value=b'{"a":1}'
            vpn.activate({},Path('Estonia'))
            stop.assert_not_called()
            start.assert_not_called()

    def test_cold_boot_requires_matching_fingerprint(self):
        st={'active':'Estonia','ipv6_mode':'blocked','since':1000,
            'ipv4_config_sha256':vpn.config_fingerprint({'a':1})}
        with patch.object(vpn.time,'time',return_value=1100):
            self.assertTrue(vpn.reuse_ipv4_mode(st,Path('Estonia'),None,{'a':1}))
            self.assertFalse(vpn.reuse_ipv4_mode(st,Path('Estonia'),None,{'a':2}))

    def test_cold_start_uses_known_v4_without_ipv6_probe(self):
        cfg={'a':1}
        st={'active':'Estonia','ipv6_mode':'blocked','since':1000,
            'ipv4_config_sha256':vpn.config_fingerprint(cfg)}
        with patch.object(vpn.time,'time',return_value=1100), \
             patch.object(vpn,'load_state',return_value=st), \
             patch.object(vpn,'RUNTIME_CONFIG') as runtime, \
             patch.object(vpn,'service_active',return_value=False), \
             patch.object(vpn,'load_profile',return_value=[{}]), \
             patch.object(vpn,'build_config',return_value=cfg) as build, \
             patch.object(vpn,'validate_candidate'), \
             patch.object(vpn,'health_check_v4',return_value=(True,'1.1.1.1')), \
             patch.object(vpn,'save_state'), \
             patch.object(vpn,'install_guard'), \
             patch.object(vpn,'probe_ipv6_via_vpn') as ipv6, \
             patch.object(vpn,'start_config',return_value=True) as start:
            runtime.exists.return_value=False
            vpn.activate({},Path('Estonia'))
            build.assert_called_once_with({},[{}],ipv6_enabled=False)
            start.assert_called_once()
            ipv6.assert_not_called()

if __name__ == '__main__':
    unittest.main()
