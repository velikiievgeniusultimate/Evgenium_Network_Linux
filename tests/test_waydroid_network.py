import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('waydroid_manager', ROOT/'src/vpnctl.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
p = m.policy


class WaydroidNetworkTests(unittest.TestCase):
    def test_watch_does_not_hold_the_global_operation_lock_forever(self):
        import argparse
        self.assertFalse(m.operation_requires_lock(argparse.Namespace(cmd='internal-waydroid-watch')))
        self.assertIn('PartOf=evgenium-policy.service', p.WAYDROID_UNIT)
        self.assertIn('Wants=evgenium-waydroid-network.service', p.UNIT)

    def test_recreated_bridge_refreshes_routes_even_with_identical_subnet(self):
        with tempfile.TemporaryDirectory() as td, patch.object(p,'RUN',Path(td)):
            cache=Path(td)/'waydroid-network.json'
            cache.write_text(json.dumps({'index':4,'networks':['192.168.240.0/24']}))
            state={'index':8,'networks':['192.168.240.0/24']}
            routes=[{'dst':'192.168.240.0/24','dev':'waydroid0'}, {'dst':'192.168.1.0/24','dev':'eth0'}]
            with patch.object(p,'waydroid_network',return_value=state),patch.object(p.tunnel,'command',return_value=subprocess.CompletedProcess([],0,json.dumps(routes),'')) as cmd:
                p.sync_waydroid_network()
                self.assertEqual(json.loads(cache.read_text()),state)
                self.assertTrue(any(c.args[0][:3]==['ip','route','replace'] for c in cmd.call_args_list))
                self.assertFalse(any('eth0' in c.args[0] for c in cmd.call_args_list))
                cmd.reset_mock();p.sync_waydroid_network();cmd.assert_not_called()

    def test_lost_bridge_removes_only_its_routes_and_clears_set(self):
        with tempfile.TemporaryDirectory() as td, patch.object(p,'RUN',Path(td)):
            state={'index':None,'networks':[]}
            routes=[{'dst':'192.168.240.0/24','dev':'waydroid0'}, {'dst':'192.168.1.0/24','dev':'eth0'}]
            with patch.object(p,'waydroid_network',return_value=state),patch.object(p.tunnel,'command',return_value=subprocess.CompletedProcess([],0,json.dumps(routes),'')) as cmd:
                p.sync_waydroid_network()
                calls=cmd.call_args_list
                self.assertIn('flush set inet',calls[1].kwargs['data'])
                self.assertNotIn('add element',calls[1].kwargs['data'])
                self.assertEqual(calls[2].args[0],['ip','route','del','192.168.240.0/24','dev','waydroid0','table',p.PHYSICAL_TABLE])

    def test_failed_set_update_is_retried_without_publishing_new_cache(self):
        with tempfile.TemporaryDirectory() as td, patch.object(p,'RUN',Path(td)):
            state={'index':5,'networks':['192.168.240.0/24']}
            with patch.object(p,'waydroid_network',return_value=state),patch.object(p.tunnel,'command',side_effect=[subprocess.CompletedProcess([],0,'[]',''),None,RuntimeError('nft failed')]):
                with self.assertRaises(RuntimeError):p.sync_waydroid_network()
                self.assertFalse((Path(td)/'waydroid-network.json').exists())

    def test_secondary_filter_preserves_unrelated_forwarding_block(self):
        rules=m.starfive_tunnel.host_rules('eth0',previous_forward=False)
        self.assertIn('oifname "waydroid0" meta nfproto ipv4 ct state established,related accept',rules)
        self.assertIn('meta nfproto ipv4 drop',rules)
        self.assertNotIn('flush ruleset',rules)


if __name__=='__main__':unittest.main()
