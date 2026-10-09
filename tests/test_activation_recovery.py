import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

spec=importlib.util.spec_from_file_location('activation',Path(__file__).parents[1]/'src/vpnctl.py')
vpn=importlib.util.module_from_spec(spec);spec.loader.exec_module(vpn)

class RecoveryTests(unittest.TestCase):
    def test_unexpected_failure_after_mutation_runs_recovery(self):
        def broken(settings,path,tx):
            tx.update(touched=True,was_active=False,old_state={},old_config=None)
            raise OSError('nft failed')
        with patch.object(vpn,'_activate',side_effect=broken),patch.object(vpn,'_recover_activation') as recover:
            with self.assertRaisesRegex(OSError,'nft failed'):vpn.activate({},Path('Estonia'))
            recover.assert_called_once()

    def test_interrupt_after_mutation_runs_recovery(self):
        def interrupted(settings,path,tx):tx.update(touched=True);raise KeyboardInterrupt()
        with patch.object(vpn,'_activate',side_effect=interrupted),patch.object(vpn,'_recover_activation') as recover:
            with self.assertRaises(KeyboardInterrupt):vpn.activate({},Path('Estonia'))
            recover.assert_called_once()

    def test_preflight_failure_does_not_touch_network(self):
        with patch.object(vpn,'_activate',side_effect=vpn.VPNError('preflight')),patch.object(vpn,'_recover_activation') as recover:
            with self.assertRaises(vpn.VPNError):vpn.activate({},Path('Estonia'))
            recover.assert_not_called()

    def test_handled_rollback_is_not_repeated(self):
        def handled(settings,path,tx):tx.update(touched=True,handled=True);raise vpn.VPNError('already restored')
        with patch.object(vpn,'_activate',side_effect=handled),patch.object(vpn,'_recover_activation') as recover:
            with self.assertRaises(vpn.VPNError):vpn.activate({},Path('Estonia'))
            recover.assert_not_called()

    def test_cold_recovery_restores_direct_and_previous_profile_selection(self):
        with patch.object(vpn,'stop_core') as stop,patch.object(vpn,'RUNTIME_CONFIG') as runtime,patch.object(vpn,'remove_guard') as guard,patch.object(vpn,'save_state') as save:
            vpn._recover_activation({},dict(was_active=False,old_state={'last_active':'Estonia'},old_config=None))
            stop.assert_called_once();guard.assert_called_once()
            save.assert_called_once_with({'last_active':'Estonia','active':None})

    def test_running_core_without_committed_profile_is_not_ready(self):
        with patch.object(vpn.starfive,'status',return_value={'active':False,'guard':False}), patch.object(vpn,'load_state',return_value={'active':None}), patch.object(vpn,'service_active',return_value=True), patch.object(vpn,'_operation_payload',return_value={}), patch.object(vpn,'nft_exists',return_value=True), patch.object(vpn,'read_direct_sites',return_value=[]), patch.object(vpn,'read_direct_networks',return_value=[]), patch.object(vpn,'read_direct_apps',return_value=[]):
            self.assertFalse(vpn._status_payload({})['active'])

    def test_operation_state_ignores_stale_and_empty_lock(self):
        import json
        with tempfile.TemporaryDirectory() as td,patch.object(vpn,'RUNTIME_DIR',Path(td)):
            p=Path(td)/'operation.lock';p.write_text('')
            self.assertEqual(vpn._operation_payload(),{})
            p.write_text(json.dumps({'pid':os.getpid(),'command':'toggle','started':0}))
            self.assertEqual(vpn._operation_payload()['command'],'toggle')
            p.write_text(json.dumps({'pid':99999999,'command':'toggle','started':0}))
            self.assertEqual(vpn._operation_payload(),{})
