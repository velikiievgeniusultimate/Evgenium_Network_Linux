"""Interrupted upgrades must retain a usable CLI/GUI and retry finalization."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('recovery_manager',ROOT/'src/vpnctl.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class RecoveryTests(unittest.TestCase):
    def fixture(self,stack,folder,events):
        stack.enter_context(patch.object(m,'INSTALL_PENDING',folder/'pending'))
        stack.enter_context(patch.object(m,'INSTALL_COMPLETE',folder/'complete'))
        for name in ('sync_system_files','cmd_gui_install','retire_legacy','core_update','ensure_gui_dependencies'):
            stack.enter_context(patch.object(m,name,side_effect=lambda *args,n=name:events.append(n)))
        stack.enter_context(patch.object(m,'_widget_package_dir',return_value=folder/'absent-widget'))
        stack.enter_context(patch.object(m,'_tray_autostart_path',return_value=folder/'absent-tray'))
        stack.enter_context(patch.object(m.policy,'migration',side_effect=lambda _:events.append('migration')))
        stack.enter_context(patch.object(m.starfive_tunnel,'status',return_value={'running':False}))
        stack.enter_context(patch.object(m.starfive_tunnel,'token_status',return_value={'has_token':False}))
        stack.enter_context(patch.object(m,'run',return_value=subprocess.CompletedProcess([],3,'','')))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        stack.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def test_dependency_failure_keeps_new_entrypoints_and_retries_same_version(self):
        with tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
            events=[];folder=Path(td);self.fixture(stack,folder,events)
            deps=stack.enter_context(patch.object(m.starfive_tunnel,'ensure_dependencies',side_effect=RuntimeError('mirror unavailable')))
            with self.assertRaisesRegex(RuntimeError,'mirror unavailable'):m.finish_installation({})
            self.assertTrue((folder/'pending').exists())
            self.assertFalse((folder/'complete').exists())
            self.assertEqual(events[:2],['sync_system_files','cmd_gui_install'])
            self.assertNotIn('retire_legacy',events)
            deps.side_effect=None
            stack.enter_context(patch.object(m,'http_get',return_value=json.dumps({'version':m.MANAGER_VERSION}).encode()))
            self.assertFalse(m.manager_update_manifest({},'https://example.test/manifest'))
            self.assertFalse((folder/'pending').exists())
            self.assertEqual(json.loads((folder/'complete').read_text())['version'],m.MANAGER_VERSION)
            self.assertEqual(events.count('cmd_gui_install'),2)

    def test_current_version_sync_does_not_reconnect_healthy_tunnel(self):
        with tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
            self.fixture(stack,Path(td),[])
            stack.enter_context(patch.object(m.starfive_tunnel,'ensure_dependencies'))
            stack.enter_context(patch.object(m.starfive_tunnel,'status',return_value={'running':True}))
            stack.enter_context(patch.object(m.starfive_tunnel,'token_status',return_value={'has_token':True}))
            stack.enter_context(patch.object(m.starfive_tunnel,'sync_device_name'))
            connect=stack.enter_context(patch.object(m.starfive_tunnel,'connect'))
            m.finish_installation({},reconnect=False);connect.assert_not_called()

    def test_pending_update_reconnects_and_keeps_pending_on_failure(self):
        with tempfile.TemporaryDirectory() as td,contextlib.ExitStack() as stack:
            folder=Path(td);self.fixture(stack,folder,[]);(folder/'pending').write_text('interrupted')
            stack.enter_context(patch.object(m.starfive_tunnel,'ensure_dependencies'))
            stack.enter_context(patch.object(m.starfive_tunnel,'status',return_value={'running':True}))
            stack.enter_context(patch.object(m.starfive_tunnel,'token_status',return_value={'has_token':True}))
            stack.enter_context(patch.object(m.starfive_tunnel,'sync_device_name'))
            connect=stack.enter_context(patch.object(m.starfive_tunnel,'connect',side_effect=RuntimeError('connect failed')))
            with self.assertRaises(RuntimeError):m.finish_installation({},reconnect=False)
            connect.assert_called_once_with(repair=True)
            self.assertTrue((folder/'pending').exists())

    def test_old_cli_only_arch_installs_qt(self):
        with patch.object(m.os,'access',side_effect=[False]*4+[True]),patch.object(m.shutil,'which',return_value='/usr/bin/pacman'),patch.object(m,'run') as run:
            m.ensure_gui_dependencies()
            self.assertIn('qt6-declarative',run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs['timeout'],300)

if __name__=='__main__':unittest.main()
