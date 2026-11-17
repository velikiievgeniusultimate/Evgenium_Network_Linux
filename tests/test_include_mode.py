import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('include_cli', ROOT/'src/vpnctl.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
p = m.policy

class IncludeModeTests(unittest.TestCase):
    def test_old_policy_keeps_full_vpn_and_separate_empty_include_list(self):
        with tempfile.TemporaryDirectory() as td, patch.object(p, 'PATH', Path(td)/'policy.json'):
            p.PATH.write_text(json.dumps({'schema':1, 'applications':['firefox']}))
            loaded = p.load()
            self.assertEqual(loaded['mode'], 'all')
            self.assertEqual(loaded['applications'], ['firefox'])
            self.assertEqual(loaded['include']['applications'], [])

    def test_cli_mode_and_lists_persist_without_inverting_saved_exceptions(self):
        with tempfile.TemporaryDirectory() as td, patch.object(p, 'PATH', Path(td)/'policy.json'), patch.object(m, 'ensure_root'), patch.object(m, 'load_settings', return_value={}), patch.object(m, 'operation_guard', return_value=contextlib.nullcontext()), patch.object(m.starfive_tunnel, 'full_guard_active', return_value=False), contextlib.redirect_stdout(io.StringIO()):
            m.main(['app','add','firefox'])
            m.main(['mode','include'])
            m.main(['include','app','add','codex'])
            m.main(['include','site','add','openai.com'])
            m.main(['mode','all'])
            self.assertEqual(p.load()['applications'], ['firefox'])
            self.assertEqual(p.load()['include']['applications'], ['codex'])
            self.assertEqual(p.load()['include']['networks'], ['openai.com'])
            m.main(['include','app','remove','codex'])
            self.assertEqual(p.load()['include']['applications'], [])

    def test_only_explicit_selection_routes_to_vpn_and_dns_defaults_direct(self):
        value=p.defaults();value['mode']='include'
        value['include']['applications']=['codex']
        value['include']['networks']=['openai.com','=exact.test','203.0.113.10/32']
        value['include']['ports']=['tcp:443:out']
        cfg=p.config(value); rules=cfg['routing']['rules']
        self.assertEqual(rules[-1]['outboundTag'],'direct')
        self.assertEqual(rules[-2]['outboundTag'],'direct')
        selected=[r for r in rules if r.get('inboundTag')==['tun'] and r['outboundTag']=='vpn']
        self.assertTrue(any(r.get('process')==['codex'] for r in selected))
        self.assertTrue(any(r.get('ip')==['203.0.113.10/32'] for r in selected))
        self.assertTrue(any(r.get('domain')==['domain:openai.com','full:exact.test'] for r in selected))
        self.assertTrue(any(r.get('port')=='443' for r in selected))
        dns=next(o for o in cfg['outbounds'] if o['tag']=='dns')
        self.assertEqual(dns['streamSettings']['sockopt']['mark'],p.DIRECT)
        with patch.object(p,'waydroid_network',return_value={'networks':[]}):
            ruleset=p.firewall(value,[],1001)
        self.assertIn('ct direction reply meta mark set '+str(p.DIRECT)+' return',ruleset)
        self.assertNotIn('dnat ip to 172.29.247.2',ruleset)
        self.assertIn('th dport 53 meta mark set '+str(p.DIRECT),ruleset)

    def test_bad_mode_or_live_failure_restores_prior_policy(self):
        with tempfile.TemporaryDirectory() as td, patch.object(p,'PATH',Path(td)/'policy.json'), patch.object(m.starfive_tunnel,'full_guard_active',return_value=True), patch.object(p.Path,'exists',return_value=True), patch.object(p,'apply',side_effect=[RuntimeError('classifier refused'),None]):
            p.save(p.defaults())
            with self.assertRaises(ValueError):p.change('mode',value='typo')
            with self.assertRaises(RuntimeError):p.change('mode',value='include')
            self.assertEqual(p.load()['mode'],'all')

    def test_outage_rejects_unapplied_selection_changes_without_saving(self):
        with tempfile.TemporaryDirectory() as td,patch.object(p,'PATH',Path(td)/'policy.json'),patch.object(m.starfive_tunnel,'full_guard_active',return_value=True):
            p.save({**p.defaults(),'mode':'include'})
            original=p.PATH.read_bytes()
            exists=p.Path.exists
            for action,cat,value in [('include-add','applications','codex'),('mode','','all')]:
                with patch.object(p.Path,'exists',lambda path: False if str(path).startswith('/sys/class/net/') else exists(path)),self.assertRaisesRegex(RuntimeError,'прежние правила сохранены'):
                    p.change(action,cat,value)
                self.assertEqual(p.PATH.read_bytes(),original)

    def test_new_cli_only_install_defaults_to_include(self):
        with tempfile.TemporaryDirectory() as td, patch.object(p,'PATH',Path(td)/'policy.json'), patch.object(m,'read_server_ports',return_value=[]):
            p.migration({'cli_only':True})
            self.assertEqual(p.load()['mode'],'include')

    def test_riscv_uses_official_xray_asset_with_release_digest(self):
        asset={'name':'Xray-linux-riscv64.zip','digest':'sha256:'+'a'*64,'browser_download_url':'https://github.com/XTLS/Xray-core/releases/download/v26.7.28/Xray-linux-riscv64.zip'}
        with patch.object(m.os,'uname',return_value=SimpleNamespace(machine='riscv64')),patch.object(m,'http_get',return_value=json.dumps({'tag_name':'v26.7.28','assets':[asset]}).encode()):
            name,url,digest,_=m.github_xray_asset()
        self.assertEqual(name,asset['name']);self.assertEqual(digest,'a'*64)

    def test_debian_dependency_install_uses_native_packages(self):
        t=m.starfive_tunnel
        with patch.object(t,'charon_binary',side_effect=[None,'/usr/sbin/charon-systemd']),patch.object(t.shutil,'which',side_effect=lambda name:'/usr/bin/'+name if name not in ('pacman','dnf') else None),patch.object(t,'command') as command,patch.object(t,'stage'),patch.object(t,'ensure_evgt_binary'):
            t.ensure_dependencies()
        self.assertEqual(command.call_args_list[0].args[0],['apt-get','update'])
        packages=command.call_args_list[1].args[0]
        self.assertIn('libcharon-extra-plugins',packages)
        self.assertNotIn('qt6-declarative',packages)

    def test_include_outage_retains_classifier_and_direct_routing(self):
        t=m.starfive_tunnel
        with tempfile.TemporaryDirectory() as td,patch.object(t,'ROOT',Path(td)),patch.object(p,'load',return_value={**p.defaults(),'mode':'include'}),patch.object(p,'stop') as stop,patch.object(t,'command') as cmd:
            t.write(t.full_state(),json.dumps({'active':True,'dns_mode':'direct'}))
            t.cleanup_full()
            stop.assert_not_called()
            self.assertFalse(any(c.args[0][:3]==['ip','route','del'] for c in cmd.call_args_list))

if __name__=='__main__':unittest.main()
