import base64,importlib.util,json,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).parents[1]
spec=importlib.util.spec_from_file_location('unified',ROOT/'src/vpnctl.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=m.policy

class PolicyTests(unittest.TestCase):
 def test_migration_retains_explicit_rules_and_defaults_waydroid_direct(self):
  with tempfile.TemporaryDirectory() as td,patch.object(p,'PATH',Path(td)/'policy.json'):
   root=Path(td)
   for name,text in [('apps','firefox\n/opt/app\n'),('nets','203.0.113.0/24\n'),('sites','example.com\n')]: (root/name).write_text(text)
   settings={'direct_apps':str(root/'apps'),'direct_networks':str(root/'nets'),'direct_sites':str(root/'sites'),'owner_home':td}
   with patch.object(m,'read_server_ports',return_value={('tcp',25565)}):p.migration(settings)
   d=p.load();self.assertEqual(d['applications'],['firefox','/opt/app']);self.assertIn('example.com',d['networks']);self.assertEqual(d['ports'],['tcp:25565:in']);self.assertTrue(d['waydroid_direct'])
   d['waydroid_direct']=False;p.save(d);p.migration(settings);self.assertFalse(p.load()['waydroid_direct'])
 def test_reject_injection_reserved_network_and_misplaced_dns_rule(self):
  for cat,value in [('networks','10.0.0.0/8'),('networks','0.0.0.0/0'),('networks','https://example.com'),('applications','a\nrule'),('dns','127.0.0.53'),('ports','udp:53:out'),('ports','tcp:70000:in')]:
   with self.subTest(cat=cat,value=value),self.assertRaises(ValueError):p.normalize(cat,value)
 def test_idna_and_direction_normalization(self):
  self.assertEqual(p.normalize('networks','=пример.рф'),'=xn--e1afmkfd.xn--p1ai')
  self.assertEqual(p.normalize('ports','TCP:25565'),'tcp:25565:both')
 def test_base_switch_round_trip_does_not_erase_user_entries(self):
  with tempfile.TemporaryDirectory() as d,patch.object(p,'PATH',Path(d)/'policy.json'),patch.object(m.starfive_tunnel,'full_guard_active',return_value=False):
   p.change('add','networks','example.com');p.change('base','networks','lan',False)
   self.assertFalse(p.public()['base']['networks'][0]['enabled']);self.assertEqual(p.load()['networks'],['example.com'])
   p.change('base','networks','lan',True);self.assertTrue(p.public()['base']['networks'][0]['enabled'])
 def test_failed_live_change_restores_saved_policy(self):
  with tempfile.TemporaryDirectory() as d,patch.object(p,'PATH',Path(d)/'policy.json'),patch.object(m.starfive_tunnel,'full_guard_active',return_value=True),patch.object(p.Path,'exists',return_value=True),patch.object(p,'apply',side_effect=[RuntimeError('bad rule'),None]):
   p.save(p.defaults())
   with self.assertRaises(RuntimeError):p.change('add','applications','firefox')
   self.assertEqual(p.load()['applications'],[])
 def test_token_action_does_not_need_network_or_start_connection(self):
  payload=base64.urlsafe_b64encode(json.dumps({'action':'token-save','token':'EVN1-'+'a'*43}).encode()).decode()
  with patch.object(m.starfive_tunnel,'save_token') as save,patch.object(m.starfive_tunnel,'connect') as connect:
   m.cmd_ui_action({},payload);save.assert_called_once();connect.assert_not_called()
 def test_policy_does_not_advertise_online_without_classifier(self):
  with patch.object(m.starfive_tunnel,'status',return_value={'active':True,'guard':True}),patch.object(m,'service_active',return_value=False),patch.object(p,'public',return_value={}):
   self.assertFalse(m.status_data()['active'])
 def test_host_egress_health_is_forced_through_vpn(self):
  text=(ROOT/'src/starfive_tunnel.py').read_text();self.assertIn("'--socks5-hostname','127.0.0.1:18554'",text)
 def test_unknown_ui_action_rejected(self):
  payload=base64.urlsafe_b64encode(json.dumps({'action':'profile_activate','path':'/etc/shadow'}).encode()).decode()
  with self.assertRaises(m.VPNError):m.cmd_ui_action({},payload)
