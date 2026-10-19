import base64,contextlib,importlib.util,io,json,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).parents[1]
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=module('cli',ROOT/'src/vpnctl.py');gui=module('gui_bridge',ROOT/'src/evgenium_gui.py')
class GuiCliIntegrationTests(unittest.TestCase):
 def test_real_gui_encoder_is_accepted_by_privileged_decoder(self):
  for action,method in [('connect','connect'),('repair','connect'),('disconnect','disconnect')]:
   with self.subTest(action=action),patch.object(m.starfive_tunnel,method) as called:
    payload=gui.encode_ui_payload({'action':action})
    with patch.object(m.sys,'stdin',io.StringIO(payload)):m.cmd_ui_action({},'-')
    called.assert_called_once()
 def test_gui_unicode_rule_and_switch_survive_wire_format(self):
  for value in [{'action':'add','category':'networks','value':'пример.рф'}, {'action':'base','category':'dns','value':'stub','enabled':False}]:
   with patch.object(m.policy,'change') as called:
    m.cmd_ui_action({},gui.encode_ui_payload(value))
    self.assertEqual(called.call_args.args[2],value['value'])
    self.assertEqual(called.call_args.args[3],value.get('enabled'))
 def test_cli_failure_is_nonzero_and_explains_how_to_recover(self):
  state={'active':False,'guard':True,'policy':m.policy.defaults(),'tunnel':{'phase':'failed','progress':0,'message':'DNS failed','error_code':'system_dns_failed'}}
  out=io.StringIO()
  with patch.object(m,'status_data',return_value=state),contextlib.redirect_stdout(out):code=m.terminal_wait()
  self.assertEqual(code,1);self.assertIn('system_dns_failed',out.getvalue());self.assertIn('vpn repair',out.getvalue());self.assertIn('ЗАБЛОКИРОВАНО',out.getvalue())
 def test_cli_success_requires_vpn_only_ip_probe(self):
  import subprocess
  state={'active':True,'guard':True,'policy':m.policy.defaults(),'tunnel':{'phase':'connected','progress':100,'message':'Connected'}}
  with patch.object(m,'status_data',return_value=state),patch.object(m,'run',return_value=subprocess.CompletedProcess([],0,'38.180.164.67','')) as run,contextlib.redirect_stdout(io.StringIO()):
   self.assertEqual(m.terminal_wait(),0)
  self.assertIn('--socks5-hostname',run.call_args.args[0]);self.assertIn('127.0.0.1:18554',run.call_args.args[0])
