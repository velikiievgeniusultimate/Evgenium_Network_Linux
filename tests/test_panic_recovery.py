import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import starfive_tunnel as t
import path_ranking

class PanicRecovery(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name)
  self.patch=patch.object(t,'ROOT',self.root);self.patch.start();self.addCleanup(self.patch.stop)
  self.addCleanup(setattr,t,'STOP',False)
 def test_settings_fail_safe_and_are_persistent(self):
  for content in ('broken','[]','{"enabled":"true"}','{"enabled":false}'):
   (self.root/'panic.json').write_text(content);self.assertFalse(t.panic_enabled())
  with patch.object(t,'connect') as start:t.set_panic(True)
  self.assertTrue(t.panic_enabled());start.assert_called_once_with(restart=True)
 def test_preparation_failure_never_exhausts_retry_budget(self):
  (self.root/'panic.json').write_text(json.dumps({'enabled':True}))
  def failed():
   if once.call_count==15:t.STOP=True
  with patch.object(t,'worker_once',side_effect=failed) as once,patch.object(t,'stage'),patch.object(t,'signal'),patch.object(t,'recovery_pause') as pause:
   t.worker()
  self.assertEqual(once.call_count,15)
  self.assertEqual(pause.call_count,14)
  self.assertLessEqual(max(c.args[0] for c in pause.call_args_list),30)
 def test_normal_mode_does_not_restart_failed_preparation(self):
  with patch.object(t,'worker_once') as once,patch.object(t,'signal'),patch.object(t,'recovery_pause') as pause:
   t.worker()
  once.assert_called_once();pause.assert_not_called()
 def test_panic_cycles_all_routes_even_after_manual_selection(self):
  rank=path_ranking.Ranking(self.root/'rank.json',[c['id'] for c in t.CANDIDATES]);rank.bootstrap()
  order=rank.candidates();current=order[0];visited=[]
  for _ in range(len(order)*3):
   visited.append(current);current=t.recovery_route(rank,current,order[0],True)
  self.assertEqual(visited,order*3)
  self.assertEqual(t.recovery_route(rank,order[0],order[0],False),order[0])
 def test_manual_off_stops_and_disables_restart_after_boot(self):
  with patch.object(t,'command') as command,patch.object(t,'cleanup'),patch.object(t,'cleanup_full'),patch.object(t,'stage'):
   t.disconnect()
  args=[c.args[0] for c in command.call_args_list]
  self.assertIn(['systemctl','disable',t.UNIT],args)
  self.assertIn(['systemctl','stop',t.UNIT],args)
 def test_panic_service_has_no_restart_limit_and_boot_activation(self):
  (self.root/'panic.json').write_text('{"enabled":true}')
  writes={}
  with patch.object(t,'write',side_effect=lambda p,s:writes.update({str(p):s})),patch.object(t,'command') as command,patch.object(t,'ensure_dependencies'),patch.object(t,'token_status',return_value={'has_token':True}),patch.object(t,'stage'):
   t.connect()
  unit=writes['/etc/systemd/system/'+t.UNIT]
  self.assertIn('StartLimitIntervalSec=0',unit);self.assertIn('Restart=always',unit)
  self.assertIn('WantedBy=multi-user.target',unit)
  self.assertIn(['systemctl','enable',t.UNIT],[c.args[0] for c in command.call_args_list])
 def test_stop_interrupts_recovery_wait(self):
  t.STOP=True
  with patch.object(t.time,'sleep') as sleep:t.recovery_pause(30)
  sleep.assert_not_called()
