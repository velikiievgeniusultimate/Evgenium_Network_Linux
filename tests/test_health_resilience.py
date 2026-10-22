import sys,unittest,subprocess
from pathlib import Path
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import starfive_tunnel as t
class HealthResilience(unittest.TestCase):
 def setUp(self):t._egress_preferred=0
 def response(self,body,code=0):return subprocess.CompletedProcess([],code,body,'')
 def test_provider_outage_uses_independent_fallback_then_sticks(self):
  with patch.object(t,'inside',side_effect=[self.response('',28),self.response('38.180.164.67'),self.response('38.180.164.67')]) as call:
   self.assertTrue(t.egress_health());self.assertTrue(t.egress_health());self.assertIn('https://api.ipify.org',call.call_args.args[0])
 def test_wrong_exit_is_not_hidden_by_second_provider(self):
  with patch.object(t,'inside',return_value=self.response('ip=192.0.2.1\n')) as call:
   self.assertFalse(t.egress_health());self.assertEqual(call.call_count,1)
 def test_timeout_does_not_prevent_fallback(self):
  with patch.object(t,'inside',side_effect=[subprocess.TimeoutExpired('curl',7),self.response('38.180.164.67')]):self.assertTrue(t.egress_health())
 def test_private_collector_is_not_required_for_live_vpn(self):
  daemon=Mock();daemon.poll.return_value=None
  with patch.object(t,'installed',return_value=True),patch.object(t,'TLS_PROCESS',None),patch.object(t,'egress_health',return_value=True),patch.object(t,'health',side_effect=AssertionError('collector consulted')):
   self.assertTrue(t.path_healthy(daemon))
 def test_dead_transport_cannot_pass_using_stale_ike(self):
  daemon=Mock();daemon.poll.return_value=None;transport=Mock();transport.poll.return_value=1
  with patch.object(t,'installed',return_value=True),patch.object(t,'TLS_PROCESS',transport),patch.object(t,'egress_health') as probe:
   self.assertFalse(t.path_healthy(daemon));probe.assert_not_called()
 def test_strict_parse_rejects_ambiguous_and_embedded_addresses(self):
  for v in ['prefix ip=38.180.164.67','ip=38.180.164.67\nip=192.0.2.1','ip=999.2.3.4']:
   self.assertIsNone(t.parse_exit(v,True))
  self.assertIsNone(t.parse_exit('38.180.164.67 evil',False))
