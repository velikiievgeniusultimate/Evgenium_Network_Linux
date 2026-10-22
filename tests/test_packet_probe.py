import unittest,sys,hmac,struct
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
from packet_probe import ProbeSessions
class PacketProbeTests(unittest.TestCase):
 def setUp(self):
  self.now=10; self.store=ProbeSessions(lambda:self.now);self.ticket=self.store.issue(b'owner','10.77.0.2')
 def packet(self,seq=0,size=128):
  b=b'EVP1'+bytes.fromhex(self.ticket['session'])+struct.pack('!I',seq)+bytes(size-56)
  return b+hmac.digest(bytes.fromhex(self.ticket['key']),b,'sha256')
 def test_authenticated_echo_and_server_counters(self):
  p=self.packet();sid,case,out=self.store.handle(p,'10.77.0.2');self.assertEqual(len(out),len(p));self.assertEqual(out[:4],b'EVP2')
  self.store.replied(sid,case);self.store.handle(p,'10.77.0.2')
  self.assertEqual(self.store.result(self.ticket['session'],b'owner')['cases'][0],dict(received=1,duplicates=1,replies=1))
  self.assertIsNone(self.store.handle(out,'10.77.0.2'))
 def test_wrong_mac_peer_sequence_size_and_expiry_rejected(self):
  p=self.packet()
  for data,peer in [(p[:-1]+bytes([p[-1]^1]),'10.77.0.2'),(p,'10.77.0.3'),(self.packet(120),'10.77.0.2'),(self.packet(0,512),'10.77.0.2')]:self.assertIsNone(self.store.handle(data,peer))
  self.now=131;self.assertIsNone(self.store.handle(p,'10.77.0.2'))
 def test_private_result_and_session_limit(self):
  with self.assertRaises(ValueError):self.store.result(self.ticket['session'],b'other')
  for _ in range(7):self.store.issue(b'owner','10.77.0.2')
  with self.assertRaises(ValueError):self.store.issue(b'owner','10.77.0.2')
 def test_duplicate_budget(self):
  for _ in range(40):self.assertIsNotNone(self.store.handle(self.packet(),'10.77.0.2'))
  self.assertIsNone(self.store.handle(self.packet(),'10.77.0.2'))
 def test_packet_api_requires_certificate_and_private_listener(self):
  import io,types
  from unittest.mock import MagicMock,patch
  import diagnostic_collector as collector
  for cert,direct,enabled,status in [(None,False,True,403),(b'cert',True,True,404),(b'cert',False,False,403)]:
   handler=object.__new__(collector.Handler);handler.path='/packet-session'
   handler.server=types.SimpleNamespace(enrollment=False,direct_only=direct)
   handler.connection=MagicMock();handler.connection.getpeercert.return_value=cert
   handler.headers={'Content-Length':'2'};handler.rfile=io.BytesIO(b'{}');handler.reply=MagicMock()
   with patch.object(collector.Path,'exists',return_value=enabled),patch('packet_probe.request') as issue:
    handler.do_POST();issue.assert_not_called()
   self.assertEqual(handler.reply.call_args.args[0],status)
