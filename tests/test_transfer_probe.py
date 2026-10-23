import io,sys,unittest,hashlib
from pathlib import Path
from unittest.mock import Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'server'))
from transfer_probe import TransferSessions
class TransferProbeTests(unittest.TestCase):
 def setUp(self):self.now=0;self.s=TransferSessions(lambda:self.now);self.owner=b'one';self.sock=Mock()
 def ticket(self):return self.s.issue(self.owner,32768)['session']
 def test_receipt_integrity_and_replay(self):
  sid=self.ticket();data=b'x'*32768;r=self.s.consume(sid,self.owner,len(data),io.BytesIO(data),self.sock)
  self.assertEqual(r['received'],len(data));self.assertTrue(r['complete']);self.assertEqual(r['sha256'],hashlib.sha256(data).hexdigest())
  with self.assertRaises(ValueError):self.s.consume(sid,self.owner,len(data),io.BytesIO(data),self.sock)
 def test_partial_upload_survives_disconnect_for_later_result(self):
  sid=self.ticket()
  with self.assertRaises(EOFError):self.s.consume(sid,self.owner,32768,io.BytesIO(b'x'*17001),self.sock)
  r=self.s.result(sid,self.owner);self.assertEqual(r['received'],17001);self.assertFalse(r['complete']);self.assertEqual(r['sha256'],'')
 def test_owner_expiry_and_bounded_size(self):
  sid=self.ticket()
  with self.assertRaises(ValueError):self.s.result(sid,b'other')
  for size in (0,-1,True,32769,1000000000):
   with self.assertRaises(ValueError):self.s.issue(self.owner,size)
  self.now=181
  with self.assertRaises(ValueError):self.s.result(sid,self.owner)
 def test_slow_trickle_cannot_hold_server_thread(self):
  sid=self.ticket();outer=self
  class Slow:
   def read1(self,n):outer.now+=5;return b'x'
  with self.assertRaises(TimeoutError):self.s.consume(sid,self.owner,32768,Slow(),self.sock)
  self.assertEqual(self.s.result(sid,self.owner)['received'],5)
 def test_capacity(self):
  for _ in range(12):self.ticket()
  with self.assertRaises(ValueError):self.ticket()
  self.now=181;self.ticket()
 def test_server_receipt_is_emitted_even_if_upload_connection_dies(self):
  sid=self.ticket();receipts=[]
  with self.assertRaises(EOFError):self.s.consume(sid,self.owner,32768,io.BytesIO(b'x'*100),self.sock,receipts.append)
  self.assertEqual(len(receipts),1);self.assertEqual(receipts[0]['received'],100);self.assertFalse(receipts[0]['complete'])
 def test_handler_never_allows_anonymous_transfer(self):
  import types
  from unittest.mock import patch
  import diagnostic_collector as collector
  h=object.__new__(collector.Handler);h.path='/transfer-start';h.server=types.SimpleNamespace(enrollment=False,direct_only=True);h.connection=Mock();h.connection.getpeercert.return_value=None;h.reply=Mock()
  with patch('transfer_probe.handle')as handle:
   h.do_POST();handle.assert_not_called()
  self.assertEqual(h.reply.call_args.args[0],403)
 def test_client_cannot_forge_authoritative_server_receipt(self):
  from diagnostic_collector import clean_report
  with self.assertRaises(ValueError):clean_report({'schema':1,'event':'transfer_receipt','flow_id':'a'*32})
