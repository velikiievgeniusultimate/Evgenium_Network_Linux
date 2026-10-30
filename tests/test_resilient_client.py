import sys,tempfile,json,unittest,time,asyncio,struct
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import path_ranking as r
import support_reports as s
import tls_transport as tls
class Ranking(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.r=r.Ranking(Path(self.tmp.name)/'ranking.json',('ru-udp','ee-udp','ee-tls'))
  self.m={'ru-udp':{'ok':True,'download_mbps':100,'upload_mbps':10},'ee-udp':{'ok':True,'download_mbps':70,'upload_mbps':70},'ee-tls':{'ok':False}}
  self.r.build(self.m)
 def test_bidirectional_score(self):self.assertEqual(self.r.candidates()[0],'ee-udp')
 def test_bootstrap_tries_ru_without_inventing_measurements(self):
  self.r.bootstrap()
  self.assertEqual(self.r.candidates(),['ru-udp','ee-udp','ee-tls'])
  for entry in self.r.data['entries'].values():
   self.assertEqual(entry,{'score':0,'losses':0})
  self.assertTrue(r.Ranking(self.r.path,self.r.ids).load())
 def test_bootstrap_recovers_exhausted_routes_without_changing_ids(self):
  for identity in self.r.ids:
   for _ in range(3):self.r.lose(identity,'connection_failed')
  self.assertEqual(self.r.candidates(),[])
  self.r.bootstrap();self.assertEqual(self.r.candidates()[0],'ru-udp')
 def test_losses_persist_and_only_repair_resets(self):
  for _ in range(3):self.r.lose('ee-udp','path_health_failed')
  fresh=r.Ranking(self.r.path,self.r.ids);self.assertTrue(fresh.load())
  self.assertNotIn('ee-udp',fresh.candidates());self.assertEqual(fresh.candidates()[0],'ru-udp')
  fresh.build(self.m);self.assertEqual(fresh.candidates()[0],'ee-udp')
 def test_next_is_lower_rank(self):self.assertEqual(self.r.next_after('ee-udp'),'ru-udp')
 def test_bad_persistent_data_rebuilds(self):
  for data in ([],{}, {'schema':1,'order':list(self.r.ids),'entries':dict.fromkeys(self.r.ids,None)}):
   self.r.path.write_text(json.dumps(data));self.assertFalse(self.r.load())
 def test_nonfinite_rejected(self):
  self.r.data['entries']['ru-udp']['score']=float('nan');self.r.save();self.assertFalse(self.r.load())
class Reports(unittest.TestCase):
 def body(self):return {'schema':1,'event':'support_bundle','consent':True,'report_id':'a'*32,'manager':'0.5.0','architecture':'x86_64','system':'arch','time':int(time.time()),'events':[]}
 def test_secrets_and_history_dropped_recursively(self):
  b=self.body();b.update(token='secret',history=['private.example'],paths={'ru-udp':{'download_mbps':3,'token':'secret'}},state={'active':True,'token':'secret'})
  clean=json.dumps(s.clean_bundle(b));self.assertNotIn('secret',clean);self.assertNotIn('private.example',clean)
 def test_consent_required_and_send_does_not_touch_network(self):
  for consent in (False,None,1,'true'):
   b=self.body();b['consent']=consent
   with self.assertRaises(ValueError):s.clean_bundle(b)
   with self.assertRaises(ValueError):s.send(None,'a'*32,consent)
 def test_dynamic_text_cannot_enter_events(self):
  b=self.body();b['events']=[{'time':1,'phase':'connected','code':'token-secret'}]
  with self.assertRaises(ValueError):s.clean_bundle(b)
 def test_no_nonfinite_or_unbounded_events(self):
  b=self.body();b['counters']={'rx_bytes':float('inf')}
  with self.assertRaises(ValueError):s.clean_bundle(b)
  b=self.body();b['events']=[{}]*129
  with self.assertRaises(ValueError):s.clean_bundle(b)
class Transport(unittest.IsolatedAsyncioTestCase):
 async def test_queue_bounded_and_other_peer_rejected(self):
  d=tls.Datagrams()
  for i in range(100):d.datagram_received(b'x',('127.0.0.1',3))
  self.assertEqual(d.queue.qsize(),32)
  d.queue.get_nowait();d.datagram_received(b'bad',('127.0.0.1',4));self.assertEqual(d.queue.qsize(),31)
 async def test_truncated_frame_closes_writer_and_tasks(self):
  class Writer:
   closed=False
   def write(self,b):pass
   async def drain(self):pass
   def close(self):self.closed=True
   async def wait_closed(self):pass
  reader=asyncio.StreamReader();reader.feed_data(struct.pack('!H',5)+b'a');reader.feed_eof()
  writer=Writer()
  with self.assertRaises(asyncio.IncompleteReadError):await tls.transfer(reader,writer,tls.Datagrams())
  self.assertTrue(writer.closed)
if __name__=='__main__':unittest.main()

import starfive_tunnel as tunnel
class Recovery(unittest.TestCase):
 def test_speed_drop_detects_upload_only_and_ignores_unavailable_measurement(self):
  baseline={'download_mbps':100,'upload_mbps':100}
  self.assertTrue(tunnel.speed_degraded({'available':True,'download_mbps':100,'upload_mbps':5},baseline))
  self.assertFalse(tunnel.speed_degraded({'available':False},baseline))
  self.assertFalse(tunnel.speed_degraded({'available':True,'download_mbps':90,'upload_mbps':80},baseline))
 def test_restore_only_our_resolver_link(self):
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'resolv.conf';path.symlink_to('/run/evgenium-resolv.conf')
   data={'resolver_original':{'link':'../original-stub','text':'','existed':True}}
   tunnel.restore_resolver_file(data,path);self.assertEqual(str(path.readlink()),'../original-stub')
   path.unlink();path.write_text('changed by network manager')
   tunnel.restore_resolver_file(data,path);self.assertEqual(path.read_text(),'changed by network manager')
 def test_measurement_refuses_unowned_routing_table(self):
  import subprocess
  with tempfile.TemporaryDirectory() as directory,patch.object(tunnel,'ROOT',Path(directory)),patch.object(tunnel,'command',return_value=subprocess.CompletedProcess([],0,'default via 192.0.2.1','')),patch.object(Path,'exists',return_value=False):
   with self.assertRaisesRegex(RuntimeError,'full_table_collision'):tunnel.prepare_data_plane('192.0.2.2')
   self.assertFalse(tunnel.full_state().exists())

import importlib.util
spec=importlib.util.spec_from_file_location('collector',Path(__file__).resolve().parents[1]/'server/diagnostic_collector.py')
collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)
class Collector(unittest.TestCase):
 def test_consent_limits_and_idempotence(self):
  with tempfile.TemporaryDirectory() as directory,patch.object(collector,'LOG',Path(directory)),patch.object(collector,'SUPPORT_LIMITS',{}):
   body=Reports().body()
   collector.store_report(b'fake-cert',body);collector.store_report(b'fake-cert',body)
   for i in range(1,6):
    body={**body,'report_id':f'{i:032x}'};collector.store_report(b'fake-cert',body)
   with self.assertRaisesRegex(ValueError,'hourly_limit'):collector.store_report(b'fake-cert',{**body,'report_id':'b'*32})
   lines=next(Path(directory).glob('*.jsonl')).read_text().splitlines();self.assertEqual(len(lines),6)
   with self.assertRaises(ValueError):collector.store_report(b'other-cert',{**body,'consent':False})
