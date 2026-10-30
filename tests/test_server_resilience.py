import importlib.util
import unittest
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('selector',Path(__file__).resolve().parents[1]/'scripts/server-link/resilience/resilient-health.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
class Selection(unittest.TestCase):
 def test_dead_main_requires_proven_backup(self):
  self.assertIsNone(s.choose('tcp',{'hy':1,'home':0},2,20))
  self.assertEqual(s.choose('tcp',{'hy':2,'home':3},2,20),'hy')
 def test_reality_xhttp_are_verified_last_resorts(self):
  self.assertEqual(s.choose('hy',{'reality':2,'xhttp':2},2,20),'reality')
  self.assertEqual(s.choose('reality',{'xhttp':2},2,20),'xhttp')
  self.assertIsNone(s.choose('hy',{'reality':1,'xhttp':1},2,20))
 def test_no_flapping(self):
  self.assertIsNone(s.choose('tcp',{'hy':5},5,5))
  self.assertIsNone(s.choose('hy',{'tcp':89},0,180))
  self.assertEqual(s.choose('hy',{'tcp':90},0,180),'tcp')
 def test_cf_backup_requires_independent_proof(self):
  self.assertIsNone(s.choose('hy',{'xhttpcf':1},20,60))
  self.assertEqual(s.choose('hy',{'xhttpcf':2},20,60),'xhttpcf')
  self.assertIsNone(s.choose('xhttpcf',{'tcp':89},0,180))
  self.assertEqual(s.choose('xhttpcf',{'tcp':90},0,180),'tcp')
 def test_packet_fallback_avoids_jitter_flapping(self):
  self.assertIsNone(s.choose('evgt',{'xhttpcf':20},2,60))
  self.assertIsNone(s.choose('evgt',{'xhttpcf':20},5,14))
  self.assertEqual(s.choose('evgt',{'xhttpcf':2},3,15),'xhttpcf')
  self.assertEqual(s.choose('xhttpcf',{'evgt':2},2,20),'evgt')
  self.assertIsNone(s.choose('xhttpcf',{'evgt':1},2,20))
 def test_direct_gre_requires_authenticated_probe_and_keeps_fallback(self):
  self.assertIsNone(s.choose('evgt',{'gre':1},3,20))
  self.assertEqual(s.choose('evgt',{'gre':2},3,20),'gre')
  self.assertEqual(s.choose('gre',{'evgt':2},2,20),'evgt')
  self.assertIsNone(s.choose('gre',{'evgt':1},2,20))
 def test_direct_gre_preference_waits_for_stability(self):
  self.assertIsNone(s.choose('evgt',{'gre':89},0,180,preferred='gre'))
  self.assertEqual(s.choose('evgt',{'gre':90},0,180,preferred='gre'),'gre')
 def test_repair_never_restarts_working_data(self):
  self.assertIsNone(s.stalled_transport('tcp',True,{'tcp':100},{'tcp':150}))
 def test_repair_waits_for_repeated_failures_and_cooldown(self):
  self.assertIsNone(s.stalled_transport('tcp',True,{'home':5},{'home':150}))
  self.assertIsNone(s.stalled_transport('tcp',True,{'home':6},{'home':119}))
  self.assertEqual(s.stalled_transport('tcp',True,{'home':6},{'home':120}),'home')
 def test_repair_can_revive_stalled_only_path(self):
  self.assertEqual(s.stalled_transport('tcp',False,{'tcp':6},{'tcp':120}),'tcp')
 def test_one_known_transport_per_attempt(self):
  self.assertEqual(s.stalled_transport('tcp',True,{'hy':6,'home':6,'ssh':100},{'hy':120,'home':120,'ssh':150}),'hy')

class ProbeDiagnostics(unittest.TestCase):
 def test_probe_reports_exit_reason_and_wall_time_without_raw_output(self):
  for code,reason in ((0,'reply'),(1,'no_reply'),(124,'process_timeout'),(2,'probe_error'),(-9,'probe_error')):
   with self.subTest(code=code), patch.object(s,'command',return_value=subprocess.CompletedProcess([],code,'sensitive-output','sensitive-error')) as command, patch.object(s.time,'monotonic',side_effect=(10,10.031)):
    result=s.ping('evg-link')
   self.assertEqual(result,{'ok':code==0,'ms':31.0,'exit':code,'reason':reason})
   self.assertNotIn('sensitive',str(result))
   command.assert_called_once_with(['ip','netns','exec','evg-link','ping','-n','-c','1','-W','1','10.203.81.1'],2)
 def test_main_probe_evidence_is_logged_independently_of_path_probe(self):
  main={'ok':False,'ms':1004.0,'exit':1,'reason':'no_reply'}
  independent={'ok':True,'ms':31.0,'exit':0,'reason':'reply'}
  rows=[]
  def record(row):
   rows.append(row);s.STOP=True
  def command(argv,timeout=3):
   self.assertEqual(argv,['ip','netns','exec','evg-link','wg','show','evg-wg','endpoints'])
   return subprocess.CompletedProcess(argv,0,'public-key\t10.203.119.1:24547\n','')
  with tempfile.TemporaryDirectory() as tmp:
   base=Path(tmp);(base/'mode').write_text('gre');(base/'preferred-mode').write_text('gre')
   # The daemon intentionally holds its lock for process lifetime; retain and
   # explicitly close that descriptor in this bounded one-iteration test.
   path_open=Path.open
   with (base/'resilient-health.lock').open('w') as lock:
    def open_path(path,*args,**kwargs):
     return lock if path.name=='resilient-health.lock' else path_open(path,*args,**kwargs)
    with patch.object(Path,'open',new=open_path),patch.object(s,'BASE',base),patch.object(s,'STOP',False),patch.object(s.signal,'signal'),patch.object(s,'append',side_effect=record),patch.object(s,'command',side_effect=command),patch.object(s,'ping',side_effect=lambda ns,*args:dict(main if ns=='evg-link' else independent)):
     s.main()
   self.assertEqual(rows[0]['main_probe'],main)
   self.assertEqual(rows[0]['paths']['gre'],independent)
   self.assertFalse(rows[0]['inner_ok'])
   self.assertEqual(rows[0]['failures'],1)
   self.assertNotIn('action',rows[0])
if __name__=='__main__':unittest.main()
