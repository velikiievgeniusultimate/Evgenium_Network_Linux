import hashlib,io,json,tempfile,unittest,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import starfive_tunnel as t
import path_ranking as ranking
import support_reports as reports

class Candidate(unittest.TestCase):
 def test_added_candidate_rebuilds_old_ranking(self):
  with tempfile.TemporaryDirectory() as folder:
   path=Path(folder)/'ranking.json';old=ranking.Ranking(path,('ru-udp','ee-udp','ee-tls'))
   old.build({x:{'ok':True,'download_mbps':10,'upload_mbps':10} for x in old.ids})
   new=ranking.Ranking(path,[x['id'] for x in t.CANDIDATES]);self.assertFalse(new.load())
   new.build({x:{'ok':True,'download_mbps':100 if x=='ee-evgt' else 10,'upload_mbps':100 if x=='ee-evgt' else 10} for x in new.ids})
   self.assertEqual(new.candidates()[0],'ee-evgt')
   for _ in range(3):new.lose('ee-evgt','path_health_failed')
   self.assertNotIn('ee-evgt',new.candidates())
 def test_binary_download_is_pinned_and_cached(self):
  blob=b'test executable';digest=hashlib.sha256(blob).hexdigest()
  with tempfile.TemporaryDirectory() as folder,patch.object(t,'ROOT',Path(folder)),patch.object(t.platform,'machine',return_value='x86_64'),patch.object(t,'EVGT_ASSETS',{'x86_64':('amd64',digest)}),patch.object(t.urllib.request,'urlopen',return_value=io.BytesIO(blob)) as fetch:
   path=t.ensure_evgt_binary();self.assertEqual(path.read_bytes(),blob);self.assertEqual(path.stat().st_mode&0o777,0o700)
   self.assertEqual(t.ensure_evgt_binary(),path);self.assertEqual(fetch.call_count,1)
 def test_bad_download_never_replaces_existing_binary(self):
  with tempfile.TemporaryDirectory() as folder,patch.object(t,'ROOT',Path(folder)),patch.object(t.platform,'machine',return_value='x86_64'),patch.object(t.urllib.request,'urlopen',return_value=io.BytesIO(b'corrupt')):
   path=Path(folder)/('evgenium-tunnel-'+t.EVGT_VERSION);path.write_bytes(b'old')
   with self.assertRaisesRegex(RuntimeError,'checksum'):t.ensure_evgt_binary()
   self.assertEqual(path.read_bytes(),b'old')
 def test_reports_accept_four_paths_without_credentials(self):
  report={'schema':1,'event':'support_bundle','consent':True,'report_id':'a'*32,'manager':'0.5.1','architecture':'x86_64','system':'arch','time':1,'paths':{x['id']:{'score':10,'token':'secret'} for x in t.CANDIDATES}}
  clean=reports.clean_bundle(report);self.assertEqual(len(clean['paths']),4);self.assertNotIn('secret',json.dumps(clean))
