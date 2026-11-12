import contextlib,sys,tempfile,unittest,json
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parents[1]/'src'))
import starfive_tunnel as t
import path_ranking
class SimpleRoutes(unittest.TestCase):
 def test_manual_choice_is_validated_and_migrates_removed_route_to_auto(self):
  with tempfile.TemporaryDirectory() as directory,patch.object(t,'ROOT',Path(directory)):
   t.select_route('ee-tls');self.assertEqual(t.selected_route(),'ee-tls')
   with self.assertRaises(ValueError):t.select_route('ee-udp')
   self.assertEqual(t.selected_route(),'ee-tls')
   (t.ROOT/'selection.json').write_text('{"route":"ee-udp"}')
   self.assertEqual(t.selected_route(),'auto')
 def test_worker_retries_every_candidate_without_changing_persistent_order(self):
  with tempfile.TemporaryDirectory() as directory,contextlib.ExitStack() as stack:
   root=Path(directory);stack.enter_context(patch.object(t,'ROOT',root))
   stack.enter_context(patch.object(t,'rank_api',path_ranking))
   ids=[c['id'] for c in t.CANDIDATES]
   r=path_ranking.Ranking(root/'ranking.json',ids)
   r.build({identity:{'ok':True,'download_mbps':10-i,'upload_mbps':10-i} for i,identity in enumerate(ids)})
   original=r.path.read_bytes();attempts=[]
   def fail(candidate,identity):
    attempts.append(candidate['id'])
    if len(attempts)>=len(ids)*4:t.STOP=True
    raise RuntimeError('path_health_failed')
   for name in ['cleanup','refresh_retained_guard','setup_network','sync_device_name','stop_candidate','stage']:
    stack.enter_context(patch.object(t,name))
   stack.enter_context(patch.object(t,'enroll',return_value=('device-test','test')))
   stack.enter_context(patch.object(t,'physical_route',return_value={'dev':'evg-test-absent'}))
   stack.enter_context(patch.object(t,'start_candidate',side_effect=fail))
   stack.enter_context(patch.object(t.time,'sleep'))
   stack.enter_context(patch.object(t.signal,'signal'))
   try:t.worker()
   finally:t.STOP=False
   self.assertEqual(attempts,ids*4)
   self.assertEqual(r.path.read_bytes(),original)
