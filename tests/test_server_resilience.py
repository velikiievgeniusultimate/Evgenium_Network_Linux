import importlib.util
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('selector',Path(__file__).resolve().parents[1]/'scripts/server-link/resilience/resilient-health.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
class Selection(unittest.TestCase):
 def test_dead_main_requires_proven_backup(self):
  self.assertIsNone(s.choose('tcp',{'hy':1,'home':0},2,20))
  self.assertEqual(s.choose('tcp',{'hy':2,'home':3},2,20),'hy')
 def test_no_flapping(self):
  self.assertIsNone(s.choose('tcp',{'hy':5},5,5))
  self.assertIsNone(s.choose('hy',{'tcp':89},0,180))
  self.assertEqual(s.choose('hy',{'tcp':90},0,180),'tcp')
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
if __name__=='__main__':unittest.main()
