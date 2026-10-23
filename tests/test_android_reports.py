import unittest,sys,copy,json
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'server'),str(Path(__file__).resolve().parents[1]/'src')]
from android_reports import clean_android
class AndroidReports(unittest.TestCase):
 def bundle(self):return {'schema':1,'event':'support_bundle','consent':True,'report_id':'a'*32,'manager':'0.1.5','architecture':'aarch64','system':'android','time':123,'events':[],'paths':{},'state':{},'android':{'sdk':36,'manufacturer':'Xiaomi','model':'POCO F6','outcome':'snapshot','samples':[{'time':123,'phase':'health_failed','path':'ee-evgt-ru','network':'wifi','error':'timeout','carrier':{'heartbeat_timeouts':2},'values':{'up':50,'discord_ok':True}}],'rankings':{}}}
 def test_accepts_detailed_metrics(self):
  r=clean_android(self.bundle());self.assertEqual(r['android']['samples'][0]['carrier']['heartbeat_timeouts'],2);self.assertEqual(r['system'],'android')
 def test_discards_raw_logs_identifiers_and_secrets(self):
  b=self.bundle();b['token']='EVN1-secret';b['android']['serial']='secretserial';b['android']['samples'][0].update(raw_log='secretlog',address='192.0.2.1');b['android']['samples'][0]['carrier']['private_key']='secretkey';s=json.dumps(clean_android(b));self.assertNotIn('secret',s);self.assertNotIn('192.0.2.1',s)
 def test_requires_consent(self):
  b=self.bundle();b['consent']=False
  with self.assertRaises(ValueError):clean_android(b)
 def test_rejects_unbounded_and_invalid_data(self):
  for change in ('rows','nan','error','hardware'):
   b=self.bundle()
   if change=='rows':b['android']['samples']*=129
   if change=='nan':b['android']['samples'][0]['carrier']['reconnects']=float('nan')
   if change=='error':b['android']['samples'][0]['error']='raw secret message'
   if change=='hardware':b['android']['model']='EVN1-secret'
   with self.assertRaises(ValueError):clean_android(b)

 def test_packet_metrics_and_nested_service_result_survive(self):
  b=self.bundle();row=b['android']['samples'][0];row['phase']='packet';row['values']={'size':1200,'sent':20,'received':18,'loss_percent':10,'secret':'EVN1-secret','metrics':{'discord_ok':False,'up':20}}
  r=clean_android(b)['android']['samples'][0]['values'];self.assertEqual(r['loss_percent'],10);self.assertFalse(r['metrics']['discord_ok']);self.assertNotIn('secret',r)

 def test_specific_ike_errors_are_accepted_without_raw_messages(self):
  for state in ('unreachable','auth_failed','peer_auth_failed','lookup_failed','generic_error','password_missing','certificate_unavailable','timeout'):
   b=self.bundle();b['android']['samples'][0]['error']='ike_'+state
   self.assertEqual(clean_android(b)['android']['samples'][0]['error'],'ike_'+state)
