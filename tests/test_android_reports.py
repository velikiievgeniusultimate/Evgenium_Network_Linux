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

 def test_transfer_receipts_keep_only_bounded_correlation_and_counters(self):
  b=self.bundle();row=b['android']['samples'][0];row.update(phase='flow',values={'flow_id':'b'*32,'flow_server_received':17001,'flow_server_complete':0,'sha256':'secret','payload':'secret'})
  safe=clean_android(b)['android']['samples'][0]['values'];self.assertEqual(safe['flow_server_received'],17001);self.assertEqual(safe['flow_id'],'b'*32);self.assertNotIn('secret',json.dumps(safe))
  row['values']['flow_id']='EVN1-secret'
  with self.assertRaises(ValueError):clean_android(b)

 def test_upload_wait_stage_and_duration_are_preserved(self):
  b=self.bundle();row=b['android']['samples'][0];row.update(phase='flow',error='timeout',values={'flow_stage':4,'flow_elapsed_ms':30000,'flow_response_wait_ms':29890,'raw_response':'secret'})
  safe=clean_android(b)['android']['samples'][0]['values'];self.assertEqual(safe,{'flow_stage':4,'flow_elapsed_ms':30000,'flow_response_wait_ms':29890})

 def test_recovery_retry_is_accepted_without_raw_details(self):
  b=self.bundle();row=b['android']['samples'][0];row.update(phase='recovery_retry',error='none');row['values']['raw_reason']='secret'
  cleaned=clean_android(b)['android']['samples'][0];self.assertEqual(cleaned['phase'],'recovery_retry');self.assertNotIn('secret',json.dumps(cleaned))
