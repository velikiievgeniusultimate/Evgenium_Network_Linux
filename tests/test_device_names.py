import importlib.util,json,multiprocessing,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).parents[1]
s=importlib.util.spec_from_file_location('name_issuer',ROOT/'server/token_issuer.py');issuer=importlib.util.module_from_spec(s);s.loader.exec_module(issuer)
def reserve(args):
 folder,token,index=args
 issuer.ROOT=Path(folder)
 return issuer.device_info({'token':token,'device':f'{index:032x}'})
class DeviceNameTests(unittest.TestCase):
 def test_atomic_numbers_rename_and_account_isolation(self):
  with tempfile.TemporaryDirectory() as d,patch.object(issuer,'ROOT',Path(d)):
   token=issuer.issue('owner');other=issuer.issue('other')
   with multiprocessing.get_context('fork').Pool(4) as pool:items=pool.map(reserve,[(d,token,i) for i in range(1,7)])
   self.assertEqual(sorted(x['number'] for x in items),list(range(1,7)))
   self.assertEqual(sorted(x['name'] for x in items),['Устройство-'+str(i) for i in range(1,7)])
   before=issuer.device_info({'token':token,'device':f'{1:032x}'})
   changed=issuer.device_info({'token':token,'device':f'{1:032x}','name':'Мой ноутбук'})
   self.assertEqual(changed['number'],before['number']);self.assertEqual(changed['name'],'Мой ноутбук')
   same_id_other_owner=issuer.device_info({'token':other,'device':f'{1:032x}'})
   self.assertEqual(same_id_other_owner,{'name':'Устройство-1','number':1})
   self.assertEqual(issuer.device_info({'token':token,'device':f'{1:032x}'})['name'],'Мой ноутбук')
 def test_old_devices_get_stable_numbers_without_replacing_credentials(self):
  account={'devices':{'b'*32:{'identity':'device-b','key_hash':'secret-hash','enrolled':200},'a'*32:{'identity':'device-a','key_hash':'other-hash','enrolled':100}}}
  original=json.dumps(account['devices'],sort_keys=True)
  names=issuer.ensure_device_names(account)
  self.assertEqual(names['a'*32]['number'],1);self.assertEqual(names['b'*32]['number'],2)
  issuer.ensure_device_names(account);self.assertEqual(account['next_device_number'],3)
  self.assertEqual(json.dumps(account['devices'],sort_keys=True),original)
 def test_disabled_account_or_device_and_bad_names_are_rejected(self):
  with tempfile.TemporaryDirectory() as d,patch.object(issuer,'ROOT',Path(d)):
   token=issuer.issue('owner');device='a'*32
   for name in ['', 'a'*65, 'hidden\u202e', 'a\nb']:
    with self.assertRaises(ValueError):issuer.device_info({'token':token,'device':device,'name':name})
   data=issuer.accounts();a=next(iter(data.values()));a['devices'][device]={'identity':'device-test','disabled':True};issuer.write_json(Path(d)/'accounts.json',data)
   with self.assertRaises(PermissionError):issuer.device_info({'token':token,'device':device})
   a['enabled']=False;issuer.write_json(Path(d)/'accounts.json',data)
   with self.assertRaises(PermissionError):issuer.device_info({'token':token,'device':'b'*32})
