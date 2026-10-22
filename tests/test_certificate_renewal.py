import importlib.util, subprocess, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
class RenewalTests(unittest.TestCase):
 def setUp(self):
  spec=importlib.util.spec_from_file_location('renew_issuer',Path(__file__).resolve().parents[1]/'server/token_issuer.py');self.i=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.i)
  self.tmp=tempfile.TemporaryDirectory();p=Path(self.tmp.name);self.i.ROOT=p/'accounts';self.i.PKI=p/'pki';p=self.i.PKI;p.mkdir()
  (p/'index.txt').touch();(p/'serial').write_text('1000\n')
  (p/'ca.conf').write_text(f'[ca]\ndefault_ca=test\n[test]\ndir={p}\ndatabase=$dir/index.txt\nnew_certs_dir=$dir\nserial=$dir/serial\ncertificate=$dir/ca.pem\nprivate_key=$dir/key.pem\ndefault_md=sha256\ndefault_days=30\npolicy=names\nunique_subject=no\n[names]\ncommonName=supplied\n')
  self.run_cmd(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','30','-subj','/CN=Test','-keyout',str(p/'key.pem'),'-out',str(p/'ca.pem')])
  self.run_cmd(['openssl','req','-new','-newkey','rsa:3072','-nodes','-subj','/CN=Device','-keyout',str(p/'device.key'),'-out',str(p/'device.csr')])
  self.body={'token':self.i.issue('Renewal test'),'device':'c'*32,'csr':(p/'device.csr').read_text()}
 def run_cmd(self,args):return subprocess.run(args,check=True,capture_output=True)
 def tearDown(self):self.tmp.cleanup()
 def test_renew_same_identity_and_key_and_reject_disabled(self):
  first=self.i.enroll(self.body);second=self.i.enroll(self.body);self.assertEqual(first['certificate'],second['certificate'])
  real=subprocess.run
  def expired(args,**kw):
   if '-checkend' in args:return subprocess.CompletedProcess(args,1)
   return real(args,**kw)
  with patch.object(self.i.subprocess,'run',side_effect=expired): renewed=self.i.enroll(self.body)
  self.assertEqual(first['identity'],renewed['identity']);self.assertNotEqual(first['certificate'],renewed['certificate'])
  data=self.i.accounts();next(iter(data.values()))['enabled']=False;self.i.write_json(self.i.ROOT/'accounts.json',data)
  with self.assertRaises(PermissionError):self.i.enroll(self.body)
 def test_failed_issuance_preserves_previous_certificate(self):
  first=self.i.enroll(self.body);original_run=self.i.run;real=subprocess.run
  def expired(args,**kw):
   if '-checkend' in args:return subprocess.CompletedProcess(args,1)
   return real(args,**kw)
  def fail(args):
   if args[:2]==['openssl','ca']:
    Path(args[args.index('-out')+1]).write_text('partial');raise RuntimeError('interrupted')
   return original_run(args)
  with patch.object(self.i.subprocess,'run',side_effect=expired),patch.object(self.i,'run',side_effect=fail):
   with self.assertRaises(RuntimeError):self.i.enroll(self.body)
  self.assertEqual((self.i.PKI/first['identity']/'cert.pem').read_text(),first['certificate'])
  self.assertFalse((self.i.PKI/first['identity']/'cert.pem.pending').exists())
