"""Exercise actual OpenSSL CRLs; replace only service/SA administration."""
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class RevocationTests(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('issuer',Path(__file__).resolve().parents[1]/'server/token_issuer.py')
        self.i=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.i)
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.i.ROOT=self.root/'accounts';self.i.PKI=self.root/'pki';self.i.PKI.mkdir()
        self.i.CRL=self.root/'devices.pem';p=self.i.PKI
        (p/'index.txt').touch();(p/'serial').write_text('1000\n')
        (p/'ca.conf').write_text(f'''[ca]
default_ca=ca_test
[ca_test]
dir={p}
database=$dir/index.txt
new_certs_dir=$dir
serial=$dir/serial
certificate=$dir/ca.pem
private_key=$dir/ca-key.pem
default_md=sha256
default_days=30
default_crl_days=30
policy=names
unique_subject=no
[names]
commonName=supplied
''')
        self.cmd(['openssl','req','-new','-x509','-nodes','-newkey','rsa:2048','-days','30','-subj','/CN=TestCA','-keyout',str(p/'ca-key.pem'),'-out',str(p/'ca.pem')])
        self.names=['device-'+'a'*24,'device-'+'b'*24]
        self.certs=[]
        for number,identity in enumerate([self.names[0],self.names[0],self.names[1]]):
            cert=p/f'client-{number}.pem';csr=p/f'{number}.csr';key=p/f'{number}.key'
            self.cmd(['openssl','req','-new','-nodes','-newkey','rsa:2048','-subj','/CN='+identity,'-keyout',str(key),'-out',str(csr)])
            self.cmd(['openssl','ca','-batch','-config',str(p/'ca.conf'),'-in',str(csr),'-out',str(cert)])
            self.certs.append(cert)
        self.tokens=[self.i.issue('First'),self.i.issue('Other')];data=self.i.accounts();self.ids=list(data)
        for n,account in enumerate(data.values()):account['devices']={str(n)*32:{'identity':self.names[n],'enrolled':1}}
        self.i.write_json(self.i.ROOT/'accounts.json',data)
        self.calls=[];self.alive=True;self.original_run=self.i.run;self.original_subprocess=subprocess.run
    def tearDown(self):self.tmp.cleanup()
    def cmd(self,args):return subprocess.run(args,capture_output=True,check=True)
    def fake_run(self,args):
        self.calls.append(args)
        if args[0]=='openssl':return self.original_run(args)
        if args[:2]==['swanctl','--list-sas']:
            owned=('list-sa event {vpn {uniqueid=19 state=ESTABLISHED remote-id='+self.names[0]+' child-sas {vpn-1 {uniqueid=80}}}}\n') if self.alive else ''
            return (owned+'list-sa event {vpn {uniqueid=29 remote-id='+self.names[1]+'}}\nlist-sas reply {}').encode()
        return b''
    def fake_subprocess(self,args,**kw):
        if args[0]=='openssl':return self.original_subprocess(args,**kw)
        self.calls.append(args)
        if args[:2]==['swanctl','--terminate']:
            self.assertEqual(args,['swanctl','--terminate','--ike-id','19']);self.alive=False
        return subprocess.CompletedProcess(args,0)
    def test_revokes_all_generations_preserves_other_user_and_retries(self):
        with patch.object(self.i,'run',side_effect=self.fake_run),patch.object(self.i.subprocess,'run',side_effect=self.fake_subprocess):
            self.assertTrue(self.i.delete_account(self.ids[0])['deleted'])
            before=len(self.calls);self.i.delete_account(self.ids[0]);self.assertEqual(len(self.calls),before)
        for cert in self.certs[:2]:
            r=subprocess.run(['openssl','verify','-CAfile',str(self.i.PKI/'ca.pem'),'-CRLfile',str(self.i.CRL),'-crl_check',str(cert)],capture_output=True)
            self.assertNotEqual(r.returncode,0);self.assertIn(b'certificate revoked',r.stderr)
        self.cmd(['openssl','verify','-CAfile',str(self.i.PKI/'ca.pem'),'-CRLfile',str(self.i.CRL),'-crl_check',str(self.certs[2])])
        with self.assertRaises(PermissionError):self.i.authenticate(self.i.accounts(),self.tokens[0])
        self.assertEqual(self.i.authenticate(self.i.accounts(),self.tokens[1])[0],self.ids[1])
        self.assertEqual([c for c in self.calls if c[:2]==['swanctl','--terminate']],[['swanctl','--terminate','--ike-id','19']])
        issued=self.cmd(['openssl','crl','-in',str(self.i.CRL),'-noout','-lastupdate']).stdout
        # A failed post-CRL service action can cause an immediate retry. Force
        # that path and verify the republished CRL has a later issue time.
        data=self.i.accounts();data[self.ids[0]].pop('deleted');data[self.ids[0]]['delete_pending']=True
        self.i.write_json(self.i.ROOT/'accounts.json',data)
        with patch.object(self.i,'run',side_effect=self.fake_run),patch.object(self.i.subprocess,'run',side_effect=self.fake_subprocess):
            self.i.delete_account(self.ids[0])
        self.assertNotEqual(issued,self.cmd(['openssl','crl','-in',str(self.i.CRL),'-noout','-lastupdate']).stdout)
    def test_failure_leaves_disabled_visible_account_and_retry_finishes(self):
        with patch.object(self.i,'run',side_effect=RuntimeError('simulated_failure')):
            with self.assertRaises(RuntimeError):self.i.delete_account(self.ids[0])
        account=self.i.accounts()[self.ids[0]]
        self.assertFalse(account['enabled']);self.assertTrue(account['delete_pending']);self.assertNotIn('deleted',account)
        with patch.object(self.i,'run',side_effect=self.fake_run),patch.object(self.i.subprocess,'run',side_effect=self.fake_subprocess):
            self.assertTrue(self.i.delete_account(self.ids[0])['deleted'])
    def test_ike_id_parser_never_uses_child_id(self):
        with self.assertRaises(RuntimeError):self.i.session_ids('list-sa event {x {remote-id='+self.names[0]+' child-sas {a {uniqueid=4}}}}',set(self.names))
        self.assertEqual(self.i.session_ids('list-sa event {x {uniqueid=3 remote-id=other}}',set(self.names)),[])
