from contextlib import closing
import base64
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from cryptography.fernet import Fernet
PANEL=Path(__file__).resolve().parents[1];sys.path.insert(0,str(PANEL))
import app as web
import broker

class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.bootstrap='a'*43;self.key=Fernet.generate_key().decode()
        self.calls=[]
        def rpc(data):self.calls.append(data);return {'ok':True,'data':{'accounts':[]}}
        self.config={'state_dir':str(self.root),'encryption_key':self.key,'allowed_hosts':['localhost'],'https_proxy':True,
                     'bootstrap_hash':web.hashlib.sha256(self.bootstrap.encode()).hexdigest(),'bootstrap_expires':time.time()+3600}
        self.app=web.create_app(self.config,rpc);self.client=self.app.test_client()
        self.csrf=self.client.get('/api/session',base_url='https://localhost').json['csrf']
    def tearDown(self):self.tmp.cleanup()
    def post(self,path,data,**kw):
        response=self.client.post(path,json=data,base_url='https://localhost',headers={'X-CSRF-Token':self.csrf,**kw})
        if response.is_json and response.json.get('csrf'):self.csrf=response.json['csrf']
        return response
    def setup_owner(self):
        self.assertEqual(self.post('/api/setup/start',{'bootstrap':self.bootstrap}).status_code,200)
        qr=self.client.get('/api/setup/qr',base_url='https://localhost');self.assertEqual(qr.status_code,200)
        self.assertEqual(qr.headers['Cache-Control'],'no-store')
        with closing(sqlite3.connect(self.root/'panel.sqlite3')) as c:encrypted=c.execute("SELECT secret FROM sessions WHERE kind='setup'").fetchone()[0]
        self.secret=Fernet(self.key.encode()).decrypt(encrypted.encode()).decode();self.step=int(time.time())//30
        self.assertEqual(self.post('/api/setup/finish',{'password':'long secure test password','code':web.totp(self.secret,self.step)}).status_code,200)
    def test_rfc6238_vectors(self):
        secret=base64.b32encode(b'12345678901234567890').decode()
        for stamp,code in [(59,'94287082'),(1111111109,'07081804'),(1111111111,'14050471'),(1234567890,'89005924'),(2000000000,'69279037'),(20000000000,'65353130')]:
            self.assertEqual(web.totp(secret,stamp//30,8),code)
    def test_protected_endpoints_do_not_reach_broker_without_two_factors(self):
        self.assertEqual(self.client.get('/api/dashboard',base_url='https://localhost').status_code,401)
        self.assertEqual(self.post('/api/accounts',{'name':'test'}).status_code,401)
        self.assertEqual(self.post('/api/accounts/'+'a'*24+'/reveal',{}).status_code,401)
        self.assertEqual(self.calls,[])
    def test_setup_requires_bootstrap_and_valid_totp(self):
        self.assertEqual(self.post('/api/setup/start',{'bootstrap':'wrong'}).status_code,403)
        self.assertEqual(self.post('/api/setup/start',{'bootstrap':self.bootstrap}).status_code,200)
        self.assertEqual(self.post('/api/setup/finish',{'password':'long secure test password','code':'abcdef'}).status_code,400)
        self.assertEqual(self.client.get('/api/dashboard',base_url='https://localhost').status_code,401)
    def test_totp_replay_and_logout_revoke_session(self):
        self.setup_owner();cookie=self.client.get_cookie(web.COOKIE).value
        self.assertEqual(self.client.get('/api/dashboard',base_url='https://localhost').status_code,200)
        self.assertEqual(self.post('/api/logout',{}).status_code,200)
        stolen=self.app.test_client();stolen.set_cookie(web.COOKIE,cookie)
        self.assertEqual(stolen.get('/api/dashboard',base_url='https://localhost').status_code,401)
        self.csrf=self.client.get('/api/session',base_url='https://localhost').json['csrf']
        self.assertEqual(self.post('/api/login',{'password':'long secure test password','code':web.totp(self.secret,self.step)}).status_code,401)
        with patch.object(web.time,'time',return_value=(self.step+1)*30+1):
            self.assertEqual(self.post('/api/login',{'password':'wrong','code':web.totp(self.secret,self.step+1)}).status_code,401)
            self.assertEqual(self.post('/api/login',{'password':'long secure test password','code':web.totp(self.secret,self.step+1)}).status_code,200)
            self.assertNotEqual(self.client.get_cookie(web.COOKIE).value,cookie)
    def test_csrf_cross_origin_and_transport_guards(self):
        self.assertEqual(self.client.post('/api/login',json={},base_url='https://localhost').status_code,403)
        self.assertEqual(self.post('/api/login',{},Origin='https://attacker.invalid').status_code,403)
        self.assertEqual(self.client.get('/',base_url='http://localhost').status_code,400)
        self.assertEqual(self.client.get('/',base_url='https://attacker.invalid').status_code,400)
        self.assertEqual(self.post('/api/login',[]).status_code,400)
    def test_trusted_front_ip_is_used_for_session_limits(self):
        response=self.client.get('/api/session',base_url='https://localhost',headers={'X-Forwarded-For':'198.51.100.123, 192.0.2.7'})
        self.assertEqual(response.status_code,200)
        # The trusted loopback frontend overwrites this header; ProxyFix trusts
        # exactly its final value, never the caller's arbitrary first address.
        fresh=self.app.test_client()
        fresh.get('/api/session',base_url='https://localhost',headers={'X-Forwarded-For':'198.51.100.123, 192.0.2.7'})
        with closing(sqlite3.connect(self.root/'panel.sqlite3')) as c:
            self.assertIsNotNone(c.execute("SELECT 1 FROM attempts WHERE bucket='session:192.0.2.7'").fetchone())
            self.assertIsNone(c.execute("SELECT 1 FROM attempts WHERE bucket='session:198.51.100.123'").fetchone())

    def test_cookie_and_headers(self):
        c=self.client.get_cookie(web.COOKIE);self.assertTrue(c.secure);self.assertTrue(c.http_only);self.assertEqual(c.same_site,'Strict')
        r=self.client.get('/',base_url='https://localhost');self.assertIn("frame-ancestors 'none'",r.headers['Content-Security-Policy']);self.assertIn('max-age=',r.headers['Strict-Transport-Security'])
    def test_setup_cannot_replace_owner(self):
        self.setup_owner()
        self.assertEqual(self.post('/api/setup/start',{'bootstrap':self.bootstrap}).status_code,403)
        self.assertEqual(self.client.get('/api/setup/qr',base_url='https://localhost').status_code,403)
    def test_rate_limit_persists_for_new_session(self):
        for _ in range(8):self.assertEqual(self.post('/api/login',{'password':'bad','code':'000000'}).status_code,401)
        self.assertEqual(self.post('/api/login',{'password':'bad','code':'000000'}).status_code,429)
    def test_expired_session_is_rejected(self):
        self.setup_owner()
        with patch.object(web.time,'time',return_value=time.time()+1801):
            self.assertEqual(self.client.get('/api/dashboard',base_url='https://localhost').status_code,401)

class AccountTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.issuer=broker.load_issuer(PANEL.parent/'token_issuer.py');self.issuer.ROOT=self.root/'enrollment'
        self.accounts=broker.Accounts(self.issuer,self.root/'vault')
    def tearDown(self):self.tmp.cleanup()
    def test_one_token_and_normalized_unique_person(self):
        identity=self.accounts.issue('  Иван   Иванов ' )['id'];first=self.accounts.token(identity)['token']
        with self.assertRaisesRegex(ValueError,'person_exists'):self.accounts.issue('ИВАН ИВАНОВ')
        self.assertEqual(self.accounts.token(identity)['token'],first)
        self.assertEqual(len(self.issuer.accounts()),1)
        self.assertNotIn(first,(self.root/'vault/tokens.json').read_text())
        self.assertNotIn(first,(self.root/'enrollment/accounts.json').read_text())
    def test_legacy_import_preserves_account_and_devices(self):
        token=self.issuer.issue('Existing');identity=next(iter(self.issuer.accounts()))
        with self.issuer.locked():
            data=self.issuer.accounts();data[identity]['devices']={'a'*32:{'identity':'device-'+'b'*24,'enrolled':1,'key_hash':'x'}};self.issuer.write_json(self.issuer.ROOT/'accounts.json',data)
        before=(self.issuer.ROOT/'accounts.json').read_bytes()
        with self.assertRaisesRegex(ValueError,'legacy_token_unavailable'):self.accounts.token(identity)
        with self.assertRaisesRegex(ValueError,'token_mismatch'):self.accounts.token(identity,'EVN1-'+'x'*43)
        self.accounts.token(identity,token)
        self.assertEqual(self.accounts.token(identity)['token'],token)
        self.assertEqual((self.issuer.ROOT/'accounts.json').read_bytes(),before)
        self.assertEqual(len(self.accounts.listing()[0]['devices']),1)
    def test_ten_devices_use_same_account_token(self):
        identity=self.accounts.issue('Ten devices')['id'];token=self.accounts.token(identity)['token']
        with self.issuer.locked():
            data=self.issuer.accounts();data[identity]['devices']={str(i):{'identity':'device-'+str(i),'enrolled':i} for i in range(10)};self.issuer.write_json(self.issuer.ROOT/'accounts.json',data)
        self.assertEqual(len(self.accounts.listing()[0]['devices']),10)
        self.assertEqual(self.accounts.token(identity)['token'],token)
        self.assertEqual(self.issuer.authenticate(self.issuer.accounts(),token)[0],identity)
    def test_client_device_rename_appears_in_panel_snapshot(self):
        identity=self.accounts.issue('Owner')['id'];token=self.accounts.token(identity)['token'];device='a'*32
        with self.issuer.locked():
            data=self.issuer.accounts();data[identity]['devices'][device]={'identity':'device-test','enrolled':1};self.issuer.write_json(self.issuer.ROOT/'accounts.json',data)
        self.assertEqual(self.accounts.listing()[0]['devices'][0]['name'],'Устройство-1')
        self.issuer.device_info({'token':token,'device':device,'name':'Рабочий ноутбук'})
        item=self.accounts.listing()[0]['devices'][0]
        self.assertEqual(item['name'],'Рабочий ноутбук');self.assertEqual(item['identity'],'device-test')

    def test_raw_vici_session_parser(self):
        raw='list-sa event {vpn {uniqueid=3 state=ESTABLISHED remote-host=192.0.2.5 remote-id=device-abcdef remote-vips=[10.77.0.20] established=120 child-sas {vpn-1 {state=INSTALLED bytes-in=321 bytes-out=654}}}}\nlist-sas reply {}'
        item=broker.parse_connections(raw)[0];self.assertEqual(item['identity'],'device-abcdef');self.assertEqual(item['virtual_ips'],['10.77.0.20']);self.assertEqual(item['children'][0]['bytes_in'],321)

if __name__=='__main__':unittest.main()
