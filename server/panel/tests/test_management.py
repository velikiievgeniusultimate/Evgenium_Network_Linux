import hashlib
import json
import sqlite3
from contextlib import closing
from unittest.mock import patch
import test_panel as base
from test_panel import web


class RememberedBrowserTests(base.AuthenticationTests):
    def test_trusted_browser_requires_fresh_totp_and_rotates(self):
        self.setup_owner()
        cookie=self.client.get_cookie(web.DEVICE_COOKIE)
        self.assertTrue(cookie.secure and cookie.http_only)
        self.assertEqual(cookie.same_site,'Strict')
        first=cookie.value
        with closing(sqlite3.connect(self.root/'panel.sqlite3')) as c:
            stored=c.execute('SELECT id FROM trusted_browsers').fetchone()[0]
        self.assertEqual(stored,hashlib.sha256(first.encode()).hexdigest())
        self.post('/api/logout',{})
        state=self.client.get('/api/session',base_url='https://localhost').json
        self.csrf=state['csrf'];self.assertTrue(state['remembered']);self.assertFalse(state['authenticated'])
        self.assertEqual(self.client.get('/api/dashboard',base_url='https://localhost').status_code,401)
        self.assertEqual(self.post('/api/login',{}).status_code,401)
        self.assertEqual(self.post('/api/login',{'code':web.totp(self.secret,self.step)}).status_code,401)
        with patch.object(web.time,'time',return_value=(self.step+1)*30+1):
            self.assertEqual(self.post('/api/login',{'code':web.totp(self.secret,self.step+1)}).status_code,200)
        self.assertNotEqual(first,self.client.get_cookie(web.DEVICE_COOKIE).value)
        with closing(sqlite3.connect(self.root/'panel.sqlite3')) as c:
            self.assertIsNone(c.execute('SELECT 1 FROM trusted_browsers WHERE id=?',(stored,)).fetchone())

    def test_forget_revokes_cookie_and_session(self):
        self.setup_owner();remembered=self.client.get_cookie(web.DEVICE_COOKIE).value
        self.assertEqual(self.client.post('/api/browser/forget',json={},base_url='https://localhost').status_code,403)
        self.assertEqual(self.post('/api/browser/forget',{}).status_code,200)
        self.assertIsNone(self.client.get_cookie(web.DEVICE_COOKIE))
        self.assertIsNone(self.client.get_cookie(web.COOKIE))
        self.client.set_cookie(web.DEVICE_COOKIE,remembered)
        state=self.client.get('/api/session',base_url='https://localhost').json;self.csrf=state['csrf']
        self.assertFalse(state['remembered'])
        with patch.object(web.time,'time',return_value=(self.step+1)*30+1):
            self.assertEqual(self.post('/api/login',{'code':web.totp(self.secret,self.step+1)}).status_code,401)
            self.assertEqual(self.post('/api/login',{'password':'long secure test password','code':web.totp(self.secret,self.step+1)}).status_code,200)

    def test_expired_or_forged_browser_cannot_replace_password(self):
        self.setup_owner();self.post('/api/logout',{})
        with closing(sqlite3.connect(self.root/'panel.sqlite3')) as c:
            c.execute('UPDATE trusted_browsers SET expires=0');c.commit()
        state=self.client.get('/api/session',base_url='https://localhost').json;self.csrf=state['csrf'];self.assertFalse(state['remembered'])
        with patch.object(web.time,'time',return_value=(self.step+1)*30+1):
            self.assertEqual(self.post('/api/login',{'code':web.totp(self.secret,self.step+1)}).status_code,401)
            self.client.set_cookie(web.DEVICE_COOKIE,'z'*43)
            self.assertEqual(self.post('/api/login',{'code':web.totp(self.secret,self.step+1)}).status_code,401)

    def test_mutations_require_owner_and_csrf(self):
        paths=['/api/accounts/'+ 'a'*24 + suffix for suffix in ['/rename','/delete','/devices/'+'b'*32+'/rename']]
        for path in paths:self.assertEqual(self.post(path,{'name':'test'}).status_code,401)
        self.assertEqual(self.calls,[])
        self.setup_owner()
        for path in paths:self.assertEqual(self.client.post(path,json={},base_url='https://localhost').status_code,403)
        for path in paths:self.assertEqual(self.post(path,{'name':'test'}).status_code,200)
        self.assertEqual([c['op'] for c in self.calls],['rename','delete','rename-device'])


class ManagementTests(base.AccountTests):
    def test_account_and_device_rename_preserve_credentials_and_isolate_owner(self):
        a=self.accounts.issue('First')['id'];b=self.accounts.issue('Second')['id'];token=self.accounts.token(a)['token']
        data=self.issuer.accounts();device='a'*32
        record={'identity':'device-'+'f'*24,'key_hash':'key','enrolled':1}
        data[a]['devices'][device]=record.copy();self.issuer.write_json(self.issuer.ROOT/'accounts.json',data)
        self.accounts.rename(a,'Новая подпись')
        self.accounts.rename(a,'Ноутбук',device)
        self.assertEqual(self.accounts.token(a)['token'],token)
        self.assertEqual(self.issuer.accounts()[a]['devices'][device],record)
        self.assertEqual(self.issuer.device_info({'token':token,'device':device})['name'],'Ноутбук')
        with self.assertRaisesRegex(ValueError,'device_missing'):self.accounts.rename(b,'Чужое',device)
        with self.assertRaisesRegex(ValueError,'person_exists'):self.accounts.rename(b,'НОВАЯ ПОДПИСЬ')
        for name in ['', 'a'*81, 'bad\nname']:
            with self.assertRaises(ValueError):self.accounts.rename(a,name)
        with self.assertRaises(ValueError):self.accounts.rename(a,'a'*65,device)

    def test_pending_delete_cannot_be_renamed_or_revealed(self):
        a=self.accounts.issue('First')['id'];data=self.issuer.accounts();data[a]['delete_pending']=True
        self.issuer.write_json(self.issuer.ROOT/'accounts.json',data)
        with self.assertRaisesRegex(ValueError,'account_missing'):self.accounts.rename(a,'New')
        with self.assertRaisesRegex(ValueError,'account_missing'):self.accounts.token(a)
        self.assertTrue(self.accounts.listing()[0]['delete_pending'])
        data[a]['deleted']=123;self.issuer.write_json(self.issuer.ROOT/'accounts.json',data)
        self.assertEqual(self.accounts.listing(),[])
        self.accounts.issue('First')


class DeviceRevokeRouteTests(base.AuthenticationTests):
    def test_revoke_requires_owner_csrf_and_explicit_confirmation(self):
        path='/api/accounts/'+'a'*24+'/devices/'+'b'*32+'/revoke'
        self.assertEqual(self.post(path,{'confirm':True}).status_code,401)
        self.assertEqual(self.calls,[])
        self.setup_owner()
        self.assertEqual(self.client.post(path,json={'confirm':True},base_url='https://localhost').status_code,403)
        for body in ({},{'confirm':'true'},{'confirm':1}):
            self.assertEqual(self.post(path,body).status_code,400)
        self.assertEqual(self.calls,[])
        self.assertEqual(self.post(path,{'confirm':True}).status_code,200)
        self.assertEqual(self.calls,[{'op':'revoke-device','id':'a'*24,'device':'b'*32}])

class WireGuardManagementTests(base.AccountTests):
    def test_wireguard_device_is_listed_and_renamed_without_changing_public_key(self):
        account=self.accounts.issue('iPhone')['id'];token=self.accounts.token(account)['token'];device='c'*32
        data=self.issuer.accounts();data[account]['devices'][device]={'type':'wireguard','identity':'wg:public',
            'public_key':'public','address':'10.78.0.2/32','enrolled':1,'revoke_pending':True,'disabled':True}
        self.issuer.write_json(self.issuer.ROOT/'accounts.json',data)
        self.accounts.rename(account,'Телефон',device)
        row=self.accounts.listing()[0]['devices'][0]
        self.assertEqual(row['type'],'wireguard');self.assertEqual(row['name'],'Телефон')
        self.assertTrue(row['revoke_pending']);self.assertEqual(row['address'],'10.78.0.2/32')
        self.assertEqual(self.issuer.accounts()[account]['devices'][device]['public_key'],'public')
        self.assertEqual(self.accounts.token(account)['token'],token)

    def test_wireguard_status_failure_keeps_certificate_status_available(self):
        from unittest.mock import patch
        from test_panel import broker
        ike={'available':True,'items':[{'identity':'device-test','state':'ESTABLISHED'}]}
        wg={'available':False,'items':[]}
        with patch.object(broker,'connections',return_value=ike),patch.object(self.issuer.wireguard,'connections',return_value=wg):
            result=broker.all_connections(self.issuer)
        self.assertFalse(result['available']);self.assertTrue(result['sources']['ikev2'])
        self.assertFalse(result['sources']['wireguard']);self.assertEqual(result['items'],ike['items'])
