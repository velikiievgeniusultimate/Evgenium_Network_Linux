import base64
import importlib.util
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('evgenium_connect_app', ROOT / 'app.py')
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)
BASE = 'https://connect.test'
TOKEN = 'EVN1-' + 't' * 43
KEY = base64.b64encode(bytes(range(32))).decode()
SERVER_KEY = base64.b64encode(bytes(range(1, 33))).decode()
DEVICE = 'a' * 32


class EnrollmentPortalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.calls = []
        self.reply = {'ok': True, 'profile': {
            'schema': 1, 'device': DEVICE, 'account': 'b' * 24,
            'device_name': 'Устройство-1', 'device_number': 1,
            'public_key': SERVER_KEY, 'endpoint': '195.209.211.163:51820',
            'address': '10.78.0.2/32', 'dns': ['1.1.1.1'], 'mtu': 1280,
            'allowed_ips': ['0.0.0.0/0', '::/0'],
        }}
        def issuer(body):
            self.calls.append(body)
            return self.reply
        self.config = {'state_dir': self.tmp.name, 'allowed_hosts': ['connect.test'], 'https_proxy': True}
        self.app = web.create_app(self.config, issuer)
        self.client = self.app.test_client()
        self.csrf = self.client.get('/api/session', base_url=BASE).json['csrf']
        self.body = {'token': TOKEN, 'device': DEVICE, 'public_key': KEY, 'name': 'Мой iPhone'}

    def post(self, body=None, headers=None):
        return self.client.post('/api/enroll', base_url=BASE, json=self.body if body is None else body,
                                headers={'X-CSRF-Token': self.csrf, **(headers or {})})

    def test_success_whitelists_profile_and_only_sends_public_key(self):
        self.reply['profile']['private_key'] = 'must-not-pass'
        response = self.post()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json['profile']['device_name'], 'Устройство-1')
        self.assertEqual(response.json['profile']['addresses'], ['10.78.0.2/32', 'fd78:6576:6765::2/128'])
        self.assertNotIn('private_key', response.json['profile'])
        self.assertNotIn(TOKEN, response.text)
        self.assertEqual(self.calls, [dict(operation='wireguard-enroll', **self.body)])

    def test_no_cookie_wrong_csrf_and_cross_site_never_reach_issuer(self):
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.post('/api/enroll', base_url=BASE, json=self.body).status_code, 403)
        self.assertEqual(self.post(headers={'X-CSRF-Token': 'wrong'}).status_code, 403)
        self.assertEqual(self.post(headers={'Origin': 'https://evil.test'}).status_code, 403)
        self.assertEqual(self.post(headers={'Sec-Fetch-Site': 'cross-site'}).status_code, 403)
        self.assertEqual(self.calls, [])

    def test_native_client_without_origin_can_use_cookie_and_csrf(self):
        self.assertEqual(self.post().status_code, 200)
        self.assertEqual(self.post(headers={'Origin': BASE}).status_code, 200)

    def test_invalid_request_values_and_private_keys_are_rejected(self):
        invalid = [('token', 'x'), ('device', '../' + DEVICE), ('device', 'a' * 24),
                   ('public_key', base64.b64encode(bytes(32)).decode()),
                   ('public_key', KEY + '\n'), ('public_key', 1), ('name', 'x\nPostUp = malware'),
                   ('name', 'x' * 65), ('name', None), ('private_key', KEY)]
        for field, value in invalid:
            with self.subTest(field=field, value=value):
                self.assertEqual(self.post({**self.body, field: value}).status_code, 400)
        self.assertEqual(self.calls, [])

    def test_host_https_query_and_non_json_guards(self):
        self.assertEqual(self.client.get('/', base_url='https://evil.test').status_code, 400)
        self.assertEqual(self.client.get('/', base_url='http://connect.test').status_code, 400)
        self.assertEqual(self.client.get('/api/session?token=secret', base_url=BASE).status_code, 400)
        self.assertEqual(self.client.post('/api/enroll', base_url=BASE, data='x',
                                        headers={'X-CSRF-Token': self.csrf}).status_code, 415)
        self.assertEqual(self.calls, [])

    def test_session_cookie_and_security_headers(self):
        response = self.app.test_client().get('/api/session', base_url=BASE)
        cookie = response.headers['Set-Cookie']
        for flag in ('__Host-', 'Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/'):
            self.assertIn(flag, cookie)
        self.assertNotIn('Domain=', cookie)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        self.assertIn("script-src 'self'", response.headers['Content-Security-Policy'])
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
        self.assertNotIn('Access-Control-Allow-Origin', response.headers)
        self.assertEqual(self.client.get('/', base_url=BASE).status_code, 200)
        with self.client.get('/static/vendor/wireguard.js', base_url=BASE) as static:
            self.assertEqual(static.status_code, 200)

    def test_sessions_do_not_store_tokens_and_expire(self):
        self.post()
        database = Path(self.tmp.name) / 'connect.sqlite3'
        self.assertEqual(database.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(TOKEN.encode(), database.read_bytes())
        conn = sqlite3.connect(database)
        try:
            with conn:
                conn.execute('UPDATE sessions SET expires=0')
        finally:
            conn.close()
        self.assertEqual(self.post().status_code, 403)
        new_csrf = self.client.get('/api/session', base_url=BASE).json['csrf']
        self.assertNotEqual(new_csrf, self.csrf)

    def test_enrollment_limits_survive_process_restart_and_sessions(self):
        self.config['enroll_limit'] = 1
        app = web.create_app(self.config, lambda body: self.reply)
        client = app.test_client()
        csrf = client.get('/api/session', base_url=BASE).json['csrf']
        self.assertEqual(client.post('/api/enroll', base_url=BASE, json=self.body,
                                     headers={'X-CSRF-Token': csrf}).status_code, 200)
        app = web.create_app(self.config, lambda body: self.reply)
        client = app.test_client()
        csrf = client.get('/api/session', base_url=BASE).json['csrf']
        response = client.post('/api/enroll', base_url=BASE, json=self.body, headers={'X-CSRF-Token': csrf})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers['Retry-After'], '900')

    def test_invalid_backend_profile_cannot_inject_configuration(self):
        bad = [('endpoint', 'evil.test:443'), ('address', '10.78.0.2/24'), ('dns', ['1.1.1.1\nPostUp=x']),
               ('public_key', 'x'), ('allowed_ips', ['0.0.0.0/0']), ('device_name', 'x\nBad'),
               ('device', 'f' * 32), ('mtu', 1)]
        good = dict(self.reply['profile'])
        for field, value in bad:
            self.reply['profile'] = {**good, field: value}
            self.assertEqual(self.post().status_code, 503, field)

    def test_backend_errors_never_disclose_token_or_internal_exception(self):
        for error, code in [('invalid_token', 401), ('invalid_token_or_device', 401), ('account_disabled', 401), ('device_conflict', 409),
                            ('too_many_attempts', 429), ('private stack trace ' + TOKEN, 503)]:
            self.reply = dict(ok=False, error=error)
            response = self.post()
            self.assertEqual(response.status_code, code)
            self.assertNotIn(TOKEN, response.text)
        with patch.object(web, 'rpc', side_effect=OSError('secret')):
            app = web.create_app(self.config)
            client = app.test_client()
            csrf = client.get('/api/session', base_url=BASE).json['csrf']
            response = client.post('/api/enroll', base_url=BASE, json=self.body, headers={'X-CSRF-Token': csrf})
            self.assertEqual(response.status_code, 503)
            self.assertNotIn('secret', response.text)


class BrowserKeyTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node is needed for vendored browser crypto vector')
    def test_upstream_generator_matches_rfc7748_alice_public_key(self):
        script = r'''
const fs=require('fs'),vm=require('vm');
const seed=Buffer.from('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a','hex');
const context={window:{crypto:{getRandomValues:out=>{out.set(seed);return out}}}};
vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),context);
process.stdout.write(JSON.stringify(context.window.wireguard.generateKeypair()));
'''
        raw = subprocess.check_output(['node', '-e', script, str(ROOT / 'static/vendor/wireguard.js')], text=True)
        keys = json.loads(raw)
        expected = bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
        self.assertEqual(base64.b64decode(keys['publicKey']), expected)
        self.assertEqual(len(base64.b64decode(keys['privateKey'])), 32)

    @unittest.skipUnless(shutil.which('node'), 'Node is needed for browser enrollment flow')
    def test_browser_flow_keeps_private_key_local_and_retries_idempotently(self):
        script = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const elements={};
for(const id of ['enroll-form','token','device-name','status','create-profile','token-toggle','result','profile-name','download-profile','change-token']){
 elements[id]={value:'',hidden:false,readOnly:false,disabled:false,textContent:'',type:'password',handlers:{},
  classList:{toggle:()=>{}},setAttribute:()=>{},focus:()=>{},addEventListener:function(e,h){this.handlers[e]=h}};
}
elements.token.value='  EVN1-'+ 't'.repeat(43)+'  ';
elements['device-name'].value='Мой iPhone';
let generated=0,requests=[],attempt=0,download,blob,rejectNext=false;
const keypair={publicKey:Buffer.alloc(32,1).toString('base64'),privateKey:Buffer.alloc(32,2).toString('base64')};
const context={Uint8Array,Blob,console,
 document:{getElementById:id=>elements[id],createElement:()=>{download={click:()=>{},remove:()=>{}};return download},body:{appendChild:()=>{}}},
 URL:{createObjectURL:b=>{blob=b;return 'blob:local'},revokeObjectURL:()=>{}},
 window:{isSecureContext:true,crypto:{getRandomValues:out=>{out.fill(7);return out}},
 wireguard:{generateKeypair:()=>{generated++;return keypair}},setTimeout:()=>{}},
 fetch:async(url,opts)=>{
  if(url==='/api/session')return{ok:true,json:async()=>({csrf:'c'.repeat(43)})};
  const request=JSON.parse(opts.body);requests.push(request);attempt++;
  if(attempt===1)throw Error('temporary network interruption');
  if(rejectNext){rejectNext=false;return {ok:false,json:async()=>({error:'token_invalid'})};}
  return {ok:true,json:async()=>({ok:true,profile:{device:request.device,device_name:'Мой iPhone',
   address:'10.78.0.2/32',addresses:['10.78.0.2/32','fd78:6576:6765::2/128'],dns:['1.1.1.1'],mtu:1280,public_key:Buffer.alloc(32,3).toString('base64'),
   allowed_ips:['0.0.0.0/0','::/0'],endpoint:'195.209.211.163:51820'}})};
 }};
vm.runInNewContext(fs.readFileSync(process.argv[1],'utf8'),context);
(async()=>{
 const submit=elements['enroll-form'].handlers.submit;
 await submit({preventDefault:()=>{}});
 assert.strictEqual(elements.token.readOnly,false);
 assert.strictEqual(elements['create-profile'].disabled,false);
 await submit({preventDefault:()=>{}});
 assert.strictEqual(generated,1);
 assert.strictEqual(requests[0].device,requests[1].device);
 assert.deepStrictEqual(Object.keys(requests[1]).sort(),['device','name','public_key','token']);
 assert.strictEqual(JSON.stringify(requests).includes(keypair.privateKey),false);
 assert.strictEqual(elements['enroll-form'].hidden,true);
 assert.strictEqual(elements.token.value,'');
 elements['download-profile'].handlers.click();
 const text=await blob.text();
 assert(text.includes('PrivateKey = '+keypair.privateKey));
 assert(text.includes('AllowedIPs = 0.0.0.0/0, ::/0'));
 assert(text.includes('Address = 10.78.0.2/32, fd78:6576:6765::2/128'));
 assert(text.includes('PersistentKeepalive = 25'));
 assert(/^EVG-[a-f0-9]{8}\.conf$/.test(download.download));
 elements['change-token'].handlers.click();
 assert.strictEqual(elements['enroll-form'].hidden,false);
 assert.strictEqual(elements.result.hidden,true);
 assert.strictEqual(elements.token.value,'');
 elements.token.value='EVN1-'+ 't'.repeat(43);
 rejectNext=true;
 await submit({preventDefault:()=>{}});
 assert.strictEqual(generated,2);
 await submit({preventDefault:()=>{}});
 assert.strictEqual(generated,3); // Revoked device receives a new key on retry.
 process.stdout.write('browser enrollment and local download passed\n');
})().catch(e=>{console.error(e);process.exitCode=1});
'''
        output = subprocess.check_output(['node', '-e', script, str(ROOT / 'static/connect.js')], text=True)
        self.assertIn('passed', output)


if __name__ == '__main__':
    unittest.main()
