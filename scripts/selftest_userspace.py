#!/usr/bin/env python3
"""Run with unshare -Urnm. No Internet or production credentials required."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time

REPO = Path(__file__).resolve().parents[1]
def run(*args, **kw):
    p=subprocess.run([str(x) for x in args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)
    if p.returncode: raise RuntimeError(str(args)+'\n'+p.stdout+p.stderr)
    return p

def inside(ns, *args, **kw):
    return run('ip', 'netns', 'exec', ns, *args, **kw)

def main():
    # The outer mount and network namespaces are mandatory safety boundaries.
    assert os.readlink('/proc/self/ns/net') != sys.argv[1], 'use unshare -Urnm'
    run('mount', '--make-rprivate', '/')
    run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
    processes=[]
    with tempfile.TemporaryDirectory(prefix='evgenium-ipsec-') as temp:
        root=Path(temp)
        (root/'empty.conf').write_text('')
        os.environ['STRONGSWAN_CONF']=str(root/'empty.conf')
        bundle=root/'bundle'; bundle.mkdir()
        spec=importlib.util.spec_from_file_location('exp',REPO/'src/starfive_experimental.py')
        exp=importlib.util.module_from_spec(spec);spec.loader.exec_module(exp)
        archive=REPO/'dist'/('starfive-userspace-x86_64-'+exp.USERSPACE_VERSION+'.tar.gz')
        assert hashlib.sha256(archive.read_bytes()).hexdigest()==exp.USERSPACE_SHA256
        with tarfile.open(archive) as f: f.extractall(bundle,filter='data')
        run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',root/'ca.key',
            '-out',root/'ca.pem','-days','1','-subj','/CN=Isolated test CA','-addext','keyUsage=critical,keyCertSign,cRLSign')
        for name in ('server','client'):
            r=root/name;r.mkdir()
            for d in ('x509','x509ca','private'): (r/d).mkdir()
            cn='10.78.0.1' if name=='server' else 'device-'+'a'*24
            run('openssl','req','-newkey','rsa:2048','-nodes','-keyout',r/'private/key.pem',
                '-out',r/'request.pem','-subj','/CN='+cn)
            (r/'extensions').write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\n'
                +'extendedKeyUsage=serverAuth,clientAuth\n'
                +('subjectAltName=IP:10.78.0.1,IP:10.77.0.1\n' if name=='server' else 'subjectAltName=DNS:'+cn+'\n'))
            run('openssl','x509','-req','-in',r/'request.pem','-CA',root/'ca.pem','-CAkey',root/'ca.key',
                '-CAcreateserial','-out',r/'x509/cert.pem','-days','1','-extfile',r/'extensions')
            (r/'x509ca/ca.pem').write_bytes((root/'ca.pem').read_bytes())
            run('ip','netns','add',name)
            inside(name,'ip','link','set','lo','up')
        try:
            run('ip','link','add','vs','type','veth','peer','name','vc')
            run('ip','link','set','vs','netns','server'); run('ip','link','set','vc','netns','client')
            for name,dev,address in [('server','vs','1'),('client','vc','2')]:
                inside(name,'ip','addr','add','10.78.0.'+address+'/24','dev',dev)
                inside(name,'ip','-6','addr','add','2001:db8::'+address+'/64','dev',dev,'nodad')
                inside(name,'ip','link','set',dev,'up')
            inside('client','ip','route','add','default','via','10.78.0.1')
            inside('server','ip','addr','add','10.77.0.1/32','dev','lo')
            exp.backend=lambda:'userspace';exp.SERVER='10.78.0.1'
            for name in ('server','client'):
                r=root/name;exp.ROOT=r;exp.URI='unix://'+str(r/'charon.vici')
                (r/'strongswan.conf').write_text(exp.render_strongswan())
                if name=='client':
                    config=exp.render_connection({'identity':'device-'+'a'*24}).replace(str(r/'client.pem'),str(r/'x509/cert.pem')).replace(str(r/'ca.pem'),str(r/'x509ca/ca.pem'))
                else:
                    config=f'''connections {{
 starfive {{
  version = 2
  local_addrs = 10.78.0.1
  proposals = aes256gcm16-prfsha384-ecp384
  pools = test
  local {{
   auth = pubkey
   id = 10.78.0.1
   certs = {r}/x509/cert.pem
  }}
  remote {{
   auth = eap-tls
   eap_id = %any
  }}
  children {{
   test {{
    local_ts = 0.0.0.0/0
    remote_ts = dynamic
    esp_proposals = aes256gcm16
   }}
  }}
 }}
}}
pools {{
 test {{
  addrs = 10.77.0.16/32
 }}
}}
'''
                (r/'connection.conf').write_text(config)

            def start(name):
                r=root/name
                log=open(r/'daemon.log','a')
                # Each classic charon has its own compiled-in PID directory.
                p=subprocess.Popen(['ip','netns','exec',name,'unshare','-m','sh','-c',
                    'mount --make-rprivate /; mount -t tmpfs tmpfs /run; mkdir -p /run/evgenium-ikev2; exec "$1"',
                    'sh',str(bundle/'charon')],env={**os.environ,'STRONGSWAN_CONF':str(r/'strongswan.conf')},stdout=log,stderr=log)
                log.close();processes.append(p)
                for _ in range(80):
                    if (r/'charon.vici').exists():
                        ready=subprocess.run(['ip','netns','exec',name,str(bundle/'swanctl'),'--stats','--uri','unix://'+str(r/'charon.vici')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                        if ready.returncode==0:break
                    if p.poll() is not None: raise AssertionError((r/'daemon.log').read_text())
                    time.sleep(.1)
                else:raise AssertionError((r/'daemon.log').read_text())
                for action in ('--load-creds','--load-conns')+ (('--load-pools',) if name=='server' else ()):
                    inside(name,bundle/'swanctl',action,'--file',r/'connection.conf','--uri','unix://'+str(r/'charon.vici'))
                return p

            start('server');client=start('client')
            # Private mTLS endpoint uses only generated test credentials.
            fixture=root/'fixture.py'
            fixture.write_text('''import http.server,ssl,sys
from pathlib import Path
r=Path(sys.argv[1])
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=b'evgenium-isolated-integrity'*50000
  self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*a): pass
s=http.server.HTTPServer(('10.77.0.1',8443),Handler)
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain(r/'x509/cert.pem',r/'private/key.pem');c.load_verify_locations(r/'x509ca/ca.pem');c.verify_mode=ssl.CERT_REQUIRED
s.socket=c.wrap_socket(s.socket,server_side=True);s.serve_forever()
''')
            processes.append(subprocess.Popen(['ip','netns','exec','server',sys.executable,str(fixture),str(root/'server')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            time.sleep(.5)
            def ping(address,ipv6=False,expected=True):
                p=subprocess.run(['ip','netns','exec','client','ping']+(['-6'] if ipv6 else [])+['-c','1','-W','1',address],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                assert (p.returncode==0)==expected,(address,p.returncode,expected)
            ping('10.78.0.1');ping('2001:db8::1',True)
            exp.ROOT=root/'client'
            guard=root/'guard.nft';guard.write_text(exp.render_guard())
            inside('client','nft','-f',guard)
            def connect():
                inside('client',bundle/'swanctl','--initiate','--child','starfive-net','--uri','unix://'+str(root/'client/charon.vici'),timeout=30)
                states=inside('client',bundle/'swanctl','--list-sas','--raw','--uri','unix://'+str(root/'client/charon.vici')).stdout
                assert 'state=INSTALLED' in states and 'state=ESTABLISHED' in states,states
                assert not inside('client','ip','xfrm','state').stdout.strip()
                inside('client','ip','link','show','ipsec0')
                print('PASS userspace CHILD_SA with empty kernel SAD',flush=True)
                probe='''import ssl,urllib.request,hashlib,sys
from pathlib import Path
r=Path(sys.argv[1]);c=ssl.create_default_context(cafile=str(r/'x509ca/ca.pem'));c.load_cert_chain(r/'x509/cert.pem',r/'private/key.pem')
o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c))
with o.open('https://10.77.0.1:8443/',timeout=8) as f: body=f.read()
assert hashlib.sha256(body).digest()==hashlib.sha256(b'evgenium-isolated-integrity'*50000).digest()
print('PASS 1.3MB mTLS transfer integrity')
'''
                result=inside('client',sys.executable,'-c',probe,root/'client');print(result.stdout.strip(),flush=True)
                ping('2001:db8::1',True,False)
            connect()
            client.terminate();client.wait(timeout=5)
            ping('10.78.0.1',expected=False);ping('2001:db8::1',True,False)
            inside('client','nft','list','table','inet',exp.TABLE)
            print('PASS daemon stop preserves IPv4/IPv6 kill switch',flush=True)
            client=start('client');connect()
            client.terminate();client.wait(timeout=5)
            inside('client','nft','delete','table','inet',exp.TABLE)
            ping('10.78.0.1');ping('2001:db8::1',True)
            print('PASS reconnect and explicit off restores connectivity',flush=True)
        except Exception:
            for name in ('server','client'):
                p=root/name/'daemon.log'
                if p.exists():print(name,p.read_text()[-12000:],file=sys.stderr)
            raise
        finally:
            for p in processes:
                if p.poll() is None:p.terminate()
            for p in processes:
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill()
            for name in ('server','client'):run('ip','netns','del',name)

if __name__=='__main__':
    if len(sys.argv)==1:
        raise SystemExit(subprocess.call(['unshare','-Urnm',sys.executable,__file__,os.readlink('/proc/self/ns/net')]))
    main()
