#!/usr/bin/env python3
"""Narrow Unix RPC for account administration; never reads the CA private key."""
import argparse
import hashlib
import hmac
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import socketserver
import struct
import subprocess
import time
import unicodedata
from cryptography.fernet import Fernet


def atomic_json(path, data):
    temporary=path.with_suffix('.new')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(data,stream,ensure_ascii=False);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def name_key(name):
    if not isinstance(name,str):raise ValueError('invalid_name')
    name=unicodedata.normalize('NFKC',name).strip()
    if not 1<=len(name)<=80 or any(unicodedata.category(c).startswith('C') for c in name):
        raise ValueError('invalid_name')
    return name, ' '.join(name.casefold().split())


def load_issuer(path):
    loader=importlib.machinery.SourceFileLoader('existing_issuer',str(path))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    module=importlib.util.module_from_spec(spec);loader.exec_module(module)
    return module


class Accounts:
    def __init__(self,issuer,vault):
        self.issuer=issuer;self.vault=Path(vault)
        self.vault.mkdir(parents=True,exist_ok=True,mode=0o700)
        key=self.vault/'vault.key'
        try:
            fd=os.open(key,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(Fernet.generate_key());stream.flush();os.fsync(stream.fileno())
        except FileExistsError:pass
        self.cipher=Fernet(key.read_bytes())
    def tokens(self):
        try:return json.loads((self.vault/'tokens.json').read_text())
        except FileNotFoundError:return {}
    def issue(self,name):
        name,key=name_key(name)
        with self.issuer.locked():
            data=self.issuer.accounts()
            if any(name_key(a['name'])[1]==key for a in data.values()):raise ValueError('person_exists')
            token='EVN1-'+secrets.token_urlsafe(32);account_id=secrets.token_hex(12)
            vault=self.tokens();vault[account_id]=self.cipher.encrypt(token.encode()).decode()
            # Save the encrypted secret first. A crash can leave only an unreferenced vault entry.
            atomic_json(self.vault/'tokens.json',vault)
            data[account_id]={'name':name,'token_hash':hashlib.sha256(token.encode()).hexdigest(),
                              'enabled':True,'created':int(time.time()),'devices':{}}
            atomic_json(self.issuer.ROOT/'accounts.json',data)
            return {'id':account_id}
    def token(self,account_id,existing=None):
        if not isinstance(account_id,str) or not re.fullmatch('[a-f0-9]{24}',account_id):raise ValueError('invalid_account')
        with self.issuer.locked():
            account=self.issuer.accounts().get(account_id)
            if not account:raise ValueError('account_missing')
            vault=self.tokens()
            if existing is not None:
                if not isinstance(existing,str) or not re.fullmatch(self.issuer.TOKEN_PATTERN,existing):raise ValueError('token_mismatch')
                if not hmac.compare_digest(account['token_hash'],hashlib.sha256(existing.encode()).hexdigest()):raise ValueError('token_mismatch')
                vault[account_id]=self.cipher.encrypt(existing.encode()).decode();atomic_json(self.vault/'tokens.json',vault)
                return {'saved':True}
            if account_id not in vault:raise ValueError('legacy_token_unavailable')
            token=self.cipher.decrypt(vault[account_id].encode()).decode()
            if not hmac.compare_digest(account['token_hash'],hashlib.sha256(token.encode()).hexdigest()):raise ValueError('token_changed_outside_panel')
            return {'token':token}
    def listing(self):
        with self.issuer.locked():
            data=self.issuer.accounts();vault=self.tokens()
            return [{'id':key,'name':a['name'],'enabled':bool(a.get('enabled')),'created':a.get('created'),
                     'token_hint':a['token_hash'][:8],'token_available':key in vault,
                     'devices':[{'id':device,'identity':d['identity'],'enrolled':d.get('enrolled'),
                                 'disabled':bool(d.get('disabled'))} for device,d in a.get('devices',{}).items()]}
                    for key,a in data.items()]


def text(value):
    return value.decode('utf-8','replace') if isinstance(value,bytes) else str(value)


def parse_connections(raw):
    out=[]
    for event in raw.split('list-sa event ')[1:]:
        def field(key,default=''):
            match=re.search(r'(?<![\w-])'+re.escape(key)+r'=([^\s{}]+)',event)
            return match[1] if match else default
        identity=field('remote-id')
        if not identity:continue
        vips=re.search(r'remote-vips=\[([^]]*)\]',event)
        child_bytes=lambda key:sum(int(n) for n in re.findall(r'(?<![\w-])'+key+r'=(\d+)',event))
        out.append({'identity':identity,'state':field('state','unknown'),'remote_host':field('remote-host'),
                    'virtual_ips':vips[1].split() if vips else [],'connected_seconds':int(field('established','0')),
                    'children':[{'bytes_in':child_bytes('bytes-in'),'bytes_out':child_bytes('bytes-out')}]})
    return out


def connections():
    """Read the installed strongSwan client; unavailable means unknown, not offline."""
    try:
        result=subprocess.run(['swanctl','--list-sas','--raw'],capture_output=True,text=True,timeout=4)
        if result.returncode or len(result.stdout)>4*1024*1024:raise ValueError('vici_unavailable')
        return {'available':True,'items':parse_connections(result.stdout),'sampled_at':int(time.time())}
    except Exception:return {'available':False,'items':[],'sampled_at':int(time.time())}


def last_record(path,keys):
    try:
        with Path(path).open('rb') as f:
            f.seek(0,2);f.seek(max(0,f.tell()-65536));lines=f.read().splitlines()
        for line in reversed(lines):
            try:
                row=json.loads(line)
                if 'utc' in row:return {k:row[k] for k in keys if k in row}
            except (ValueError,UnicodeError):continue
    except OSError:pass
    return None


def health():
    states={}
    for unit in ('strongswan','evgenium-enrollment','evgenium-relay','evgenium-link','evgenium-link-tcp','evgenium-link-hy'):
        try:
            r=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True,timeout=2)
            states[unit]=r.stdout.strip() or 'unknown'
        except subprocess.TimeoutExpired:states[unit]='unknown'
    memory={line.split(':')[0]:int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()}
    return {'sampled_at':int(time.time()),'services':states,'load_average':list(os.getloadavg()),
            'memory_available_mib':round(memory['MemAvailable']/1024),
            'resource_hold':Path('/var/lib/evgenium-link/resource-hold').exists(),
            'link':last_record('/var/log/evgenium-link/health.jsonl',('utc','inner_ok','local_ok','mode','last_egress_ok','egress_age_s','handshake_age_s','action','action_ok'))}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(15)
        uid=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
        if uid!=self.server.allowed_uid:return
        try:
            raw=self.rfile.readline(4097)
            if len(raw)>4096 or not raw.endswith(b'\n'):raise ValueError('request_size')
            data=json.loads(raw)
            if not isinstance(data,dict):raise ValueError('invalid_request')
            op=data.get('op');accounts=self.server.accounts
            if op=='snapshot':result={'accounts':accounts.listing(),'connections':connections(),'health':health()}
            elif op=='issue':result=accounts.issue(data.get('name'))
            elif op=='reveal':result=accounts.token(data.get('id'))
            elif op=='import':result=accounts.token(data.get('id'),data.get('token',''))
            else:raise ValueError('operation_not_allowed')
            response={'ok':True,'data':result}
        except ValueError as error:
            allowed={'invalid_name','person_exists','invalid_account','account_missing','token_mismatch','legacy_token_unavailable','token_changed_outside_panel','operation_not_allowed','request_size'}
            response={'ok':False,'error':str(error) if str(error) in allowed else 'invalid_request'}
        except Exception:response={'ok':False,'error':'broker_unavailable'}
        self.wfile.write(json.dumps(response,separators=(',',':')).encode()+b'\n')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--socket',default='/run/evgenium-panel-broker/admin.sock')
    parser.add_argument('--issuer',default='/usr/local/sbin/evgenium-token-issuer');parser.add_argument('--vault',default='/var/lib/evgenium-panel-broker')
    parser.add_argument('--user',default='evg-panel');args=parser.parse_args()
    os.umask(0o077);user=pwd.getpwnam(args.user);path=Path(args.socket)
    path.parent.mkdir(mode=0o750,exist_ok=True);os.chown(path.parent,0,user.pw_gid);path.unlink(missing_ok=True)
    with socketserver.UnixStreamServer(str(path),Handler) as server:
        server.allowed_uid=user.pw_uid;server.accounts=Accounts(load_issuer(args.issuer),args.vault)
        os.chown(path,0,user.pw_gid);path.chmod(0o660);server.serve_forever()

if __name__=='__main__':main()
