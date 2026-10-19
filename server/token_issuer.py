#!/usr/bin/env python3
"""Token accounts and per-device CSR signing. Only a root-owned Unix socket is exposed."""
import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import struct
import subprocess
import time

ROOT = Path('/var/lib/evgenium-enrollment')
PKI = Path('/root/evgenium-ikev2-pki')
SOCKET = Path('/run/evgenium-enrollment/issuer.sock')
MAX_REQUEST = 20000
TOKEN_PATTERN = r'EVN1-[A-Za-z0-9_-]{43}'
CRL = Path('/etc/swanctl/x509crl/devices.pem')


def session_ids(raw, identities):
    """Read only the IKE header, never a child-SA uniqueid."""
    found=[]
    for event in raw.split('list-sa event ')[1:]:
        header=event.split('child-sas',1)[0]
        remote=re.search(r'(?<![\w-])remote-id=([^\s{}]+)',header)
        number=re.search(r'(?<![\w-])uniqueid=(\d+)(?=[\s}])',header)
        if remote and remote[1] in identities:
            if not number:raise RuntimeError('invalid_session_response')
            found.append(number[1])
    return found


def delete_account(account_id):
    """Fail closed, revoke all certificate generations, then close only this user's SAs.

    Tombstones retain revocation history. A failed deletion stays visible and can
    safely be retried; tokens are disabled before touching the CA or the network.
    """
    if not isinstance(account_id,str) or not re.fullmatch(r'[a-f0-9]{24}',account_id):
        raise ValueError('invalid_account')
    with locked():
        data=accounts();account=data.get(account_id)
        if not account:raise ValueError('account_missing')
        if account.get('deleted'):return {'deleted':True}
        identities={d['identity'] for d in account.get('devices',{}).values()}
        if any(not re.fullmatch(r'device-[a-f0-9]{24}',i) for i in identities):
            raise ValueError('invalid_device')
        account['enabled']=False;account['delete_pending']=True
        for device in account.get('devices',{}).values():device['disabled']=True
        write_json(ROOT/'accounts.json',data)
        if identities:
            with (PKI/'ca.lock').open('a') as ca_lock:
                fcntl.flock(ca_lock,fcntl.LOCK_EX)
                seen=set()
                for row in (PKI/'index.txt').read_text().splitlines():
                    columns=row.split('\t')
                    if len(columns)!=6:raise RuntimeError('invalid_ca_index')
                    status,_,_,serial,_,subject=columns
                    identity=subject.removeprefix('/CN=')
                    if identity not in identities:continue
                    seen.add(identity)
                    if status=='R':continue
                    if not re.fullmatch(r'[A-Fa-f0-9]+',serial):raise RuntimeError('invalid_serial')
                    run(['openssl','ca','-batch','-config',str(PKI/'ca.conf'),'-revoke',str(PKI/(serial+'.pem'))])
                if seen!=identities:raise RuntimeError('missing_certificate_history')
                temporary=CRL.with_suffix('.new')
                run(['openssl','ca','-batch','-config',str(PKI/'ca.conf'),'-gencrl','-out',str(temporary)])
                os.replace(temporary,CRL)
            run(['swanctl','--load-creds','--noprompt'])
            # Stop authenticated sessions after the new CRL prevents reconnection.
            for _ in range(3):
                raw=run(['swanctl','--list-sas','--raw']).decode()
                if 'list-sas reply' not in raw:raise RuntimeError('invalid_session_response')
                sessions=session_ids(raw,identities)
                if not sessions:break
                for number in sessions:
                    # A concurrently closed SA is harmless; the next snapshot verifies it.
                    subprocess.run(['swanctl','--terminate','--ike-id',number],capture_output=True,timeout=20)
            else:raise RuntimeError('sessions_still_active')
            for unit in ('evgenium-diagnostic-direct','evgenium-diagnostic-collector'):
                active=subprocess.run(['systemctl','is-active','--quiet',unit],timeout=5).returncode==0
                if active:run(['systemctl','restart',unit])
        account['deleted']=int(time.time());account.pop('delete_pending',None)
        write_json(ROOT/'accounts.json',data)
        return {'deleted':True}


def write_json(path, value):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    temporary = path.with_suffix('.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, separators=(',', ':'))
    os.replace(temporary, path)


@contextlib.contextmanager
def locked():
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (ROOT/'accounts.lock').open('a') as stream:
        os.chmod(ROOT/'accounts.lock', 0o600)
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def accounts():
    try:
        return json.loads((ROOT/'accounts.json').read_text())
    except FileNotFoundError:
        return {}


def issue(name):
    if not name or len(name) > 80 or any(ord(c) < 32 for c in name):
        raise ValueError('Invalid customer name')
    token = 'EVN1-' + secrets.token_urlsafe(32)
    account = secrets.token_hex(12)
    with locked():
        data = accounts()
        data[account] = {'name': name, 'token_hash': hashlib.sha256(token.encode()).hexdigest(),
                         'enabled': True, 'created': int(time.time()), 'devices': {}}
        write_json(ROOT/'accounts.json', data)
    return token


def run(args):
    cp = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False)
    if cp.returncode:
        # Never return command output, CSR or credential material to public clients.
        raise RuntimeError('certificate_operation_failed')
    return cp.stdout


def authenticate(data, token):
    if not isinstance(token, str) or not re.fullmatch(TOKEN_PATTERN, token):
        raise PermissionError('invalid_token')
    digest = hashlib.sha256(token.encode()).hexdigest()
    for identity, account in data.items():
        if hmac.compare_digest(account['token_hash'], digest) and account.get('enabled'):
            return identity, account
    raise PermissionError('invalid_token')


def normalize_device_name(value):
    import unicodedata
    if not isinstance(value, str):raise ValueError('invalid_device_name')
    value=unicodedata.normalize('NFC',value).strip()
    if not 1<=len(value)<=64 or any(unicodedata.category(c).startswith('C') for c in value):
        raise ValueError('invalid_device_name')
    return value


def ensure_device_names(account):
    names=account.setdefault('device_names',{})
    counter=max([int(account.get('next_device_number',1))-1]+[int(d.get('number',0)) for d in names.values()])
    for device,record in sorted(account.get('devices',{}).items(),key=lambda item:(item[1].get('enrolled',0),item[0])):
        if device not in names:
            counter+=1;names[device]={'number':counter,'name':'Устройство-'+str(counter)}
    account['next_device_number']=counter+1
    return names


def reserve_device_name(account,device):
    names=ensure_device_names(account)
    if device not in names:
        if len(names)>=12:raise PermissionError('device_limit')
        number=account['next_device_number'];account['next_device_number']=number+1
        names[device]={'number':number,'name':'Устройство-'+str(number)}
    return names[device]


def device_info(body):
    if not isinstance(body,dict):raise ValueError('invalid_request')
    device=body.get('device','')
    if not isinstance(device,str) or not re.fullmatch(r'[a-f0-9]{32}',device):raise ValueError('invalid_device')
    name=normalize_device_name(body['name']) if 'name' in body else None
    with locked():
        data=accounts();_,account=authenticate(data,body.get('token'))
        if account.get('devices',{}).get(device,{}).get('disabled'):raise PermissionError('device_disabled')
        record=reserve_device_name(account,device)
        if name is not None:record['name']=name
        write_json(ROOT/'accounts.json',data)
        return {'name':record['name'],'number':record['number']}


def enroll(body):
    if not isinstance(body, dict):
        raise ValueError('invalid_request')
    device = body.get('device', '')
    csr = body.get('csr', '')
    if not isinstance(device, str) or not re.fullmatch(r'[a-f0-9]{32}', device):
        raise ValueError('invalid_device')
    if not isinstance(csr, str) or not 100 <= len(csr) <= 12000 or '-----BEGIN CERTIFICATE REQUEST-----' not in csr:
        raise ValueError('invalid_csr')
    with locked():
        data = accounts()
        account_id, account = authenticate(data, body.get('token'))
        records = account['devices']
        previous = records.get(device)
        if previous and previous.get('disabled'):
            raise PermissionError('device_disabled')
        if not previous and len(records) >= 12:
            raise PermissionError('device_limit')
        identity = previous['identity'] if previous else 'device-' + secrets.token_hex(12)
        folder = PKI/identity
        folder.mkdir(mode=0o700, exist_ok=True)
        request = folder/'client.csr'
        request.write_text(csr)
        request.chmod(0o600)
        run(['openssl', 'req', '-in', str(request), '-noout', '-verify'])
        public_key = run(['openssl', 'req', '-in', str(request), '-noout', '-pubkey'])
        cp = subprocess.run(['openssl', 'pkey', '-pubin', '-text', '-noout'], input=public_key,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        if cp.returncode or not re.search(rb'Public-Key: \((3072|4096) bit\)', cp.stdout) or b'Modulus:' not in cp.stdout:
            raise ValueError('rsa3072_required')
        key_hash = hashlib.sha256(public_key).hexdigest()
        if previous and not hmac.compare_digest(previous['key_hash'], key_hash):
            raise PermissionError('device_key_changed')
        certificate = folder/'cert.pem'
        # Reusing the same account token on a second device creates another identity/key.
        valid = certificate.exists() and subprocess.run(
            ['openssl', 'x509', '-in', str(certificate), '-checkend', str(7*86400), '-noout'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5).returncode == 0
        if not valid:
            extension = folder/'client.ext'
            extension.write_text('[client]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:'+identity+'\n')
            # Share this lock with the administrative issue/revoke commands.
            with (PKI/'ca.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                run(['openssl', 'ca', '-batch', '-notext', '-config', str(PKI/'ca.conf'),
                     '-subj', '/CN='+identity, '-extensions', 'client', '-extfile', str(extension),
                     '-in', str(request), '-out', str(certificate)])
        records[device] = {**(previous or {}), 'identity': identity, 'key_hash': key_hash, 'enrolled': previous.get('enrolled',int(time.time())) if previous else int(time.time())}
        device_name=reserve_device_name(account,device)
        write_json(ROOT/'accounts.json', data)
        return {'schema': 1, 'server': '195.209.211.163', 'identity': identity,
                'account': account_id, 'device_name':device_name['name'], 'device_number':device_name['number'], 'certificate': certificate.read_text(), 'ca': (PKI/'ca.pem').read_text()}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(30)
        try:
            raw = self.rfile.readline(MAX_REQUEST+1)
            if len(raw) > MAX_REQUEST or not raw.endswith(b'\n'):
                raise ValueError('request_size')
            body=json.loads(raw)
            if isinstance(body,dict) and body.get('operation')=='admin-delete-account':
                uid=struct.unpack('3i',self.connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
                if uid!=0:raise PermissionError('root_required')
                result={'ok':True,'result':delete_account(body.get('id'))}
            elif isinstance(body,dict) and body.get('operation')=='device':
                result={'ok':True,'device':device_info(body)}
            else:result = {'ok': True, 'profile': enroll(body)}
        except PermissionError:
            time.sleep(.3)
            result = {'ok': False, 'error': 'invalid_token_or_device'}
        except (ValueError, OSError, subprocess.TimeoutExpired, RuntimeError):
            result = {'ok': False, 'error': 'enrollment_failed'}
        self.wfile.write(json.dumps(result, separators=(',', ':')).encode()+b'\n')


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='command', required=True)
    new = sub.add_parser('issue'); new.add_argument('name')
    sub.add_parser('serve'); sub.add_parser('list')
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == 'issue':
        print(issue(args.name))
    elif args.command == 'list':
        with locked():
            print(json.dumps([{'id': key, 'name': value['name'], 'enabled': value['enabled'],
                               'devices': len(value['devices'])} for key,value in accounts().items()]))
    else:
        SOCKET.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        SOCKET.unlink(missing_ok=True)
        with socketserver.UnixStreamServer(str(SOCKET), Handler) as server:
            SOCKET.chmod(0o600)
            server.serve_forever()


if __name__ == '__main__':
    main()
