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
import socketserver
import subprocess
import time

ROOT = Path('/var/lib/evgenium-enrollment')
PKI = Path('/root/evgenium-ikev2-pki')
SOCKET = Path('/run/evgenium-enrollment/issuer.sock')
MAX_REQUEST = 20000
TOKEN_PATTERN = r'EVN1-[A-Za-z0-9_-]{43}'


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
        records[device] = {'identity': identity, 'key_hash': key_hash, 'enrolled': int(time.time())}
        write_json(ROOT/'accounts.json', data)
        return {'schema': 1, 'server': '109.194.67.159', 'identity': identity,
                'account': account_id, 'certificate': certificate.read_text(), 'ca': (PKI/'ca.pem').read_text()}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(30)
        try:
            raw = self.rfile.readline(MAX_REQUEST+1)
            if len(raw) > MAX_REQUEST or not raw.endswith(b'\n'):
                raise ValueError('request_size')
            result = {'ok': True, 'profile': enroll(json.loads(raw))}
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
