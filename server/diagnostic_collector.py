#!/usr/bin/env python3
"""Private mTLS collector: bounded pseudonymous reports; no HTTP access logging."""
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import threading
import time

LOG = Path('/var/log/evgenium-experimental')
LOCK = threading.Lock()
MAX_SIZE = 8 * 1024 * 1024
MAX_AGE = 7 * 86400


def clean_report(body):
    if not isinstance(body, dict) or body.get('schema') != 1:
        raise ValueError('schema')
    if body.get('event') not in ('sample', 'site_report'):
        raise ValueError('event')
    probes = body.get('probes')
    if not isinstance(probes, list) or not 1 <= len(probes) <= 8:
        raise ValueError('probes')
    result = []
    for item in probes:
        if not isinstance(item, dict):
            raise ValueError('probe')
        name = item.get('domain', '')
        if not isinstance(name, str) or len(name) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', name) or '.' not in name:
            raise ValueError('domain')
        if any(not x or len(x) > 63 or x.startswith('-') or x.endswith('-') for x in name.split('.')):
            raise ValueError('domain')
        try:
            ipaddress.ip_address(name)
        except ValueError:
            pass
        else:
            raise ValueError('ip')
        result.append({'domain': name, 'ok': item.get('ok') is True,
                       'latency_ms': max(0, min(120000, int(item.get('latency_ms', 0)))),
                       'http_status': max(0, min(599, int(item.get('http_status', 0))))})
    version = body.get('manager', '')
    if not isinstance(version, str) or not re.fullmatch(r'[0-9.]{1,20}', version):
        raise ValueError('version')
    return {'schema': 1, 'event': body['event'], 'manager': version, 'probes': result}


def prune():
    LOG.mkdir(mode=0o700, parents=True, exist_ok=True)
    now = time.time()
    for path in LOG.glob('*.jsonl'):
        if now - path.stat().st_mtime > MAX_AGE:
            path.unlink()


def store_report(cert, body):
    record = clean_report(body)
    # Stable only for this individual certificate; no account, machine or peer IP.
    record['device'] = hashlib.sha256(cert).hexdigest()[:24]
    record['received'] = int(time.time())
    with LOCK:
        prune()
        path = LOG / (time.strftime('%Y-%m-%d', time.gmtime()) + '.jsonl')
        if path.exists() and path.stat().st_size >= MAX_SIZE:
            raise ValueError('daily_limit')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as f:
            f.write(json.dumps(record, separators=(',', ':')) + '\n')


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def setup(self):
        self.request.settimeout(8)
        self.request = self.server.context.wrap_socket(self.request, server_side=True)
        super().setup()
        self.connection.settimeout(10)
    def log_message(self, *args):
        pass
    def reply(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_GET(self):
        if self.path == '/health':
            self.reply(200, {'service': 'evgenium-starfive', 'egress': 'RU-test'})
        else:
            self.reply(404, {})
    def do_POST(self):
        if self.path != '/report' or not Path('/etc/evgenium-diagnostics-enabled').exists():
            self.reply(403, {})
            return
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 16384:
                raise ValueError('size')
            store_report(self.connection.getpeercert(binary_form=True), json.loads(self.rfile.read(size)))
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            self.reply(400, {'accepted': False})
            return
        self.reply(200, {'accepted': True})


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    slots = threading.BoundedSemaphore(8)
    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise
    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()
    def handle_error(self, request, address):
        # No peer addresses or handshake failures in persistent HTTP logs.
        pass


if __name__ == '__main__':
    prune()
    server = Server(('10.77.0.1', 8443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain('/etc/swanctl/x509/starfive.pem', '/etc/swanctl/private/starfive.pem')
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations('/etc/swanctl/x509ca/starfive-ca.pem')
    context.load_verify_locations('/etc/swanctl/x509crl/devices.pem')
    context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    server.context = context
    server.serve_forever()
