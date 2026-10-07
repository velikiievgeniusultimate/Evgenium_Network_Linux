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
import urllib.parse
import socket

LOG = Path('/var/log/evgenium-experimental')
LOCK = threading.Lock()
MAX_SIZE = 8 * 1024 * 1024
MAX_AGE = 7 * 86400
RU_DOMAINS = ('yandex.ru', 'mail.ru', 'www.rt.ru')
BLOCK = hashlib.shake_256(b'evgenium-starfive-integrity-v1').digest(65536)
MAX_BLOB = 64 * 1024 * 1024


def blob_chunks(size, offset=0):
    while size:
        chunk = BLOCK[offset % len(BLOCK):][:min(size, len(BLOCK)-offset % len(BLOCK))]
        yield chunk
        offset += len(chunk)
        size -= len(chunk)


def blob_hash(size, offset=0):
    digest = hashlib.sha256()
    for chunk in blob_chunks(size, offset):
        digest.update(chunk)
    return digest.hexdigest()


def server_metrics():
    result = {'load1': int(float(Path('/proc/loadavg').read_text().split()[0])*1000)}
    ticks = [int(x) for x in Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
    result.update(cpu_total_ticks=sum(ticks[:8]), cpu_idle_ticks=ticks[3]+ticks[4])
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'): result['memory_available_kb'] = int(line.split()[1])
    for line in Path('/proc/net/dev').read_text().splitlines():
        if line.strip().startswith('eth0:'):
            values = [int(x) for x in line.split(':',1)[1].split()]
            result.update(rx_bytes=values[0], rx_errors=values[2], rx_dropped=values[3],
                          tx_bytes=values[8], tx_errors=values[10], tx_dropped=values[11])
    return result


def control_probes():
    # Probe without following redirects or recording HTTP bodies/cookies.
    probes=[]
    for domain in RU_DOMAINS:
        start=time.monotonic(); code=0
        try:
            addresses=socket.getaddrinfo(domain,443,socket.AF_INET,socket.SOCK_STREAM)
            address=next(x[4][0] for x in addresses if ipaddress.ip_address(x[4][0]).is_global)
            with socket.create_connection((address,443),timeout=4) as sock:
                with ssl.create_default_context().wrap_socket(sock,server_hostname=domain) as conn:
                    conn.sendall(('HEAD / HTTP/1.1\r\nHost: '+domain+'\r\nConnection: close\r\n\r\n').encode())
                    parts=conn.recv(256).split(b'\r\n',1)[0].split()
                    if len(parts)>1 and parts[1].isdigit(): code=int(parts[1])
        except (OSError,StopIteration): pass
        probes.append({'domain':domain,'ok':bool(code),'http_status':code,
                       'latency_ms':round((time.monotonic()-start)*1000)})
    return {'probes':probes, 'metrics':server_metrics()}



def clean_report(body):
    if not isinstance(body, dict) or body.get('schema') != 1:
        raise ValueError('schema')
    if body.get('event') == 'global_test':
        return clean_global_report(body)
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


TEST_KINDS = {'health','ping','download','upload','resume','parallel','idle','reconnect','daemon_restart','guard','ru_probe','server_control','counters'}
TEST_OUTCOMES = {'completed','failed','cancelled'}
TEST_METRICS = {'bytes','received_bytes','elapsed_ms','mbps_milli','sent','received','loss_milli','rtt_min_us','rtt_avg_us','rtt_max_us','rtt_mdev_us','http_status','latency_ms','offset','attempt','size','packets_in','packets_out','bytes_in','bytes_out','load1','cpu_total_ticks','cpu_idle_ticks','memory_available_kb','rx_bytes','rx_errors','rx_dropped','tx_bytes','tx_errors','tx_dropped','retrans_segments','out_segments','timeouts','xfrm_errors','duration_ms','at_ms'}


def clean_global_report(body):
    version=body.get('manager',''); run=body.get('run','')
    if not isinstance(version,str) or not re.fullmatch(r'[0-9.]{1,20}',version): raise ValueError('version')
    if not isinstance(run,str) or not re.fullmatch(r'[a-f0-9]{24}',run): raise ValueError('run')
    outcome=body.get('outcome')
    if outcome not in TEST_OUTCOMES: raise ValueError('outcome')
    records=body.get('records')
    if not isinstance(records,list) or len(records)>256: raise ValueError('records')
    result=[]
    for item in records:
        if not isinstance(item,dict) or item.get('kind') not in TEST_KINDS: raise ValueError('kind')
        row={'kind':item['kind'],'ok':item.get('ok') is True}
        if 'domain' in item:
            if item['domain'] not in RU_DOMAINS: raise ValueError('domain')
            row['domain']=item['domain']
        for key in TEST_METRICS:
            if key in item:
                value=item[key]
                if type(value) is not int or not 0 <= value <= 10**18: raise ValueError('metric')
                row[key]=value
        if 'integrity' in item: row['integrity']=item['integrity'] is True
        result.append(row)
    duration=body.get('duration_ms',0)
    if type(duration) is not int or not 0 <= duration <= 1800000: raise ValueError('duration')
    return {'schema':1,'event':'global_test','manager':version,'run':run,
            'outcome':outcome,'duration_ms':duration,'records':result}


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
        path=urllib.parse.urlsplit(self.path)
        if path.path == '/health':
            self.reply(200, {'service': 'evgenium-starfive', 'egress': 'RU-test', 'test_api':1})
        elif path.path == '/control':
            self.reply(200, control_probes())
        elif path.path == '/blob':
            try:
                query=urllib.parse.parse_qs(path.query)
                size=int(query.get('size',['0'])[0]); offset=0; count=size
                if not 1 <= size <= MAX_BLOB: raise ValueError('size')
                header=self.headers.get('Range','')
                if header:
                    match=re.fullmatch(r'bytes=(\d+)-(\d*)',header)
                    if not match: raise ValueError('range')
                    offset=int(match[1]); end=int(match[2]) if match[2] else size-1
                    if not 0 <= offset <= end < size: raise ValueError('range')
                    count=end-offset+1
            except (ValueError,TypeError):
                self.reply(416,{}); return
            self.send_response(206 if header else 200)
            self.send_header('Content-Type','application/octet-stream')
            self.send_header('Content-Length',str(count))
            self.send_header('Accept-Ranges','bytes')
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-SHA256',blob_hash(count,offset))
            if header: self.send_header('Content-Range',f'bytes {offset}-{offset+count-1}/{size}')
            self.end_headers()
            for chunk in blob_chunks(count,offset): self.wfile.write(chunk)
        else:
            self.reply(404, {})
    def do_POST(self):
        if not Path('/etc/evgenium-diagnostics-enabled').exists():
            self.reply(403, {}); return
        try:
            size=int(self.headers.get('Content-Length','0'))
            if self.path == '/upload':
                if not 0 < size <= 8*1024*1024: raise ValueError('size')
                digest=hashlib.sha256(); remaining=size
                while remaining:
                    data=self.rfile.read(min(65536,remaining))
                    if not data: raise ValueError('truncated')
                    digest.update(data); remaining-=len(data)
                self.reply(200,{'received_bytes':size,'sha256':digest.hexdigest()}); return
            if self.path != '/report' or not 0 < size <= 131072:
                raise ValueError('size')
            store_report(self.connection.getpeercert(binary_form=True), json.loads(self.rfile.read(size)))
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            self.reply(400, {'accepted': False}); return
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
