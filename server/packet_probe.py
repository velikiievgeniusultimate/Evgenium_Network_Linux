"""Bounded UDP synthetic probes inside VPN, authorised by an mTLS session.

Never accepts arbitrary destinations or records user packets. Responses are no
larger than requests. Tickets expire in two minutes and are bound to certificate
and VPN source IP; request/response MAC domains differ to prevent reflection.
"""
import hashlib
import hmac
import secrets
import socket
import struct
import threading
import time

PORT = 24584
SIZES = (128, 512, 1200)
class ProbeSessions:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.sessions = {}
        self.lock = threading.Lock()

    def issue(self, owner, peer):
        with self.lock:
            now = self.clock()
            self.sessions = {k:v for k,v in self.sessions.items() if now < v['expires']}
            if len(self.sessions) >= 128 or sum(v['owner']==owner for v in self.sessions.values()) >= 8:
                raise ValueError('probe_capacity')
            sid, key = secrets.token_bytes(16), secrets.token_bytes(32)
            self.sessions[sid] = dict(key=key, owner=owner, peer=peer, expires=now+120,
                cases=[dict(seen=set(), received=0, duplicates=0, replies=0) for _ in range(6)])
            return dict(session=sid.hex(), key=key.hex(), port=PORT, packets=120, expires_seconds=120)

    def handle(self, data, peer):
        if len(data) not in SIZES or data[:4] != b'EVP1': return None
        sid = data[4:20]
        seq = struct.unpack('!I', data[20:24])[0]
        if seq >= 120 or len(data) != SIZES[seq//40]: return None
        with self.lock:
            s = self.sessions.get(sid)
            if not s or self.clock() >= s['expires'] or s['peer'] != peer: return None
            if not hmac.compare_digest(data[-32:], hmac.digest(s['key'], data[:-32], 'sha256')): return None
            case = s['cases'][seq//20]
            if case['received'] >= 40: return None
            case['received'] += 1
            if seq in case['seen']: case['duplicates'] += 1
            case['seen'].add(seq)
            body = b'EVP2' + data[4:-32]
            return sid, seq//20, body + hmac.digest(s['key'], body, 'sha256')

    def replied(self, sid, case):
        with self.lock:
            if sid in self.sessions: self.sessions[sid]['cases'][case]['replies'] += 1

    def result(self, sid, owner):
        with self.lock:
            s = self.sessions.get(bytes.fromhex(sid))
            if not s or self.clock() >= s['expires'] or s['owner'] != owner: raise ValueError('probe_session')
            return {'cases':[dict(received=len(c['seen']), duplicates=c['duplicates'], replies=c['replies']) for c in s['cases']]}

sessions = ProbeSessions()
_listener = None
_lock = threading.Lock()
def start():
    global _listener
    with _lock:
        if _listener is not None: return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: sock.bind(('10.77.0.1', PORT))
        except Exception: sock.close(); raise
        _listener = sock
        def serve():
            while True:
                try:
                    data, peer = sock.recvfrom(1401)
                    reply = sessions.handle(data, peer[0])
                    if reply:
                        sid, case, payload = reply
                        sock.sendto(payload, peer)
                        sessions.replied(sid, case)
                except OSError: continue
        threading.Thread(target=serve, name='synthetic-packet-probe', daemon=True).start()

def request(path, body, cert, peer):
    if not peer.startswith('10.77.0.'): raise ValueError('vpn_only')
    owner = hashlib.sha256(cert).digest()
    if path == '/packet-session':
        start()
        return sessions.issue(owner, peer)
    return sessions.result(body['session'], owner)
