"""Bounded mTLS transfer receipts. Only synthetic bytes; no payload is retained."""
import hashlib
import json
import re
import secrets
import threading
import time

class TransferSessions:
    def __init__(self, clock=time.monotonic):
        self.clock=clock;self.lock=threading.Lock();self.sessions={};self.rates={}
    def issue(self, owner, size):
        if type(size) is not int or size not in (32768,4194304):raise ValueError('size')
        with self.lock:
            now=self.clock()
            self.sessions={k:v for k,v in self.sessions.items() if now<v['expires']}
            self.rates={k:v for k,v in self.rates.items() if now-v[0]<3600}
            rate=self.rates.get(owner,(now,0))
            if len(self.sessions)>=256 or sum(s['owner']==owner for s in self.sessions.values())>=12 or rate[1]>=180 or len(self.rates)>=4096 and owner not in self.rates:raise ValueError('capacity')
            self.rates[owner]=(rate[0],rate[1]+1)
            sid=secrets.token_hex(16)
            self.sessions[sid]=dict(owner=owner,expires=now+180,size=size,started=False,received=0,complete=False,elapsed_ms=0,max_read_ms=0,sha256='')
            return {'session':sid,'size':size}
    def _get(self,sid,owner):
        if not isinstance(sid,str) or not re.fullmatch('[a-f0-9]{32}',sid):raise ValueError('session')
        s=self.sessions.get(sid)
        if not s or s['owner']!=owner or self.clock()>=s['expires']:raise ValueError('session')
        return s
    def result(self,sid,owner):
        with self.lock:
            s=self._get(sid,owner)
            return {k:s[k] for k in ('size','received','complete','elapsed_ms','max_read_ms','sha256')}
    def consume(self,sid,owner,size,stream,connection,receipt=None):
        with self.lock:
            s=self._get(sid,owner)
            if size!=s['size'] or s['started']:raise ValueError('replay_or_size')
            s['started']=True
        start=self.clock();digest=hashlib.sha256();count=0
        try:
            while count<size:
                remaining=25-(self.clock()-start)
                if remaining<=0:raise TimeoutError('transfer_deadline')
                connection.settimeout(min(8,remaining))
                at=self.clock();chunk=stream.read1(min(16384,size-count))
                if not chunk:raise EOFError('transfer_truncated')
                digest.update(chunk);count+=len(chunk)
                with self.lock:
                    s['received']=count;s['max_read_ms']=max(s['max_read_ms'],round((self.clock()-at)*1000));s['elapsed_ms']=round((self.clock()-start)*1000)
            with self.lock:s['complete']=True;s['sha256']=digest.hexdigest()
        finally:
            with self.lock:s['elapsed_ms']=round((self.clock()-start)*1000)
            if receipt is not None:
                try:receipt(self.result(sid,owner))
                except (OSError,ValueError):pass  # Logging must not break transport checks.
        return self.result(sid,owner)

sessions=TransferSessions()
def handle(handler):
    """Called only after the collector checks mTLS and its enable switch."""
    cert=handler.connection.getpeercert(binary_form=True)
    if not cert:raise ValueError('certificate')
    owner=hashlib.sha256(cert).digest()
    if handler.headers.get('Transfer-Encoding') or len(handler.headers.get_all('Content-Length',[]))!=1:raise ValueError('framing')
    size=int(handler.headers['Content-Length'])
    if handler.path=='/transfer-upload':
        result=sessions.consume(handler.headers.get('X-Evgenium-Session',''),owner,size,handler.rfile,handler.connection,
            (lambda r:handler.transfer_receipt(handler.headers.get('X-Evgenium-Session',''),r)) if size==4194304 else None)
        # Client validates both receipt and full response body. Write != peer ACK.
        handler.reply(200,{**result,'padding':'x'*16384});return
    if not 0<size<=128:raise ValueError('size')
    body=json.loads(handler.rfile.read(size))
    if handler.path=='/transfer-start':result=sessions.issue(owner,body['size'])
    elif handler.path=='/transfer-result':result=sessions.result(body['session'],owner)
    else:raise ValueError('path')
    handler.reply(200,result)
