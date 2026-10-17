"""Evgenium owner panel: password + replay-resistant TOTP, server-side sessions."""
import base64
from contextlib import contextmanager
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import struct
import time
from urllib.parse import quote
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify, g, render_template, make_response, abort
from werkzeug.middleware.proxy_fix import ProxyFix

COOKIE='evg_panel_session'


def totp(secret,counter,digits=6):
    digest=hmac.new(base64.b32decode(secret),struct.pack('>Q',counter),hashlib.sha1).digest()
    offset=digest[-1]&15
    return str((struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff)%10**digits).zfill(digits)


def match_totp(secret,code,last=-1,now=None):
    if not isinstance(code,str) or not re.fullmatch('[0-9]{6}',code):return None
    step=int(time.time() if now is None else now)//30
    for counter in (step,step-1,step+1):
        if counter>last and hmac.compare_digest(totp(secret,counter),code):return counter
    return None


def password_hash(password,salt=None):
    salt=salt or secrets.token_bytes(16)
    digest=hashlib.scrypt(password.encode(),salt=salt,n=32768,r=8,p=1,maxmem=67108864)
    return base64.b64encode(salt+digest).decode()


def password_valid(password,stored):
    try:
        raw=base64.b64decode(stored,validate=True)
        return hmac.compare_digest(password_hash(password,raw[:16]),stored)
    except (ValueError,TypeError):return False


def rpc(path,body):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(20);sock.connect(path);sock.sendall(json.dumps(body).encode()+b'\n')
        with sock.makefile('rb') as reader:raw=reader.readline(4*1024*1024+1)
    if len(raw)>4*1024*1024 or not raw.endswith(b'\n'):raise OSError('broker_response')
    return json.loads(raw)


def create_app(config=None,broker_call=None):
    cfg=config or json.loads(Path(os.environ.get('EVG_PANEL_CONFIG','/etc/evgenium-panel/config.json')).read_text())
    app=Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=4096,MAX_FORM_PARTS=8)
    if cfg.get('https_proxy'):app.wsgi_app=ProxyFix(app.wsgi_app,x_proto=1)
    state=Path(cfg['state_dir']);state.mkdir(mode=0o700,parents=True,exist_ok=True)
    cipher=Fernet(cfg['encryption_key'].encode());database=state/'panel.sqlite3'
    broker_call=broker_call or (lambda body:rpc(cfg['broker_socket'],body))
    @contextmanager
    def db():
        conn=sqlite3.connect(database,timeout=10);conn.row_factory=sqlite3.Row
        try:
            conn.execute('PRAGMA busy_timeout=10000');yield conn;conn.commit()
        except Exception:conn.rollback();raise
        finally:conn.close()
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS owner(id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, password TEXT NOT NULL, totp TEXT NOT NULL, last_counter INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, kind TEXT NOT NULL, csrf TEXT NOT NULL, created INTEGER NOT NULL, seen INTEGER NOT NULL, expires INTEGER NOT NULL, secret TEXT);
        CREATE TABLE IF NOT EXISTS attempts(bucket TEXT PRIMARY KEY, start INTEGER NOT NULL, count INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, event TEXT NOT NULL, subject TEXT NOT NULL DEFAULT '');
        ''')
    database.chmod(0o600)
    def audit(c,event,subject=''):
        c.execute('INSERT INTO audit(ts,event,subject) VALUES(?,?,?)',(int(time.time()),event,subject))
        c.execute('DELETE FROM audit WHERE id <= (SELECT COALESCE(MAX(id),0)-10000 FROM audit)')
    def limit(c,bucket,maximum,period=900):
        now=int(time.time());c.execute('DELETE FROM attempts WHERE start < ?',(now-86400,))
        row=c.execute('SELECT * FROM attempts WHERE bucket=?',(bucket,)).fetchone()
        if row and row['start']>now-period:
            if row['count']>=maximum:return False
            c.execute('UPDATE attempts SET count=count+1 WHERE bucket=?',(bucket,))
        else:c.execute('INSERT OR REPLACE INTO attempts VALUES(?,?,1)',(bucket,now))
        return True
    def attempt():
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            allowed=limit(c,'login:'+request.remote_addr,8) and limit(c,'login-global',80)
        if not allowed:abort(429)
    def new_session(kind='anonymous',secret=None):
        sid=secrets.token_urlsafe(32);now=int(time.time());csrf=secrets.token_urlsafe(32)
        with db() as c:
            c.execute('DELETE FROM sessions WHERE expires < ? OR seen < ?',(now,now-1800))
            if getattr(g,'sid_hash',None):c.execute('DELETE FROM sessions WHERE id=?',(g.sid_hash,))
            c.execute('INSERT INTO sessions VALUES(?,?,?,?,?,?,?)',
                      (hashlib.sha256(sid.encode()).hexdigest(),kind,csrf,now,now,now+(28800 if kind=='owner' else 600),secret))
        g.set_sid=sid;g.session={'kind':kind,'csrf':csrf,'secret':secret}
        return csrf
    def owner_required():
        if not g.session or g.session['kind']!='owner':abort(401)
    @app.before_request
    def guard():
        g.set_sid=None;g.session=None;g.sid_hash=None
        if request.host not in cfg['allowed_hosts']:abort(400)
        if cfg.get('https_proxy') and not request.is_secure:abort(400)
        if not cfg.get('https_proxy') and request.remote_addr not in ('127.0.0.1','::1'):abort(403)
        sid=request.cookies.get(COOKIE,'')
        if re.fullmatch('[A-Za-z0-9_-]{43}',sid):
            g.sid_hash=hashlib.sha256(sid.encode()).hexdigest()
            with db() as c:
                row=c.execute('SELECT * FROM sessions WHERE id=?',(g.sid_hash,)).fetchone();now=int(time.time())
                if row and row['expires']>now and row['seen']>now-1800:
                    g.session=dict(row);c.execute('UPDATE sessions SET seen=? WHERE id=?',(now,g.sid_hash))
                elif row:c.execute('DELETE FROM sessions WHERE id=?',(g.sid_hash,))
        if request.method=='POST':
            if request.headers.get('Origin') not in (None,request.host_url.rstrip('/')):abort(403)
            if request.headers.get('Sec-Fetch-Site')=='cross-site':abort(403)
            if request.content_type!='application/json':abort(415)
            if not isinstance(request.get_json(),dict):abort(400)
            if not g.session or not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),g.session['csrf']):abort(403)
    @app.after_request
    def security(response):
        response.headers.update({'Cache-Control':'no-store','Pragma':'no-cache','X-Content-Type-Options':'nosniff',
          'X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Permissions-Policy':'camera=(), microphone=(), geolocation=()',
          'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"})
        if cfg.get('https_proxy'):response.headers['Strict-Transport-Security']='max-age=31536000'
        if getattr(g,'set_sid',None):response.set_cookie(COOKIE,g.set_sid,secure=bool(cfg.get('https_proxy')),httponly=True,samesite='Strict',path='/')
        return response
    for code in (400,401,403,404,413,415,429,500):
        app.register_error_handler(code,lambda e:(jsonify(error={400:'invalid_request',401:'login_required',403:'request_rejected',404:'not_found',413:'too_large',415:'json_required',429:'too_many_attempts',500:'internal_error'}[e.code]),e.code))
    @app.get('/')
    def index():return render_template('index.html')
    @app.get('/api/session')
    def current():
        if not g.session:
            with db() as c:
                c.execute('BEGIN IMMEDIATE');allowed=limit(c,'session:'+request.remote_addr,120,60)
            if not allowed:abort(429)
            new_session()
        with db() as c:configured=c.execute('SELECT 1 FROM owner').fetchone() is not None
        return jsonify(authenticated=g.session['kind']=='owner',setup_required=not configured,csrf=g.session['csrf'])
    @app.post('/api/setup/start')
    def setup_start():
        attempt();body=request.get_json()
        with db() as c:
            if c.execute('SELECT 1 FROM owner').fetchone():abort(403)
        supplied=body.get('bootstrap','')
        if not isinstance(supplied,str) or not hmac.compare_digest(hashlib.sha256(supplied.encode()).hexdigest(),cfg['bootstrap_hash']) or time.time()>cfg['bootstrap_expires']:abort(403)
        secret=base64.b32encode(secrets.token_bytes(20)).decode()
        csrf=new_session('setup',cipher.encrypt(secret.encode()).decode())
        return jsonify(csrf=csrf,qr='/api/setup/qr')
    @app.get('/api/setup/qr')
    def setup_qr():
        if not g.session or g.session['kind']!='setup':abort(403)
        import qrcode
        import qrcode.image.svg
        secret=cipher.decrypt(g.session['secret'].encode()).decode()
        uri='otpauth://totp/'+quote('Evgenium Network:admin')+'?secret='+secret+'&issuer=Evgenium%20Network&algorithm=SHA1&digits=6&period=30'
        image=qrcode.make(uri,image_factory=qrcode.image.svg.SvgPathImage);output=io.BytesIO();image.save(output)
        return app.response_class(output.getvalue(),mimetype='image/svg+xml')
    @app.post('/api/setup/finish')
    def setup_finish():
        if not g.session or g.session['kind']!='setup':abort(403)
        attempt();body=request.get_json();password=body.get('password','')
        if not isinstance(password,str) or not 14<=len(password)<=256:return jsonify(error='password_length'),400
        secret=cipher.decrypt(g.session['secret'].encode()).decode();counter=match_totp(secret,body.get('code'))
        if counter is None:return jsonify(error='invalid_code'),400
        digest=password_hash(password)
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT 1 FROM owner').fetchone():abort(403)
            c.execute('INSERT INTO owner VALUES(1,?,?,?,?)',('admin',digest,cipher.encrypt(secret.encode()).decode(),counter))
            c.execute('DELETE FROM sessions');audit(c,'owner_initialized')
        csrf=new_session('owner');return jsonify(ok=True,csrf=csrf)
    @app.post('/api/login')
    def login():
        attempt();body=request.get_json();password=body.get('password','')
        if not isinstance(password,str) or len(password)>256:abort(400)
        with db() as c:
            c.execute('BEGIN IMMEDIATE');owner=c.execute('SELECT * FROM owner WHERE id=1').fetchone()
            valid=bool(owner) and password_valid(password,owner['password'])
            counter=match_totp(cipher.decrypt(owner['totp'].encode()).decode(),body.get('code'),owner['last_counter']) if valid else None
            if counter is not None:
                c.execute('UPDATE owner SET last_counter=? WHERE id=1',(counter,));audit(c,'login_success')
            else:audit(c,'login_failed')
        if counter is None:return jsonify(error='invalid_credentials'),401
        csrf=new_session('owner');return jsonify(ok=True,csrf=csrf)
    @app.post('/api/logout')
    def logout():
        with db() as c:
            c.execute('DELETE FROM sessions WHERE id=?',(g.sid_hash,));audit(c,'logout')
        response=jsonify(ok=True);response.delete_cookie(COOKIE,path='/',secure=bool(cfg.get('https_proxy')),httponly=True,samesite='Strict');return response
    def call(body,event=None):
        owner_required()
        try:result=broker_call(body)
        except (OSError,ValueError):return jsonify(error='broker_unavailable'),503
        if not result.get('ok'):return jsonify(error=result.get('error','broker_unavailable')),400
        if event:
            with db() as c:audit(c,event,body.get('id',result.get('data',{}).get('id','')))
        return jsonify(result['data'])
    @app.get('/api/dashboard')
    def dashboard():return call({'op':'snapshot'})
    @app.post('/api/accounts')
    def issue():return call({'op':'issue','name':request.get_json().get('name')},'account_created')
    @app.post('/api/accounts/<account_id>/reveal')
    def reveal(account_id):return call({'op':'reveal','id':account_id},'token_revealed')
    @app.post('/api/accounts/<account_id>/import')
    def import_token(account_id):return call({'op':'import','id':account_id,'token':request.get_json().get('token')},'legacy_token_imported')
    @app.get('/api/audit')
    def activity():
        owner_required()
        with db() as c:rows=[dict(r) for r in c.execute('SELECT ts,event,subject FROM audit ORDER BY id DESC LIMIT 50')]
        return jsonify(items=rows)
    return app
