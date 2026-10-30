"""Public device enrollment. No owner credentials or client private keys are read here."""
from contextlib import contextmanager
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import time

from flask import Flask, abort, g, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

COOKIE = '__Host-evg_connect'
TOKEN = re.compile(r'EVN1-[A-Za-z0-9_-]{43}\Z')
DEVICE = re.compile(r'[a-f0-9]{32}\Z')


def rpc(path, body):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(20)
        sock.connect(path)
        sock.sendall(json.dumps(body, ensure_ascii=False).encode() + b'\n')
        with sock.makefile('rb') as reader:
            raw = reader.readline(16385)
    if len(raw) > 16384 or not raw.endswith(b'\n'):
        raise OSError('invalid_backend_response')
    return json.loads(raw)


def valid_key(value):
    if not isinstance(value, str):
        return False
    try:
        raw = base64.b64decode(value, validate=True)
        return len(raw) == 32 and raw != bytes(32) and base64.b64encode(raw).decode() == value
    except (ValueError, TypeError):
        return False


def safe_profile(result, device, endpoint):
    """Whitelist fields and validate all values that the browser puts in a .conf."""
    p = result.get('profile')
    if not isinstance(p, dict) or p.get('schema') != 1 or p.get('device') != device:
        raise ValueError('invalid_profile')
    if not valid_key(p.get('public_key')) or p.get('endpoint') != endpoint:
        raise ValueError('invalid_profile')
    address = ipaddress.ip_interface(p['address'])
    if address.version != 4 or address.network.prefixlen != 32:
        raise ValueError('invalid_profile')
    dns = p.get('dns')
    if not isinstance(dns, list) or not 1 <= len(dns) <= 3:
        raise ValueError('invalid_profile')
    dns = [str(ipaddress.ip_address(v)) for v in dns]
    if p.get('allowed_ips') != ['0.0.0.0/0', '::/0'] or not isinstance(p.get('mtu'), int) or not 1280 <= p['mtu'] <= 1420:
        raise ValueError('invalid_profile')
    name = p.get('device_name')
    if not isinstance(name, str) or not 1 <= len(name) <= 64 or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError('invalid_profile')
    return dict(schema=1, device=device, account=str(p.get('account', ''))[:64],
                device_name=name, device_number=p.get('device_number'), public_key=p['public_key'],
                endpoint=endpoint, address=str(address),
                addresses=[str(address), 'fd78:6576:6765::' + format(int(address.ip) & 255, 'x') + '/128'],
                dns=dns, mtu=p['mtu'],
                allowed_ips=['0.0.0.0/0', '::/0'])


def create_app(config=None, issuer_call=None):
    cfg = config or json.loads(Path(os.environ.get('EVG_CONNECT_CONFIG', '/etc/evgenium-connect/config.json')).read_text())
    app = Flask(__name__, root_path=str(Path(__file__).resolve().parent))
    app.config.update(MAX_CONTENT_LENGTH=2048, MAX_FORM_PARTS=2)
    # Gunicorn must bind to loopback only; nginx overwrites these two headers.
    if cfg.get('https_proxy', True):
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
    state = Path(cfg['state_dir'])
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    database = state / 'connect.sqlite3'
    issuer_call = issuer_call or (lambda body: rpc(cfg.get('issuer_socket', '/run/evgenium-wireguard/enroll.sock'), body))

    @contextmanager
    def db():
        connection = sqlite3.connect(database, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute('PRAGMA busy_timeout=10000')
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts(bucket TEXT PRIMARY KEY, start INTEGER NOT NULL, count INTEGER NOT NULL);
        ''')
    database.chmod(0o600)

    def limited(kind, maximum, period, global_maximum):
        now = int(time.time())
        identity = hashlib.sha256((request.remote_addr or 'unknown').encode()).hexdigest()
        allowed = True
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            c.execute('DELETE FROM attempts WHERE start < ?', (now - 86400,))
            for bucket, cap in ((kind + ':' + identity, maximum), (kind + ':global', global_maximum)):
                row = c.execute('SELECT start,count FROM attempts WHERE bucket=?', (bucket,)).fetchone()
                if row and row['start'] > now - period:
                    if row['count'] >= cap:
                        allowed = False
                    else:
                        c.execute('UPDATE attempts SET count=count+1 WHERE bucket=?', (bucket,))
                else:
                    c.execute('INSERT OR REPLACE INTO attempts VALUES(?,?,1)', (bucket, now))
        if not allowed:
            abort(429)

    @app.before_request
    def guard():
        g.set_cookie = None
        g.session = None
        if request.host not in cfg.get('allowed_hosts', ['connect.velikiievgenius.com']) or not request.is_secure or request.query_string:
            abort(400)
        if request.method not in ('GET', 'HEAD', 'POST'):
            abort(405)
        sid = request.cookies.get(COOKIE, '')
        if re.fullmatch('[A-Za-z0-9_-]{43}', sid):
            with db() as c:
                row = c.execute('SELECT csrf,expires FROM sessions WHERE id=?', (hashlib.sha256(sid.encode()).hexdigest(),)).fetchone()
                if row and row['expires'] > int(time.time()):
                    g.session = dict(row)
        if request.method == 'POST':
            if request.headers.get('Origin') not in (None, request.host_url.rstrip('/')) or request.headers.get('Sec-Fetch-Site') == 'cross-site':
                abort(403)
            if request.mimetype != 'application/json':
                abort(415)
            csrf = request.headers.get('X-CSRF-Token', '')
            if not re.fullmatch('[A-Za-z0-9_-]{43}', csrf) or not g.session or not hmac.compare_digest(csrf, g.session['csrf']):
                abort(403)

    @app.after_request
    def security(response):
        response.headers.update({
            'Cache-Control': 'no-store', 'Pragma': 'no-cache', 'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
            'Strict-Transport-Security': 'max-age=31536000',
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
            'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        })
        if getattr(g, 'set_cookie', None):
            response.set_cookie(COOKIE, g.set_cookie, max_age=7200, secure=True, httponly=True, samesite='Strict', path='/')
        if response.status_code == 429:
            response.headers['Retry-After'] = '900'
        return response

    errors = {400: 'invalid_request', 401: 'token_invalid', 403: 'request_rejected', 404: 'not_found',
              405: 'method_not_allowed', 409: 'device_conflict', 413: 'too_large', 415: 'json_required',
              429: 'too_many_attempts', 500: 'internal_error', 503: 'enrollment_unavailable'}
    for code in errors:
        app.register_error_handler(code, lambda e: (jsonify(error=errors[e.code]), e.code))

    @app.get('/')
    def index():
        return render_template('index.html')

    @app.get('/api/session')
    def session():
        if not g.session:
            limited('session', cfg.get('session_limit', 40), 900, cfg.get('session_global_limit', 1000))
            sid = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(32)
            now = int(time.time())
            with db() as c:
                c.execute('DELETE FROM sessions WHERE expires <= ?', (now,))
                c.execute('INSERT INTO sessions VALUES(?,?,?)', (hashlib.sha256(sid.encode()).hexdigest(), csrf, now + 7200))
            g.set_cookie = sid
            return jsonify(csrf=csrf)
        return jsonify(csrf=g.session['csrf'])

    @app.post('/api/enroll')
    def enroll():
        limited('enroll', cfg.get('enroll_limit', 30), 900, cfg.get('enroll_global_limit', 300))
        body = request.get_json(silent=True)
        if not isinstance(body, dict) or set(body) - {'token', 'device', 'name', 'public_key'}:
            abort(400)
        token, device, key, name = body.get('token'), body.get('device'), body.get('public_key'), body.get('name', '')
        if not isinstance(token, str) or not TOKEN.fullmatch(token) or not isinstance(device, str) or not DEVICE.fullmatch(device) or not valid_key(key):
            abort(400)
        if not isinstance(name, str) or len(name) > 64 or any(ord(c) < 32 or ord(c) == 127 for c in name):
            abort(400)
        try:
            result = issuer_call(dict(operation='wireguard-enroll', token=token, device=device, name=name.strip(), public_key=key))
        except (OSError, ValueError, TypeError):
            abort(503)
        if not isinstance(result, dict):
            abort(503)
        if not result.get('ok'):
            error = result.get('error')
            if error in ('token_invalid', 'invalid_token', 'invalid_token_or_device', 'unauthorized', 'token_disabled', 'account_disabled'):
                abort(401)
            if error in ('device_conflict', 'public_key_conflict'):
                abort(409)
            if error in ('too_many_attempts', 'rate_limited'):
                abort(429)
            abort(503)
        try:
            profile = safe_profile(result, device, cfg.get('endpoint', '195.209.211.163:51820'))
        except (ValueError, TypeError, KeyError):
            abort(503)
        return jsonify(ok=True, profile=profile)

    return app
