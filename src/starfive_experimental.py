"""Opt-in IKEv2 backend. Embedded in vpnctl releases; no import-time side effects."""
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.request
import urllib.error
import http.client
import uuid
import fcntl

ROOT = pathlib.Path("/etc/vpn-manager/starfive")
STATE = pathlib.Path("/var/lib/vpn-manager/starfive.json")
RUNTIME = pathlib.Path("/run/evgenium-ikev2")
UNIT = "evgenium-ikev2.service"
MONITOR = "evgenium-ikev2-diagnostic.service"
GUARD = "evgenium-ikev2-guard.service"
TABLE = "evgenium_ikev2_guard"
URI = "unix:///run/evgenium-ikev2/charon.vici"
SERVER = "109.194.67.159"
HEALTH = "https://10.77.0.1:8443"
REQID = 77
DIRECT_PORT = 8443
DIRECT_MARK = 0xE771
DELIVERY = "evgenium-ikev2-delivery.service"


def failure_code(exc):
    text = str(exc).lower()
    if isinstance(exc, ssl.SSLCertVerificationError): return 'certificate'
    if isinstance(exc, ssl.SSLError): return 'tls'
    if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)): return 'timeout'
    if 'certificate' in text or 'authentication' in text: return 'authentication'
    if 'proposal' in text: return 'proposal'
    if 'retransmit' in text or 'timed out' in text: return 'timeout'
    if 'permission' in text or 'operation not permitted' in text: return 'permission'
    if isinstance(exc, OSError): return 'network'
    return 'other'


def queue_connection(stage, error, elapsed=0):
    if not stored().get('telemetry'): return
    directory = ROOT / 'outbox'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = sorted(directory.glob('*.json'), key=lambda p: p.stat().st_mtime)
    for old in files[:-9]: old.unlink(missing_ok=True)
    report_id = uuid.uuid4().hex
    body = {'schema':1, 'event':'connection_diagnostic', 'manager':'0.2.22',
            'time':int(time.time()),
            'report_id':report_id, 'stage':stage, 'error':error,
            'elapsed_ms':min(1800000, max(0, int(elapsed))),
            'guard':active_guard(), 'ipsec':connected()}
    try:
        # Send counts and fixed categories, never raw journal lines or addresses.
        journal=cmd(['journalctl','-u',UNIT,'--since','2 minutes ago','-n','80','--no-pager'],check=False,timeout=3).stdout.lower()
        body.update(ike_received=journal.count('received packet:'),
                    ike_sent=journal.count('sending packet:'),
                    retransmits=journal.count('retransmit'))
        if error == 'other':
            if 'authentication' in journal and 'failed' in journal: body['error']='authentication'
            elif 'no proposal' in journal: body['error']='proposal'
        os_release=pathlib.Path('/etc/os-release').read_text().lower()
        body['platform']='steamos' if 'steamos' in os_release else ('fedora' if 'fedora' in os_release else ('arch' if 'arch' in os_release else 'other'))
    except Exception: pass
    write(directory / (report_id + '.json'), json.dumps(body))
    patch_state({ 'delivery_status':'queued', 'delivery_error':''})
    kick_delivery()


def kick_delivery():
    if stored().get('telemetry'):
        cmd(['systemctl','start','--no-block',DELIVERY], check=False)


def direct_endpoint(body):
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (ROOT/"delivery.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        return _direct_endpoint(body)


def _direct_endpoint(body):
    # Only this root-owned socket can bypass the guard; never environment proxies.
    # The marked socket selects the physical route before IPsec source selection.
    sock = None
    connection = None
    stage = 'credentials'
    try:
        context = ssl.create_default_context(cafile=str(ROOT / 'ca.pem'))
        context.load_cert_chain(str(ROOT / 'client.pem'),str(ROOT / 'client-key.pem'))
        stage = 'route'
        rule=['priority','90','fwmark',str(DIRECT_MARK),'to',SERVER+'/32','lookup','main']
        # Clean up an exact stale rule left by process termination before adding it.
        cmd(['ip','rule','del',*rule],check=False)
        cmd(['ip','rule','add',*rule])
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stage = 'tcp'
        sock.settimeout(6)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, DIRECT_MARK)
        sock.connect((SERVER,DIRECT_PORT))
        stage = 'tls'
        tls = context.wrap_socket(sock,server_hostname=SERVER)
        connection = http.client.HTTPConnection(SERVER,DIRECT_PORT,timeout=6)
        connection.sock = tls
        stage = 'http'
        data = json.dumps(body,separators=(',',':')).encode()
        connection.request('POST','/report',body=data,
                           headers={'Content-Type':'application/json','Connection':'close'})
        response = connection.getresponse()
        reply = json.loads(response.read(4096))
        if response.status != 200 or reply.get('accepted') is not True:
            error=RuntimeError('Report rejected')
            error.delivery_code={403:'disabled',400:'invalid_report'}.get(response.status,'rejected')
            raise error
        if body.get('report_id') and reply.get('report_id') != body['report_id']:
            error=RuntimeError('Acknowledgement mismatch')
            error.delivery_code='ack_mismatch'
            raise error
        return reply
    except Exception as exc:
        patch_state({ 'delivery_status':'retry',
              'delivery_error':stage+'_'+getattr(exc,'delivery_code',failure_code(exc))})
        raise
    finally:
        if connection: connection.close()
        if sock: sock.close()
        # Remove our exact scoped rule, including on failed TCP/TLS handshakes.
        cmd(['ip','rule','del','priority','90','fwmark',str(DIRECT_MARK),
             'to',SERVER+'/32','lookup','main'],check=False)


def deliver_report(body):
    if not stored().get('telemetry'): return False
    patch_state({ 'delivery_status':'sending', 'delivery_attempt':int(time.time())})
    body={**body, 'previous_delivery_error':stored().get('delivery_error','')}
    direct_endpoint(body)
    patch_state({ 'delivery_status':'sent', 'delivery_error':'',
          'last_report':time.strftime('%Y-%m-%d %H:%M:%S UTC',time.gmtime())})
    return True


def delivery_worker():
    delay=15
    while stored().get('telemetry'):
        files=list((ROOT/'outbox').glob('*.json'))
        if not files and not PENDING_TEST.exists(): return
        try:
            for path in files:
                if deliver_report(json.loads(path.read_text())): path.unlink(missing_ok=True)
            flush_test_report()
            delay=15
        except Exception:
            time.sleep(delay)
            delay=min(delay*2,300)


def cmd(args, check=True, timeout=20, data=None):
    cp = subprocess.run([str(x) for x in args], input=data, text=True,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and cp.returncode:
        raise RuntimeError((cp.stderr or cp.stdout or "command failed")[-1200:])
    return cp


def write(path, data, mode=0o600):
    path = pathlib.Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    tmp.chmod(mode)
    tmp.replace(path)


def stored():
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


def save(state):
    write(STATE, json.dumps(state, ensure_ascii=False) + "\n")


def patch_state(changes):
    # Keep sender updates from overwriting a concurrent telemetry-off operation.
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (ROOT/'state.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        save({**stored(),**changes})


def active_guard():
    if not shutil.which("nft"):
        return False
    return cmd(["nft", "list", "table", "inet", TABLE], check=False).returncode == 0


def swan(*args, check=True, timeout=20):
    binary = shutil.which("swanctl") or "/usr/sbin/swanctl"
    return cmd([binary, *args, "--uri", URI], check=check, timeout=timeout)


def connected():
    if not RUNTIME.joinpath("charon.vici").exists():
        return False
    try:
        cp = swan("--list-sas", "--raw", check=False, timeout=3)
        return cp.returncode == 0 and "state=INSTALLED" in cp.stdout and "state=ESTABLISHED" in cp.stdout
    except (OSError, subprocess.TimeoutExpired):
        return False


def status():
    state = stored()
    guard = active_guard()
    live = connected()
    return {"configured": ROOT.joinpath("profile.json").exists(),
            "available": bool(shutil.which("swanctl")),
            "active": live, "guard": guard,
            "telemetry": bool(state.get("telemetry", False)),
            "phase": "connected" if live else ("blocked" if guard else "off"),
            "server": SERVER, "egress": "Россия — тестовый выход",
            "last_report": state.get("last_report", ""),
            "last_error": state.get("last_error", ""),
            "delivery": {"status":state.get('delivery_status','idle'),
                         "error":state.get('delivery_error',''),
                         "attempt":state.get('delivery_attempt',0),
                         "pending":len(list((ROOT/'outbox').glob('*.json'))) + int(PENDING_TEST.exists())},
            "test": test_status(),
            "profile_path": "~/Vpn/StarFive/profile.json"}


def validate_profile(p):
    if not isinstance(p, dict) or p.get("schema") != 1 or p.get("server") != SERVER:
        raise ValueError("Ожидается персональный профиль StarFive schema=1.")
    if not re.fullmatch(r"device-[a-f0-9]{24}", str(p.get("identity", ""))):
        raise ValueError("Некорректный идентификатор устройства.")
    for field, marker in (("ca", "CERTIFICATE"), ("certificate", "CERTIFICATE"),
                          ("private_key", "PRIVATE KEY")):
        s = p.get(field)
        if not isinstance(s, str) or len(s) > 32768 or ("-----BEGIN " + marker + "-----") not in s:
            raise ValueError("Некорректные данные сертификатов.")
    return p


def import_profile(settings, name):
    if active_guard():
        raise RuntimeError("Сначала выключи экспериментальное соединение.")
    path = pathlib.Path(name).expanduser()
    if name.startswith("~/"):
        path = pathlib.Path(settings["owner_home"]) / name[2:]
    import pwd
    uid = pwd.getpwnam(str(settings["owner_user"])).pw_uid
    # Never let a passwordless sudo action read a root secret or a special file.
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        import stat
        if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_size > 110000:
            raise RuntimeError("Профиль должен быть обычным файлом владельца клиента, не более 110 КБ.")
        p = validate_profile(json.loads(f.read(110001)))
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        stage = pathlib.Path(tmp)
        for key, filename in (("ca", "ca.pem"), ("certificate", "cert.pem"), ("private_key", "key.pem")):
            write(stage / filename, p[key])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(str(stage / "ca.pem"))
        ctx.load_cert_chain(str(stage / "cert.pem"), str(stage / "key.pem"))
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    write(ROOT / "profile.json", json.dumps(p))
    write(ROOT / "ca.pem", p["ca"])
    write(ROOT / "client.pem", p["certificate"])
    write(ROOT / "client-key.pem", p["private_key"])
    write(ROOT / "private" / "client-key.pem", p["private_key"])
    write(ROOT / "x509" / "client.pem", p["certificate"])
    write(ROOT / "x509ca" / "ca.pem", p["ca"])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(str(ROOT / "ca.pem"))
    context.load_cert_chain(str(ROOT / "client.pem"), str(ROOT / "client-key.pem"))
    save({"telemetry": True, "last_error": ""})
    print("Профиль установлен. Временная диагностика включена; её можно выключить здесь же.")


def prepare():
    if shutil.which("swanctl"):
        return
    if shutil.which("pacman"):
        cmd(["pacman", "-S", "--needed", "--noconfirm", "strongswan"], timeout=300)
    elif shutil.which("dnf"):
        cmd(["dnf", "install", "-y", "--setopt=install_weak_deps=False", "strongswan"], timeout=300)
    else:
        raise RuntimeError("Установи strongSwan с swanctl средствами своего дистрибутива.")
    print("strongSwan установлен; автоподключение не включено.")


def render_guard():
    return f"""table inet {TABLE} {{
 chain output {{
  type filter hook output priority -10; policy drop;
  oifname "lo" accept
  ip daddr {SERVER} udp dport {{ 500, 4500 }} accept
  meta skuid 0 meta mark {DIRECT_MARK} ip daddr {SERVER} tcp dport {DIRECT_PORT} accept
  meta nfproto ipv4 udp sport 68 udp dport 67 accept
  meta nfproto ipv4 ipsec out reqid {REQID} accept
 }}
 chain forward {{
  type filter hook forward priority -10; policy drop;
 }}
}}
"""


def render_connection(p):
    return f"""connections {{
 starfive {{
  version = 2
  remote_addrs = {SERVER}
  vips = 0.0.0.0
  proposals = aes256gcm16-prfsha384-ecp384,aes256-sha256-modp2048
  encap = yes
  fragmentation = yes
  mobike = yes
  dpd_delay = 30s
  local {{
   auth = eap-tls
   id = {p['identity']}
   eap_id = {p['identity']}
   certs = {ROOT}/client.pem
  }}
  remote {{
   auth = pubkey
   id = {SERVER}
   cacerts = {ROOT}/ca.pem
  }}
  children {{
   starfive-net {{
    local_ts = dynamic
    remote_ts = 0.0.0.0/0
    reqid = {REQID}
    esp_proposals = aes256gcm16,aes256-sha256
    dpd_action = clear
    start_action = none
   }}
  }}
 }}
}}
"""


def service_files():
    candidates = ["/usr/sbin/charon-systemd", "/usr/bin/charon-systemd", "/usr/lib/ipsec/charon-systemd", "/usr/libexec/ipsec/charon-systemd",
                  "/usr/lib/strongswan/charon-systemd", "/usr/libexec/strongswan/charon-systemd"]
    binary = next((x for x in candidates if pathlib.Path(x).is_file()), None)
    if not binary:
        raise RuntimeError("Не найден charon-systemd. Нужен пакет strongSwan с systemd backend.")
    configs = [str(p) for pattern in ("/etc/strongswan.d/charon/*.conf", "/etc/strongswan/strongswan.d/charon/*.conf")
               for p in pathlib.Path("/").glob(pattern.lstrip("/"))]
    includes = "\n".join("include " + x for x in configs)
    # DNS is managed transactionally by this backend, not by the resolve plugin.
    write(ROOT / "strongswan.conf", """charon {
 load_modular = yes
 install_routes = yes
 routing_table = 51822
 routing_table_prio = 100
 plugins {
""" + includes + f"""
  vici {{
   socket = {URI}
  }}
  resolve {{
   load = no
  }}
 }}
}}
charon-systemd {{
 journal {{
  default = 1
 }}
}}
""")
    write(pathlib.Path("/etc/systemd/system") / UNIT, f"""[Unit]
Description=Evgenium experimental StarFive IKEv2
After=network.target
[Service]
Type=notify
Environment=STRONGSWAN_CONF={ROOT}/strongswan.conf
ExecStart={binary}
RuntimeDirectory=evgenium-ikev2
RuntimeDirectoryMode=0700
Restart=no
TimeoutStartSec=20
""", 0o644)
    write(ROOT / "guard.nft", render_guard())
    write(pathlib.Path("/etc/systemd/system") / GUARD, f"""[Unit]
Description=Fail-closed guard for experimental IKEv2
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
After=local-fs.target nftables.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={shutil.which("nft")} -f {ROOT}/guard.nft
ExecStop=-{shutil.which("nft")} delete table inet {TABLE}
[Install]
WantedBy=multi-user.target
""", 0o644)
    write(pathlib.Path("/etc/systemd/system") / MONITOR, """[Unit]
Description=Temporary StarFive VPN diagnostics
After=evgenium-ikev2.service
[Service]
ExecStart=/usr/local/sbin/vpnctl internal-starfive-monitor
StandardOutput=null
StandardError=null
Restart=no
""", 0o644)
    install_delivery()


def install_delivery():
    write(pathlib.Path('/etc/systemd/system') / DELIVERY, """[Unit]
Description=Experimental direct mTLS diagnostic delivery
After=network.target
[Service]
ExecStart=/usr/local/sbin/vpnctl internal-starfive-delivery
StandardOutput=null
StandardError=null
Restart=on-failure
RestartSec=30
[Install]
WantedBy=multi-user.target
""", 0o644)
    cmd(["systemctl", "daemon-reload"])
    cmd(['systemctl','enable',DELIVERY],check=False)
    # Upgrade an already active experimental guard without opening ordinary traffic.
    if active_guard():
        rules=cmd(['nft','list','chain','inet',TABLE,'output'],check=False).stdout
        if str(DIRECT_MARK) not in rules and hex(DIRECT_MARK) not in rules:
            cmd(['nft','insert','rule','inet',TABLE,'output','meta','skuid','0',
                 'meta','mark',str(DIRECT_MARK),'ip','daddr',SERVER,'tcp','dport',str(DIRECT_PORT),'accept'])


def set_dns():
    resolved = ROOT / "resolved-backup.json"
    backup = ROOT / "resolv-backup"
    if backup.exists() or resolved.exists():
        raise RuntimeError("Есть незавершённое восстановление DNS. Сначала vpn experimental off.")
    if shutil.which("resolvectl") and cmd(["systemctl", "is-active", "systemd-resolved"], check=False).returncode == 0:
        route = json.loads(cmd(["ip", "-j", "route", "get", SERVER]).stdout)[0]
        iface = route["dev"]
        def previous(kind):
            text = cmd(["resolvectl", kind, iface]).stdout
            return text.split("):", 1)[1].strip().split() if "):" in text else []
        write(resolved, json.dumps({"iface": iface, "dns": previous("dns"), "domain": previous("domain")}))
        cmd(["resolvectl", "dns", iface, "77.88.8.8", "77.88.8.1"])
        cmd(["resolvectl", "domain", iface, "~."])
        cmd(["resolvectl", "flush-caches"], check=False)
        return
    write(backup, pathlib.Path("/etc/resolv.conf").read_text())
    # Keep the symlink itself intact (NetworkManager/systemd-resolved setups).
    pathlib.Path("/etc/resolv.conf").write_text("# Evgenium experimental VPN\nnameserver 77.88.8.8\nnameserver 77.88.8.1\noptions timeout:2 attempts:2\n")


def restore_dns():
    resolved = ROOT / "resolved-backup.json"
    if resolved.exists():
        data = json.loads(resolved.read_text())
        for key in ("dns", "domain"):
            cmd(["resolvectl", key, data["iface"], *(data[key] or [""])])
        cmd(["resolvectl", "flush-caches"], check=False)
        resolved.unlink()
    backup = ROOT / "resolv-backup"
    if backup.exists():
        pathlib.Path("/etc/resolv.conf").write_text(backup.read_text())
        backup.unlink()


def endpoint(path, payload=None):
    context = ssl.create_default_context(cafile=str(ROOT / "ca.pem"))
    context.load_cert_chain(str(ROOT / "client.pem"), str(ROOT / "client-key.pem"))
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(HEALTH + path, data=data, headers={"Content-Type": "application/json"})
    # Never consult environment proxy variables for a private diagnostic endpoint.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    with opener.open(req, timeout=8) as response:
        return json.loads(response.read(65536))


def on(api, settings):
    started=time.monotonic()
    stage='prepare'
    if api.service_active():
        raise RuntimeError("Сначала выключи обычный Xray VPN. Одновременно два режима не запускаются.")
    if active_guard():
        raise RuntimeError("Режим уже включён или заблокирован после сбоя. Выключи его перед повтором.")
    if not ROOT.joinpath("profile.json").exists():
        raise RuntimeError("Сначала импортируй персональный профиль StarFive.")
    if not shutil.which("swanctl"):
        raise RuntimeError("Сначала нажми «Подготовить IKEv2».")
    # Existing unrelated IPsec state must never be replaced.
    if cmd(["ip", "xfrm", "state"], check=False).stdout.strip():
        raise RuntimeError("Обнаружен другой IPsec VPN. Сначала отключи его.")
    p = validate_profile(json.loads((ROOT / "profile.json").read_text()))
    service_files()
    write(ROOT / "connection.conf", render_connection(p))
    try:
        stage='daemon'
        cmd(["systemctl", "start", UNIT])
        stage='credentials'
        swan("--load-creds", "--file", ROOT / "connection.conf")
        swan("--load-conns", "--file", ROOT / "connection.conf")
        stage='guard'
        write(RUNTIME / "guard.nft", render_guard())
        cmd(["nft", "-c", "-f", RUNTIME / "guard.nft"])
        # All preparatory checks above are non-disruptive. The guard goes first.
        cmd(["systemctl", "enable", "--now", GUARD])
        if not active_guard():
            # Recover a stale active systemd unit whose table was externally removed.
            cmd(["nft", "-f", ROOT / "guard.nft"])
        if not active_guard():
            raise RuntimeError("Не удалось подтвердить установку kill switch.")
        patch_state({ "phase": "connecting", "last_error": ""})
        stage='handshake'
        swan("--initiate", "--child", "starfive-net", timeout=55)
        if not connected():
            raise RuntimeError("IPsec CHILD_SA не установлен.")
        stage='dns'
        set_dns()
        stage='health'
        health = endpoint("/health")
        if health.get("service") != "evgenium-starfive":
            raise RuntimeError("Не подтверждён диагностический сервер StarFive.")
        patch_state({ "phase": "connected", "since": int(time.time()), "last_error": ""})
        if stored().get("telemetry"):
            cmd(["systemctl", "start", MONITOR])
        try: queue_connection('connected','none',(time.monotonic()-started)*1000)
        except Exception: pass
        print("StarFive подключён. Тестовый выход: Россия. IPv6 и DIRECT-исключения заблокированы.")
    except Exception as exc:
        cmd(["systemctl", "stop", MONITOR], check=False)
        cmd(["systemctl", "stop", UNIT], check=False)
        restore_dns()
        patch_state({ "phase": "blocked", "last_error": "Подключение не установлено; интернет заблокирован до выключения режима."})
        try: queue_connection(stage,failure_code(exc),(time.monotonic()-started)*1000)
        except Exception: pass
        error=RuntimeError("Подключение StarFive не удалось. Kill switch оставлен включённым. "
                           "Нажми переключатель ещё раз или выполни vpn experimental off. " + str(exc))
        error.diagnostic_queued=True
        raise error from exc


def off():
    cmd(["systemctl", "stop", TEST_UNIT], check=False)
    cmd(["systemctl", "stop", MONITOR], check=False)
    cmd(["systemctl", "stop", UNIT], check=False)
    restore_dns()
    cmd(["systemctl", "disable", "--now", GUARD], check=False)
    cmd(["nft", "delete", "table", "inet", TABLE], check=False)
    patch_state({ "phase": "off", "last_error": ""})
    print("Экспериментальное соединение выключено. Обычный интернет восстановлен.")


def telemetry(enabled):
    patch_state({ "telemetry": bool(enabled)})
    if not enabled:
        cmd(['systemctl','stop',DELIVERY],check=False)
        cmd(["systemctl", "stop", TEST_UNIT], check=False)
    cmd(["systemctl", "start" if enabled and connected() else "stop", MONITOR], check=False)
    if enabled: kick_delivery()
    print("Временная диагностика " + ("включена" if enabled else "выключена"))


def domain_only(value):
    # Explicit domain-only report. Never accept URLs, paths, tokens or arbitrary log text.
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value) or "." not in value:
        raise ValueError("Введи домен без https://, пути и параметров.")
    for label in value.split("."):
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValueError("Некорректный домен.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("Нужен домен сайта, а не IP-адрес.")


def probe_domain(domain):
    domain = domain_only(domain)
    start = time.monotonic()
    try:
        resolved = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        addresses = list(dict.fromkeys(x[4][0] for x in resolved
                                       if ipaddress.ip_address(x[4][0]).is_global))[:3]
        for address in addresses:
            try:
                with socket.create_connection((address, 443), timeout=4) as sock:
                    with ssl.create_default_context().wrap_socket(sock, server_hostname=domain) as conn:
                        conn.sendall(("HEAD / HTTP/1.1\r\nHost: " + domain + "\r\nConnection: close\r\n\r\n").encode())
                        line = conn.recv(256).split(b"\r\n", 1)[0]
                        parts = line.split()
                        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                        if code:
                            return {"domain": domain, "ok": True, "http_status": code,
                                    "latency_ms": round((time.monotonic()-start)*1000)}
            except (OSError, ssl.SSLError):
                continue
    except OSError:
        pass
    return {"domain": domain, "ok": False, "error": "dns_tcp_or_tls_failed",
            "latency_ms": round((time.monotonic()-start)*1000)}


def report(domain=None):
    if not stored().get("telemetry"):
        raise RuntimeError("Диагностика выключена. Включи её явно перед отправкой.")
    if not connected():
        raise RuntimeError("Отчёт отправляется только внутри установленного StarFive VPN.")
    domains = [domain_only(domain)] if domain else list(RU_DOMAINS)
    probes = [probe_domain(x) for x in domains]
    body = {"schema": 1, "event": "site_report" if domain else "sample",
            "time": int(time.time()), "manager": "0.2.22", "platform": "linux",
            "probes": probes, "ipsec": "installed"}
    endpoint("/report", body)
    patch_state({ "last_report": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + " UTC"})
    print(json.dumps({"sent": True, "probes": probes}, ensure_ascii=False))


def monitor():
    while stored().get("telemetry") and connected():
        try:
            flush_test_report()
            report()
        except Exception:
            pass
        time.sleep(60)
    if stored().get('telemetry') and active_guard():
        try: queue_connection('disconnected','network')
        except Exception: pass


def dispatch(api, settings, action, target=""):
    try:
        if action == "global-test": start_global_test()
        elif action == "cancel-test": cmd(["systemctl", "stop", TEST_UNIT],check=False)
        elif action == "prepare": prepare()
        elif action == "import": import_profile(settings, target)
        elif action == "on": on(api, settings)
        elif action == "off": off()
        elif action == "telemetry-on": telemetry(True)
        elif action == "telemetry-off": telemetry(False)
        elif action == "report": report(target or None)
        elif action == "send-diagnostics":
            if not ROOT.joinpath('profile.json').exists(): raise RuntimeError('Сначала импортируй профиль.')
            install_delivery()
            queue_connection('manual','none')
            print('Диагностика сохранена. Прямая отправка выполняется в фоне.')
        elif action == "status": print(json.dumps(status(), ensure_ascii=False))
        else: raise ValueError("Неизвестная экспериментальная операция.")
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        if action == 'on' and not getattr(exc,'diagnostic_queued',False):
            try:
                install_delivery()
                queue_connection('prepare',failure_code(exc))
            except Exception: pass
        raise api.VPNError(str(exc)) from exc


TEST_UNIT = 'evgenium-ikev2-global-test.service'
TEST_STATE = pathlib.Path('/var/lib/vpn-manager/starfive-test.json')
PENDING_TEST = ROOT / 'pending-global-test.json'
RU_DOMAINS = ('yandex.ru', 'mail.ru', 'www.rt.ru')
TEST_BLOCK = hashlib.shake_256(b'evgenium-starfive-integrity-v1').digest(65536)


def test_status():
    try:
        state=json.loads(TEST_STATE.read_text())
    except (OSError,ValueError):
        return {'phase':'idle','progress':0}
    if state.get('phase')=='running' and cmd(['systemctl','is-active',TEST_UNIT],check=False).returncode:
        state.update(phase='interrupted',message='Тест прерван. Защита VPN сохраняется.')
    return state


def test_state(**fields):
    try: state=json.loads(TEST_STATE.read_text())
    except (OSError,ValueError): state={}
    write(TEST_STATE,json.dumps({**state,**fields},ensure_ascii=False))


def test_request(path, data=None, headers=None, timeout=30):
    context=ssl.create_default_context(cafile=str(ROOT/'ca.pem'))
    context.load_cert_chain(str(ROOT/'client.pem'),str(ROOT/'client-key.pem'))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
    request=urllib.request.Request(HEALTH+path,data=data,headers=headers or {})
    return opener.open(request,timeout=timeout)


def expected_hash(size, offset=0):
    digest=hashlib.sha256()
    while size:
        part=TEST_BLOCK[offset % len(TEST_BLOCK):][:min(size,len(TEST_BLOCK)-offset % len(TEST_BLOCK))]
        digest.update(part); size-=len(part); offset+=len(part)
    return digest.hexdigest()


def transfer_download(size, offset=0, limit=None):
    start=time.monotonic(); received=0; digest=hashlib.sha256()
    headers={'Range':f'bytes={offset}-'} if offset else {}
    with test_request('/blob?size='+str(size),headers=headers) as response:
        if response.status != (206 if offset else 200): raise RuntimeError('Unexpected file response')
        if offset and response.headers.get('Content-Range')!=f'bytes {offset}-{size-1}/{size}':
            raise RuntimeError('Invalid resume range')
        total=size-offset if limit is None else min(limit,size-offset)
        while received<total:
            block=response.read(min(65536,total-received))
            if not block: break
            digest.update(block); received+=len(block)
        integrity=received==total and digest.hexdigest()==expected_hash(total,offset)
        if limit is None:
            integrity=integrity and response.headers.get('X-Content-SHA256')==digest.hexdigest()
    elapsed=max(time.monotonic()-start,0.001)
    return {'kind':'download','ok':integrity,'integrity':integrity,'bytes':received,
            'size':size,'offset':offset,'elapsed_ms':round(elapsed*1000),
            'mbps_milli':round(received*8/elapsed/1000)}


def transfer_upload(size):
    data=(TEST_BLOCK*((size+len(TEST_BLOCK)-1)//len(TEST_BLOCK)))[:size]
    start=time.monotonic()
    with test_request('/upload',data=data,headers={'Content-Type':'application/octet-stream'}) as response:
        reply=json.loads(response.read(4096))
    elapsed=max(time.monotonic()-start,0.001)
    integrity=reply.get('received_bytes')==size and reply.get('sha256')==hashlib.sha256(data).hexdigest()
    return {'kind':'upload','ok':integrity,'integrity':integrity,'bytes':size,
            'elapsed_ms':round(elapsed*1000),'mbps_milli':round(size*8/elapsed/1000)}


def ping_test(size=56, count=20):
    cp=cmd(['ping','-n','-M','do','-s',str(size),'-c',str(count),'-i','0.2','-W','2','10.77.0.1'],check=False,timeout=45)
    packets=re.search(r'(\d+) packets transmitted, (\d+) received',cp.stdout)
    sent,received=(int(x) for x in packets.groups()) if packets else (count,0)
    row={'kind':'ping','ok':received==sent,'sent':sent,'received':received,
         'loss_milli':round((sent-received)*100000/max(sent,1)),'size':size}
    rtt=re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms',cp.stdout)
    if rtt:
        row.update({key:round(float(value)*1000) for key,value in zip(
            ('rtt_min_us','rtt_avg_us','rtt_max_us','rtt_mdev_us'),rtt.groups())})
    return row


def transport_counters():
    result={'kind':'counters','ok':True}
    try:
        raw=swan('--list-sas','--raw').stdout
        for source,target in (('bytes-in','bytes_in'),('bytes-out','bytes_out'),('packets-in','packets_in'),('packets-out','packets_out')):
            result[target]=sum(int(x) for x in re.findall(r'\b'+source+r'=(\d+)',raw))
        lines=pathlib.Path('/proc/net/snmp').read_text().splitlines()
        for first,second in zip(lines,lines[1:]):
            if first.startswith('Tcp:') and second.startswith('Tcp:'):
                values=dict(zip(first.split()[1:],second.split()[1:]))
                if 'RetransSegs' in values:
                    result['retrans_segments']=int(values['RetransSegs'])
                    result['out_segments']=int(values['OutSegs'])
        result['xfrm_errors']=sum(int(x.split()[1]) for x in pathlib.Path('/proc/net/xfrm_stat').read_text().splitlines())
    except (OSError,ValueError,RuntimeError): result['ok']=False
    return result


def flush_test_report():
    if not stored().get('telemetry') or not PENDING_TEST.exists(): return False
    body=json.loads(PENDING_TEST.read_text())
    if not deliver_report(body): return False
    PENDING_TEST.unlink(missing_ok=True)
    test_state(sent=True,message='Тест завершён. Отчёт доставлен на StarFive.')
    return True


def start_global_test():
    if cmd(['systemctl','is-active',TEST_UNIT],check=False).returncode==0:
        raise RuntimeError('Глобальный тест уже выполняется.')
    if not stored().get('telemetry'): raise RuntimeError('Включи временную диагностику для отправки результатов.')
    if not connected() or not active_guard(): raise RuntimeError('Сначала подключись к StarFive.')
    if endpoint('/health').get('test_api')!=1: raise RuntimeError('Сначала обновить тестовый сервис StarFive.')
    if PENDING_TEST.exists() and not flush_test_report(): raise RuntimeError('Ожидает отправки предыдущий отчёт.')
    unit='''[Unit]
Description=Evgenium global VPN stability test
After=evgenium-ikev2.service
[Service]
Type=exec
ExecStart=/usr/local/sbin/vpnctl internal-starfive-global-test
StandardOutput=null
StandardError=null
TimeoutStopSec=12
RuntimeMaxSec=900
Restart=no
'''
    write(pathlib.Path('/etc/systemd/system')/TEST_UNIT,unit,0o644)
    cmd(['systemctl','daemon-reload'])
    test_state(phase='running',progress=0,sent=False,passed=0,failed=0,duration_s=0,message='Запуск теста',run=os.urandom(12).hex(),started=int(time.time()))
    try: cmd(['systemctl','start',TEST_UNIT])
    except Exception:
        test_state(phase='failed',message='Не удалось запустить тест.'); raise
    print('Глобальный тест запущен в фоне. Интернет несколько раз прервётся; kill switch остаётся включённым.')


class TestCancelled(Exception): pass


def run_global_test():
    import signal
    from concurrent.futures import ThreadPoolExecutor
    def cancel(*_): raise TestCancelled()
    old=signal.signal(signal.SIGTERM,cancel)
    records=[]; outcome='completed'; started=time.monotonic()
    def stage(progress,message): test_state(phase='running',progress=progress,message=message)
    def measure(kind,operation,**fields):
        before=time.monotonic()
        try: row=operation()
        except TestCancelled: raise
        except Exception as exc:
            error='other'
            if isinstance(exc,urllib.error.HTTPError): error='http'
            elif isinstance(exc,(TimeoutError,subprocess.TimeoutExpired)): error='timeout'
            elif isinstance(exc,ssl.SSLError): error='tls'
            elif isinstance(exc,OSError): error='network'
            row={'kind':kind,'ok':False,'error':error}
            if isinstance(exc,urllib.error.HTTPError): row['http_status']=exc.code
        row.setdefault('elapsed_ms',round((time.monotonic()-before)*1000))
        row['at_ms']=round((time.monotonic()-started)*1000)
        row.update(fields); records.append(row); return row
    def reconnect(restart=False):
        before=time.monotonic()
        if restart:
            candidates=socket.getaddrinfo('yandex.ru',443,socket.AF_INET,socket.SOCK_STREAM)
            address=next(x[4][0] for x in candidates if ipaddress.ip_address(x[4][0]).is_global)
            cmd(['systemctl','stop',UNIT])
            leaked=False
            try:
                with socket.create_connection((address,443),timeout=2): leaked=True
            except OSError: pass
            records.append({'kind':'guard','ok':active_guard() and not leaked})
            # Never remove the guard, even during a deliberate daemon failure.
            if not active_guard(): raise RuntimeError('Guard missing')
            cmd(['systemctl','start',UNIT])
            swan('--load-creds','--file',ROOT/'connection.conf')
            swan('--load-conns','--file',ROOT/'connection.conf')
        else:
            swan('--terminate','--ike','starfive',check=False)
        swan('--initiate','--child','starfive-net',timeout=55)
        good=connected() and endpoint('/health').get('service')=='evgenium-starfive'
        return {'kind':'daemon_restart' if restart else 'reconnect','ok':good,'elapsed_ms':round((time.monotonic()-before)*1000)}
    def control():
        with test_request('/control',timeout=45) as response: data=json.loads(response.read(16384))
        records.append({'kind':'server_control','ok':True,**data['metrics']})
        for probe in data['probes']: records.append({'kind':'server_control',**probe})
        return {'kind':'health','ok':True}
    try:
        cmd(['systemctl','stop',MONITOR],check=False)
        # Use Russian DNS for this test even on a session created by an older client.
        if not (ROOT/'resolv-backup').exists() and not (ROOT/'resolved-backup.json').exists(): set_dns()
        elif (ROOT/'resolved-backup.json').exists():
            interface=json.loads((ROOT/'resolved-backup.json').read_text())['iface']
            cmd(['resolvectl','dns',interface,'77.88.8.8','77.88.8.1'])
        else:
            pathlib.Path('/etc/resolv.conf').write_text('nameserver 77.88.8.8\nnameserver 77.88.8.1\noptions timeout:2 attempts:2\n')
        stage(3,'Контрольные замеры StarFive и российских сервисов')
        measure('health',control); records.append(transport_counters())
        for domain in RU_DOMAINS: measure('ru_probe',lambda d=domain:{'kind':'ru_probe',**probe_domain(d)})
        stage(12,'Задержки, потери и размеры пакетов')
        for size in (56,1200,1360): measure('ping',lambda s=size:ping_test(s))
        for attempt in range(12):
            before=time.monotonic()
            measure('health',lambda:{'kind':'health','ok':endpoint('/health').get('service')=='evgenium-starfive'})
            time.sleep(0.25)
        stage(25,'Скачивание и отправка файлов: проверка SHA-256')
        for size in (65536,1048576,8388608,33554432): measure('download',lambda s=size:transfer_download(s))
        for size in (524288,4194304): measure('upload',lambda s=size:transfer_upload(s))
        stage(40,'Докачка файла после разрыва и переподключения')
        measure('resume',lambda:{**transfer_download(8388608,limit=3145728),'kind':'resume'})
        measure('reconnect',reconnect)
        measure('resume',lambda:{**transfer_download(8388608,offset=3145728),'kind':'resume'})
        stage(50,'Параллельная передача в обе стороны')
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures=[pool.submit(transfer_download,8388608),pool.submit(transfer_download,8388608),pool.submit(transfer_upload,4194304)]
            for future in futures: measure('parallel',lambda f=future:{**f.result(),'kind':'parallel'})
        stage(62,'Длительная передача: до 60 секунд / 64 МиБ')
        load_started=time.monotonic(); until=load_started+60; count=0
        while time.monotonic()<until and count<16:
            measure('download',lambda:transfer_download(4194304)); count+=1
            measure('health',lambda:{'kind':'health','ok':endpoint('/health').get('service')=='evgenium-starfive'})
            time.sleep(max(0,load_started+count*4-time.monotonic()))
        stage(75,'Простой 45 секунд и восстановление активности')
        time.sleep(45)
        measure('idle',lambda:{'kind':'idle','ok':endpoint('/health').get('service')=='evgenium-starfive','elapsed_ms':45000})
        stage(82,'Пять повторных подключений')
        for attempt in range(5):
            measure('reconnect',reconnect,attempt=attempt+1); time.sleep(1)
        stage(92,'Перезапуск VPN-демона с сохранением kill switch')
        measure('daemon_restart',lambda:reconnect(True))
        records.append({'kind':'guard','ok':active_guard()})
        stage(96,'Заключительные замеры и отправка отчёта')
        for domain in RU_DOMAINS: measure('ru_probe',lambda d=domain:{'kind':'ru_probe',**probe_domain(d)})
        measure('health',control); records.append(transport_counters())
        if any(not x.get('ok') for x in records): outcome='failed'
    except TestCancelled: outcome='cancelled'
    except Exception: outcome='failed'
    finally:
        # Recover only our daemon/session. Never disable the guard or restore direct traffic.
        if outcome!='cancelled' and not connected():
            try: measure('daemon_restart',lambda:reconnect(True))
            except Exception: pass
        body={'schema':1,'event':'global_test','manager':'0.2.22','run':test_status().get('run',os.urandom(12).hex()),'outcome':outcome,'duration_ms':round((time.monotonic()-started)*1000),'records':records[:256]}
        write(PENDING_TEST,json.dumps(body))
        test_state(phase=outcome,progress=100,sent=False,duration_s=round(time.monotonic()-started),
                   passed=sum(bool(x.get('ok')) for x in records),failed=sum(not x.get('ok') for x in records),
                   message='Отчёт сохранён. Ожидает отправки через StarFive.')
        try: flush_test_report()
        except Exception: kick_delivery()
        if connected() and stored().get('telemetry'):
            cmd(['systemctl','start',MONITOR],check=False)
        signal.signal(signal.SIGTERM,old)
