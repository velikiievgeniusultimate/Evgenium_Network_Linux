"""Opt-in IKEv2 backend. Embedded in vpnctl releases; no import-time side effects."""
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
  default = -1
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
    cmd(["systemctl", "daemon-reload"])


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
        cmd(["resolvectl", "dns", iface, "1.1.1.1", "9.9.9.9"])
        cmd(["resolvectl", "domain", iface, "~."])
        cmd(["resolvectl", "flush-caches"], check=False)
        return
    write(backup, pathlib.Path("/etc/resolv.conf").read_text())
    # Keep the symlink itself intact (NetworkManager/systemd-resolved setups).
    pathlib.Path("/etc/resolv.conf").write_text("# Evgenium experimental VPN\nnameserver 1.1.1.1\nnameserver 9.9.9.9\noptions timeout:2 attempts:2\n")


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
    cmd(["systemctl", "start", UNIT])
    try:
        swan("--load-creds", "--file", ROOT / "connection.conf")
        swan("--load-conns", "--file", ROOT / "connection.conf")
        write(RUNTIME / "guard.nft", render_guard())
        cmd(["nft", "-c", "-f", RUNTIME / "guard.nft"])
        # All preparatory checks above are non-disruptive. The guard goes first.
        cmd(["systemctl", "enable", "--now", GUARD])
        if not active_guard():
            # Recover a stale active systemd unit whose table was externally removed.
            cmd(["nft", "-f", ROOT / "guard.nft"])
        if not active_guard():
            raise RuntimeError("Не удалось подтвердить установку kill switch.")
        save({**stored(), "phase": "connecting", "last_error": ""})
        swan("--initiate", "--child", "starfive-net", timeout=55)
        if not connected():
            raise RuntimeError("IPsec CHILD_SA не установлен.")
        set_dns()
        health = endpoint("/health")
        if health.get("service") != "evgenium-starfive":
            raise RuntimeError("Не подтверждён диагностический сервер StarFive.")
        save({**stored(), "phase": "connected", "since": int(time.time()), "last_error": ""})
        if stored().get("telemetry"):
            cmd(["systemctl", "start", MONITOR])
        print("StarFive подключён. Тестовый выход: Россия. IPv6 и DIRECT-исключения заблокированы.")
    except Exception as exc:
        cmd(["systemctl", "stop", MONITOR], check=False)
        cmd(["systemctl", "stop", UNIT], check=False)
        restore_dns()
        save({**stored(), "phase": "blocked", "last_error": "Подключение не установлено; интернет заблокирован до выключения режима."})
        raise RuntimeError("Подключение StarFive не удалось. Kill switch оставлен включённым. "
                           "Нажми переключатель ещё раз или выполни vpn experimental off. " + str(exc)) from exc


def off():
    cmd(["systemctl", "stop", MONITOR], check=False)
    cmd(["systemctl", "stop", UNIT], check=False)
    restore_dns()
    cmd(["systemctl", "disable", "--now", GUARD], check=False)
    cmd(["nft", "delete", "table", "inet", TABLE], check=False)
    save({**stored(), "phase": "off", "last_error": ""})
    print("Экспериментальное соединение выключено. Обычный интернет восстановлен.")


def telemetry(enabled):
    save({**stored(), "telemetry": bool(enabled)})
    cmd(["systemctl", "start" if enabled and connected() else "stop", MONITOR], check=False)
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
    domains = [domain_only(domain)] if domain else ["example.com", "www.wikipedia.org", "www.youtube.com"]
    probes = [probe_domain(x) for x in domains]
    body = {"schema": 1, "event": "site_report" if domain else "sample",
            "time": int(time.time()), "manager": "0.2.20", "platform": "linux",
            "probes": probes, "ipsec": "installed"}
    endpoint("/report", body)
    save({**stored(), "last_report": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()) + " UTC"})
    print(json.dumps({"sent": True, "probes": probes}, ensure_ascii=False))


def monitor():
    while stored().get("telemetry") and connected():
        try:
            report()
        except Exception:
            pass
        time.sleep(60)


def dispatch(api, settings, action, target=""):
    try:
        if action == "prepare": prepare()
        elif action == "import": import_profile(settings, target)
        elif action == "on": on(api, settings)
        elif action == "off": off()
        elif action == "telemetry-on": telemetry(True)
        elif action == "telemetry-off": telemetry(False)
        elif action == "report": report(target or None)
        elif action == "status": print(json.dumps(status(), ensure_ascii=False))
        else: raise ValueError("Неизвестная экспериментальная операция.")
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        raise api.VPNError(str(exc)) from exc
