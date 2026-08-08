#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import pwd
import pathlib
import random
import struct
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from typing import NoReturn

MANAGER_VERSION = "0.2.2"

# Не "latest". Это намеренно совместимый pin.
# Его меняет следующая проверенная версия VPN Manager.
SAFE_XRAY_VERSION = "26.6.27"

SETTINGS = pathlib.Path("/etc/vpn-manager/settings.json")
STATE = pathlib.Path("/var/lib/vpn-manager/state.json")
RUNTIME_DIR = pathlib.Path("/run/vpn-manager")
RUNTIME_CONFIG = RUNTIME_DIR / "config.json"

XRAY = pathlib.Path("/opt/vpn-manager/bin/xray")
XRAY_PREVIOUS = pathlib.Path("/opt/vpn-manager/bin/xray.previous")
SERVICE = "vpn-xray.service"
TUN_NAME = "xraytun"
NFT_TABLE = "vpn_guard"

RELEASES = pathlib.Path("/opt/vpn-manager/releases")
CURRENT = pathlib.Path("/opt/vpn-manager/current")
PREVIOUS = pathlib.Path("/opt/vpn-manager/previous")

MAX_PROFILE_BYTES = 5 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 150 * 1024 * 1024

DNS_DISCOVERY_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
DNS_SNAPSHOT_BEGIN = "# EVGENIUM-DNS-BEGIN "
DNS_SNAPSHOT_END = "# EVGENIUM-DNS-END "

XRAY_RELEASE_API = (
    "https://api.github.com/repos/XTLS/Xray-core/releases/tags/v"
    + SAFE_XRAY_VERSION
)

SERVICE_TEXT = r"""[Unit]
Description=Evgenius VPN Manager - Xray core
Wants=network-online.target
After=network-online.target
ConditionPathExists=/run/vpn-manager/config.json

[Service]
Type=simple
User=vpn-xray
Group=vpn-xray
ExecStart=/opt/vpn-manager/bin/xray run -config /run/vpn-manager/config.json
Restart=on-failure
RestartSec=2

AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=/var/lib/vpn-manager /run/vpn-manager
DeviceAllow=/dev/net/tun rw
UMask=0077

[Install]
WantedBy=multi-user.target
"""

WRAPPER_TEXT = r"""#!/usr/bin/env bash
set -e
exec /usr/bin/sudo -n /usr/local/sbin/vpnctl "$@"
"""

class VPNError(RuntimeError):
    pass

def color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def info(msg: str) -> None:
    print(color("==>", "1;36"), msg)

def ok(msg: str) -> None:
    print(color("✓", "1;32"), msg)

def warn(msg: str) -> None:
    print(color("!", "1;33"), msg, file=sys.stderr)

def fail(msg: str) -> NoReturn:
    raise VPNError(msg)

def run(args, *, check=True, capture=False, input_text=None, timeout=None, user=None):
    cmd = [str(x) for x in args]
    if user:
        cmd = ["/usr/bin/runuser", "-u", user, "--"] + cmd
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        input=input_text,
        timeout=timeout,
    )

def ensure_root() -> None:
    if os.geteuid() != 0:
        fail("vpnctl должен запускаться через команду vpn.")

def load_settings() -> dict:
    try:
        data = json.loads(SETTINGS.read_text())
    except Exception as exc:
        fail(f"Не могу прочитать {SETTINGS}: {exc}")
    required = (
        "owner_user", "owner_home", "config_dir", "direct_sites",
        "direct_networks", "xray_uid", "xray_gid",
    )
    for key in required:
        if key not in data:
            fail(f"settings.json не содержит {key}")
    return data

def save_settings(data: dict) -> None:
    tmp = SETTINGS.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, SETTINGS)

def load_state() -> dict:
    if not STATE.exists():
        return {"active": None}
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {"active": None}

def save_state(data: dict) -> None:
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE)

def ensure_runtime(settings: dict) -> None:
    RUNTIME_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(RUNTIME_DIR, 0, int(settings["xray_gid"]))
    os.chmod(RUNTIME_DIR, 0o750)

def http_get(url: str, max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        fail("Разрешены только HTTPS URL.")
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"EvgeniusVPNManager/{MANAGER_VERSION}",
            "Accept": "application/vnd.github+json, application/json, text/plain, */*",
        },
    )
    ctx = ssl.create_default_context()
    try:
        r = urllib.request.urlopen(req, timeout=40, context=ctx)
    except Exception as exc:
        fail(f"HTTPS download failed: {exc}")
    with r:
        out = bytearray()
        while True:
            chunk = r.read(65536)
            if not chunk:
                break
            out += chunk
            if len(out) > max_bytes:
                fail(f"Загрузка превысила лимит {max_bytes} bytes.")
        return bytes(out)

def list_config_paths(settings: dict) -> list[pathlib.Path]:
    d = pathlib.Path(settings["config_dir"])
    d.mkdir(parents=True, exist_ok=True)
    return sorted(
        [
            p for p in d.iterdir()
            if p.is_file() and not p.is_symlink() and not p.name.startswith(".")
        ],
        key=lambda p: p.name.lower(),
    )

def choose_config(settings: dict, requested: str | None) -> pathlib.Path:
    paths = list_config_paths(settings)
    if not paths:
        fail(f"В {settings['config_dir']} нет конфигов.")

    if requested:
        for p in paths:
            if p.name == requested or p.stem == requested:
                return p
        fail(f"Конфиг '{requested}' не найден. Используй: vpn list")

    if not sys.stdin.isatty():
        fail("Не указан конфиг: vpn on <имя>")

    print("Доступные VPN-конфиги:")
    for i, p in enumerate(paths, 1):
        print(f"  {i}) {p.name}")
    while True:
        raw = input("> ").strip()
        try:
            n = int(raw)
            if 1 <= n <= len(paths):
                return paths[n - 1]
        except ValueError:
            pass
        print("Введи номер из списка.")

def q1(q: dict[str, list[str]], *names: str, default=""):
    for name in names:
        vals = q.get(name)
        if vals:
            return vals[0]
    return default

def truthy(v: str) -> bool:
    return str(v).lower() in {"1", "true", "yes", "on"}

def resolve_server(host: str) -> str:
    # Резолвим ДО поднятия TUN, чтобы адрес VPN-сервера не зависел
    # от DNS уже внутри VPN.
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        fail(f"Не могу разрешить адрес VPN-сервера {host}: {exc}")
    v4, v6 = [], []
    for fam, _, _, _, sa in infos:
        if fam == socket.AF_INET:
            v4.append(sa[0])
        elif fam == socket.AF_INET6:
            v6.append(sa[0])
    if v4:
        return v4[0]
    if v6:
        return v6[0]
    fail(f"DNS не вернул IP для {host}")

def parse_xhttp_extra(raw: str):
    if not raw:
        return None
    try:
        obj = json.loads(urllib.parse.unquote(raw))
    except Exception as exc:
        fail(f"Некорректный XHTTP extra JSON: {exc}")
    if not isinstance(obj, dict):
        fail("XHTTP extra должен быть JSON-объектом.")
    return obj

def parse_vless_url(url: str, fallback_name: str) -> dict:
    try:
        u = urllib.parse.urlsplit(url.strip())
    except Exception as exc:
        fail(f"Некорректный VLESS URL: {exc}")
    if u.scheme.lower() != "vless":
        fail("Ожидался vless:// URL.")
    if not u.username or not u.hostname or u.port is None:
        fail("В VLESS URL отсутствует UUID/server/port.")

    q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
    security = q1(q, "security", default="").lower()
    transport = q1(q, "type", "network", default="tcp").lower()
    if transport == "tcp":
        transport = "raw"

    server_host = u.hostname
    server_ip = resolve_server(server_host)

    settings = {
        "address": server_ip,
        "port": int(u.port),
        "id": urllib.parse.unquote(u.username),
        "encryption": q1(q, "encryption", default="none") or "none",
    }
    flow = q1(q, "flow")
    if flow:
        settings["flow"] = flow

    stream: dict = {
        "network": transport,
        "security": security if security in {"reality", "tls"} else "none",
    }

    sni = q1(q, "sni", "servername")
    fp = q1(q, "fp", "fingerprint", default="chrome") or "chrome"
    alpn = q1(q, "alpn")

    if security == "reality":
        pbk = q1(q, "pbk", "publicKey", "password")
        sid = q1(q, "sid", "shortId")
        spx = urllib.parse.unquote(q1(q, "spx", "spiderX", default=""))
        if not pbk:
            fail("REALITY link не содержит pbk/publicKey.")
        reality = {
            "serverName": sni,
            "fingerprint": fp,
            # 26.6.27 принимает publicKey; в новых версиях это alias password.
            "publicKey": pbk,
            "shortId": sid,
            "spiderX": spx,
        }
        pqv = q1(q, "pqv", "mldsa65Verify")
        if pqv:
            reality["mldsa65Verify"] = pqv
        stream["realitySettings"] = reality
    elif security == "tls":
        tls = {
            "serverName": sni or server_host,
            "fingerprint": fp,
            "allowInsecure": truthy(q1(q, "allowInsecure", default="false")),
        }
        if alpn:
            tls["alpn"] = [x for x in re.split(r"[,|]", alpn) if x]
        stream["tlsSettings"] = tls

    path = urllib.parse.unquote(q1(q, "path", default=""))
    host = q1(q, "host", default="")
    mode = q1(q, "mode", default="")
    extra_raw = q1(q, "extra", default="")

    if transport == "xhttp":
        xh = {}
        if path:
            xh["path"] = path
        if host:
            xh["host"] = host
        if mode:
            xh["mode"] = mode
        extra = parse_xhttp_extra(extra_raw)
        if extra is not None:
            xh["extra"] = extra
        stream["xhttpSettings"] = xh

    elif transport == "grpc":
        grpc = {}
        service = urllib.parse.unquote(q1(q, "serviceName", "service-name", default=""))
        authority = q1(q, "authority", default="")
        if service:
            grpc["serviceName"] = service
        if authority:
            grpc["authority"] = authority
        stream["grpcSettings"] = grpc

    elif transport == "websocket" or transport == "ws":
        stream["network"] = "websocket"
        ws = {}
        if path:
            ws["path"] = path
        if host:
            ws["headers"] = {"Host": host}
        stream["wsSettings"] = ws

    elif transport == "httpupgrade":
        hu = {}
        if path:
            hu["path"] = path
        if host:
            hu["host"] = host
        stream["httpupgradeSettings"] = hu

    elif transport == "raw":
        # Не добавляем лишних rawSettings: defaults надёжнее.
        pass
    else:
        fail(f"Этот manager пока не поддерживает VLESS transport '{transport}'.")

    return {
        "name": urllib.parse.unquote(u.fragment) if u.fragment else fallback_name,
        "server_host": server_host,
        "server_ip": server_ip,
        "outbound": {
            "tag": "proxy",
            "protocol": "vless",
            "settings": settings,
            "streamSettings": stream,
        },
    }

def maybe_decode_subscription(text: str) -> str:
    compact = "".join(text.split())
    if not compact:
        return text
    if compact.startswith("vless://") or compact.startswith("https://"):
        return text
    # Многие subscription endpoints возвращают base64 без заголовка.
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        pad = "=" * (-len(compact) % 4)
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                raw = decoder((compact + pad).encode())
                decoded = raw.decode("utf-8-sig")
                if "vless://" in decoded:
                    return decoded
            except Exception:
                pass
    return text

def parse_profile_bytes(raw: bytes, fallback_name: str) -> list[dict]:
    if len(raw) > MAX_PROFILE_BYTES:
        fail("Конфиг слишком большой.")
    try:
        text = raw.decode("utf-8-sig").strip()
    except UnicodeDecodeError:
        fail("Конфиг должен быть текстовым UTF-8.")
    if not text:
        fail("Пустой конфиг.")

    text = maybe_decode_subscription(text)
    lines = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    if len(lines) == 1 and lines[0].lower().startswith("https://"):
        info("Загружаю HTTPS subscription до поднятия TUN...")
        remote = http_get(lines[0], MAX_PROFILE_BYTES)
        return parse_profile_bytes(remote, fallback_name)

    vless = [line for line in lines if line.lower().startswith("vless://")]
    if not vless:
        fail(
            "В конфиге не найден vless:// link. "
            "В 0.2.0 поддерживаются VLESS share links и HTTPS subscriptions."
        )
    return [
        parse_vless_url(link, f"{fallback_name}-{i}")
        for i, link in enumerate(vless, 1)
    ]

def load_profile(path: pathlib.Path) -> list[dict]:
    if path.stat().st_size > MAX_PROFILE_BYTES:
        fail("Конфиг слишком большой.")
    return parse_profile_bytes(path.read_bytes(), path.stem)

def read_direct_sites(settings: dict) -> list[tuple[str, str]]:
    p = pathlib.Path(settings["direct_sites"])
    if not p.exists():
        return []
    out = []
    for raw in p.read_text(errors="strict").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        exact = s.startswith("=")
        if exact:
            s = s[1:].strip()
        if s.startswith("*."):
            s = s[2:]
        s = s.strip(".").lower()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", s) or ".." in s:
            fail(f"Некорректный DIRECT domain: {raw!r}")
        out.append(("full" if exact else "domain", s))
    return out

def read_direct_networks(settings: dict) -> list[ipaddress._BaseNetwork]:
    p = pathlib.Path(settings["direct_networks"])
    if not p.exists():
        return []
    out = []
    for raw in p.read_text().splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        try:
            out.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            fail(f"Некорректная DIRECT network: {raw!r}")
    return out


def _owner_ids(settings: dict) -> tuple[int, int]:
    try:
        pw = pwd.getpwnam(str(settings["owner_user"]))
    except KeyError:
        fail(f"Не найден пользователь {settings['owner_user']!r}.")
    return pw.pw_uid, pw.pw_gid


def _safe_direct_path(settings: dict, key: str) -> pathlib.Path:
    p = pathlib.Path(settings[key])
    if p.is_symlink():
        fail(f"Отказываюсь изменять symlink: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _write_direct_file(settings: dict, key: str, text: str) -> None:
    p = _safe_direct_path(settings, key)
    uid, gid = _owner_ids(settings)
    mode = 0o600
    if p.exists():
        st = p.stat()
        uid, gid = st.st_uid, st.st_gid
        mode = st.st_mode & 0o777 or 0o600
    fd, tmpname = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=p.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmpname, mode)
        os.chown(tmpname, uid, gid)
        os.replace(tmpname, p)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmpname)


def _normalize_domain_target(target: str) -> tuple[str, bool]:
    raw = target.strip()
    exact = raw.startswith("=")
    if exact:
        raw = raw[1:].strip()
    if not raw:
        fail("Пустой domain.")

    if "://" in raw:
        host = urllib.parse.urlsplit(raw).hostname
    else:
        # Разрешаем вставить example.com/path без схемы.
        host = urllib.parse.urlsplit("//" + raw).hostname
    if not host:
        fail(f"Не могу извлечь domain из {target!r}.")
    host = host.rstrip(".")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        fail(f"Некорректный domain {target!r}: {exc}")
    if len(host) > 253 or ".." in host:
        fail(f"Некорректный domain: {host!r}")
    labels = host.split(".")
    if len(labels) < 2:
        fail("Нужен обычный DNS-domain вроде example.com.")
    for label in labels:
        if not label or len(label) > 63 or not re.fullmatch(r"[A-Za-z0-9-]+", label):
            fail(f"Некорректный DNS label: {label!r}")
        if label.startswith("-") or label.endswith("-"):
            fail(f"Некорректный DNS label: {label!r}")
    return host, exact


def _classify_direct_target(target: str):
    raw = target.strip()
    try:
        net = ipaddress.ip_network(raw, strict=False)
        return "network", net.compressed
    except ValueError:
        pass
    domain, exact = _normalize_domain_target(raw)
    return "domain", ("full" if exact else "domain"), domain


def _clean_lines(text: str) -> list[str]:
    return text.splitlines()


def _append_unique_domain(settings: dict, domain: str, exact: bool = False) -> bool:
    p = _safe_direct_path(settings, "direct_sites")
    old = p.read_text() if p.exists() else ""
    existing = {(kind, d) for kind, d in read_direct_sites(settings)}
    kind = "full" if exact else "domain"
    if (kind, domain) in existing:
        return False
    line = ("=" if exact else "") + domain
    new = old
    if new and not new.endswith("\n"):
        new += "\n"
    new += line + "\n"
    _write_direct_file(settings, "direct_sites", new)
    return True


def _remove_domain_entry(settings: dict, domain: str) -> bool:
    p = _safe_direct_path(settings, "direct_sites")
    if not p.exists():
        return False
    old_lines = p.read_text().splitlines()
    new_lines = []
    changed = False
    for raw in old_lines:
        s = raw.strip()
        probe = s[1:].strip() if s.startswith("=") else s
        if probe.startswith("*."):
            probe = probe[2:]
        probe = probe.strip(".").lower()
        if probe == domain:
            changed = True
            continue
        new_lines.append(raw)
    if changed:
        _write_direct_file(settings, "direct_sites", "\n".join(new_lines) + ("\n" if new_lines else ""))
    return changed


def _append_unique_network(settings: dict, network: str) -> bool:
    canonical = ipaddress.ip_network(network, strict=False).compressed
    if any(n.compressed == canonical for n in read_direct_networks(settings)):
        return False
    p = _safe_direct_path(settings, "direct_networks")
    old = p.read_text() if p.exists() else ""
    new = old
    if new and not new.endswith("\n"):
        new += "\n"
    new += canonical + "\n"
    _write_direct_file(settings, "direct_networks", new)
    return True


def _parse_dns_blocks(text: str) -> dict[str, list[str]]:
    blocks: dict[str, list[str]] = {}
    current = None
    for raw in text.splitlines():
        if raw.startswith(DNS_SNAPSHOT_BEGIN):
            current = raw[len(DNS_SNAPSHOT_BEGIN):].strip().lower()
            blocks[current] = []
            continue
        if raw.startswith(DNS_SNAPSHOT_END):
            current = None
            continue
        if current is not None:
            s = raw.strip()
            if s and not s.startswith("#"):
                blocks[current].append(s)
    return blocks


def _replace_dns_block_text(text: str, domain: str, networks: list[str] | None) -> str:
    begin = re.escape(DNS_SNAPSHOT_BEGIN + domain)
    end = re.escape(DNS_SNAPSHOT_END + domain)
    pattern = re.compile(rf"(?ms)^{begin}\n.*?^{end}\n?")
    text = pattern.sub("", text)
    text = text.rstrip("\n")
    if networks is None:
        return text + ("\n" if text else "")
    block = [
        DNS_SNAPSHOT_BEGIN + domain,
        "# DNS snapshot: these IPs may change; use `vpn direct refresh`.",
        *networks,
        DNS_SNAPSHOT_END + domain,
    ]
    if text:
        text += "\n\n"
    return text + "\n".join(block) + "\n"


def _set_dns_snapshot(settings: dict, domain: str, networks: list[str] | None) -> bool:
    p = _safe_direct_path(settings, "direct_networks")
    old = p.read_text() if p.exists() else ""
    new = _replace_dns_block_text(old, domain, networks)
    if new == old:
        return False
    _write_direct_file(settings, "direct_networks", new)
    return True


def _remove_network_entry(settings: dict, network: str) -> bool:
    canonical = ipaddress.ip_network(network, strict=False).compressed
    p = _safe_direct_path(settings, "direct_networks")
    if not p.exists():
        return False
    old_lines = p.read_text().splitlines()
    new_lines = []
    changed = False
    for raw in old_lines:
        s = raw.strip()
        if s and not s.startswith("#"):
            try:
                if ipaddress.ip_network(s, strict=False).compressed == canonical:
                    changed = True
                    continue
            except ValueError:
                pass
        new_lines.append(raw)
    if changed:
        _write_direct_file(settings, "direct_networks", "\n".join(new_lines) + ("\n" if new_lines else ""))
    return changed


def _dns_encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii")
        if not 1 <= len(b) <= 63:
            raise ValueError("bad DNS label")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _dns_decode_name(packet: bytes, offset: int, seen=None) -> tuple[str, int]:
    if seen is None:
        seen = set()
    labels = []
    original_next = None
    while True:
        if offset >= len(packet):
            raise ValueError("DNS name outside packet")
        length = packet[offset]
        if length == 0:
            offset += 1
            if original_next is None:
                original_next = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            ptr = ((length & 0x3F) << 8) | packet[offset + 1]
            if ptr in seen:
                raise ValueError("DNS compression loop")
            seen.add(ptr)
            if original_next is None:
                original_next = offset + 2
            offset = ptr
            continue
        if length & 0xC0:
            raise ValueError("unsupported DNS label type")
        offset += 1
        if offset + length > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[offset:offset + length].decode("ascii"))
        offset += length
    return ".".join(labels).lower(), int(original_next)


def _parse_dns_answer(packet: bytes, tid: int) -> tuple[set[str], set[str], bool]:
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", packet[:12])
    if rid != tid:
        raise ValueError("DNS transaction mismatch")
    if flags & 0x000F:
        return set(), set(), bool(flags & 0x0200)
    off = 12
    for _ in range(qd):
        _name, off = _dns_decode_name(packet, off)
        off += 4
        if off > len(packet):
            raise ValueError("truncated DNS question")
    ips: set[str] = set()
    cnames: set[str] = set()
    for _ in range(an):
        _name, off = _dns_decode_name(packet, off)
        if off + 10 > len(packet):
            raise ValueError("truncated DNS RR")
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", packet[off:off + 10])
        off += 10
        rdata_off = off
        if off + rdlen > len(packet):
            raise ValueError("truncated DNS rdata")
        if rclass == 1 and rtype == 1 and rdlen == 4:
            ips.add(str(ipaddress.IPv4Address(packet[off:off + 4])))
        elif rclass == 1 and rtype == 28 and rdlen == 16:
            ips.add(str(ipaddress.IPv6Address(packet[off:off + 16])))
        elif rclass == 1 and rtype == 5:
            cname, _ = _dns_decode_name(packet, rdata_off)
            cnames.add(cname)
        off += rdlen
    return ips, cnames, bool(flags & 0x0200)


def _dns_query_tcp(resolver: str, name: str, qtype: int, tid: int, query: bytes, timeout: float) -> tuple[set[str], set[str]]:
    s = socket.create_connection((resolver, 53), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(struct.pack("!H", len(query)) + query)
        hdr = b""
        while len(hdr) < 2:
            chunk = s.recv(2 - len(hdr))
            if not chunk:
                raise OSError("DNS TCP closed")
            hdr += chunk
        length = struct.unpack("!H", hdr)[0]
        data = b""
        while len(data) < length:
            chunk = s.recv(length - len(data))
            if not chunk:
                raise OSError("DNS TCP closed")
            data += chunk
        ips, cnames, _ = _parse_dns_answer(data, tid)
        return ips, cnames
    finally:
        s.close()


def _dns_query(resolver: str, name: str, qtype: int, timeout: float = 1.5) -> tuple[set[str], set[str]]:
    tid = random.randrange(65536)
    query = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0) + _dns_encode_name(name) + struct.pack("!HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, (resolver, 53))
        data, _ = s.recvfrom(65535)
    finally:
        s.close()
    ips, cnames, truncated = _parse_dns_answer(data, tid)
    if truncated:
        return _dns_query_tcp(resolver, name, qtype, tid, query, timeout)
    return ips, cnames


def discover_dns_ips(domain: str, rounds: int = 2) -> list[str]:
    rounds = max(1, min(int(rounds), 5))
    ips: set[str] = set()
    names = {domain}

    # Системный resolver — полезен для локального/ISP/VPN-вида DNS.
    with contextlib.suppress(OSError):
        for fam, _sock, _proto, _canon, sa in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM):
            if fam in {socket.AF_INET, socket.AF_INET6}:
                ips.add(sa[0])

    # Несколько публичных resolver'ов + несколько раундов ловят часть rotating/CDN RRsets.
    # Это всё равно snapshot, а не математически полный список всех IP сайта.
    for _round in range(rounds):
        queue = list(names)
        queried = set()
        while queue and len(queried) < 12:
            name = queue.pop(0)
            if name in queried:
                continue
            queried.add(name)
            for resolver in DNS_DISCOVERY_RESOLVERS:
                for qtype in (1, 28):
                    try:
                        found, cnames = _dns_query(resolver, name, qtype)
                    except (OSError, ValueError):
                        continue
                    ips.update(found)
                    for cname in cnames:
                        if cname not in names and len(names) < 12:
                            names.add(cname)
                            queue.append(cname)

    if not ips:
        fail(f"DNS discovery не нашёл ни одного A/AAAA для {domain}.")
    return sorted(ips, key=lambda s: (ipaddress.ip_address(s).version, int(ipaddress.ip_address(s))))


def _host_network(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    return ipaddress.ip_network(f"{addr}/{32 if addr.version == 4 else 128}", strict=False).compressed


def _reload_direct_if_active(settings: dict) -> None:
    st = load_state()
    if st.get("active") and service_active():
        info("Применяю DIRECT-правила к активному VPN...")
        activate(settings, choose_config(settings, st["active"]))
    else:
        ok("Правило сохранено; применится при следующем vpn on.")


def cmd_direct_list(settings: dict) -> None:
    print("DIRECT domains:")
    sites = read_direct_sites(settings)
    if not sites:
        print("  (нет)")
    else:
        for kind, domain in sites:
            print(f"  {'=' if kind == 'full' else ''}{domain}")

    p = _safe_direct_path(settings, "direct_networks")
    raw = p.read_text() if p.exists() else ""
    blocks = _parse_dns_blocks(raw)
    block_ips = {ip for values in blocks.values() for ip in values}
    manual = []
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s in block_ips:
            continue
        with contextlib.suppress(ValueError):
            manual.append(ipaddress.ip_network(s, strict=False).compressed)

    print("DIRECT networks:")
    if not manual:
        print("  (нет)")
    else:
        for n in sorted(set(manual)):
            print(f"  {n}")

    print("DNS snapshots:")
    if not blocks:
        print("  (нет)")
    else:
        for domain in sorted(blocks):
            print(f"  {domain}: {len(blocks[domain])} IP")
            for n in blocks[domain]:
                print(f"    {n}")


def cmd_direct_add(settings: dict, target: str) -> None:
    kind, *rest = _classify_direct_target(target)
    if kind == "network":
        changed = _append_unique_network(settings, rest[0])
        if changed:
            ok(f"Добавлено DIRECT network: {rest[0]}")
        else:
            ok(f"DIRECT network уже есть: {rest[0]}")
    else:
        match_kind, domain = rest
        changed = _append_unique_domain(settings, domain, exact=(match_kind == "full"))
        if changed:
            ok(f"Добавлен DIRECT domain: {'=' if match_kind == 'full' else ''}{domain}")
        else:
            ok(f"DIRECT domain уже есть: {'=' if match_kind == 'full' else ''}{domain}")
    if changed:
        _reload_direct_if_active(settings)


def cmd_direct_remove(settings: dict, target: str) -> None:
    kind, *rest = _classify_direct_target(target)
    changed = False
    if kind == "network":
        changed = _remove_network_entry(settings, rest[0])
        label = rest[0]
    else:
        _match_kind, domain = rest
        changed = _remove_domain_entry(settings, domain)
        changed = _set_dns_snapshot(settings, domain, None) or changed
        label = domain
    if changed:
        ok(f"Удалено из DIRECT: {label}")
        _reload_direct_if_active(settings)
    else:
        ok(f"В DIRECT ничего не найдено: {label}")


def _confirm_shared_ip_risk(domain: str, yes: bool) -> None:
    warn(
        "DNS-IP исключения являются snapshot. CDN может менять адреса, а один IP "
        "может обслуживать несколько сайтов — тогда DIRECT затронет весь трафик к этому IP."
    )
    if yes:
        return
    if not sys.stdin.isatty():
        fail("Для неинтерактивного запуска добавь --yes.")
    ans = input(f"Добавить найденные IP для {domain} в DIRECT? [y/N] ").strip().lower()
    if ans not in {"y", "yes", "д", "да"}:
        fail("Отменено пользователем.")


def cmd_direct_discover(settings: dict, target: str, rounds: int, yes: bool) -> None:
    domain, _exact = _normalize_domain_target(target)
    info(f"Ищу A/AAAA для {domain}: system DNS + {len(DNS_DISCOVERY_RESOLVERS)} public resolvers...")
    ips = discover_dns_ips(domain, rounds)
    networks = [_host_network(ip) for ip in ips]
    print("Найдено:")
    for n in networks:
        print(f"  {n}")
    _confirm_shared_ip_risk(domain, yes)

    changed = _append_unique_domain(settings, domain, exact=False)
    changed = _set_dns_snapshot(settings, domain, networks) or changed
    ok(f"DNS snapshot сохранён: {domain} -> {len(networks)} IP")
    if changed:
        _reload_direct_if_active(settings)


def cmd_direct_refresh(settings: dict, target: str | None, rounds: int) -> None:
    p = _safe_direct_path(settings, "direct_networks")
    raw = p.read_text() if p.exists() else ""
    blocks = _parse_dns_blocks(raw)
    if target:
        domain, _exact = _normalize_domain_target(target)
        domains = [domain]
    else:
        domains = sorted(blocks)
    if not domains:
        fail("Нет DNS snapshots. Сначала: vpn direct discover example.com")

    changed = False
    for domain in domains:
        info(f"Обновляю DNS snapshot: {domain}")
        ips = discover_dns_ips(domain, rounds)
        networks = [_host_network(ip) for ip in ips]
        changed = _append_unique_domain(settings, domain, exact=False) or changed
        changed = _set_dns_snapshot(settings, domain, networks) or changed
        ok(f"{domain}: {len(networks)} IP")
    if changed:
        _reload_direct_if_active(settings)
    else:
        ok("DNS snapshots не изменились.")

def build_config(settings: dict, nodes: list[dict], selected: int = 0,
                 ipv6_enabled: bool = True) -> dict:
    if not nodes:
        fail("Нет VLESS nodes.")
    if not (0 <= selected < len(nodes)):
        selected = 0

    proxy = nodes[selected]["outbound"]

    domains = []
    for kind, domain in read_direct_sites(settings):
        domains.append(f"{kind}:{domain}")

    ips = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    ips += [n.compressed for n in read_direct_networks(settings)]

    rules = []
    if domains:
        rules.append({
            "type": "field",
            "inboundTag": ["tun-in"],
            "domain": domains,
            "outboundTag": "direct",
            "ruleTag": "user-direct-domains",
        })
    if ips:
        rules.append({
            "type": "field",
            "inboundTag": ["tun-in"],
            "ip": ips,
            "outboundTag": "direct",
            "ruleTag": "local-and-user-direct-networks",
        })
    rules.append({
        "type": "field",
        "inboundTag": ["tun-in"],
        "outboundTag": "proxy",
        "ruleTag": "default-vpn",
    })

    gateways = ["172.31.255.1/30"]
    auto_routes = ["0.0.0.0/0"]
    if ipv6_enabled:
        gateways.append("fd7a:115c:a1e0::1/126")
        auto_routes.append("::/0")

    return {
        "log": {
            "loglevel": "info",
        },
        "inbounds": [{
            "tag": "tun-in",
            "protocol": "tun",
            "settings": {
                "name": TUN_NAME,
                "mtu": 1500,
                "gateway": gateways,
                "autoSystemRoutingTable": auto_routes,
                "autoOutboundsInterface": "auto",
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "metadataOnly": False,
                "routeOnly": True,
            },
        }],
        "outbounds": [
            proxy,
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {"domainStrategy": "AsIs"},
            },
            {
                "tag": "block",
                "protocol": "blackhole",
                "settings": {},
            },
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules,
        },
    }

def write_runtime_config(settings: dict, cfg: dict) -> None:
    ensure_runtime(settings)
    fd, tmpname = tempfile.mkstemp(
        prefix="config.", suffix=".json", dir=RUNTIME_DIR
    )
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chown(tmpname, 0, int(settings["xray_gid"]))
        os.chmod(tmpname, 0o640)
        os.replace(tmpname, RUNTIME_CONFIG)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmpname)

def test_config(path: pathlib.Path = RUNTIME_CONFIG,
                binary: pathlib.Path = XRAY) -> None:
    if not binary.exists():
        fail("Xray core не установлен. Выполни: vpn core-update")
    cp = run(
        [binary, "run", "-test", "-config", path],
        check=False, capture=True, timeout=20
    )
    if cp.returncode != 0:
        msg = ((cp.stderr or "") + "\n" + (cp.stdout or "")).strip()
        fail("Xray отклонил конфиг:\n" + msg[-5000:])

def nft_exists() -> bool:
    return run(
        ["/usr/bin/nft", "list", "table", "inet", NFT_TABLE],
        check=False, capture=True
    ).returncode == 0

def install_guard(settings: dict) -> None:
    uid = int(settings["xray_uid"])
    rules = f"""
table inet {NFT_TABLE} {{
  chain output {{
    type filter hook output priority filter; policy accept;

    oifname "lo" accept
    meta skuid {uid} accept

    ip daddr 127.0.0.0/8 accept
    ip daddr 10.0.0.0/8 accept
    ip daddr 172.16.0.0/12 accept
    ip daddr 192.168.0.0/16 accept
    ip daddr 169.254.0.0/16 accept
    ip daddr 224.0.0.0/4 accept
    ip daddr 255.255.255.255/32 accept

    ip6 daddr ::1/128 accept
    ip6 daddr fc00::/7 accept
    ip6 daddr fe80::/10 accept
    ip6 daddr ff00::/8 accept

    udp sport 68 udp dport 67 accept
    udp sport 67 udp dport 68 accept

    oifname "{TUN_NAME}" accept

    reject with icmpx type admin-prohibited
  }}
}}
"""
    run(
        ["/usr/bin/nft", "delete", "table", "inet", NFT_TABLE],
        check=False, capture=True
    )
    cp = run(
        ["/usr/bin/nft", "-f", "-"],
        check=False, capture=True, input_text=rules
    )
    if cp.returncode != 0:
        fail("Не удалось поставить kill switch:\n" + (cp.stderr or ""))

def remove_guard() -> None:
    run(
        ["/usr/bin/nft", "delete", "table", "inet", NFT_TABLE],
        check=False, capture=True
    )

def service_active() -> bool:
    return run(
        ["/usr/bin/systemctl", "is-active", "--quiet", SERVICE],
        check=False
    ).returncode == 0

def wait_service(timeout=12) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if service_active() and pathlib.Path(f"/sys/class/net/{TUN_NAME}").exists():
            return True
        time.sleep(0.25)
    return False

def journal_tail(lines=100) -> str:
    cp = run(
        ["/usr/bin/journalctl", "-u", SERVICE, "-n", str(lines),
         "--no-pager", "-o", "cat"],
        check=False, capture=True
    )
    return cp.stdout or ""

def health_check_v4() -> tuple[bool, str]:
    dns = run(
        ["/usr/bin/getent", "ahostsv4", "example.com"],
        check=False, capture=True, timeout=5
    )
    if dns.returncode != 0 or not (dns.stdout or "").strip():
        return False, "IPv4 DNS resolution через активный VPN не работает."

    cp = run(
        ["/usr/bin/curl", "-4", "--fail", "--silent", "--show-error",
         "--connect-timeout", "5", "--max-time", "12",
         "https://api.ipify.org"],
        check=False, capture=True, timeout=15
    )
    if cp.returncode != 0:
        return False, "IPv4 HTTPS через VPN не работает: " + (cp.stderr or "").strip()
    ip = (cp.stdout or "").strip()
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.version != 4:
            return False, f"Ожидался IPv4, получено: {ip!r}"
    except ValueError:
        return False, f"Health endpoint вернул неожиданный ответ: {ip[:120]!r}"
    return True, ip

def probe_ipv6_via_vpn(timeout: float = 4.0) -> tuple[bool, str]:
    """
    Проверяет не наличие IPv6 на локальной машине, а реальную возможность
    открыть TLS-соединение к публичному IPv6 ЧЕРЕЗ текущий Xray TUN/VLESS.

    Используется фиксированный IPv6 Cloudflare DNS, чтобы результат не зависел
    от локального DNS. Если VPS не имеет IPv6 egress, соединение не пройдёт.
    """
    raw = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect(("2606:4700:4700::1111", 443, 0, 0))
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(raw, server_hostname="cloudflare-dns.com") as tls:
            return True, tls.version() or "TLS OK"
    except Exception as exc:
        with contextlib.suppress(Exception):
            raw.close()
        return False, f"{type(exc).__name__}: {exc}"

def udp_dns_check(timeout: float = 5.0) -> tuple[bool, str]:
    tid = random.randrange(65536)
    qname = b""
    for part in "example.com".split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\0"
    packet = (
        struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        + qname
        + struct.pack("!HH", 1, 1)
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, ("1.1.1.1", 53))
        data, addr = s.recvfrom(4096)
        if len(data) < 12:
            return False, "слишком короткий UDP DNS reply"
        rid = struct.unpack("!H", data[:2])[0]
        if rid != tid:
            return False, "DNS transaction ID не совпал"
        return True, f"{addr[0]}:{addr[1]}, {len(data)} bytes"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        s.close()

def ipv6_tun_route_present() -> bool:
    cp = run(
        ["/usr/bin/ip", "-6", "route", "get", "2606:4700:4700::1111"],
        check=False, capture=True
    )
    return cp.returncode == 0 and TUN_NAME in (cp.stdout or "")

def stop_core() -> None:
    run(["/usr/bin/systemctl", "stop", SERVICE], check=False)
    for _ in range(50):
        if not service_active():
            break
        time.sleep(0.1)

def validate_candidate(settings: dict, cfg: dict) -> None:
    ensure_runtime(settings)
    candidate = RUNTIME_DIR / "candidate.json"
    candidate.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")
    os.chown(candidate, 0, int(settings["xray_gid"]))
    os.chmod(candidate, 0o640)
    try:
        test_config(candidate)
    finally:
        candidate.unlink(missing_ok=True)

def start_config(settings: dict, cfg: dict) -> bool:
    write_runtime_config(settings, cfg)
    run(["/usr/bin/systemctl", "start", SERVICE], check=False, capture=True)
    return wait_service()

def activate(settings: dict, path: pathlib.Path) -> None:
    old_state = load_state()
    old_config = RUNTIME_CONFIG.read_bytes() if RUNTIME_CONFIG.exists() else None
    was_active = service_active()

    info(f"Разбираю конфиг: {path.name}")
    nodes = load_profile(path)

    # Сначала пробуем настоящий dual-stack. Если удалённый VPS не умеет IPv6,
    # автоматически перестраиваем TUN в IPv4-only fail-closed режиме.
    cfg_dual = build_config(settings, nodes, ipv6_enabled=True)
    validate_candidate(settings, cfg_dual)

    if not was_active:
        install_guard(settings)
    else:
        stop_core()

    failure_reason = "неизвестная ошибка"

    if start_config(settings, cfg_dual):
        info("TUN поднят. Проверяю IPv4 через VLESS...")
        v4_ok, v4_detail = health_check_v4()

        if v4_ok:
            info("IPv4 работает. Проверяю IPv6 egress через тот же VPN...")
            v6_ok, v6_detail = probe_ipv6_via_vpn()

            if v6_ok:
                save_state({
                    "active": path.name,
                    "node": nodes[0]["name"],
                    "server_ip": nodes[0]["server_ip"],
                    "ipv6_mode": "vpn",
                    "since": int(time.time()),
                })
                ok(f"VPN включён: {path.name}")
                ok(f"IPv4: VPN, внешний адрес {v4_detail}")
                ok("IPv6: VPN")
                ok("Kill switch: ACTIVE")
                return

            warn(
                "IPv6 через VPN не работает. "
                "Переключаю TUN в IPv4-only режим; публичный IPv6 будет BLOCKED."
            )
            warn(f"IPv6 probe: {v6_detail}")

            # Guard не снимаем ни на мгновение.
            stop_core()
            cfg_v4 = build_config(settings, nodes, ipv6_enabled=False)
            validate_candidate(settings, cfg_v4)

            if start_config(settings, cfg_v4):
                info("ПроверяЎ IPv4 после IPv6 fallback...")
                v4_ok2, v4_detail2 = health_check_v4()
                if v4_ok2:
                    # В этом режиме Xray не создаёт ::/0 через TUN.
                    # Публичный IPv6 физического интерфейса режеч vpn_guard.
                    save_state({
                        "active": path.name,
                        "node": nodes[0]["name"],
                        "server_ip": nodes[0]["server_ip"],
                        "ipv6_mode": "blocked",
                        "ipv6_probe_error": v6_detail,
                        "since": int(time.time()),
                    })
                    ok(f"VPN включён: {path.name}")
                    ok(f"IPv4: VPN, внешний адрес {v4_detail2}")
                    ok("IPv6: BLOCKED (у VPN нет рабочего IPv6 egress)")
                    ok("Kill switch: ACTIVE")
                    return
                failure_reason = v4_detail2
            else:
                failure_reason = "Xray не поднял IPv4-only TUN"
        else:
            failure_reason = v4_detail
    else:
        failure_reason = "Xray не поднял dual-stack TUN"

    warn("Новый VPN не прошёл реальную проверку. Откатываю.")
    log = journal_tail(100)
    stop_core()

    if was_active and old_config is not None:
        RUNTIME_CONFIG.write_bytes(old_config)
        os.chown(RUNTIME_CONFIG, 0, int(settings["xray_gid"]))
        os.chmod(RUNTIME_CONFIG, 0o640)
        run(["/usr/bin/systemctl", "start", SERVICE], check=False)
        if wait_service():
            healthy, _ = health_check_v4()
            if healthy:
                save_state(old_state)
                fail(
                    "Новый конфиг не работает; предыдущий VPN восстановлен.\n"
                    f"Причина: {failure_reason}\n" + log[-5000:]
                )
        fail(
            "Новый VPN не работает и rollback старого тоже не прошёл. "
            "Kill switch ОСТАВЛЕН.\nИспользуй `vpn logs`; `vpn off` "
            "вернёт прямой интернет.\n"
            f"Причина: {failure_reason}\n" + log[-5000:]
        )

    RUNTIME_CONFIG.unlink(missing_ok=True)
    remove_guard()
    save_state({"active": None})
    fail(
        "VPN не прошёл реальную проверку; прямой интернет "
        "автоматически восстановлен.\n"
        f"Причина: {failure_reason}\n" + log[-5000:]
    )

def deactivate() -> None:
    info("Выключаю VPN...")
    stop_core()
    RUNTIME_CONFIG.unlink(missing_ok=True)
    remove_guard()
    save_state({"active": None})
    ok("VPN выключен. Прямой интернет разрешён.")

def default_physical_iface() -> str | None:
    cp = run(
        ["/usr/bin/ip", "-4", "route", "show", "default", "table", "main"],
        check=False, capture=True
    )
    for line in (cp.stdout or "").splitlines():
        m = re.search(r"\bdev\s+(\S+)", line)
        if m and m.group(1) != TUN_NAME:
            return m.group(1)
    return None

def bound_direct_test(iface: str) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.5)
    try:
        s.setsockopt(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
            iface.encode() + b"\0"
        )
        return s.connect_ex(("1.1.1.1", 443)) == 0
    finally:
        s.close()

def bound_direct_test_v6(iface: str) -> bool:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.settimeout(2.5)
    try:
        s.setsockopt(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
            iface.encode() + b"\0"
        )
        return s.connect_ex(("2606:4700:4700::1111", 443, 0, 0)) == 0
    finally:
        s.close()

def cmd_status(settings: dict, with_ip=False) -> None:
    st = load_state()
    active = service_active()
    ipv6_mode = st.get("ipv6_mode", "unknown")

    print(f"Manager:      {MANAGER_VERSION}")
    print(f"Safe Xray:    {SAFE_XRAY_VERSION}")
    if XRAY.exists():
        cp = run([XRAY, "version"], check=False, capture=True)
        first = ((cp.stdout or cp.stderr or "").splitlines() or ["installed"])[0]
        print(f"Xray:         {first}")
    else:
        print("Xray:         NOT INSTALLED")
    print(f"VPN:          {'ON' if active else 'OFF'}")
    print(f"Config:       {st.get('active') or '-'}")
    print(f"TUN {TUN_NAME}:  {'YES' if pathlib.Path('/sys/class/net/'+TUN_NAME).exists() else 'NO'}")
    print(f"Kill switch:  {'ACTIVE' if nft_exists() else 'OFF'}")

    if active:
        print("IPv4:         VPN")
        if ipv6_mode == "vpn":
            print("IPv6:         VPN")
        elif ipv6_mode == "blocked":
            print("IPv6:         BLOCKED (remote VPN has no working IPv6)")
        else:
            print("IPv6:         UNKNOWN")
    else:
        print("IPv4:         DIRECT")
        print("IPv6:         DIRECT/system")

    print(f"Configs dir:  {settings['config_dir']}")
    print(
        f"DIRECT rules: {len(read_direct_sites(settings))} domains / "
        f"{len(read_direct_networks(settings))} networks"
    )

    if with_ip and active:
        v4_ok, v4_detail = health_check_v4()
        print(f"IPv4 health:  {'OK' if v4_ok else 'FAIL'}")
        print(f"Public IPv4:  {v4_detail if v4_ok else '-'}")
        if not v4_ok:
            print(f"IPv4 reason:  {v4_detail}")

        if ipv6_mode == "vpn":
            v6_ok, v6_detail = probe_ipv6_via_vpn()
            print(f"IPv6 health:  {'OK' if v6_ok else 'FAIL'}")
            if not v6_ok:
                print(f"IPv6 reason:  {v6_detail}")
        elif ipv6_mode == "blocked":
            print("IPv6 health:  BLOCKED BY DESIGN")

def cmd_test(settings: dict) -> None:
    if not service_active():
        fail("VPN выключен.")

    st = load_state()
    ipv6_mode = st.get("ipv6_mode", "unknown")

    checks: list[tuple[str, bool]] = [
        ("systemd service", service_active()),
        (f"{TUN_NAME} exists", pathlib.Path(f"/sys/class/net/{TUN_NAME}").exists()),
        ("kill switch", nft_exists()),
    ]

    v4_ok, v4_detail = health_check_v4()
    checks.append(("real IPv4 DNS + HTTPS through VPN", v4_ok))

    udp_ok, udp_detail = udp_dns_check()
    checks.append(("real UDP through VLESS (DNS to 1.1.1.1:53)", udp_ok))

    if ipv6_mode == "vpn":
        v6_ok, v6_detail = probe_ipv6_via_vpn()
        checks.append(("real IPv6 TLS through VPN", v6_ok))
    elif ipv6_mode == "blocked":
        v6_ok = not ipv6_tun_route_present()
        v6_detail = "public IPv6 intentionally blocked"
        checks.append(("IPv6 ::/0 is NOT routed into broken VPN", v6_ok))
    else:
        v6_ok, v6_detail = False, "unknown IPv6 mode"
        checks.append(("IPv6 mode known", False))

    iface = default_physical_iface()
    if iface:
        try:
            leak4 = bound_direct_test(iface)
        except OSError:
            leak4 = False
        checks.append((f"direct IPv4 leak via {iface} BLOCKED", not leak4))

        try:
            leak6 = bound_direct_test_v6(iface)
        except OSError:
            leak6 = False
        checks.append((f"direct IPv6 leak via {iface} BLOCKED", not leak6))

    for name, passed in checks:
        print(f"{color('✓','1;32') if passed else color('✗','1;31')} {name}")

    print(f"IPv4: {v4_detail}")
    print(f"UDP:  {udp_detail}")
    print(f"IPv6: {v6_detail}")

    if not all(p for _, p in checks):
        fail("Одна или несколько проверок не пройдены.")

def cmd_route(settings: dict, target: str) -> None:
    t = target.strip().lower().rstrip(".")
    state = load_state()
    try:
        addr = ipaddress.ip_address(t)
    except ValueError:
        addr = None

    if addr:
        if (
            addr.version == 6
            and state.get("ipv6_mode") == "blocked"
            and not (addr.is_private or addr.is_loopback or addr.is_link_local)
        ):
            print(f"{target} -> BLOCKED (VPN has no working IPv6 egress)")
            return
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            print(f"{target} -> DIRECT (local/private)")
            return
        for net in read_direct_networks(settings):
            if addr in net:
                print(f"{target} -> DIRECT ({net})")
                return
        print(f"{target} -> VPN")
        return

    for kind, domain in read_direct_sites(settings):
        if kind == "full" and t == domain:
            print(f"{target} -> DIRECT (= {domain})")
            return
        if kind == "domain" and (t == domain or t.endswith("." + domain)):
            print(f"{target} -> DIRECT ({domain} + subdomains)")
            return
    print(f"{target} -> VPN")

def inspect_profile(settings: dict, requested: str | None) -> None:
    p = choose_config(settings, requested)
    nodes = load_profile(p)
    for i, n in enumerate(nodes, 1):
        out = n["outbound"]
        ss = out["streamSettings"]
        s = out["settings"]
        print(f"NODE {i}: {n['name']}")
        print(f"  server: [REDACTED] -> {n['server_ip']}")
        print(f"  port: {s['port']}")
        print(f"  uuid: [REDACTED]")
        print(f"  encryption: {s.get('encryption')}")
        print(f"  flow: {s.get('flow','-')}")
        print(f"  network: {ss.get('network')}")
        print(f"  security: {ss.get('security')}")
        if "realitySettings" in ss:
            r = ss["realitySettings"]
            print(f"  reality.serverName: {'[SET]' if r.get('serverName') else '[EMPTY]'}")
            print(f"  reality.publicKey: {'[SET]' if r.get('publicKey') else '[EMPTY]'}")
            print(f"  reality.shortId: {'[SET]' if r.get('shortId') else '[EMPTY]'}")
            print(f"  reality.spiderX: {r.get('spiderX','')!r}")
        if "xhttpSettings" in ss:
            x = ss["xhttpSettings"]
            print(f"  xhttp.path: {x.get('path','')!r}")
            print(f"  xhttp.host: {x.get('host','')!r}")
            print(f"  xhttp.mode: {x.get('mode','auto')!r}")
            print(f"  xhttp.extra: {'[SET]' if 'extra' in x else '[NONE]'}")

def github_xray_asset() -> tuple[str, str, str | None, str | None]:
    data = json.loads(http_get(XRAY_RELEASE_API, 5 * 1024 * 1024))
    tag = str(data.get("tag_name") or "")
    if tag != "v" + SAFE_XRAY_VERSION:
        fail(f"GitHub tag mismatch: {tag}")

    machine = os.uname().machine
    if machine in {"x86_64", "amd64"}:
        asset_name = "Xray-linux-64.zip"
    elif machine in {"aarch64", "arm64"}:
        asset_name = "Xray-linux-arm64-v8a.zip"
    else:
        fail(f"Автоустановка Xray пока не поддерживает {machine}.")

    assets = data.get("assets") or []
    asset = next((a for a in assets if a.get("name") == asset_name), None)
    if not asset:
        fail(f"В Xray release нет {asset_name}")

    digest = str(asset.get("digest") or "")
    expected = digest.split(":", 1)[1] if digest.startswith("sha256:") else None

    dgst_asset = next(
        (a for a in assets if a.get("name") in {
            asset_name + ".dgst",
            asset_name + ".sha256",
        }),
        None,
    )
    dgst_url = str(dgst_asset.get("browser_download_url")) if dgst_asset else None
    return asset_name, str(asset["browser_download_url"]), expected, dgst_url

def parse_checksum_text(raw: bytes) -> str | None:
    text = raw.decode("utf-8", errors="ignore")
    m = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    return m.group(1).lower() if m else None

def core_update(settings: dict) -> bool:
    info(f"Проверяю совместимый Xray core v{SAFE_XRAY_VERSION}...")
    if XRAY.exists():
        cp = run([XRAY, "version"], check=False, capture=True)
        current = (cp.stdout or cp.stderr or "")
        if SAFE_XRAY_VERSION in current:
            ok(f"Xray уже на совместимой версии {SAFE_XRAY_VERSION}")
            return False

    asset_name, url, expected, dgst_url = github_xray_asset()
    blob = http_get(url, MAX_DOWNLOAD_BYTES)

    if expected is None and dgst_url:
        expected = parse_checksum_text(http_get(dgst_url, 1024 * 1024))
    if expected is None:
        fail(
            "GitHub release не дал SHA-256 ни через digest, ни через .dgst. "
            "Установка отменена."
        )

    got = hashlib.sha256(blob).hexdigest()
    if got != expected:
        fail(
            f"SHA-256 Xray НЕ СОВПАЛ.\nExpected: {expected}\nGot: {got}"
        )
    ok(f"SHA-256 официального {asset_name} подтверждён.")

    with tempfile.TemporaryDirectory() as td:
        zpath = pathlib.Path(td) / "xray.zip"
        zpath.write_bytes(blob)
        try:
            with zipfile.ZipFile(zpath) as zf:
                names = zf.namelist()
                if "xray" not in names:
                    fail("В официальном Xray zip нет файла xray.")
                extracted = pathlib.Path(td) / "xray"
                with zf.open("xray") as src, extracted.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
        except zipfile.BadZipFile:
            fail("Скачанный Xray asset не является корректным ZIP.")

        os.chmod(extracted, 0o755)
        cp = run([extracted, "version"], check=False, capture=True)
        if cp.returncode != 0 or SAFE_XRAY_VERSION not in (
            (cp.stdout or "") + (cp.stderr or "")
        ):
            fail("Распакованный Xray binary не прошёл version check.")

        if RUNTIME_CONFIG.exists():
            test_config(RUNTIME_CONFIG, extracted)

        tmp_target = pathlib.Path("/opt/vpn-manager/bin/.xray.new")
        shutil.copy2(extracted, tmp_target)
        os.chmod(tmp_target, 0o755)

    active = service_active()
    if XRAY.exists():
        shutil.copy2(XRAY, XRAY_PREVIOUS)
        os.chmod(XRAY_PREVIOUS, 0o755)
    os.replace(tmp_target, XRAY)

    if active:
        info("Перезапускаю Xray; kill switch остаётся...")
        run(["/usr/bin/systemctl", "restart", SERVICE], check=False)
        if not wait_service():
            warn("Новый Xray не поднялся; откатываю binary.")
            if XRAY_PREVIOUS.exists():
                shutil.copy2(XRAY_PREVIOUS, XRAY)
                os.chmod(XRAY, 0o755)
                run(["/usr/bin/systemctl", "restart", SERVICE], check=False)
            fail("Xray core update откатился.")

    ok(f"Xray core установлен: {SAFE_XRAY_VERSION}")
    return True

def sync_system_files() -> None:
    pathlib.Path("/etc/systemd/system/vpn-xray.service").write_text(SERVICE_TEXT)
    os.chmod("/etc/systemd/system/vpn-xray.service", 0o644)

    pathlib.Path("/usr/local/bin/vpn").write_text(WRAPPER_TEXT)
    os.chmod("/usr/local/bin/vpn", 0o755)

    run(["/usr/bin/systemctl", "daemon-reload"], check=False)

def safe_extract_manager(tar_path: pathlib.Path, dest: pathlib.Path) -> str:
    allowed = {"vpnctl.py", "vpnadmin.py", "VERSION"}
    with tarfile.open(tar_path, "r:gz") as tf:
        members = tf.getmembers()
        names = {m.name for m in members}
        if names != allowed:
            fail(f"Manager archive: ожидались {sorted(allowed)}, получено {sorted(names)}")
        for m in members:
            pp = pathlib.PurePosixPath(m.name)
            if not m.isfile() or pp.is_absolute() or ".." in pp.parts:
                fail("Небезопасный manager archive.")
        tf.extractall(dest)
    version = (dest / "VERSION").read_text().strip()
    if not re.fullmatch(r"[0-9A-Za-z._+-]+", version):
        fail("Некорректный VERSION.")
    os.chmod(dest / "vpnctl.py", 0o755)
    os.chmod(dest / "vpnadmin.py", 0o755)
    return version

def manager_update_manifest(settings: dict, manifest_url: str) -> bool:
    info("Проверяю обновление VPN Manager...")
    manifest = json.loads(http_get(manifest_url, 1024 * 1024))
    version = str(manifest.get("version") or "")
    url = str(manifest.get("url") or "")
    expected = str(manifest.get("sha256") or "").lower()

    if version == MANAGER_VERSION:
        ok(f"VPN Manager уже актуален: {MANAGER_VERSION}")
        return False
    if not re.fullmatch(r"[0-9A-Za-z._+-]+", version):
        fail("Некорректная version в manager manifest.")
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        fail("Некорректный sha256 в manager manifest.")

    blob = http_get(url, 20 * 1024 * 1024)
    if hashlib.sha256(blob).hexdigest() != expected:
        fail("SHA-256 VPN Manager release НЕ СОВПАЛ.")

    with tempfile.TemporaryDirectory(dir="/opt/vpn-manager/releases") as td:
        tdpath = pathlib.Path(td)
        tarpath = tdpath / "release.tar.gz"
        tarpath.write_bytes(blob)
        unpack = tdpath / "unpack"
        unpack.mkdir()
        actual_version = safe_extract_manager(tarpath, unpack)
        if actual_version != version:
            fail("VERSION внутри manager archive не совпал с manifest.")

        cp = run(
            [sys.executable, str(unpack / "vpnctl.py"), "--self-test"],
            check=False, capture=True
        )
        if cp.returncode != 0:
            fail("Self-test новой версии manager не прошёл.")

        dest = RELEASES / version
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(unpack, dest)

    old = pathlib.Path(os.path.realpath(CURRENT)) if CURRENT.exists() else None
    PREVIOUS.unlink(missing_ok=True)
    if old and old.exists():
        PREVIOUS.symlink_to(old)

    newlink = pathlib.Path("/opt/vpn-manager/.current.new")
    newlink.unlink(missing_ok=True)
    newlink.symlink_to(dest)
    os.replace(newlink, CURRENT)
    os.symlink(CURRENT / "vpnctl.py", "/usr/local/sbin/vpnctl.new")
    os.replace("/usr/local/sbin/vpnctl.new", "/usr/local/sbin/vpnctl")

    ok(f"VPN Manager обновлён: {MANAGER_VERSION} -> {version}")
    os.execv(
        "/usr/local/sbin/vpnctl",
        ["/usr/local/sbin/vpnctl", "internal-after-update"]
    )

def manager_rollback() -> None:
    if not PREVIOUS.exists():
        fail("Нет previous manager release.")
    target = pathlib.Path(os.path.realpath(PREVIOUS))
    cp = run(
        [sys.executable, str(target / "vpnctl.py"), "--self-test"],
        check=False, capture=True
    )
    if cp.returncode != 0:
        fail("Previous manager не проходит self-test.")
    newlink = pathlib.Path("/opt/vpn-manager/.current.new")
    newlink.unlink(missing_ok=True)
    newlink.symlink_to(target)
    os.replace(newlink, CURRENT)
    with contextlib.suppress(FileExistsError):
        os.symlink(CURRENT / "vpnctl.py", "/usr/local/sbin/vpnctl.new")
    os.replace("/usr/local/sbin/vpnctl.new", "/usr/local/sbin/vpnctl")
    sync_system_files()
    ok("Manager rollback выполнен.")

def self_test() -> None:
    # Никакой сети. Проверяем парсер на VLESS + XHTTP + REALITY.
    old = globals()["resolve_server"]
    globals()["resolve_server"] = lambda host: "203.0.113.1"
    try:
        sample = (
            "vless://11111111-1111-1111-1111-111111111111@vpn.example.com:443"
            "?type=xhttp&encryption=none&security=reality&"
            "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&"
            "sni=www.microsoft.com&sid=aa11&spx=%2F&path=%2Fsync&mode=auto"
            "#Test"
        )
        node = parse_vless_url(sample, "Test")
        out = node["outbound"]
        assert out["protocol"] == "vless"
        assert out["settings"]["address"] == "203.0.113.1"
        assert out["streamSettings"]["network"] == "xhttp"
        assert out["streamSettings"]["realitySettings"]["spiderX"] == "/"
        assert out["streamSettings"]["xhttpSettings"]["path"] == "/sync"

        fake_settings = {
            "direct_sites": "/nonexistent/direct-sites",
            "direct_networks": "/nonexistent/direct-networks",
        }
        dual = build_config(fake_settings, [node], ipv6_enabled=True)
        v4 = build_config(fake_settings, [node], ipv6_enabled=False)
        assert dual["inbounds"][0]["settings"]["autoSystemRoutingTable"] == ["0.0.0.0/0", "::/0"]
        assert v4["inbounds"][0]["settings"]["autoSystemRoutingTable"] == ["0.0.0.0/0"]
        assert len(v4["inbounds"][0]["settings"]["gateway"]) == 1

        d, exact = _normalize_domain_target("https://Example.COM/path")
        assert d == "example.com" and exact is False
        assert _classify_direct_target("1.2.3.4")[1] == "1.2.3.4/32"
        sample_rules = "1.2.3.0/24\n"
        sample_rules = _replace_dns_block_text(sample_rules, "example.com", ["203.0.113.1/32", "2001:db8::1/128"])
        blocks = _parse_dns_blocks(sample_rules)
        assert blocks["example.com"] == ["203.0.113.1/32", "2001:db8::1/128"]
        sample_rules = _replace_dns_block_text(sample_rules, "example.com", None)
        assert "EVGENIUM-DNS-BEGIN" not in sample_rules
    finally:
        globals()["resolve_server"] = old
    print("self-test OK")

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="vpn", add_help=False)
    p.add_argument("--self-test", action="store_true")
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("help")
    sub.add_parser("list")
    pon = sub.add_parser("on"); pon.add_argument("config", nargs="?")
    psw = sub.add_parser("switch"); psw.add_argument("config")
    sub.add_parser("off")
    pst = sub.add_parser("status"); pst.add_argument("--ip", action="store_true")
    sub.add_parser("test")
    pr = sub.add_parser("route"); pr.add_argument("target")

    pd = sub.add_parser("direct")
    pdsub = pd.add_subparsers(dest="direct_cmd")
    pdsub.add_parser("list")
    pda = pdsub.add_parser("add"); pda.add_argument("target")
    pdr = pdsub.add_parser("remove"); pdr.add_argument("target")
    pdd = pdsub.add_parser("discover")
    pdd.add_argument("target")
    pdd.add_argument("--rounds", type=int, default=2)
    pdd.add_argument("--yes", action="store_true")
    pdf = pdsub.add_parser("refresh")
    pdf.add_argument("target", nargs="?")
    pdf.add_argument("--rounds", type=int, default=2)
    pre = sub.add_parser("reload-rules")
    pl = sub.add_parser("logs"); pl.add_argument("-n", "--lines", type=int, default=100)
    pi = sub.add_parser("inspect"); pi.add_argument("config", nargs="?")
    sub.add_parser("doctor")
    sub.add_parser("core-update")
    sub.add_parser("update")
    sub.add_parser("version")
    sub.add_parser("internal-sync")
    sub.add_parser("internal-after-update")
    sub.add_parser("manager-rollback")

    args = p.parse_args(argv)

    if args.self_test:
        self_test()
        return 0

    ensure_root()
    settings = load_settings()

    if args.cmd in {None, "help"}:
        print(f"""VPN Manager {MANAGER_VERSION} — Xray edition

  vpn list
  vpn on [CONFIG]
  vpn switch CONFIG
  vpn off
  vpn status [--ip]
  vpn test
  vpn route DOMAIN|IP
  vpn direct list
  vpn direct add DOMAIN|IP|CIDR
  vpn direct remove DOMAIN|IP|CIDR
  vpn direct discover DOMAIN [--yes] [--rounds N]
  vpn direct refresh [DOMAIN] [--rounds N]
  vpn reload-rules
  vpn inspect [CONFIG]
  vpn logs [-n 100]
  vpn doctor
  vpn update
  vpn core-update
  vpn version

Конфиги:
  {settings['config_dir']}

DIRECT domains:
  {settings['direct_sites']}

DIRECT networks:
  {settings['direct_networks']}
""")
        return 0

    if args.cmd == "list":
        paths = list_config_paths(settings)
        if not paths:
            print("(конфигов нет)")
        else:
            for x in paths:
                print(x.name)
        return 0

    if args.cmd in {"on", "switch"}:
        activate(settings, choose_config(settings, args.config))
        return 0

    if args.cmd == "off":
        deactivate()
        return 0

    if args.cmd == "status":
        cmd_status(settings, args.ip)
        return 0

    if args.cmd == "test":
        cmd_test(settings)
        return 0

    if args.cmd == "route":
        cmd_route(settings, args.target)
        return 0

    if args.cmd == "direct":
        if args.direct_cmd in {None, "list"}:
            cmd_direct_list(settings)
            return 0
        if args.direct_cmd == "add":
            cmd_direct_add(settings, args.target)
            return 0
        if args.direct_cmd == "remove":
            cmd_direct_remove(settings, args.target)
            return 0
        if args.direct_cmd == "discover":
            cmd_direct_discover(settings, args.target, args.rounds, args.yes)
            return 0
        if args.direct_cmd == "refresh":
            cmd_direct_refresh(settings, args.target, args.rounds)
            return 0

    if args.cmd == "reload-rules":
        st = load_state()
        if not st.get("active"):
            ok("VPN выключен; правила применятся при следующем vpn on.")
            return 0
        activate(settings, choose_config(settings, st["active"]))
        return 0

    if args.cmd == "logs":
        print(journal_tail(max(1, min(args.lines, 1000))), end="")
        return 0

    if args.cmd == "inspect":
        inspect_profile(settings, args.config)
        return 0

    if args.cmd == "doctor":
        cmd_status(settings, False)
        print()
        for path in (
            "/usr/bin/nft", "/usr/bin/ip", "/usr/bin/curl",
            "/dev/net/tun", str(XRAY),
        ):
            print(f"{'OK' if pathlib.Path(path).exists() else 'MISSING'}  {path}")
        if RUNTIME_CONFIG.exists():
            try:
                test_config()
                print("OK  current Xray config")
            except VPNError as exc:
                print(f"FAIL current Xray config: {exc}")
        return 0

    if args.cmd == "core-update":
        core_update(settings)
        return 0

    if args.cmd == "update":
        manifest = str(settings.get("manager_manifest_url") or "")
        if manifest:
            manager_update_manifest(settings, manifest)
            # если обновился — exec, сюда не вернётся
        else:
            warn(
                "Источник обновлений VPN Manager пока не настроен; "
                "проверяю только совместимый Xray core."
            )
        core_update(settings)
        return 0

    if args.cmd == "version":
        print(f"VPN Manager {MANAGER_VERSION}")
        print(f"Safe Xray target: {SAFE_XRAY_VERSION}")
        if XRAY.exists():
            cp = run([XRAY, "version"], check=False, capture=True)
            print((cp.stdout or cp.stderr or "").strip())
        return 0

    if args.cmd == "internal-sync":
        sync_system_files()
        return 0

    if args.cmd == "internal-after-update":
        sync_system_files()
        # Новый код сам решит свой safe core.
        core_update(settings)
        ok("Обновление manager полностью применено.")
        return 0

    if args.cmd == "manager-rollback":
        manager_rollback()
        return 0

    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except VPNError as exc:
        print(color("ERROR:", "1;31"), str(exc), file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\nОтменено.", file=sys.stderr)
        raise SystemExit(130)
