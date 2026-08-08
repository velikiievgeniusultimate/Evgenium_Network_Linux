#!/usr/bin/env python3
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
VPNCTL = ROOT / "src" / "vpnctl.py"
README = ROOT / "README.md"
CHANGELOG = ROOT / "CHANGELOG.md"
VERSION = ROOT / "VERSION"
WORKFLOW = ROOT / ".github" / "workflows" / "prepare-0.2.3.yml"
SELF = Path(__file__).resolve()

def once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, got {count}")
    return text.replace(old, new, 1)

s = VPNCTL.read_text()

s = once(s, 'MANAGER_VERSION = "0.2.2"', 'MANAGER_VERSION = "0.2.3"', "version")

s = once(
    s,
    'DNS_SNAPSHOT_END = "# EVGENIUM-DNS-END "\n',
    'DNS_SNAPSHOT_END = "# EVGENIUM-DNS-END "\n'
    'SERVER_BYPASS_MARK = 0x45564E01\n'
    'SERVER_BYPASS_RULE_PREF = 50\n',
    "server constants",
)

feature_code = r"""
def _server_ports_path(settings: dict) -> pathlib.Path:
    p = pathlib.Path(settings["owner_home"]) / "Vpn" / "SERVER ports.txt"
    if p.is_symlink():
        fail(f"Отказываюсь изменять symlink: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _parse_server_port_entry(raw: str) -> tuple[str, int] | None:
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    parts = s.split()
    if len(parts) != 2:
        fail(f"Некорректная SERVER port запись: {raw!r}; ожидается `tcp 25565`.")
    proto = parts[0].lower()
    if proto not in {"tcp", "udp"}:
        fail(f"Некорректный протокол SERVER port: {proto!r}.")
    try:
        port = int(parts[1])
    except ValueError:
        fail(f"Некорректный SERVER port: {parts[1]!r}.")
    if not 1 <= port <= 65535:
        fail(f"SERVER port вне диапазона 1..65535: {port}.")
    return proto, port


def read_server_ports(settings: dict) -> set[tuple[str, int]]:
    p = _server_ports_path(settings)
    if not p.exists():
        return set()
    entries: set[tuple[str, int]] = set()
    for raw in p.read_text(errors="strict").splitlines():
        parsed = _parse_server_port_entry(raw)
        if parsed is not None:
            entries.add(parsed)
    return entries


def _write_server_ports(settings: dict, entries: set[tuple[str, int]]) -> None:
    p = _server_ports_path(settings)
    uid, gid = _owner_ids(settings)
    text = "".join(
        f"{proto} {port}\n"
        for proto, port in sorted(entries, key=lambda x: (x[0], x[1]))
    )
    fd, tmpname = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=p.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmpname, 0o600)
        os.chown(tmpname, uid, gid)
        os.replace(tmpname, p)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmpname)


def _server_port_sets(settings: dict) -> tuple[set[int], set[int]]:
    entries = read_server_ports(settings)
    tcp = {port for proto, port in entries if proto == "tcp"}
    udp = {port for proto, port in entries if proto == "udp"}
    return tcp, udp


def _normalize_server_proto(proto: str) -> tuple[str, ...]:
    p = proto.lower()
    if p == "both":
        return ("tcp", "udp")
    if p in {"tcp", "udp"}:
        return (p,)
    fail(f"Некорректный протокол {proto!r}; используй tcp, udp или both.")


def _validate_server_port(port: int) -> int:
    if not 1 <= int(port) <= 65535:
        fail(f"Порт вне диапазона 1..65535: {port}.")
    return int(port)


def _apply_server_ports_if_active(settings: dict) -> None:
    if service_active() and nft_exists():
        info("Применяю SERVER-port bypass без выключения VPN...")
        install_guard(settings)
        ok("SERVER-port bypass применён.")
    else:
        ok("Правило сохранено; применится при следующем vpn on.")


def cmd_port_list(settings: dict) -> None:
    entries = sorted(read_server_ports(settings), key=lambda x: (x[0], x[1]))
    if not entries:
        print("(SERVER ports нет)")
        return
    print("SERVER ports (ответы на входящие соединения идут DIRECT):")
    for proto, port in entries:
        print(f"  {proto.upper():3} {port}")


def cmd_port_add(settings: dict, port: int, proto: str) -> None:
    port = _validate_server_port(port)
    entries = read_server_ports(settings)
    old = set(entries)
    for p in _normalize_server_proto(proto):
        entries.add((p, port))
    if entries == old:
        ok(f"SERVER port уже есть: {proto} {port}")
        return
    _write_server_ports(settings, entries)
    try:
        _apply_server_ports_if_active(settings)
    except Exception:
        _write_server_ports(settings, old)
        if service_active() and nft_exists():
            with contextlib.suppress(Exception):
                install_guard(settings)
        raise
    ok(f"Добавлен SERVER port: {proto} {port}")


def cmd_port_remove(settings: dict, port: int, proto: str) -> None:
    port = _validate_server_port(port)
    entries = read_server_ports(settings)
    old = set(entries)
    for p in _normalize_server_proto(proto):
        entries.discard((p, port))
    if entries == old:
        ok(f"SERVER port не найден: {proto} {port}")
        return
    _write_server_ports(settings, entries)
    try:
        _apply_server_ports_if_active(settings)
    except Exception:
        _write_server_ports(settings, old)
        if service_active() and nft_exists():
            with contextlib.suppress(Exception):
                install_guard(settings)
        raise
    ok(f"Удалён SERVER port: {proto} {port}")


def _nft_port_set(ports: set[int]) -> str:
    return "{ " + ", ".join(str(p) for p in sorted(ports)) + " }"


def render_guard_rules(uid: int, tcp_ports: set[int], udp_ports: set[int]) -> str:
    mark = f"0x{SERVER_BYPASS_MARK:08x}"
    mark_lines = []
    allow_lines = []

    if tcp_ports:
        ports = _nft_port_set(tcp_ports)
        mark_lines.append(
            f"    ct state established tcp sport {ports} meta mark set {mark}"
        )
        allow_lines.append(
            f"    meta mark {mark} ct state established tcp sport {ports} accept"
        )
    if udp_ports:
        ports = _nft_port_set(udp_ports)
        mark_lines.append(
            f"    ct state established udp sport {ports} meta mark set {mark}"
        )
        allow_lines.append(
            f"    meta mark {mark} ct state established udp sport {ports} accept"
        )

    lines = [
        "",
        f"table inet {NFT_TABLE} {{",
    ]
    if mark_lines:
        lines.extend([
            "",
            "  chain server_port_mark {",
            "    type route hook output priority mangle; policy accept;",
            *mark_lines,
            "  }",
        ])
    lines.extend([
        "",
        "  chain output {",
        "    type filter hook output priority filter; policy accept;",
        "",
        '    oifname "lo" accept',
        f"    meta skuid {uid} accept",
    ])
    if allow_lines:
        lines.extend(["", *allow_lines])
    lines.extend([
        "",
        "    ip daddr 127.0.0.0/8 accept",
        "    ip daddr 10.0.0.0/8 accept",
        "    ip daddr 172.16.0.0/12 accept",
        "    ip daddr 192.168.0.0/16 accept",
        "    ip daddr 169.254.0.0/16 accept",
        "    ip daddr 224.0.0.0/4 accept",
        "    ip daddr 255.255.255.255/32 accept",
        "",
        "    ip6 daddr ::1/128 accept",
        "    ip6 daddr fc00::/7 accept",
        "    ip6 daddr fe80::/10 accept",
        "    ip6 daddr ff00::/8 accept",
        "",
        "    udp sport 68 udp dport 67 accept",
        "    udp sport 67 udp dport 68 accept",
        "",
        f'    oifname "{TUN_NAME}" accept',
        "",
        "    reject with icmpx type admin-prohibited",
        "  }",
        "}",
        "",
    ])
    return "\n".join(lines)


def _delete_server_bypass_policy_rules() -> None:
    mark = f"0x{SERVER_BYPASS_MARK:08x}/0xffffffff"
    for family in (["/usr/bin/ip"], ["/usr/bin/ip", "-6"]):
        for _ in range(8):
            cp = run(
                family + [
                    "rule", "del",
                    "pref", str(SERVER_BYPASS_RULE_PREF),
                    "fwmark", mark,
                    "lookup", "main",
                ],
                check=False, capture=True
            )
            if cp.returncode != 0:
                break


def _install_server_bypass_policy_rules(enabled: bool) -> None:
    _delete_server_bypass_policy_rules()
    if not enabled:
        return

    mark = f"0x{SERVER_BYPASS_MARK:08x}/0xffffffff"
    v4 = run(
        [
            "/usr/bin/ip", "rule", "add",
            "pref", str(SERVER_BYPASS_RULE_PREF),
            "fwmark", mark,
            "lookup", "main",
        ],
        check=False, capture=True
    )
    if v4.returncode != 0:
        fail("Не удалось поставить IPv4 policy rule для SERVER ports:\n" + (v4.stderr or ""))

    v6 = run(
        [
            "/usr/bin/ip", "-6", "rule", "add",
            "pref", str(SERVER_BYPASS_RULE_PREF),
            "fwmark", mark,
            "lookup", "main",
        ],
        check=False, capture=True
    )
    if v6.returncode != 0:
        warn("IPv6 SERVER-port policy rule не установлен: " + (v6.stderr or "").strip())
"""

s = once(
    s,
    '\ndef build_config(settings: dict, nodes: list[dict], selected: int = 0,\n',
    "\n" + feature_code + "\ndef build_config(settings: dict, nodes: list[dict], selected: int = 0,\n",
    "insert server port feature",
)

start = s.index("def install_guard(settings: dict) -> None:")
end = s.index("def service_active() -> bool:", start)
new_guard = r"""def install_guard(settings: dict) -> None:
    uid = int(settings["xray_uid"])
    tcp_ports, udp_ports = _server_port_sets(settings)
    rules = render_guard_rules(uid, tcp_ports, udp_ports)

    script = rules
    if nft_exists():
        script = f"delete table inet {NFT_TABLE}\n" + rules

    cp = run(
        ["/usr/bin/nft", "-f", "-"],
        check=False, capture=True, input_text=script
    )
    if cp.returncode != 0:
        fail("Не удалось поставить kill switch:\n" + (cp.stderr or ""))

    _install_server_bypass_policy_rules(bool(tcp_ports or udp_ports))

def remove_guard() -> None:
    run(
        ["/usr/bin/nft", "delete", "table", "inet", NFT_TABLE],
        check=False, capture=True
    )
    _delete_server_bypass_policy_rules()

"""
s = s[:start] + new_guard + s[end:]

status_anchor = """    print(
        f"DIRECT rules: {len(read_direct_sites(settings))} domains / "
        f"{len(read_direct_networks(settings))} networks"
    )
"""
status_new = status_anchor + """    tcp_ports, udp_ports = _server_port_sets(settings)
    print(f"SERVER ports: {len(tcp_ports)} TCP / {len(udp_ports)} UDP")
"""
s = once(s, status_anchor, status_new, "status server ports")

self_anchor = """        sample_rules = _replace_dns_block_text(sample_rules, "example.com", None)
        assert "EVGENIUM-DNS-BEGIN" not in sample_rules
"""
self_new = self_anchor + """
        assert _parse_server_port_entry("tcp 25565") == ("tcp", 25565)
        guard = render_guard_rules(943, {25565}, {19132})
        assert "type route hook output priority mangle" in guard
        assert "tcp sport { 25565 }" in guard
        assert "udp sport { 19132 }" in guard
        assert f"meta mark 0x{SERVER_BYPASS_MARK:08x}" in guard
"""
s = once(s, self_anchor, self_new, "self test")

arg_anchor = """    pdf = pdsub.add_parser("refresh")
    pdf.add_argument("target", nargs="?")
    pdf.add_argument("--rounds", type=int, default=2)
    pre = sub.add_parser("reload-rules")
"""
arg_new = """    pdf = pdsub.add_parser("refresh")
    pdf.add_argument("target", nargs="?")
    pdf.add_argument("--rounds", type=int, default=2)

    pp = sub.add_parser("port")
    ppsub = pp.add_subparsers(dest="port_cmd")
    ppsub.add_parser("list")
    ppa = ppsub.add_parser("add")
    ppa.add_argument("port", type=int)
    ppa.add_argument("proto", nargs="?", default="tcp", choices=["tcp", "udp", "both"])
    ppr = ppsub.add_parser("remove")
    ppr.add_argument("port", type=int)
    ppr.add_argument("proto", nargs="?", default="tcp", choices=["tcp", "udp", "both"])

    pre = sub.add_parser("reload-rules")
"""
s = once(s, arg_anchor, arg_new, "argparse port")

help_anchor = """  vpn direct discover DOMAIN [--yes] [--rounds N]
  vpn direct refresh [DOMAIN] [--rounds N]
  vpn reload-rules
"""
help_new = """  vpn direct discover DOMAIN [--yes] [--rounds N]
  vpn direct refresh [DOMAIN] [--rounds N]
  vpn port list
  vpn port add PORT [tcp|udp|both]
  vpn port remove PORT [tcp|udp|both]
  vpn reload-rules
"""
s = once(s, help_anchor, help_new, "help port")

dispatch_anchor = """        if args.direct_cmd == "refresh":
            cmd_direct_refresh(settings, args.target, args.rounds)
            return 0

    if args.cmd == "reload-rules":
"""
dispatch_new = """        if args.direct_cmd == "refresh":
            cmd_direct_refresh(settings, args.target, args.rounds)
            return 0

    if args.cmd == "port":
        if args.port_cmd in {None, "list"}:
            cmd_port_list(settings)
            return 0
        if args.port_cmd == "add":
            cmd_port_add(settings, args.port, args.proto)
            return 0
        if args.port_cmd == "remove":
            cmd_port_remove(settings, args.port, args.proto)
            return 0

    if args.cmd == "reload-rules":
"""
s = once(s, dispatch_anchor, dispatch_new, "dispatch port")

VPNCTL.write_text(s)
VERSION.write_text("0.2.3\n")

readme = README.read_text()
readme = once(readme, "Current stable baseline: **0.2.2**.", "Current stable baseline: **0.2.3**.", "readme version")
readme = once(
    readme,
    "- optional DNS snapshot discovery across the system resolver plus multiple public resolvers\n",
    "- optional DNS snapshot discovery across the system resolver plus multiple public resolvers\n"
    "- inbound server-port bypass for services hosted behind the full-TUN VPN\n",
    "readme feature",
)
readme = once(
    readme,
    "vpn direct refresh\nvpn reload-rules\n",
    "vpn direct refresh\n"
    "vpn port list\n"
    "vpn port add 25565\n"
    "vpn port remove 25565\n"
    "vpn reload-rules\n",
    "readme commands",
)
readme += """

## Hosting inbound services while the VPN is on

A full-TUN client changes the normal route for locally generated replies. If an
Internet client connects to a service on this machine's public address, the
reply must leave through the normal physical route rather than through the VPN.

For a Minecraft Java server on the default port:

```bash
vpn port add 25565
```

TCP is the default. UDP or both protocols can be selected explicitly:

```bash
vpn port add 19132 udp
vpn port add 27015 both
```

The manager marks only established reply traffic whose local source port matches
a configured SERVER port, policy-routes that marked traffic through the normal
`main` table, and permits only that marked reply through the kill switch. Other
traffic from the same Java/process remains on the VPN.

Persistent SERVER-port entries are stored in:

```text
~/Vpn/SERVER ports.txt
```
"""
README.write_text(readme)

ch = CHANGELOG.read_text()
ch = once(
    ch,
    "# Changelog\n\n",
    "# Changelog\n\n"
    "## 0.2.3\n\n"
    "- add `vpn port add/remove/list` for inbound services behind full-TUN\n"
    "- default `vpn port add PORT` to TCP; support UDP and both\n"
    "- policy-route established server replies through the normal main table\n"
    "- keep unrelated process traffic inside the VPN\n"
    "- persist server-port rules in `~/Vpn/SERVER ports.txt`\n"
    "- atomically replace the nftables kill-switch table during live rule changes\n"
    "- remove tracked Python bytecode from the repository\n\n",
    "changelog",
)
CHANGELOG.write_text(ch)

gitignore = ROOT / ".gitignore"
existing = gitignore.read_text() if gitignore.exists() else ""
for line in ("__pycache__/\n", "*.py[cod]\n"):
    if line not in existing:
        existing += line
gitignore.write_text(existing)

for p in (ROOT / "src" / "__pycache__", ROOT / "scripts" / "__pycache__"):
    shutil.rmtree(p, ignore_errors=True)

WORKFLOW.unlink(missing_ok=True)
SELF.unlink(missing_ok=True)
