#!/usr/bin/env python3
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
VPNCTL = ROOT / "src" / "vpnctl.py"
README = ROOT / "README.md"
CHANGELOG = ROOT / "CHANGELOG.md"
VERSION = ROOT / "VERSION"
WORKFLOW = ROOT / ".github" / "workflows" / "prepare-0.2.2.yml"


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"anchor count != 1: {old[:80]!r}")
    return text.replace(old, new, 1)


def main() -> None:
    text = VPNCTL.read_text()
    text = replace_once(text, 'MANAGER_VERSION = "0.2.1"', 'MANAGER_VERSION = "0.2.2"')
    text = replace_once(text, 'import os\n', 'import os\nimport pwd\n')

    constants_anchor = 'MAX_DOWNLOAD_BYTES = 150 * 1024 * 1024\n'
    constants = '''MAX_DOWNLOAD_BYTES = 150 * 1024 * 1024\n\nDNS_DISCOVERY_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")\nDNS_SNAPSHOT_BEGIN = "# EVGENIUM-DNS-BEGIN "\nDNS_SNAPSHOT_END = "# EVGENIUM-DNS-END "\n'''
    text = replace_once(text, constants_anchor, constants)

    insert_anchor = 'def build_config(settings: dict, nodes: list[dict], selected: int = 0,\n'
    direct_code = r'''
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

'''
    text = replace_once(text, insert_anchor, direct_code + insert_anchor)

    parser_anchor = '    pr = sub.add_parser("route"); pr.add_argument("target")\n'
    parser = '''    pr = sub.add_parser("route"); pr.add_argument("target")\n\n    pd = sub.add_parser("direct")\n    pdsub = pd.add_subparsers(dest="direct_cmd")\n    pdsub.add_parser("list")\n    pda = pdsub.add_parser("add"); pda.add_argument("target")\n    pdr = pdsub.add_parser("remove"); pdr.add_argument("target")\n    pdd = pdsub.add_parser("discover")\n    pdd.add_argument("target")\n    pdd.add_argument("--rounds", type=int, default=2)\n    pdd.add_argument("--yes", action="store_true")\n    pdf = pdsub.add_parser("refresh")\n    pdf.add_argument("target", nargs="?")\n    pdf.add_argument("--rounds", type=int, default=2)\n'''
    text = replace_once(text, parser_anchor, parser)

    help_anchor = '  vpn route DOMAIN|IP\n  vpn reload-rules\n'
    help_new = '''  vpn route DOMAIN|IP\n  vpn direct list\n  vpn direct add DOMAIN|IP|CIDR\n  vpn direct remove DOMAIN|IP|CIDR\n  vpn direct discover DOMAIN [--yes] [--rounds N]\n  vpn direct refresh [DOMAIN] [--rounds N]\n  vpn reload-rules\n'''
    text = replace_once(text, help_anchor, help_new)

    dispatch_anchor = '    if args.cmd == "route":\n        cmd_route(settings, args.target)\n        return 0\n\n'
    dispatch = '''    if args.cmd == "route":\n        cmd_route(settings, args.target)\n        return 0\n\n    if args.cmd == "direct":\n        if args.direct_cmd in {None, "list"}:\n            cmd_direct_list(settings)\n            return 0\n        if args.direct_cmd == "add":\n            cmd_direct_add(settings, args.target)\n            return 0\n        if args.direct_cmd == "remove":\n            cmd_direct_remove(settings, args.target)\n            return 0\n        if args.direct_cmd == "discover":\n            cmd_direct_discover(settings, args.target, args.rounds, args.yes)\n            return 0\n        if args.direct_cmd == "refresh":\n            cmd_direct_refresh(settings, args.target, args.rounds)\n            return 0\n\n'''
    text = replace_once(text, dispatch_anchor, dispatch)

    self_anchor = '        assert len(v4["inbounds"][0]["settings"]["gateway"]) == 1\n'
    self_new = '''        assert len(v4["inbounds"][0]["settings"]["gateway"]) == 1\n\n        d, exact = _normalize_domain_target("https://Example.COM/path")\n        assert d == "example.com" and exact is False\n        assert _classify_direct_target("1.2.3.4")[1] == "1.2.3.4/32"\n        sample_rules = "1.2.3.0/24\\n"\n        sample_rules = _replace_dns_block_text(sample_rules, "example.com", ["203.0.113.1/32", "2001:db8::1/128"])\n        blocks = _parse_dns_blocks(sample_rules)\n        assert blocks["example.com"] == ["203.0.113.1/32", "2001:db8::1/128"]\n        sample_rules = _replace_dns_block_text(sample_rules, "example.com", None)\n        assert "EVGENIUM-DNS-BEGIN" not in sample_rules\n'''
    text = replace_once(text, self_anchor, self_new)

    VPNCTL.write_text(text)
    VERSION.write_text("0.2.2\n")

    readme = README.read_text()
    readme = readme.replace("Current stable baseline: **0.2.1**.", "Current stable baseline: **0.2.2**.")
    readme = readme.replace(
        "- DIRECT domain/network lists\n",
        "- DIRECT domain/network lists\n- CLI management for DIRECT domains, IPs and CIDRs\n- optional DNS snapshot discovery across the system resolver plus multiple public resolvers\n",
    )
    readme = readme.replace(
        "vpn route example.com\n",
        "vpn route example.com\nvpn direct list\nvpn direct add example.com\nvpn direct add 203.0.113.10\nvpn direct add 203.0.113.0/24\nvpn direct discover example.com\nvpn direct refresh\n",
    )
    readme += '''\n## DIRECT rules\n\nPrefer a domain rule for websites:\n\n```bash\nvpn direct add example.com\n```\n\nIt matches the domain and its subdomains in Xray routing. IP and CIDR exclusions are also supported directly.\n\nFor applications that connect to numeric addresses, `vpn direct discover example.com` can create a DNS snapshot. It queries the system resolver and several public recursive resolvers for A/AAAA records, follows CNAMEs and stores the observed host IPs as `/32` or `/128` DIRECT networks. Re-run `vpn direct refresh` to update managed snapshots.\n\nA DNS snapshot is intentionally described as a snapshot: CDNs can rotate or geo-shard addresses, and the root domain cannot reveal every hostname/API used by a site. Shared CDN IPs are especially broad exclusions because other sites on the same destination IP may also become DIRECT. The command therefore shows the discovered set and asks for confirmation unless `--yes` is supplied.\n'''
    README.write_text(readme)

    changelog = CHANGELOG.read_text()
    entry = '''# Changelog\n\n## 0.2.2\n\n- add `vpn direct` command family\n- add/remove DIRECT domains, individual IPs and CIDRs without editing text files manually\n- add DNS snapshot discovery using system DNS plus Cloudflare, Google and Quad9 recursive resolvers\n- follow DNS CNAMEs and collect both A and AAAA answers\n- managed DNS snapshots can be refreshed with `vpn direct refresh`\n- active VPN rules are re-applied automatically after DIRECT changes\n- warn before broad IP snapshots because CDN IPs may be shared\n\n'''
    if changelog.startswith("# Changelog\n"):
        changelog = entry + changelog[len("# Changelog\n\n"):]
    else:
        changelog = entry + changelog
    CHANGELOG.write_text(changelog)

    subprocess.run(["python", "-m", "py_compile", "src/vpnctl.py", "src/vpnadmin.py", "scripts/build_release.py"], cwd=ROOT, check=True)
    subprocess.run(["python", "src/vpnctl.py", "--self-test"], cwd=ROOT, check=True)
    subprocess.run(["python", "scripts/build_release.py", "--channels", "stable", "testing"], cwd=ROOT, check=True)

    # Bootstrap-only files: keep the final product branch clean.
    with contextlib.suppress(FileNotFoundError):
        Path(__file__).unlink()
    with contextlib.suppress(FileNotFoundError):
        WORKFLOW.unlink()


if __name__ == "__main__":
    import contextlib
    main()
