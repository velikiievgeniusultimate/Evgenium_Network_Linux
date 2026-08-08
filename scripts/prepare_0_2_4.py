#!/usr/bin/env python3
from pathlib import Path

VERSION = "0.2.4"

NEW_POLICY_BLOCK = r'''def _delete_server_bypass_policy_rules() -> None:
    mark = f"0x{SERVER_BYPASS_MARK:08x}/0xffffffff"
    # Remove both the broken 0.2.3 rule -> main and the fixed rule -> dedicated table.
    for famflag in ("-4", "-6"):
        for table in ("main", str(SERVER_BYPASS_TABLE)):
            for _ in range(8):
                cp = run(
                    [
                        "/usr/bin/ip", famflag, "rule", "del",
                        "pref", str(SERVER_BYPASS_RULE_PREF),
                        "fwmark", mark,
                        "lookup", table,
                    ],
                    check=False, capture=True
                )
                if cp.returncode != 0:
                    break
        run(
            [
                "/usr/bin/ip", famflag, "route", "flush",
                "table", str(SERVER_BYPASS_TABLE),
            ],
            check=False, capture=True
        )


def _physical_routes_from_main(family: int) -> tuple[str | None, list[dict]]:
    famflag = "-4" if family == 4 else "-6"
    cp = run(
        ["/usr/bin/ip", "-j", famflag, "route", "show", "table", "main"],
        check=False, capture=True
    )
    if cp.returncode != 0:
        return None, []
    try:
        routes = json.loads(cp.stdout or "[]")
    except json.JSONDecodeError:
        return None, []
    if not isinstance(routes, list):
        return None, []

    defaults = [
        r for r in routes
        if isinstance(r, dict)
        and r.get("dst", "default") == "default"
        and r.get("dev")
        and r.get("dev") != TUN_NAME
        and r.get("type", "unicast") == "unicast"
    ]
    if not defaults:
        return None, []

    def metric(route: dict) -> int:
        try:
            return int(route.get("metric", 0))
        except (TypeError, ValueError):
            return 0

    chosen = min(defaults, key=metric)
    iface = str(chosen["dev"])
    selected = [
        r for r in routes
        if isinstance(r, dict)
        and r.get("dev") == iface
        and r.get("type", "unicast") == "unicast"
    ]
    # Install connected/link routes before the default route so its gateway is reachable.
    selected.sort(key=lambda r: (r.get("dst", "default") == "default", metric(r)))
    return iface, selected


def _populate_server_bypass_table(family: int) -> str | None:
    famflag = "-4" if family == 4 else "-6"
    iface, routes = _physical_routes_from_main(family)
    run(
        [
            "/usr/bin/ip", famflag, "route", "flush",
            "table", str(SERVER_BYPASS_TABLE),
        ],
        check=False, capture=True
    )
    if not iface:
        return None

    for route in routes:
        dst = str(route.get("dst", "default"))
        cmd = [
            "/usr/bin/ip", famflag, "route", "replace",
            "table", str(SERVER_BYPASS_TABLE), dst,
        ]
        gateway = route.get("gateway")
        if gateway:
            cmd += ["via", str(gateway)]
        cmd += ["dev", iface]
        prefsrc = route.get("prefsrc")
        if prefsrc:
            cmd += ["src", str(prefsrc)]
        metric = route.get("metric")
        if metric is not None:
            cmd += ["metric", str(metric)]
        cp = run(cmd, check=False, capture=True)
        if cp.returncode != 0:
            fail(
                f"Не удалось скопировать физический маршрут в table {SERVER_BYPASS_TABLE}: "
                + (cp.stderr or "").strip()
            )
    return iface


def _verify_server_bypass_route(family: int, iface: str) -> None:
    famflag = "-4" if family == 4 else "-6"
    target = "1.1.1.1" if family == 4 else "2606:4700:4700::1111"
    cp = run(
        [
            "/usr/bin/ip", famflag, "route", "get", target,
            "mark", f"0x{SERVER_BYPASS_MARK:08x}",
        ],
        check=False, capture=True
    )
    out = (cp.stdout or "").strip()
    if cp.returncode != 0 or TUN_NAME in out or f"dev {iface}" not in out:
        fail(
            "SERVER-port policy route не обходит TUN. "
            f"Ожидался dev {iface}, получено: {out or (cp.stderr or '').strip()}"
        )


def _install_server_bypass_policy_rules(enabled: bool) -> None:
    _delete_server_bypass_policy_rules()
    if not enabled:
        return

    mark = f"0x{SERVER_BYPASS_MARK:08x}/0xffffffff"

    iface4 = _populate_server_bypass_table(4)
    if not iface4:
        fail("Не найден физический IPv4 default route для SERVER-port bypass.")
    v4 = run(
        [
            "/usr/bin/ip", "-4", "rule", "add",
            "pref", str(SERVER_BYPASS_RULE_PREF),
            "fwmark", mark,
            "lookup", str(SERVER_BYPASS_TABLE),
        ],
        check=False, capture=True
    )
    if v4.returncode != 0:
        fail("Не удалось поставить IPv4 policy rule для SERVER ports:\n" + (v4.stderr or ""))
    _verify_server_bypass_route(4, iface4)

    # IPv6 is best effort: the host may have no physical IPv6 default route at all.
    iface6 = _populate_server_bypass_table(6)
    if iface6:
        v6 = run(
            [
                "/usr/bin/ip", "-6", "rule", "add",
                "pref", str(SERVER_BYPASS_RULE_PREF),
                "fwmark", mark,
                "lookup", str(SERVER_BYPASS_TABLE),
            ],
            check=False, capture=True
        )
        if v6.returncode == 0:
            _verify_server_bypass_route(6, iface6)
        else:
            warn("IPv6 SERVER-port policy rule не установлен: " + (v6.stderr or "").strip())

'''


def main() -> None:
    p = Path("src/vpnctl.py")
    s = p.read_text()
    s = s.replace('MANAGER_VERSION = "0.2.3"', f'MANAGER_VERSION = "{VERSION}"', 1)
    marker = "SERVER_BYPASS_RULE_PREF = 50\n"
    if "SERVER_BYPASS_TABLE = 51820" not in s:
        if marker not in s:
            raise SystemExit("constant marker not found")
        s = s.replace(marker, marker + "SERVER_BYPASS_TABLE = 51820\n", 1)

    start = s.index("def _delete_server_bypass_policy_rules() -> None:")
    end = s.index("def build_config(", start)
    s = s[:start] + NEW_POLICY_BLOCK + s[end:]

    old_after = '''    if args.cmd == "internal-after-update":
        sync_system_files()
        # Новый код сам решит свой safe core.
        core_update(settings)
        ok("Обновление manager полностью применено.")
        return 0
'''
    new_after = '''    if args.cmd == "internal-after-update":
        sync_system_files()
        # Migrate an active 0.2.3 rule -> main without cycling the VPN.
        if service_active() and nft_exists() and read_server_ports(settings):
            info("Мигрирую SERVER-port bypass на выделенную физическую routing table...")
            install_guard(settings)
        # Новый код сам решит свой safe core.
        core_update(settings)
        ok("Обновление manager полностью применено.")
        return 0
'''
    if old_after not in s:
        raise SystemExit("internal-after-update marker not found")
    s = s.replace(old_after, new_after, 1)
    p.write_text(s)

    Path("VERSION").write_text(VERSION + "\n")

    ch = Path("CHANGELOG.md")
    c = ch.read_text()
    entry = '''## 0.2.4

- fix SERVER-port bypass: 0.2.3 incorrectly sent the mark back to `main`, whose preferred default is still `xraytun`
- build dedicated routing table 51820 from the physical interface routes
- send marked established server replies to table 51820 instead of `main`
- verify the marked route resolves to the physical interface and never to `xraytun`
- migrate an active 0.2.3 installation during `vpn update` without requiring VPN off/on

'''
    if "## 0.2.4" not in c:
        c = c.replace("# Changelog\n\n", "# Changelog\n\n" + entry, 1)
        ch.write_text(c)

    r = Path("README.md")
    t = r.read_text().replace(
        "Current stable baseline: **0.2.3**.",
        "Current stable baseline: **0.2.4**.",
        1,
    )
    r.write_text(t)


if __name__ == "__main__":
    main()
