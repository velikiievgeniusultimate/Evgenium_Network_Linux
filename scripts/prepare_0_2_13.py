#!/usr/bin/env python3
from __future__ import annotations

import base64
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QML = ROOT / "src" / "evgenium_gui.qml"
VPNCTL = ROOT / "src" / "vpnctl.py"
VERSION = ROOT / "VERSION"
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "README.md"
TEST = ROOT / ".github" / "workflows" / "test.yml"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, replacement: str, label: str) -> str:
    out, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one regex match, got {count}")
    return out


def patch_qml() -> None:
    s = QML.read_text(encoding="utf-8")

    marker = '''                                    C.Label { text: "Версия manager"; color: root.textMuted }\n                                    C.Label {\n                                        text: String(root.state.manager || "—")\n                                        color: root.textMain\n                                        font.weight: Font.DemiBold\n                                    }\n                                }\n\n                                Item { Layout.fillHeight: true }\n'''

    replacement = '''                                    C.Label { text: "Версия manager"; color: root.textMuted }\n                                    C.Label {\n                                        text: String(root.state.manager || "—")\n                                        color: root.textMain\n                                        font.weight: Font.DemiBold\n                                    }\n                                }\n\n                                Rectangle {\n                                    Layout.fillWidth: true\n                                    implicitHeight: 92\n                                    radius: 14\n                                    color: "#f8fafc"\n                                    border.width: 1\n                                    border.color: root.border\n\n                                    RowLayout {\n                                        anchors.fill: parent\n                                        anchors.margins: 16\n                                        spacing: 14\n\n                                        Rectangle {\n                                            width: 46\n                                            height: 46\n                                            radius: 13\n                                            color: Boolean(root.state.waydroid_vpn_effective) ? root.accentSoft : "#eef2f7"\n                                            C.Label {\n                                                anchors.centerIn: parent\n                                                text: "WD"\n                                                color: Boolean(root.state.waydroid_vpn_effective) ? root.accent : root.textMuted\n                                                font.pixelSize: 13\n                                                font.weight: Font.Bold\n                                            }\n                                        }\n\n                                        ColumnLayout {\n                                            Layout.fillWidth: true\n                                            spacing: 4\n                                            C.Label {\n                                                text: "VPN для Waydroid"\n                                                color: root.textMain\n                                                font.pixelSize: 15\n                                                font.weight: Font.DemiBold\n                                            }\n                                            C.Label {\n                                                Layout.fillWidth: true\n                                                text: !Boolean(root.state.active)\n                                                    ? "Общий VPN выключен — Waydroid тоже работает без VPN."\n                                                    : (Boolean(root.state.waydroid_vpn_effective)\n                                                        ? "Трафик Waydroid идёт через E-VPN."\n                                                        : "Waydroid использует прямой интернет в обход E-VPN.")\n                                                color: root.textMuted\n                                                font.pixelSize: 12\n                                                wrapMode: Text.WordWrap\n                                            }\n                                        }\n\n                                        Item {\n                                            id: waydroidSwitch\n                                            Layout.preferredWidth: 48\n                                            Layout.preferredHeight: 26\n                                            opacity: Boolean(root.state.active) && !root.busy ? 1.0 : 0.45\n\n                                            Rectangle {\n                                                anchors.fill: parent\n                                                radius: height / 2\n                                                color: Boolean(root.state.waydroid_vpn_effective) ? root.accent : "#cbd5e1"\n                                            }\n                                            Rectangle {\n                                                width: 20\n                                                height: 20\n                                                radius: 10\n                                                y: 3\n                                                x: Boolean(root.state.waydroid_vpn_effective) ? waydroidSwitch.width - width - 3 : 3\n                                                color: "white"\n                                                Behavior on x { NumberAnimation { duration: 120 } }\n                                            }\n                                            MouseArea {\n                                                anchors.fill: parent\n                                                enabled: Boolean(root.state.active) && !root.busy\n                                                cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor\n                                                onClicked: root.action({\n                                                    action: "waydroid_vpn_set",\n                                                    target: Boolean(root.state.waydroid_vpn_effective) ? "off" : "on"\n                                                })\n                                            }\n                                        }\n                                    }\n                                }\n\n                                Item { Layout.fillHeight: true }\n'''

    s = replace_once(s, marker, replacement, "Waydroid GUI card")
    QML.write_text(s, encoding="utf-8")


def patch_vpnctl() -> None:
    s = VPNCTL.read_text(encoding="utf-8")

    s = replace_once(s, 'MANAGER_VERSION = "0.2.12"', 'MANAGER_VERSION = "0.2.13"', "manager version")
    s = replace_once(
        s,
        'SERVER_BYPASS_TABLE = 51820\n',
        'SERVER_BYPASS_TABLE = 51820\n'
        'WAYDROID_IFACE = "waydroid0"\n'
        'WAYDROID_BYPASS_MARK = 0x45564E02\n'
        'WAYDROID_BYPASS_RULE_PREF = 51\n'
        'WAYDROID_BYPASS_TABLE = 51821\n',
        "Waydroid constants",
    )

    migration_marker = '    required = (\n'
    migration = '''    # 0.2.13 adds a persistent Waydroid VPN preference.  True preserves\n    # the historical behavior: Waydroid follows the main VPN while it is active.\n    if "waydroid_vpn_enabled" not in data:\n        data["waydroid_vpn_enabled"] = True\n        save_settings(data)\n\n'''
    if '"waydroid_vpn_enabled" not in data' not in s:
        s = replace_once(s, migration_marker, migration + migration_marker, "Waydroid settings migration")
    s = replace_once(
        s,
        '        "direct_networks", "direct_apps", "xray_uid", "xray_gid",\n',
        '        "direct_networks", "direct_apps", "xray_uid", "xray_gid",\n        "waydroid_vpn_enabled",\n',
        "Waydroid required setting",
    )

    old_render_pattern = r'''def render_guard_rules\(uid: int, tcp_ports: set\[int\], udp_ports: set\[int\]\) -> str:\n.*?\n\ndef _delete_server_bypass_policy_rules'''
    new_render = '''def render_guard_rules(uid: int, tcp_ports: set[int], udp_ports: set[int],\n                       waydroid_direct: bool = False,\n                       waydroid_iface: str = WAYDROID_IFACE) -> str:\n    server_mark = f"0x{SERVER_BYPASS_MARK:08x}"\n    waydroid_mark = f"0x{WAYDROID_BYPASS_MARK:08x}"\n    mark_lines = []\n    allow_lines = []\n\n    if tcp_ports:\n        ports = _nft_port_set(tcp_ports)\n        mark_lines.append(\n            f"    ct state established tcp sport {ports} meta mark set {server_mark}"\n        )\n        allow_lines.append(\n            f"    meta mark {server_mark} ct state established tcp sport {ports} accept"\n        )\n    if udp_ports:\n        ports = _nft_port_set(udp_ports)\n        mark_lines.append(\n            f"    ct state established udp sport {ports} meta mark set {server_mark}"\n        )\n        allow_lines.append(\n            f"    meta mark {server_mark} ct state established udp sport {ports} accept"\n        )\n\n    lines = [\n        "",\n        f"table inet {NFT_TABLE} {{",\n    ]\n    if mark_lines:\n        lines.extend([\n            "",\n            "  chain server_port_mark {",\n            "    type route hook output priority mangle; policy accept;",\n            *mark_lines,\n            "  }",\n        ])\n    if waydroid_direct:\n        lines.extend([\n            "",\n            "  chain waydroid_mark {",\n            "    type filter hook prerouting priority mangle; policy accept;",\n            f'    meta nfproto ipv4 iifname "{waydroid_iface}" meta mark set {waydroid_mark}',\n            "  }",\n        ])\n\n    lines.extend([\n        "",\n        "  chain output {",\n        "    type filter hook output priority filter; policy accept;",\n        "",\n        '    oifname "lo" accept',\n        f"    meta skuid {uid} accept",\n    ])\n    if allow_lines:\n        lines.extend(["", *allow_lines])\n    lines.extend([\n        "",\n        "    ip daddr 127.0.0.0/8 accept",\n        "    ip daddr 10.0.0.0/8 accept",\n        "    ip daddr 172.16.0.0/12 accept",\n        "    ip daddr 192.168.0.0/16 accept",\n        "    ip daddr 169.254.0.0/16 accept",\n        "    ip daddr 224.0.0.0/4 accept",\n        "    ip daddr 255.255.255.255/32 accept",\n        "",\n        "    ip6 daddr ::1/128 accept",\n        "    ip6 daddr fc00::/7 accept",\n        "    ip6 daddr fe80::/10 accept",\n        "    ip6 daddr ff00::/8 accept",\n        "",\n        "    udp sport 68 udp dport 67 accept",\n        "    udp sport 67 udp dport 68 accept",\n        "",\n        f'    oifname "{TUN_NAME}" accept',\n        "",\n        "    reject with icmpx type admin-prohibited",\n        "  }",\n        "",\n        "  chain forward {",\n        "    type filter hook forward priority filter; policy accept;",\n        "",\n        f'    iifname "{waydroid_iface}" ip daddr 10.0.0.0/8 accept',\n        f'    iifname "{waydroid_iface}" ip daddr 172.16.0.0/12 accept',\n        f'    iifname "{waydroid_iface}" ip daddr 192.168.0.0/16 accept',\n        f'    iifname "{waydroid_iface}" ip daddr 169.254.0.0/16 accept',\n    ])\n    if waydroid_direct:\n        lines.append(\n            f'    iifname "{waydroid_iface}" meta mark {waydroid_mark} accept'\n        )\n    lines.extend([\n        f'    iifname "{waydroid_iface}" oifname "{TUN_NAME}" accept',\n        f'    iifname "{waydroid_iface}" reject with icmpx type admin-prohibited',\n        "  }",\n        "}",\n        "",\n    ])\n    return "\\n".join(lines)\n\n\ndef _delete_server_bypass_policy_rules'''
    s = regex_once(s, old_render_pattern, new_render, "render guard")

    waydroid_policy = '''\n\ndef _delete_waydroid_bypass_policy_rules() -> None:\n    mark = f"0x{WAYDROID_BYPASS_MARK:08x}/0xffffffff"\n    for _ in range(8):\n        cp = run(\n            [\n                "/usr/bin/ip", "-4", "rule", "del",\n                "pref", str(WAYDROID_BYPASS_RULE_PREF),\n                "fwmark", mark,\n                "lookup", str(WAYDROID_BYPASS_TABLE),\n            ],\n            check=False, capture=True\n        )\n        if cp.returncode != 0:\n            break\n    run(\n        [\n            "/usr/bin/ip", "-4", "route", "flush",\n            "table", str(WAYDROID_BYPASS_TABLE),\n        ],\n        check=False, capture=True\n    )\n\n\ndef _populate_waydroid_bypass_table() -> str | None:\n    iface, routes = _physical_routes_from_main(4)\n    run(\n        [\n            "/usr/bin/ip", "-4", "route", "flush",\n            "table", str(WAYDROID_BYPASS_TABLE),\n        ],\n        check=False, capture=True\n    )\n    if not iface:\n        return None\n\n    for route in routes:\n        dst = str(route.get("dst", "default"))\n        cmd = [\n            "/usr/bin/ip", "-4", "route", "replace",\n            "table", str(WAYDROID_BYPASS_TABLE), dst,\n        ]\n        gateway = route.get("gateway")\n        if gateway:\n            cmd += ["via", str(gateway)]\n        cmd += ["dev", iface]\n        prefsrc = route.get("prefsrc")\n        if prefsrc:\n            cmd += ["src", str(prefsrc)]\n        metric = route.get("metric")\n        if metric is not None:\n            cmd += ["metric", str(metric)]\n        cp = run(cmd, check=False, capture=True)\n        if cp.returncode != 0:\n            fail(\n                f"Не удалось скопировать физический маршрут в table {WAYDROID_BYPASS_TABLE}: "\n                + (cp.stderr or "").strip()\n            )\n    return iface\n\n\ndef _verify_waydroid_bypass_route(iface: str) -> None:\n    cp = run(\n        [\n            "/usr/bin/ip", "-4", "route", "get", "1.1.1.1",\n            "mark", f"0x{WAYDROID_BYPASS_MARK:08x}",\n        ],\n        check=False, capture=True\n    )\n    out = (cp.stdout or "").strip()\n    if cp.returncode != 0 or TUN_NAME in out or f"dev {iface}" not in out:\n        fail(\n            "Waydroid DIRECT policy route не обходит TUN. "\n            f"Ожидался dev {iface}, получено: {out or (cp.stderr or '').strip()}"\n        )\n\n\ndef _install_waydroid_bypass_policy_rules(enabled: bool) -> None:\n    _delete_waydroid_bypass_policy_rules()\n    if not enabled:\n        return\n\n    iface = _populate_waydroid_bypass_table()\n    if not iface:\n        fail("Не найден физический IPv4 default route для Waydroid DIRECT.")\n\n    cp = run(\n        [\n            "/usr/bin/ip", "-4", "rule", "add",\n            "pref", str(WAYDROID_BYPASS_RULE_PREF),\n            "fwmark", f"0x{WAYDROID_BYPASS_MARK:08x}/0xffffffff",\n            "lookup", str(WAYDROID_BYPASS_TABLE),\n        ],\n        check=False, capture=True\n    )\n    if cp.returncode != 0:\n        fail("Не удалось поставить IPv4 policy rule для Waydroid DIRECT:\\n" + (cp.stderr or ""))\n    _verify_waydroid_bypass_route(iface)\n\n'''
    s = replace_once(s, '\ndef build_config(settings: dict, nodes: list[dict], selected: int = 0,\n', waydroid_policy + '\ndef build_config(settings: dict, nodes: list[dict], selected: int = 0,\n', "Waydroid policy functions")

    old_install = '''def install_guard(settings: dict) -> None:\n    uid = int(settings["xray_uid"])\n    tcp_ports, udp_ports = _server_port_sets(settings)\n    rules = render_guard_rules(uid, tcp_ports, udp_ports)\n\n    script = rules\n'''
    new_install = '''def install_guard(settings: dict) -> None:\n    uid = int(settings["xray_uid"])\n    tcp_ports, udp_ports = _server_port_sets(settings)\n    waydroid_direct = not bool(settings.get("waydroid_vpn_enabled", True))\n    rules = render_guard_rules(\n        uid, tcp_ports, udp_ports,\n        waydroid_direct=waydroid_direct,\n        waydroid_iface=WAYDROID_IFACE,\n    )\n\n    script = rules\n'''
    s = replace_once(s, old_install, new_install, "install_guard Waydroid state")
    s = replace_once(
        s,
        '    _install_server_bypass_policy_rules(bool(tcp_ports or udp_ports))\n\ndef remove_guard() -> None:\n',
        '    _install_server_bypass_policy_rules(bool(tcp_ports or udp_ports))\n    _install_waydroid_bypass_policy_rules(waydroid_direct)\n\ndef remove_guard() -> None:\n',
        "install Waydroid policy",
    )
    s = replace_once(
        s,
        '    _delete_server_bypass_policy_rules()\n\ndef service_active() -> bool:\n',
        '    _delete_server_bypass_policy_rules()\n    _delete_waydroid_bypass_policy_rules()\n\ndef service_active() -> bool:\n',
        "remove Waydroid policy",
    )

    setter = '''\n\ndef cmd_waydroid_vpn_set(settings: dict, enabled: bool) -> None:\n    old_enabled = bool(settings.get("waydroid_vpn_enabled", True))\n    enabled = bool(enabled)\n    if old_enabled == enabled:\n        return\n\n    settings["waydroid_vpn_enabled"] = enabled\n    save_settings(settings)\n    if not service_active():\n        return\n\n    try:\n        install_guard(settings)\n    except Exception:\n        settings["waydroid_vpn_enabled"] = old_enabled\n        save_settings(settings)\n        with contextlib.suppress(Exception):\n            install_guard(settings)\n        raise\n\n'''
    s = replace_once(s, '\ndef _server_ports_path(settings: dict) -> pathlib.Path:\n', setter + '\ndef _server_ports_path(settings: dict) -> pathlib.Path:\n', "Waydroid setter")

    s = replace_once(
        s,
        'def _ui_state_payload(settings: dict) -> dict:\n    state = _status_payload(settings)\n',
        'def _ui_state_payload(settings: dict) -> dict:\n    state = _status_payload(settings)\n    waydroid_preference = bool(settings.get("waydroid_vpn_enabled", True))\n    waydroid_effective = bool(state.get("active") and waydroid_preference)\n',
        "Waydroid UI state prelude",
    )
    s = replace_once(
        s,
        '            "config_dir": str(settings["config_dir"]),\n',
        '            "config_dir": str(settings["config_dir"]),\n            "waydroid_vpn_preference": waydroid_preference,\n            "waydroid_vpn_effective": waydroid_effective,\n            "waydroid_present": pathlib.Path(f"/sys/class/net/{WAYDROID_IFACE}").exists(),\n            "waydroid_iface": WAYDROID_IFACE,\n',
        "Waydroid UI state fields",
    )

    action_marker = '''    if action == "profile_activate":\n'''
    action_branch = '''    if action == "waydroid_vpn_set":\n        mode = _ui_payload_target(payload).strip().lower()\n        if mode not in {"on", "off"}:\n            fail("Waydroid VPN ожидает on или off.")\n        cmd_waydroid_vpn_set(settings, mode == "on")\n        return\n    if action == "profile_activate":\n'''
    s = replace_once(s, action_marker, action_branch, "Waydroid UI action")

    old_update = '''        # Migrate an active 0.2.3 rule -> main without cycling the VPN.\n        if service_active() and nft_exists() and read_server_ports(settings):\n            info("Мигрирую SERVER-port bypass на выделенную физическую routing table...")\n            install_guard(settings)\n'''
    new_update = '''        # Refresh the active guard in-place so newly added policy features\n        # (including the Waydroid switch) take effect without cycling the VPN.\n        if service_active() and nft_exists():\n            info("Обновляю активный kill switch и policy routing...")\n            install_guard(settings)\n'''
    s = replace_once(s, old_update, new_update, "after-update guard refresh")

    selftest_old = '''        guard = render_guard_rules(943, {25565}, {19132})\n        assert "type route hook output priority mangle" in guard\n        assert "tcp sport { 25565 }" in guard\n        assert "udp sport { 19132 }" in guard\n        assert f"meta mark 0x{SERVER_BYPASS_MARK:08x}" in guard\n'''
    selftest_new = '''        guard = render_guard_rules(943, {25565}, {19132})\n        assert "type route hook output priority mangle" in guard\n        assert "tcp sport { 25565 }" in guard\n        assert "udp sport { 19132 }" in guard\n        assert f"meta mark 0x{SERVER_BYPASS_MARK:08x}" in guard\n        assert f'iifname "{WAYDROID_IFACE}" oifname "{TUN_NAME}" accept' in guard\n        waydroid_guard = render_guard_rules(943, set(), set(), waydroid_direct=True)\n        assert "chain waydroid_mark" in waydroid_guard\n        assert f"meta mark 0x{WAYDROID_BYPASS_MARK:08x}" in waydroid_guard\n        assert f'iifname "{WAYDROID_IFACE}" reject with icmpx type admin-prohibited' in waydroid_guard\n'''
    s = replace_once(s, selftest_old, selftest_new, "Waydroid self-test")

    s = replace_once(
        s,
        '        assert "Профили VPN" in gui_qml\n        assert \'action: "profile_activate"\' in gui_qml\n',
        '        assert "Профили VPN" in gui_qml\n        assert \'action: "profile_activate"\' in gui_qml\n        assert "VPN для Waydroid" in gui_qml\n        assert \'action: "waydroid_vpn_set"\' in gui_qml\n',
        "Waydroid GUI self-test",
    )

    qml_b64 = base64.b64encode(QML.read_bytes()).decode("ascii")
    chunks = [qml_b64[i:i + 100] for i in range(0, len(qml_b64), 100)]
    replacement = "STANDALONE_GUI_QML_B64 = (\n" + "".join(f"    {chunk!r}\n" for chunk in chunks) + ")\n"
    s = regex_once(
        s,
        r"STANDALONE_GUI_QML_B64 = \(\n.*?\n\)\n(?=\n[A-Z_]+|\ndef |\nclass |\nGUI_DESKTOP_ENTRY)",
        replacement.rstrip("\n"),
        "embedded QML",
    )

    VPNCTL.write_text(s, encoding="utf-8")


def patch_docs_and_tests() -> None:
    VERSION.write_text("0.2.13\n", encoding="utf-8")

    changelog = CHANGELOG.read_text(encoding="utf-8")
    entry = '''# Changelog\n\n## 0.2.13\n\n- add an independent `VPN для Waydroid` switch in the standalone E-VPN application\n- when the main VPN is off, Waydroid is always direct regardless of the stored Waydroid preference\n- when the main VPN is on, Waydroid can either follow Xray TUN or use a dedicated IPv4 physical policy route\n- add a Waydroid-specific fail-closed FORWARD guard so a TUN failure cannot silently leak Waydroid traffic\n- apply Waydroid changes live without restarting Xray and keep the Plasma widget intentionally unchanged\n\n'''
    if not changelog.startswith("# Changelog\n\n"):
        raise SystemExit("unexpected changelog header")
    CHANGELOG.write_text(entry + changelog[len("# Changelog\n\n"):], encoding="utf-8")

    readme = README.read_text(encoding="utf-8")
    readme = readme.replace("Current stable baseline: **0.2.12**.", "Current stable baseline: **0.2.13**.")
    README.write_text(readme, encoding="utf-8")

    test = TEST.read_text(encoding="utf-8")
    test = replace_once(
        test,
        "          grep -F 'profile_activate' src/vpnctl.py\n",
        "          grep -F 'profile_activate' src/vpnctl.py\n          grep -F 'waydroid_vpn_set' src/vpnctl.py\n          grep -F 'VPN для Waydroid' src/evgenium_gui.qml\n",
        "GUI contract Waydroid checks",
    )
    old_nft = '''          python - <<'PY' > /tmp/vpn-guard.nft\n          import importlib.util\n          spec = importlib.util.spec_from_file_location('vpnctl', 'src/vpnctl.py')\n          mod = importlib.util.module_from_spec(spec)\n          spec.loader.exec_module(mod)\n          print(mod.render_guard_rules(943, {25565}, {19132}))\n          PY\n          sudo nft -c -f /tmp/vpn-guard.nft\n          ip rule help 2>&1 | grep -F 'fwmark'\n'''
    new_nft = '''          python - <<'PY'\n          import importlib.util\n          from pathlib import Path\n          spec = importlib.util.spec_from_file_location('vpnctl', 'src/vpnctl.py')\n          mod = importlib.util.module_from_spec(spec)\n          spec.loader.exec_module(mod)\n          Path('/tmp/vpn-guard.nft').write_text(mod.render_guard_rules(943, {25565}, {19132}))\n          Path('/tmp/vpn-guard-waydroid.nft').write_text(mod.render_guard_rules(943, set(), set(), waydroid_direct=True))\n          PY\n          sudo nft -c -f /tmp/vpn-guard.nft\n          sudo nft -c -f /tmp/vpn-guard-waydroid.nft\n          ip rule help 2>&1 | grep -F 'fwmark'\n'''
    test = replace_once(test, old_nft, new_nft, "nft Waydroid validation")

    insert_after = '''          print('dedicated bypass table wiring OK')\n          PY\n'''
    waydroid_step = '''          print('dedicated bypass table wiring OK')\n          PY\n      - name: Validate Waydroid bypass policy\n        run: |\n          grep -F 'WAYDROID_BYPASS_TABLE = 51821' src/vpnctl.py\n          grep -F 'WAYDROID_BYPASS_MARK = 0x45564E02' src/vpnctl.py\n          grep -F 'WAYDROID_IFACE = "waydroid0"' src/vpnctl.py\n          grep -F '_install_waydroid_bypass_policy_rules(waydroid_direct)' src/vpnctl.py\n          grep -F 'chain waydroid_mark' src/vpnctl.py\n          grep -F 'chain forward' src/vpnctl.py\n'''
    test = replace_once(test, insert_after, waydroid_step, "Waydroid policy CI step")
    TEST.write_text(test, encoding="utf-8")


def main() -> None:
    patch_qml()
    patch_vpnctl()
    patch_docs_and_tests()


if __name__ == "__main__":
    main()
