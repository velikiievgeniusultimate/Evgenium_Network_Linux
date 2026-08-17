#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
VPNCTL = ROOT / "src" / "vpnctl.py"
PLASMA = ROOT / "scripts" / "plasma_0_2_9"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, repl: str, label: str) -> str:
    new, count = re.subn(pattern, lambda _m: repl, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one regex match, got {count}")
    return new


def qml_constant(name: str, filename: str) -> str:
    text = (PLASMA / filename).read_text()
    if "'''" in text:
        raise SystemExit(f"{filename}: triple single quote is not allowed")
    return f"{name} = r'''{text}'''\n"


UI_BLOCK = r'''def _ui_direct_network_state(settings: dict) -> tuple[list[str], list[dict]]:
    p = _safe_direct_path(settings, "direct_networks")
    raw = p.read_text() if p.exists() else ""
    blocks = _parse_dns_blocks(raw)
    block_ips = {value for values in blocks.values() for value in values}
    manual: set[str] = set()
    for raw_line in raw.splitlines():
        value = raw_line.strip()
        if not value or value.startswith("#") or value in block_ips:
            continue
        with contextlib.suppress(ValueError):
            manual.add(ipaddress.ip_network(value, strict=False).compressed)
    snapshots = [
        {"domain": domain, "networks": list(values)}
        for domain, values in sorted(blocks.items())
    ]
    return sorted(
        manual,
        key=lambda value: (
            ipaddress.ip_network(value, strict=False).version,
            int(ipaddress.ip_network(value, strict=False).network_address),
            ipaddress.ip_network(value, strict=False).prefixlen,
        ),
    ), snapshots


def _direct_app_rule_matches(rule: str, process_name: str, executable: str) -> bool:
    if "/" not in rule:
        return rule == process_name
    if rule.endswith("/"):
        return executable.startswith(rule)
    return executable == rule


def _running_user_applications(settings: dict) -> list[dict]:
    uid, _gid = _owner_ids(settings)
    rules = read_direct_apps(settings)
    grouped: dict[tuple[str, str], dict] = {}

    try:
        proc_entries = list(os.scandir("/proc"))
    except OSError:
        return []

    for entry in proc_entries:
        if not entry.name.isdigit():
            continue
        proc_dir = pathlib.Path("/proc") / entry.name
        try:
            if proc_dir.stat().st_uid != uid:
                continue
            name = (proc_dir / "comm").read_text(errors="replace").strip()
            executable = os.readlink(proc_dir / "exe")
        except (OSError, PermissionError):
            continue

        if executable.endswith(" (deleted)"):
            executable = executable[:-10]
        if not name or not executable.startswith("/"):
            continue

        key = (name, executable)
        item = grouped.setdefault(
            key,
            {"name": name, "exe": executable, "count": 0, "excluded": False},
        )
        item["count"] += 1

    out = []
    for item in grouped.values():
        item["excluded"] = any(
            _direct_app_rule_matches(rule, str(item["name"]), str(item["exe"]))
            for rule in rules
        )
        out.append(item)

    return sorted(
        out,
        key=lambda item: (
            0 if item["excluded"] else 1,
            str(item["name"]).lower(),
            str(item["exe"]).lower(),
        ),
    )


def _ui_state_payload(settings: dict) -> dict:
    state = _status_payload(settings)
    manual_networks, snapshots = _ui_direct_network_state(settings)
    tcp_ports, udp_ports = _server_port_sets(settings)
    ports = (
        [{"proto": "tcp", "port": port} for port in sorted(tcp_ports)]
        + [{"proto": "udp", "port": port} for port in sorted(udp_ports)]
    )
    state.update(
        {
            "applications": read_direct_apps(settings),
            "domains": [
                ("=" if kind == "full" else "") + domain
                for kind, domain in read_direct_sites(settings)
            ],
            "networks": manual_networks,
            "dns_snapshots": snapshots,
            "server_ports": ports,
        }
    )
    return state


def cmd_ui_state(settings: dict) -> None:
    print(json.dumps(_ui_state_payload(settings), ensure_ascii=False, separators=(",", ":")))


def cmd_ui_running(settings: dict) -> None:
    print(
        json.dumps(
            {"applications": _running_user_applications(settings)},
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )


def _decode_ui_action_payload(token: str) -> dict:
    if not token or len(token) > 16384:
        fail("Некорректный UI payload.")
    try:
        encoded = base64.b64decode(token.encode("ascii"), validate=True).decode("ascii")
        payload = json.loads(urllib.parse.unquote(encoded))
    except Exception as exc:
        fail(f"Некорректный UI payload: {exc}")
    if not isinstance(payload, dict):
        fail("UI payload должен быть JSON object.")
    return payload


def _ui_payload_target(payload: dict) -> str:
    target = payload.get("target")
    if not isinstance(target, str):
        fail("UI action требует строковый target.")
    return target


def cmd_ui_action(settings: dict, token: str) -> None:
    payload = _decode_ui_action_payload(token)
    action = str(payload.get("action") or "")

    if action == "app_add":
        cmd_app_add(settings, _ui_payload_target(payload))
        return
    if action == "app_remove":
        cmd_app_remove(settings, _ui_payload_target(payload))
        return
    if action == "direct_add":
        cmd_direct_add(settings, _ui_payload_target(payload))
        return
    if action == "direct_remove":
        cmd_direct_remove(settings, _ui_payload_target(payload))
        return
    if action in {"port_add", "port_remove"}:
        try:
            port = int(payload.get("port"))
        except (TypeError, ValueError):
            fail("UI action содержит некорректный port.")
        proto = str(payload.get("proto") or "tcp").lower()
        if action == "port_add":
            cmd_port_add(settings, port, proto)
        else:
            cmd_port_remove(settings, port, proto)
        return

    fail(f"Неизвестная UI action: {action!r}.")
'''

s = VPNCTL.read_text()
s = replace_once(s, 'MANAGER_VERSION = "0.2.8"', 'MANAGER_VERSION = "0.2.9"', "manager version")
s = replace_once(s, '"Version": "1.1"', '"Version": "1.2"', "plasmoid version")

constants = "".join(
    [
        qml_constant("PLASMOID_MAIN_QML", "main.qml"),
        qml_constant("PLASMOID_BACKEND_QML", "VpnBackend.qml"),
        qml_constant("PLASMOID_CONFIG_QML", "config.qml"),
        qml_constant("PLASMOID_CONFIG_XML", "main.xml"),
        qml_constant("PLASMOID_CONFIG_APPS_QML", "configApplications.qml"),
        qml_constant("PLASMOID_CONFIG_NETWORK_QML", "configNetwork.qml"),
        qml_constant("PLASMOID_CONFIG_PORTS_QML", "configPorts.qml"),
        qml_constant("PLASMOID_CONFIG_GENERAL_QML", "configGeneral.qml"),
    ]
)
s = regex_once(
    s,
    r"PLASMOID_MAIN_QML = r'''.*?'''\n\nRELEASES =",
    constants + "\nRELEASES =",
    "plasmoid constants",
)

status_anchor = (
    'def cmd_status_json(settings: dict) -> None:\n'
    '    print(json.dumps(_status_payload(settings), ensure_ascii=False, separators=(",", ":")))\n'
    '\n\n'
    'def cmd_toggle(settings: dict) -> None:\n'
)
status_repl = (
    'def cmd_status_json(settings: dict) -> None:\n'
    '    print(json.dumps(_status_payload(settings), ensure_ascii=False, separators=(",", ":")))\n'
    '\n\n'
    + UI_BLOCK
    + '\n\ndef cmd_toggle(settings: dict) -> None:\n'
)
s = replace_once(s, status_anchor, status_repl, "UI manager block")

old_safe = '''def _widget_target_safe(settings: dict, package: pathlib.Path) -> None:
    home = pathlib.Path(str(settings["owner_home"])).resolve()
    try:
        package.resolve(strict=False).relative_to(home)
    except ValueError:
        fail("Некорректный путь установки Plasma-виджета.")
    for candidate in (package, package / "contents", package / "contents" / "ui"):
        if candidate.is_symlink():
            fail(f"Отказываюсь изменять symlink Plasma-виджета: {candidate}")
        if candidate.exists() and not candidate.is_dir():
            fail(f"Ожидалась папка Plasma-виджета: {candidate}")
'''
new_safe = '''def _widget_target_safe(settings: dict, package: pathlib.Path) -> None:
    home = pathlib.Path(str(settings["owner_home"])).resolve()
    try:
        package.resolve(strict=False).relative_to(home)
    except ValueError:
        fail("Некорректный путь установки Plasma-виджета.")
    for candidate in (
        package,
        package / "contents",
        package / "contents" / "ui",
        package / "contents" / "config",
    ):
        if candidate.is_symlink():
            fail(f"Отказываюсь изменять symlink Plasma-виджета: {candidate}")
        if candidate.exists() and not candidate.is_dir():
            fail(f"Ожидалась папка Plasma-виджета: {candidate}")
'''
s = replace_once(s, old_safe, new_safe, "widget safe paths")

old_install = '''def cmd_widget_install(settings: dict) -> None:
    package = _widget_package_dir(settings)
    _widget_target_safe(settings, package)
    uid, gid = _owner_ids(settings)
    ui = package / "contents" / "ui"
    ui.mkdir(parents=True, exist_ok=True)
    for directory in (package, package / "contents", ui):
        os.chown(directory, uid, gid)
        os.chmod(directory, 0o755)

    _write_owner_text(package / "metadata.json", PLASMOID_METADATA, uid, gid)
    _write_owner_text(ui / "main.qml", PLASMOID_MAIN_QML, uid, gid)

    kbuild = shutil.which("kbuildsycoca6")
'''
new_install = '''def cmd_widget_install(settings: dict) -> None:
    package = _widget_package_dir(settings)
    _widget_target_safe(settings, package)
    uid, gid = _owner_ids(settings)
    ui = package / "contents" / "ui"
    config = package / "contents" / "config"
    ui.mkdir(parents=True, exist_ok=True)
    config.mkdir(parents=True, exist_ok=True)
    for directory in (package, package / "contents", ui, config):
        os.chown(directory, uid, gid)
        os.chmod(directory, 0o755)

    _write_owner_text(package / "metadata.json", PLASMOID_METADATA, uid, gid)
    _write_owner_text(ui / "main.qml", PLASMOID_MAIN_QML, uid, gid)
    _write_owner_text(ui / "VpnBackend.qml", PLASMOID_BACKEND_QML, uid, gid)
    _write_owner_text(ui / "configApplications.qml", PLASMOID_CONFIG_APPS_QML, uid, gid)
    _write_owner_text(ui / "configNetwork.qml", PLASMOID_CONFIG_NETWORK_QML, uid, gid)
    _write_owner_text(ui / "configPorts.qml", PLASMOID_CONFIG_PORTS_QML, uid, gid)
    _write_owner_text(ui / "configGeneral.qml", PLASMOID_CONFIG_GENERAL_QML, uid, gid)
    _write_owner_text(config / "config.qml", PLASMOID_CONFIG_QML, uid, gid)
    _write_owner_text(config / "main.xml", PLASMOID_CONFIG_XML, uid, gid)

    kbuild = shutil.which("kbuildsycoca6")
'''
s = replace_once(s, old_install, new_install, "widget install files")

parser_anchor = '''    pw = sub.add_parser("widget")
    pwsub = pw.add_subparsers(dest="widget_cmd")
    pwsub.add_parser("install")
    pwsub.add_parser("remove")

    pp = sub.add_parser("port")
'''
parser_repl = '''    pw = sub.add_parser("widget")
    pwsub = pw.add_subparsers(dest="widget_cmd")
    pwsub.add_parser("install")
    pwsub.add_parser("remove")

    pui = sub.add_parser("ui")
    puisub = pui.add_subparsers(dest="ui_cmd")
    puisub.add_parser("state")
    puisub.add_parser("running")
    puia = puisub.add_parser("action")
    puia.add_argument("payload")

    pp = sub.add_parser("port")
'''
s = replace_once(s, parser_anchor, parser_repl, "UI parser")

dispatch_anchor = '''    if args.cmd == "widget":
        if args.widget_cmd in {None, "install"}:
            cmd_widget_install(settings)
            return 0
        if args.widget_cmd == "remove":
            cmd_widget_remove(settings)
            return 0

    if args.cmd == "port":
'''
dispatch_repl = '''    if args.cmd == "ui":
        if args.ui_cmd in {None, "state"}:
            cmd_ui_state(settings)
            return 0
        if args.ui_cmd == "running":
            cmd_ui_running(settings)
            return 0
        if args.ui_cmd == "action":
            cmd_ui_action(settings, args.payload)
            return 0

    if args.cmd == "widget":
        if args.widget_cmd in {None, "install"}:
            cmd_widget_install(settings)
            return 0
        if args.widget_cmd == "remove":
            cmd_widget_remove(settings)
            return 0

    if args.cmd == "port":
'''
s = replace_once(s, dispatch_anchor, dispatch_repl, "UI dispatch")

old_asserts = '''        assert 'icon.name: "configure"' in PLASMOID_MAIN_QML
        assert 'text: ""' in PLASMOID_MAIN_QML
'''
new_asserts = '''        assert 'icon.name: "configure"' in PLASMOID_MAIN_QML
        assert 'text: "E-VPN"' in PLASMOID_MAIN_QML
        assert 'plasmoid.action("configure")' in PLASMOID_MAIN_QML
        assert 'ConfigCategory' in PLASMOID_CONFIG_QML
        assert 'name: "Приложения"' in PLASMOID_CONFIG_QML
        assert '/usr/local/bin/vpn ui state' in PLASMOID_BACKEND_QML
        assert '/usr/local/bin/vpn ui running' in PLASMOID_BACKEND_QML
        assert '/usr/local/bin/vpn ui action ' in PLASMOID_BACKEND_QML
        assert 'target: String(modelData.name || "")' in PLASMOID_CONFIG_APPS_QML
        assert _direct_app_rule_matches("firefox", "firefox", "/usr/lib/firefox/firefox")
        assert _direct_app_rule_matches("/opt/example/", "helper", "/opt/example/bin/helper")
        payload = {"action": "app_add", "target": "firefox"}
        token = base64.b64encode(
            urllib.parse.quote(json.dumps(payload, ensure_ascii=False)).encode("ascii")
        ).decode("ascii")
        assert _decode_ui_action_payload(token) == payload
'''
s = replace_once(s, old_asserts, new_asserts, "widget self-test")
VPNCTL.write_text(s)

(ROOT / "VERSION").write_text("0.2.9\n")

changelog = (ROOT / "CHANGELOG.md").read_text()
entry = '''## 0.2.9

- shrink the Plasma desktop widget to `E-VPN` + one switch + one settings gear
- open the native Plasma configuration window instead of expanding the desktop widget
- add graphical tabs for DIRECT applications, domains/IP networks, server ports and VPN status
- add one-click DIRECT exclusions from currently running desktop processes
- add safe machine-readable `vpn ui state|running|action` helpers for the Plasma settings UI

'''
if "## 0.2.9\n" not in changelog:
    changelog = changelog.replace("# Changelog\n\n", "# Changelog\n\n" + entry, 1)
(ROOT / "CHANGELOG.md").write_text(changelog)

readme = (ROOT / "README.md").read_text()
readme = readme.replace("Current stable baseline: **0.2.8**.", "Current stable baseline: **0.2.9**.", 1)
readme_section = '''## KDE Plasma 6 widget

Version 0.2.9 keeps the desktop widget deliberately tiny: **E-VPN**, one ON/OFF switch, and one settings gear.

Install it once with:

```bash
vpn widget install
```

Then right-click the desktop, choose **Add Widgets**, search for **Evgenium Network**, and place it on the desktop.

The gear opens Plasma's separate native configuration window. Its tabs manage:

- application DIRECT exclusions;
- domain/IP/CIDR DIRECT exclusions;
- inbound server-port bypass rules;
- current VPN status.

Application exclusions can be entered manually by process name/path, or selected from a live list of processes currently running under the desktop user. Selecting a running application adds its process name to the existing Xray DIRECT application rules. Changes are applied immediately.

The desktop widget itself only calls the local manager (`vpn status --json` and `vpn toggle`). The settings window uses the restricted `vpn ui ...` helper; user-entered values are encoded into a data payload and the manager accepts only a fixed allow-list of actions. VLESS credentials are never exposed to the widget.

## Update channel
'''
readme, count = re.subn(
    r"## KDE Plasma 6 widget\n.*?\n## Update channel\n",
    lambda _m: readme_section,
    readme,
    count=1,
    flags=re.S,
)
if count != 1:
    raise SystemExit(f"README widget section: expected 1 match, got {count}")
(ROOT / "README.md").write_text(readme)

test_path = ROOT / ".github" / "workflows" / "test.yml"
test = test_path.read_text()
needle = "          grep -F 'if _widget_package_dir(settings).exists()' src/vpnctl.py\n"
extra = needle + (
    "          grep -F 'plasmoid.action(\"configure\")' src/vpnctl.py\n"
    "          grep -F 'text: \"E-VPN\"' src/vpnctl.py\n"
    "          grep -F 'pui = sub.add_parser(\"ui\")' src/vpnctl.py\n"
    "          grep -F 'def _running_user_applications' src/vpnctl.py\n"
    "          grep -F '/usr/local/bin/vpn ui running' src/vpnctl.py\n"
)
test = replace_once(test, needle, extra, "CI widget contract")
test_path.write_text(test)
