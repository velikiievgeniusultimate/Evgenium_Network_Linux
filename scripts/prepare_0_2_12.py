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
TEST = ROOT / ".github" / "workflows" / "test.yml"
ICON = ROOT / "assets" / "evgenium-network.svg"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return text.replace(old, new, 1)


def patch_qml() -> None:
    s = QML.read_text(encoding="utf-8")

    s = replace_once(
        s,
        "        signal clicked()\n        height: 48\n        radius: 11\n",
        "        signal clicked()\n        Layout.fillWidth: true\n        implicitWidth: 186\n        height: 48\n        radius: 11\n",
        "nav width",
    )

    old_nav = '''                NavButton { label: "VPN"; shortLabel: "VPN"; index: 0 }\n                NavButton {\n                    label: "Приложения"; shortLabel: "APP"; index: 1\n                    onClicked: root.refreshRunning()\n                }\n                NavButton { label: "Сайты и IP"; shortLabel: "NET"; index: 2 }\n                NavButton { label: "Порты"; shortLabel: "PRT"; index: 3 }\n                NavButton { label: "Диагностика"; shortLabel: "SYS"; index: 4 }\n'''
    new_nav = '''                NavButton { label: "VPN"; shortLabel: "VPN"; index: 0 }\n                NavButton { label: "Профили VPN"; shortLabel: "PRF"; index: 1 }\n                NavButton {\n                    label: "Приложения"; shortLabel: "APP"; index: 2\n                    onClicked: root.refreshRunning()\n                }\n                NavButton { label: "Сайты и IP"; shortLabel: "NET"; index: 3 }\n                NavButton { label: "Порты"; shortLabel: "PRT"; index: 4 }\n                NavButton { label: "Диагностика"; shortLabel: "SYS"; index: 5 }\n'''
    s = replace_once(s, old_nav, new_nav, "nav entries")

    s = replace_once(
        s,
        '                        text: ["VPN", "Приложения без VPN", "Сайты и IP без VPN", "Входящие порты", "Диагностика"][root.pageIndex]\n',
        '                        text: ["VPN", "Профили VPN", "Приложения без VPN", "Сайты и IP без VPN", "Входящие порты", "Диагностика"][root.pageIndex]\n',
        "page titles",
    )
    s = replace_once(
        s,
        "                            if (root.pageIndex === 1)\n                                root.refreshRunning()\n",
        "                            if (root.pageIndex === 2)\n                                root.refreshRunning()\n",
        "refresh apps page",
    )

    profiles_page = r'''
                    // VPN profiles
                    Item {
                        ColumnLayout {
                            anchors.fill: parent
                            spacing: 14

                            Card {
                                Layout.fillWidth: true
                                height: 78
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 16
                                    spacing: 12
                                    Rectangle {
                                        width: 42
                                        height: 42
                                        radius: 12
                                        color: root.accentSoft
                                        C.Label {
                                            anchors.centerIn: parent
                                            text: "PRF"
                                            color: root.accent
                                            font.pixelSize: 11
                                            font.weight: Font.Bold
                                        }
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 2
                                        C.Label {
                                            text: "VPN-профили"
                                            color: root.textMain
                                            font.pixelSize: 16
                                            font.weight: Font.Bold
                                        }
                                        C.Label {
                                            Layout.fillWidth: true
                                            text: String(root.state.config_dir || "")
                                            color: root.textMuted
                                            font.pixelSize: 11
                                            elide: Text.ElideMiddle
                                        }
                                    }
                                    C.Label {
                                        text: String((root.state.profiles || []).length) + " шт."
                                        color: root.textMuted
                                        font.pixelSize: 12
                                    }
                                }
                            }

                            Card {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                ListView {
                                    anchors.fill: parent
                                    anchors.margins: 10
                                    clip: true
                                    spacing: 7
                                    model: root.state.profiles || []
                                    delegate: Rectangle {
                                        id: profileRow
                                        required property var modelData
                                        width: ListView.view.width
                                        height: 66
                                        radius: 12
                                        color: Boolean(profileRow.modelData.active) ? root.accentSoft : "#f8fafc"
                                        border.width: Boolean(profileRow.modelData.active) ? 1 : 0
                                        border.color: root.accent

                                        RowLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: 14
                                            anchors.rightMargin: 10
                                            spacing: 12

                                            Rectangle {
                                                width: 12
                                                height: 12
                                                radius: 6
                                                color: Boolean(profileRow.modelData.active)
                                                    ? root.good
                                                    : (Boolean(profileRow.modelData.last) ? root.accent : "#cbd5e1")
                                            }

                                            ColumnLayout {
                                                Layout.fillWidth: true
                                                spacing: 2
                                                C.Label {
                                                    Layout.fillWidth: true
                                                    text: String(profileRow.modelData.stem || profileRow.modelData.name || "")
                                                    color: root.textMain
                                                    font.pixelSize: 14
                                                    font.weight: Font.DemiBold
                                                    elide: Text.ElideRight
                                                }
                                                C.Label {
                                                    Layout.fillWidth: true
                                                    text: Boolean(profileRow.modelData.active)
                                                        ? "Активный профиль"
                                                        : (Boolean(profileRow.modelData.last) ? "Последний использованный" : String(profileRow.modelData.name || ""))
                                                    color: Boolean(profileRow.modelData.active) ? root.good : root.textMuted
                                                    font.pixelSize: 11
                                                    elide: Text.ElideMiddle
                                                }
                                            }

                                            FlatButton {
                                                label: Boolean(profileRow.modelData.active) ? "Активен" : "Подключить"
                                                primary: !Boolean(profileRow.modelData.active)
                                                enabledButton: !root.busy && !Boolean(profileRow.modelData.active)
                                                onClicked: root.action({
                                                    action: "profile_activate",
                                                    target: String(profileRow.modelData.name || "")
                                                })
                                            }
                                        }
                                    }
                                    C.ScrollBar.vertical: C.ScrollBar {}
                                    C.Label {
                                        anchors.centerIn: parent
                                        visible: (root.state.profiles || []).length === 0
                                        text: "В папке VPN configs пока нет профилей"
                                        color: root.textMuted
                                    }
                                }
                            }
                        }
                    }

'''
    marker = "                    // Applications\n"
    if marker not in s:
        raise SystemExit("profiles insert marker missing")
    s = s.replace(marker, profiles_page + marker, 1)

    QML.write_text(s, encoding="utf-8")


def patch_vpnctl() -> None:
    s = VPNCTL.read_text(encoding="utf-8")
    icon_svg = ICON.read_text(encoding="utf-8").rstrip() + "\n"

    s = replace_once(s, 'MANAGER_VERSION = "0.2.11"', 'MANAGER_VERSION = "0.2.12"', "manager version")

    icon_const = "APP_ICON_NAME = \"evgenium-network\"\nAPP_ICON_SVG = r'''" + icon_svg + "'''\n\n"
    s = replace_once(s, 'PLASMOID_ID = "com.evgenium.network"\n', 'PLASMOID_ID = "com.evgenium.network"\n' + icon_const, "icon constant")
    s = replace_once(s, '    "Icon": "network-vpn",\n', '    "Icon": "evgenium-network",\n', "plasmoid metadata icon")
    s = replace_once(s, '    "Version": "1.4"\n', '    "Version": "1.5"\n', "plasmoid version")
    s = replace_once(s, '    Plasmoid.icon: "network-vpn"\n', '    Plasmoid.icon: "evgenium-network"\n', "plasmoid runtime icon")
    s = replace_once(s, 'Icon=network-vpn\n', 'Icon=evgenium-network\n', "desktop icon")

    helper_old = '''def _gui_desktop_path(settings: dict) -> pathlib.Path:\n    return pathlib.Path(str(settings["owner_home"])) / ".local" / "share" / "applications" / "evgenium-network.desktop"\n\n\ndef _gui_target_safe(settings: dict, target: pathlib.Path) -> None:\n'''
    helper_new = '''def _gui_desktop_path(settings: dict) -> pathlib.Path:\n    return pathlib.Path(str(settings["owner_home"])) / ".local" / "share" / "applications" / "evgenium-network.desktop"\n\n\ndef _gui_icon_path(settings: dict) -> pathlib.Path:\n    return pathlib.Path(str(settings["owner_home"])) / ".local" / "share" / "icons" / "hicolor" / "scalable" / "apps" / "evgenium-network.svg"\n\n\ndef _gui_target_safe(settings: dict, target: pathlib.Path) -> None:\n'''
    s = replace_once(s, helper_old, helper_new, "gui icon helper")

    install_old = '''def cmd_gui_install(settings: dict) -> None:\n    package = _gui_package_dir(settings)\n    desktop = _gui_desktop_path(settings)\n    _gui_target_safe(settings, package)\n    _gui_target_safe(settings, desktop)\n    uid, gid = _owner_ids(settings)\n\n    package.mkdir(parents=True, exist_ok=True)\n    desktop.parent.mkdir(parents=True, exist_ok=True)\n    for directory in (package, desktop.parent):\n        os.chown(directory, uid, gid)\n        os.chmod(directory, 0o755)\n\n    gui_py = base64.b64decode(STANDALONE_GUI_PY_B64).decode("utf-8")\n    gui_qml = base64.b64decode(STANDALONE_GUI_QML_B64).decode("utf-8")\n    _write_owner_text(package / "evgenium_gui.py", gui_py, uid, gid)\n    _write_owner_text(package / "evgenium_gui.qml", gui_qml, uid, gid)\n    _write_owner_text(desktop, GUI_DESKTOP_ENTRY, uid, gid)\n    os.chmod(package / "evgenium_gui.py", 0o755)\n    os.chmod(package / "evgenium_gui.qml", 0o644)\n'''
    install_new = '''def cmd_gui_install(settings: dict) -> None:\n    package = _gui_package_dir(settings)\n    desktop = _gui_desktop_path(settings)\n    icon = _gui_icon_path(settings)\n    _gui_target_safe(settings, package)\n    _gui_target_safe(settings, desktop)\n    _gui_target_safe(settings, icon)\n    uid, gid = _owner_ids(settings)\n\n    package.mkdir(parents=True, exist_ok=True)\n    desktop.parent.mkdir(parents=True, exist_ok=True)\n    icon.parent.mkdir(parents=True, exist_ok=True)\n    for directory in (package, desktop.parent, icon.parent):\n        os.chown(directory, uid, gid)\n        os.chmod(directory, 0o755)\n\n    gui_py = base64.b64decode(STANDALONE_GUI_PY_B64).decode("utf-8")\n    gui_qml = base64.b64decode(STANDALONE_GUI_QML_B64).decode("utf-8")\n    _write_owner_text(package / "evgenium_gui.py", gui_py, uid, gid)\n    _write_owner_text(package / "evgenium_gui.qml", gui_qml, uid, gid)\n    _write_owner_text(desktop, GUI_DESKTOP_ENTRY, uid, gid)\n    _write_owner_text(icon, APP_ICON_SVG, uid, gid)\n    os.chmod(package / "evgenium_gui.py", 0o755)\n    os.chmod(package / "evgenium_gui.qml", 0o644)\n    os.chmod(icon, 0o644)\n'''
    s = replace_once(s, install_old, install_new, "gui icon install")

    state_old = '''    ports = (\n        [{"proto": "tcp", "port": port} for port in sorted(tcp_ports)]\n        + [{"proto": "udp", "port": port} for port in sorted(udp_ports)]\n    )\n    state.update(\n'''
    state_new = '''    ports = (\n        [{"proto": "tcp", "port": port} for port in sorted(tcp_ports)]\n        + [{"proto": "udp", "port": port} for port in sorted(udp_ports)]\n    )\n    stored = load_state()\n    active_name = str(stored.get("active") or "")\n    last_name = str(stored.get("last_active") or active_name)\n    active_now = service_active()\n    profiles = [\n        {\n            "name": path.name,\n            "stem": path.stem,\n            "active": bool(active_now and path.name == active_name),\n            "last": bool(path.name == last_name),\n        }\n        for path in list_config_paths(settings)\n    ]\n    state.update(\n'''
    s = replace_once(s, state_old, state_new, "ui profiles state prelude")
    s = replace_once(
        s,
        '            "server_ports": ports,\n',
        '            "server_ports": ports,\n            "profiles": profiles,\n            "config_dir": str(settings["config_dir"]),\n',
        "ui profiles state fields",
    )

    action_old = '''    action = str(payload.get("action") or "")\n\n    if action == "app_add":\n'''
    action_new = '''    action = str(payload.get("action") or "")\n\n    if action == "profile_activate":\n        activate(settings, choose_config(settings, _ui_payload_target(payload)))\n        return\n    if action == "app_add":\n'''
    s = replace_once(s, action_old, action_new, "profile action")

    s = replace_once(
        s,
        '        assert \'text: "E-VPN"\' in PLASMOID_MAIN_QML\n',
        '        assert \'text: "E-VPN"\' in PLASMOID_MAIN_QML\n        assert \'Plasmoid.icon: "evgenium-network"\' in PLASMOID_MAIN_QML\n        assert "E-VPN" in APP_ICON_SVG\n',
        "self-test icon",
    )
    s = replace_once(
        s,
        '        assert "Запущены сейчас" in gui_qml\n',
        '        assert "Запущены сейчас" in gui_qml\n        assert "Профили VPN" in gui_qml\n        assert \'action: "profile_activate"\' in gui_qml\n',
        "self-test profiles",
    )

    qml_b64 = base64.b64encode(QML.read_bytes()).decode("ascii")
    chunks = [qml_b64[i:i + 100] for i in range(0, len(qml_b64), 100)]
    replacement = "STANDALONE_GUI_QML_B64 = (\n" + "".join(f"    {c!r}\n" for c in chunks) + ")"
    pattern = r"STANDALONE_GUI_QML_B64 = \(\n(?:\s*'[^']*'\n)+\)"
    s, count = re.subn(pattern, replacement, s, count=1)
    if count != 1:
        raise SystemExit(f"embedded QML replacement count={count}")

    VPNCTL.write_text(s, encoding="utf-8")


def patch_metadata() -> None:
    VERSION.write_text("0.2.12\n", encoding="utf-8")

    ch = CHANGELOG.read_text(encoding="utf-8")
    entry = '''# Changelog\n\n## 0.2.12\n\n- fix the standalone GUI sidebar layout and make every navigation row fully clickable\n- add a dedicated VPN profiles page with one-click switching between configs\n- expose VPN profiles and config directory through the existing local UI state API\n- add an original E-VPN application icon inspired by an anime drill-pigtail silhouette and install it for the desktop entry and Plasma widget\n\n'''
    if not ch.startswith("# Changelog\n\n"):
        raise SystemExit("unexpected changelog header")
    CHANGELOG.write_text(entry + ch[len("# Changelog\n\n"):], encoding="utf-8")

    t = TEST.read_text(encoding="utf-8")
    t = replace_once(
        t,
        "          grep -F 'Запущены сейчас' src/evgenium_gui.qml\n",
        "          grep -F 'Запущены сейчас' src/evgenium_gui.qml\n          grep -F 'Профили VPN' src/evgenium_gui.qml\n          grep -F 'profile_activate' src/vpnctl.py\n          grep -F '\"profiles\": profiles' src/vpnctl.py\n          grep -F 'APP_ICON_SVG' src/vpnctl.py\n          grep -F 'Icon=evgenium-network' src/vpnctl.py\n",
        "CI GUI checks",
    )
    TEST.write_text(t, encoding="utf-8")


def main() -> None:
    if VERSION.read_text(encoding="utf-8").strip() != "0.2.11":
        raise SystemExit("prepare script expects 0.2.11 base")
    patch_qml()
    patch_vpnctl()
    patch_metadata()
    print("prepared 0.2.12")


if __name__ == "__main__":
    main()
