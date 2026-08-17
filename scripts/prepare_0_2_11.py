#!/usr/bin/env python3
from __future__ import annotations

import base64
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VPNCTL = ROOT / "src" / "vpnctl.py"
GUI_PY = ROOT / "src" / "evgenium_gui.py"
GUI_QML = ROOT / "src" / "evgenium_gui.qml"

WIDGET_QML = r'''import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3
import org.kde.plasma.plasmoid
import org.kde.plasma.plasma5support as Plasma5Support

PlasmoidItem {
    id: root

    property bool vpnActive: false
    property bool busy: false
    property bool settingsBusy: false
    property string errorText: ""

    readonly property string statusCommand: "/usr/local/bin/vpn status --json"
    readonly property string toggleCommand: "/usr/local/bin/vpn toggle"
    readonly property string settingsCommand: "/usr/local/bin/evgenium-network --detach"

    Plasmoid.icon: "network-vpn"
    toolTipMainText: "E-VPN"
    toolTipSubText: errorText.length > 0
        ? errorText
        : (busy ? "Переключаю VPN…" : (vpnActive ? "VPN включён" : "VPN выключен"))
    preferredRepresentation: fullRepresentation

    width: Kirigami.Units.gridUnit * 9
    height: Kirigami.Units.gridUnit * 2.7

    function requestStatus() {
        statusSource.connectSource(statusCommand)
    }

    function toggleVpn() {
        if (busy)
            return
        busy = true
        errorText = ""
        actionSource.connectSource(toggleCommand)
    }

    function openSettings() {
        if (settingsBusy)
            return
        settingsBusy = true
        errorText = ""
        settingsSource.connectSource(settingsCommand)
    }

    Component.onCompleted: requestStatus()

    Timer {
        interval: 1500
        repeat: true
        running: true
        onTriggered: root.requestStatus()
    }

    Plasma5Support.DataSource {
        id: statusSource
        engine: "executable"

        onNewData: function(sourceName, data) {
            if (sourceName !== root.statusCommand)
                return
            const output = String(data["stdout"] || "").trim()
            if (output.length > 0) {
                try {
                    const state = JSON.parse(output)
                    root.vpnActive = Boolean(state.active)
                } catch (error) {
                    root.errorText = "Не удалось прочитать состояние VPN"
                }
            }
            statusSource.disconnectSource(sourceName)
        }
    }

    Plasma5Support.DataSource {
        id: actionSource
        engine: "executable"

        onNewData: function(sourceName, data) {
            const exitCode = Number(data["exit code"] === undefined ? 0 : data["exit code"])
            const stderrText = String(data["stderr"] || "").trim()
            const stdoutText = String(data["stdout"] || "").trim()
            if (exitCode !== 0)
                root.errorText = stderrText.length > 0 ? stderrText : stdoutText
            root.busy = false
            actionSource.disconnectSource(sourceName)
            root.requestStatus()
        }
    }

    Plasma5Support.DataSource {
        id: settingsSource
        engine: "executable"

        onNewData: function(sourceName, data) {
            if (sourceName !== root.settingsCommand)
                return
            const exitCode = Number(data["exit code"] === undefined ? 0 : data["exit code"])
            const stderrText = String(data["stderr"] || "").trim()
            const stdoutText = String(data["stdout"] || "").trim()
            if (exitCode !== 0)
                root.errorText = stderrText.length > 0 ? stderrText : (stdoutText.length > 0 ? stdoutText : "Не удалось открыть Evgenium Network")
            root.settingsBusy = false
            settingsSource.disconnectSource(sourceName)
        }
    }

    fullRepresentation: Item {
        Layout.minimumWidth: Kirigami.Units.gridUnit * 8
        Layout.preferredWidth: Kirigami.Units.gridUnit * 9
        Layout.minimumHeight: Kirigami.Units.gridUnit * 2.4
        Layout.preferredHeight: Kirigami.Units.gridUnit * 2.7

        RowLayout {
            anchors.fill: parent
            anchors.margins: Kirigami.Units.smallSpacing * 2
            spacing: Kirigami.Units.smallSpacing

            PlasmaComponents3.Label {
                text: "E-VPN"
                font.bold: true
                Layout.fillWidth: true
            }

            Item {
                id: switchControl
                Layout.preferredWidth: 44
                Layout.preferredHeight: 24
                opacity: root.busy ? 0.55 : 1.0

                Rectangle {
                    anchors.fill: parent
                    radius: height / 2
                    color: root.vpnActive
                        ? Kirigami.Theme.highlightColor
                        : Kirigami.Theme.disabledTextColor
                    opacity: root.vpnActive ? 0.95 : 0.45
                }

                Rectangle {
                    width: 18
                    height: 18
                    radius: 9
                    y: 3
                    x: root.vpnActive ? switchControl.width - width - 3 : 3
                    color: Kirigami.Theme.backgroundColor

                    Behavior on x {
                        NumberAnimation { duration: 120 }
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    enabled: !root.busy
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.toggleVpn()
                }
            }

            PlasmaComponents3.ToolButton {
                Layout.preferredWidth: 30
                Layout.preferredHeight: 30
                icon.name: "configure"
                text: ""
                enabled: !root.settingsBusy
                onClicked: root.openSettings()
            }
        }
    }
}
'''

DESKTOP_ENTRY = r'''[Desktop Entry]
Type=Application
Name=Evgenium Network
Comment=Evgenium VPN control and exclusions
Exec=/usr/local/bin/evgenium-network
Icon=network-vpn
Terminal=false
Categories=Network;Settings;
StartupNotify=true
'''

GUI_WRAPPER = r'''#!/usr/bin/env bash
set -e
GUI="$HOME/.local/share/evgenium-network/evgenium_gui.py"
if [[ ! -f "$GUI" ]]; then
  echo "Evgenium Network GUI is not installed. Run: vpn gui install" >&2
  exit 1
fi
exec /usr/bin/python3 "$GUI" "$@"
'''


def chunks(data: bytes) -> str:
    b64 = base64.b64encode(data).decode("ascii")
    lines = [b64[i:i + 100] for i in range(0, len(b64), 100)]
    return "(\n" + "\n".join(f"    {line!r}" for line in lines) + "\n)"


def replace_between(text: str, start: str, end: str, replacement: str) -> str:
    a = text.index(start)
    b = text.index(end, a)
    return text[:a] + replacement.rstrip() + "\n\n" + text[b:]


def main() -> None:
    text = VPNCTL.read_text()
    text = text.replace('MANAGER_VERSION = "0.2.10"', 'MANAGER_VERSION = "0.2.11"', 1)
    text = text.replace('"Version": "1.3"', '"Version": "1.4"', 1)

    asset_block = (
        "PLASMOID_MAIN_QML = r'''" + WIDGET_QML + "'''\n"
        "GUI_DESKTOP_ENTRY = r'''" + DESKTOP_ENTRY + "'''\n"
        "STANDALONE_GUI_PY_B64 = " + chunks(GUI_PY.read_bytes()) + "\n"
        "STANDALONE_GUI_QML_B64 = " + chunks(GUI_QML.read_bytes()) + "\n"
    )
    text = replace_between(text, "PLASMOID_MAIN_QML = r'''", "RELEASES = pathlib.Path", asset_block)

    wrapper_marker = 'WRAPPER_TEXT = r"""#!/usr/bin/env bash\nset -e\nexec /usr/bin/sudo -n /usr/local/sbin/vpnctl "$@"\n"""'
    if wrapper_marker not in text:
        raise SystemExit("WRAPPER_TEXT marker missing")
    text = text.replace(wrapper_marker, wrapper_marker + "\n\nGUI_WRAPPER_TEXT = r'''" + GUI_WRAPPER + "'''", 1)

    old_sync = '''def sync_system_files() -> None:\n    pathlib.Path("/etc/systemd/system/vpn-xray.service").write_text(SERVICE_TEXT)\n    os.chmod("/etc/systemd/system/vpn-xray.service", 0o644)\n\n    pathlib.Path("/usr/local/bin/vpn").write_text(WRAPPER_TEXT)\n    os.chmod("/usr/local/bin/vpn", 0o755)\n\n    run(["/usr/bin/systemctl", "daemon-reload"], check=False)'''
    new_sync = '''def sync_system_files() -> None:\n    pathlib.Path("/etc/systemd/system/vpn-xray.service").write_text(SERVICE_TEXT)\n    os.chmod("/etc/systemd/system/vpn-xray.service", 0o644)\n\n    pathlib.Path("/usr/local/bin/vpn").write_text(WRAPPER_TEXT)\n    os.chmod("/usr/local/bin/vpn", 0o755)\n\n    pathlib.Path("/usr/local/bin/evgenium-network").write_text(GUI_WRAPPER_TEXT)\n    os.chmod("/usr/local/bin/evgenium-network", 0o755)\n\n    run(["/usr/bin/systemctl", "daemon-reload"], check=False)'''
    if old_sync not in text:
        raise SystemExit("sync_system_files marker missing")
    text = text.replace(old_sync, new_sync, 1)

    widget_start = text.index("def cmd_widget_install(settings: dict) -> None:")
    widget_end = text.index("def cmd_widget_remove(settings: dict) -> None:", widget_start)
    new_gui_widget = r'''def _gui_package_dir(settings: dict) -> pathlib.Path:
    return pathlib.Path(str(settings["owner_home"])) / ".local" / "share" / "evgenium-network"


def _gui_desktop_path(settings: dict) -> pathlib.Path:
    return pathlib.Path(str(settings["owner_home"])) / ".local" / "share" / "applications" / "evgenium-network.desktop"


def _gui_target_safe(settings: dict, target: pathlib.Path) -> None:
    home = pathlib.Path(str(settings["owner_home"])).resolve()
    try:
        target.resolve(strict=False).relative_to(home)
    except ValueError:
        fail(f"GUI path выходит за пределы home: {target}")
    if target.is_symlink():
        fail(f"Отказываюсь изменять symlink GUI: {target}")


def cmd_gui_install(settings: dict) -> None:
    package = _gui_package_dir(settings)
    desktop = _gui_desktop_path(settings)
    _gui_target_safe(settings, package)
    _gui_target_safe(settings, desktop)
    uid, gid = _owner_ids(settings)

    package.mkdir(parents=True, exist_ok=True)
    desktop.parent.mkdir(parents=True, exist_ok=True)
    for directory in (package, desktop.parent):
        os.chown(directory, uid, gid)
        os.chmod(directory, 0o755)

    gui_py = base64.b64decode(STANDALONE_GUI_PY_B64).decode("utf-8")
    gui_qml = base64.b64decode(STANDALONE_GUI_QML_B64).decode("utf-8")
    _write_owner_text(package / "evgenium_gui.py", gui_py, uid, gid)
    _write_owner_text(package / "evgenium_gui.qml", gui_qml, uid, gid)
    _write_owner_text(desktop, GUI_DESKTOP_ENTRY, uid, gid)
    os.chmod(package / "evgenium_gui.py", 0o755)
    os.chmod(package / "evgenium_gui.qml", 0o644)
    os.chmod(desktop, 0o644)

    kbuild = shutil.which("kbuildsycoca6")
    if kbuild:
        run([kbuild], check=False, capture=True, user=str(settings["owner_user"]))
    ok(f"Evgenium Network GUI установлен: {package}")


def cmd_gui_remove(settings: dict) -> None:
    package = _gui_package_dir(settings)
    desktop = _gui_desktop_path(settings)
    _gui_target_safe(settings, package)
    _gui_target_safe(settings, desktop)
    if package.exists():
        shutil.rmtree(package)
    desktop.unlink(missing_ok=True)
    kbuild = shutil.which("kbuildsycoca6")
    if kbuild:
        run([kbuild], check=False, capture=True, user=str(settings["owner_user"]))
    ok("Evgenium Network GUI удалён из профиля пользователя.")


def cmd_widget_install(settings: dict) -> None:
    cmd_gui_install(settings)
    package = _widget_package_dir(settings)
    _widget_target_safe(settings, package)
    uid, gid = _owner_ids(settings)
    ui = package / "contents" / "ui"
    ui.mkdir(parents=True, exist_ok=True)
    for directory in (package, package / "contents", ui):
        os.chown(directory, uid, gid)
        os.chmod(directory, 0o755)

    stale_config = package / "contents" / "config"
    if stale_config.exists():
        if stale_config.is_symlink():
            fail(f"Отказываюсь удалять symlink Plasma config: {stale_config}")
        shutil.rmtree(stale_config)
    for stale in (
        "VpnBackend.qml", "configApplications.qml", "configNetwork.qml",
        "configPorts.qml", "configGeneral.qml",
    ):
        candidate = ui / stale
        if candidate.is_symlink():
            fail(f"Отказываюсь удалять symlink Plasma UI: {candidate}")
        candidate.unlink(missing_ok=True)

    _write_owner_text(package / "metadata.json", PLASMOID_METADATA, uid, gid)
    _write_owner_text(ui / "main.qml", PLASMOID_MAIN_QML, uid, gid)

    kbuild = shutil.which("kbuildsycoca6")
    if kbuild:
        run([kbuild], check=False, capture=True, user=str(settings["owner_user"]))

    ok(f"Plasma 6 виджет установлен: {package}")
    print("Шестерёнка E-VPN открывает отдельное приложение Evgenium Network.")


'''
    text = text[:widget_start] + new_gui_widget + text[widget_end:]

    old_asserts = '''        assert "PlasmoidItem" in PLASMOID_MAIN_QML\n        assert 'engine: "executable"' in PLASMOID_MAIN_QML\n        assert "/usr/local/bin/vpn status --json" in PLASMOID_MAIN_QML\n        assert "/usr/local/bin/vpn toggle" in PLASMOID_MAIN_QML\n        assert 'icon.name: "configure"' in PLASMOID_MAIN_QML\n        assert 'text: "E-VPN"' in PLASMOID_MAIN_QML\n        assert 'Plasmoid.hasConfigurationInterface: true' in PLASMOID_MAIN_QML\n        assert 'plasmoid.internalAction("configure")' in PLASMOID_MAIN_QML\n        assert 'plasmoid.action("configure")' in PLASMOID_MAIN_QML\n        assert 'ConfigCategory' in PLASMOID_CONFIG_QML\n        assert 'name: "Приложения"' in PLASMOID_CONFIG_QML\n        assert '/usr/local/bin/vpn ui state' in PLASMOID_BACKEND_QML\n        assert '/usr/local/bin/vpn ui running' in PLASMOID_BACKEND_QML\n        assert '/usr/local/bin/vpn ui action ' in PLASMOID_BACKEND_QML\n        assert 'target: String(modelData.name || "")' in PLASMOID_CONFIG_APPS_QML'''
    new_asserts = '''        assert "PlasmoidItem" in PLASMOID_MAIN_QML\n        assert 'engine: "executable"' in PLASMOID_MAIN_QML\n        assert "/usr/local/bin/vpn status --json" in PLASMOID_MAIN_QML\n        assert "/usr/local/bin/vpn toggle" in PLASMOID_MAIN_QML\n        assert "/usr/local/bin/evgenium-network --detach" in PLASMOID_MAIN_QML\n        assert 'icon.name: "configure"' in PLASMOID_MAIN_QML\n        assert 'text: "E-VPN"' in PLASMOID_MAIN_QML\n        assert "internalAction" not in PLASMOID_MAIN_QML\n        gui_py = base64.b64decode(STANDALONE_GUI_PY_B64).decode("utf-8")\n        gui_qml = base64.b64decode(STANDALONE_GUI_QML_B64).decode("utf-8")\n        assert "ThreadingHTTPServer" in gui_py\n        assert "/api/running" in gui_py and "/api/action" in gui_py\n        assert "Evgenium Network" in gui_qml\n        assert "Запущены сейчас" in gui_qml\n        assert 'action: "app_add"' in gui_qml'''
    if old_asserts not in text:
        raise SystemExit("self-test Plasma assertion block missing")
    text = text.replace(old_asserts, new_asserts, 1)

    parser_marker = '''    pw = sub.add_parser("widget")\n    pwsub = pw.add_subparsers(dest="widget_cmd")\n    pwsub.add_parser("install")\n    pwsub.add_parser("remove")\n'''
    parser_new = parser_marker + '''\n    pg = sub.add_parser("gui")\n    pgsub = pg.add_subparsers(dest="gui_cmd")\n    pgsub.add_parser("install")\n    pgsub.add_parser("remove")\n'''
    if parser_marker not in text:
        raise SystemExit("widget parser marker missing")
    text = text.replace(parser_marker, parser_new, 1)

    help_marker = "  vpn widget install|remove\n"
    if help_marker not in text:
        raise SystemExit("help marker missing")
    text = text.replace(help_marker, help_marker + "  vpn gui install|remove\n  evgenium-network\n", 1)

    dispatch_marker = '''    if args.cmd == "widget":\n        if args.widget_cmd in {None, "install"}:\n            cmd_widget_install(settings)\n            return 0\n        if args.widget_cmd == "remove":\n            cmd_widget_remove(settings)\n            return 0\n'''
    dispatch_new = '''    if args.cmd == "gui":\n        if args.gui_cmd in {None, "install"}:\n            cmd_gui_install(settings)\n            return 0\n        if args.gui_cmd == "remove":\n            cmd_gui_remove(settings)\n            return 0\n\n''' + dispatch_marker
    if dispatch_marker not in text:
        raise SystemExit("widget dispatch marker missing")
    text = text.replace(dispatch_marker, dispatch_new, 1)

    sync_dispatch = '''    if args.cmd == "internal-sync":\n        sync_system_files()\n        return 0'''
    sync_new = '''    if args.cmd == "internal-sync":\n        sync_system_files()\n        cmd_gui_install(settings)\n        return 0'''
    if sync_dispatch not in text:
        raise SystemExit("internal-sync marker missing")
    text = text.replace(sync_dispatch, sync_new, 1)

    after_marker = '''    if args.cmd == "internal-after-update":\n        sync_system_files()\n        if _widget_package_dir(settings).exists():'''
    after_new = '''    if args.cmd == "internal-after-update":\n        sync_system_files()\n        cmd_gui_install(settings)\n        if _widget_package_dir(settings).exists():'''
    if after_marker not in text:
        raise SystemExit("internal-after-update marker missing")
    text = text.replace(after_marker, after_new, 1)

    VPNCTL.write_text(text)
    (ROOT / "VERSION").write_text("0.2.11\n")

    changelog = (ROOT / "CHANGELOG.md").read_text()
    entry = '''## 0.2.11\n\n- replace the Plasma-owned settings dialog with a standalone Evgenium Network application\n- keep the desktop widget minimal: `E-VPN`, ON/OFF switch and a gear that launches the standalone GUI\n- add a custom Qt Quick interface for VPN status, DIRECT applications, sites/IPs, server ports and diagnostics\n- add one-click exclusions from currently running applications in the standalone GUI\n- install an `evgenium-network` launcher and desktop-menu entry without adding new package dependencies\n- keep the manager release archive backward-compatible with old updaters by embedding GUI assets inside `vpnctl.py`\n\n'''
    if not changelog.startswith("# Changelog\n\n"):
        raise SystemExit("unexpected changelog header")
    changelog = "# Changelog\n\n" + entry + changelog[len("# Changelog\n\n"):]
    (ROOT / "CHANGELOG.md").write_text(changelog)


if __name__ == "__main__":
    main()
