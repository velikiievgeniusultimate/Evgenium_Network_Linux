#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VPN = ROOT / "src" / "vpnctl.py"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {text.count(old)}")
    return text.replace(old, new, 1)


s = VPN.read_text()
s = replace_once(s, 'MANAGER_VERSION = "0.2.6"', 'MANAGER_VERSION = "0.2.7"', "version")

widget_constants = r'''
PLASMOID_ID = "com.evgenium.network"
PLASMOID_METADATA = r'''{
  "KPlugin": {
    "Authors": [
      {
        "Name": "Evgenium"
      }
    ],
    "Category": "System Information",
    "Description": "Quick VPN switch for Evgenium Network Linux",
    "Icon": "network-vpn",
    "Id": "com.evgenium.network",
    "Name": "Evgenium Network",
    "Version": "1.0"
  },
  "X-Plasma-API-Minimum-Version": "6.0",
  "KPackageStructure": "Plasma/Applet"
}
'''
PLASMOID_MAIN_QML = r'''import QtQuick
import QtQuick.Layouts
import org.kde.kirigami as Kirigami
import org.kde.plasma.components as PlasmaComponents3
import org.kde.plasma.plasmoid
import org.kde.plasma.plasma5support as Plasma5Support

PlasmoidItem {
    id: root

    property bool vpnActive: false
    property bool busy: false
    property bool settingsVisible: false
    property string activeProfile: ""
    property string lastProfile: ""
    property string errorText: ""
    property int appExclusions: 0
    property int domainExclusions: 0
    property int networkExclusions: 0

    readonly property string statusCommand: "/usr/local/bin/vpn status --json"
    readonly property string toggleCommand: "/usr/local/bin/vpn toggle"

    Plasmoid.icon: "network-vpn"
    Plasmoid.toolTipMainText: "Evgenium Network"
    Plasmoid.toolTipSubText: busy
        ? "Переключаю VPN…"
        : (vpnActive ? "VPN включён" : "VPN выключен")
    Plasmoid.preferredRepresentation: Plasmoid.fullRepresentation

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
                    root.activeProfile = String(state.profile || "")
                    root.lastProfile = String(state.last_profile || "")
                    root.appExclusions = Number(state.direct_applications || 0)
                    root.domainExclusions = Number(state.direct_domains || 0)
                    root.networkExclusions = Number(state.direct_networks || 0)
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

    Plasmoid.fullRepresentation: Item {
        Layout.minimumWidth: Kirigami.Units.gridUnit * 14
        Layout.preferredWidth: Kirigami.Units.gridUnit * 15
        Layout.minimumHeight: root.settingsVisible
            ? Kirigami.Units.gridUnit * 10
            : Kirigami.Units.gridUnit * 4
        Layout.preferredHeight: Layout.minimumHeight

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: Kirigami.Units.smallSpacing * 2
            spacing: Kirigami.Units.smallSpacing

            RowLayout {
                Layout.fillWidth: true
                spacing: Kirigami.Units.smallSpacing

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 0

                    PlasmaComponents3.Label {
                        text: "VPN"
                        font.bold: true
                    }

                    PlasmaComponents3.Label {
                        text: root.busy
                            ? "Переключаю…"
                            : (root.vpnActive
                                ? "Включён" + (root.activeProfile.length > 0 ? " • " + root.activeProfile : "")
                                : "Выключен")
                        opacity: 0.72
                        elide: Text.ElideRight
                        Layout.fillWidth: true
                    }
                }

                Item {
                    id: switchControl
                    Layout.preferredWidth: 48
                    Layout.preferredHeight: 26
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
                        width: 20
                        height: 20
                        radius: 10
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
                    icon.name: "configure"
                    text: "Настройки"
                    onClicked: root.settingsVisible = !root.settingsVisible
                }
            }

            ColumnLayout {
                visible: root.settingsVisible
                Layout.fillWidth: true
                spacing: Kirigami.Units.smallSpacing

                Rectangle {
                    Layout.fillWidth: true
                    height: 1
                    color: Kirigami.Theme.textColor
                    opacity: 0.12
                }

                PlasmaComponents3.Label {
                    text: "Настройки"
                    font.bold: true
                }

                PlasmaComponents3.Label {
                    Layout.fillWidth: true
                    text: "Приложения-исключения: " + root.appExclusions
                    opacity: 0.82
                }

                PlasmaComponents3.Label {
                    Layout.fillWidth: true
                    text: "Исключённые сайты: " + root.domainExclusions
                    opacity: 0.82
                }

                PlasmaComponents3.Label {
                    Layout.fillWidth: true
                    text: "Исключённые IP/сети: " + root.networkExclusions
                    opacity: 0.82
                }

                PlasmaComponents3.Label {
                    Layout.fillWidth: true
                    text: "Редактирование этих списков появится здесь в следующих версиях."
                    wrapMode: Text.WordWrap
                    opacity: 0.58
                }
            }

            PlasmaComponents3.Label {
                visible: root.errorText.length > 0
                Layout.fillWidth: true
                text: root.errorText
                color: Kirigami.Theme.negativeTextColor
                wrapMode: Text.WordWrap
                font.pixelSize: Kirigami.Theme.smallFont.pixelSize
            }
        }
    }
}
'''
'''

s = replace_once(
    s,
    'DIRECT_SOCKS_PORT = 18443\n',
    'DIRECT_SOCKS_PORT = 18443\n' + widget_constants,
    "widget constants",
)

# Preserve the last successfully connected profile so a one-click widget can
# turn the VPN back on without exposing configuration details to QML.
s = s.replace('                    "active": path.name,\n', '                    "active": path.name,\n                    "last_active": path.name,\n')
if s.count('"last_active": path.name') != 2:
    raise SystemExit("expected two successful activation state blocks")

old_deactivate = '''def deactivate() -> None:
    info("Выключаю VPN...")
    stop_core()
    RUNTIME_CONFIG.unlink(missing_ok=True)
    remove_guard()
    save_state({"active": None})
    ok("VPN выключен. Прямой интернет разрешён.")
'''
new_deactivate = '''def deactivate() -> None:
    info("Выключаю VPN...")
    st = load_state()
    last_active = st.get("active") or st.get("last_active")
    stop_core()
    RUNTIME_CONFIG.unlink(missing_ok=True)
    remove_guard()
    save_state({"active": None, "last_active": last_active})
    ok("VPN выключен. Прямой интернет разрешён.")
'''
s = replace_once(s, old_deactivate, new_deactivate, "deactivate")

widget_functions = r'''
def _status_payload(settings: dict) -> dict:
    st = load_state()
    active = service_active()
    return {
        "manager": MANAGER_VERSION,
        "active": active,
        "profile": str(st.get("active") or "") if active else "",
        "last_profile": str(st.get("last_active") or st.get("active") or ""),
        "ipv6_mode": str(st.get("ipv6_mode") or "unknown"),
        "tun": pathlib.Path(f"/sys/class/net/{TUN_NAME}").exists(),
        "kill_switch": nft_exists(),
        "direct_domains": len(read_direct_sites(settings)),
        "direct_networks": len(read_direct_networks(settings)),
        "direct_applications": len(read_direct_apps(settings)),
    }


def cmd_status_json(settings: dict) -> None:
    print(json.dumps(_status_payload(settings), ensure_ascii=False, separators=(",", ":")))


def cmd_toggle(settings: dict) -> None:
    if service_active():
        deactivate()
        return

    st = load_state()
    requested = str(st.get("last_active") or st.get("active") or "").strip()
    if requested:
        activate(settings, choose_config(settings, requested))
        return

    paths = list_config_paths(settings)
    if len(paths) == 1:
        activate(settings, paths[0])
        return
    if not paths:
        fail("Нет VPN-конфигов. Добавь конфиг в папку VPN configs.")
    fail(
        "Виджет пока не знает, какой профиль включать. Один раз выполни "
        "`vpn on <имя>`; после этого переключатель запомнит последний профиль."
    )


def _widget_package_dir(settings: dict) -> pathlib.Path:
    home = pathlib.Path(str(settings["owner_home"]))
    return home / ".local" / "share" / "plasma" / "plasmoids" / PLASMOID_ID


def _widget_target_safe(settings: dict, package: pathlib.Path) -> None:
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


def _write_owner_text(path: pathlib.Path, text: str, uid: int, gid: int) -> None:
    fd, tmpname = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmpname, 0o644)
        os.chown(tmpname, uid, gid)
        os.replace(tmpname, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmpname)


def cmd_widget_install(settings: dict) -> None:
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
    if kbuild:
        run([kbuild], check=False, capture=True, user=str(settings["owner_user"]))

    ok(f"Plasma 6 виджет установлен: {package}")
    print("Добавь его один раз: ПКМ по рабочему столу -> Добавить виджеты -> Evgenium Network.")


def cmd_widget_remove(settings: dict) -> None:
    package = _widget_package_dir(settings)
    _widget_target_safe(settings, package)
    if package.exists():
        shutil.rmtree(package)
        kbuild = shutil.which("kbuildsycoca6")
        if kbuild:
            run([kbuild], check=False, capture=True, user=str(settings["owner_user"]))
        ok("Plasma-виджет Evgenium Network удалён.")
    else:
        ok("Plasma-виджет не установлен.")

'''
s = replace_once(s, '\ndef cmd_test(settings: dict) -> None:\n', '\n' + widget_functions + 'def cmd_test(settings: dict) -> None:\n', "widget functions")

# Validate embedded Plasma package in the manager self-test.
self_test_anchor = '''        assert f"meta mark 0x{SERVER_BYPASS_MARK:08x}" in guard
    finally:
'''
self_test_new = '''        assert f"meta mark 0x{SERVER_BYPASS_MARK:08x}" in guard

        metadata = json.loads(PLASMOID_METADATA)
        assert metadata["KPlugin"]["Id"] == PLASMOID_ID
        assert metadata["X-Plasma-API-Minimum-Version"] == "6.0"
        assert "PlasmoidItem" in PLASMOID_MAIN_QML
        assert 'engine: "executable"' in PLASMOID_MAIN_QML
        assert "/usr/local/bin/vpn status --json" in PLASMOID_MAIN_QML
        assert "/usr/local/bin/vpn toggle" in PLASMOID_MAIN_QML
    finally:
'''
s = replace_once(s, self_test_anchor, self_test_new, "self-test")

# CLI parser.
s = replace_once(
    s,
    '    sub.add_parser("off")\n    pst = sub.add_parser("status"); pst.add_argument("--ip", action="store_true")\n',
    '    sub.add_parser("off")\n    sub.add_parser("toggle")\n    pst = sub.add_parser("status"); pst.add_argument("--ip", action="store_true"); pst.add_argument("--json", action="store_true")\n',
    "status parser",
)
parser_anchor = '''    pp = sub.add_parser("port")
'''
parser_widget = '''    pw = sub.add_parser("widget")
    pwsub = pw.add_subparsers(dest="widget_cmd")
    pwsub.add_parser("install")
    pwsub.add_parser("remove")

    pp = sub.add_parser("port")
'''
s = replace_once(s, parser_anchor, parser_widget, "widget parser")

# Help text.
s = replace_once(
    s,
    '  vpn off\n  vpn status [--ip]\n',
    '  vpn off\n  vpn toggle\n  vpn status [--ip|--json]\n',
    "help toggle",
)
s = replace_once(
    s,
    '  vpn app remove PROCESS|/absolute/path|/directory/\n  vpn port list\n',
    '  vpn app remove PROCESS|/absolute/path|/directory/\n  vpn widget install|remove\n  vpn port list\n',
    "help widget",
)

# Command dispatch.
s = replace_once(
    s,
    '''    if args.cmd == "off":
        deactivate()
        return 0

    if args.cmd == "status":
        cmd_status(settings, args.ip)
        return 0
''',
    '''    if args.cmd == "off":
        deactivate()
        return 0

    if args.cmd == "toggle":
        cmd_toggle(settings)
        return 0

    if args.cmd == "status":
        if args.json:
            cmd_status_json(settings)
        else:
            cmd_status(settings, args.ip)
        return 0
''',
    "dispatch toggle/status",
)
widget_dispatch_anchor = '''    if args.cmd == "port":
'''
widget_dispatch = '''    if args.cmd == "widget":
        if args.widget_cmd in {None, "install"}:
            cmd_widget_install(settings)
            return 0
        if args.widget_cmd == "remove":
            cmd_widget_remove(settings)
            return 0

    if args.cmd == "port":
'''
s = replace_once(s, widget_dispatch_anchor, widget_dispatch, "widget dispatch")

VPN.write_text(s)

(ROOT / "VERSION").write_text("0.2.7\n")

changelog = (ROOT / "CHANGELOG.md").read_text()
entry = '''## 0.2.7

- add a Plasma 6 desktop widget with a one-click VPN ON/OFF switch and a compact settings gear
- add `vpn toggle` and remember the last successful VPN profile across `vpn off`
- add `vpn status --json` for a stable machine-readable local UI interface
- add `vpn widget install|remove`; the widget is embedded in the signed/hashed manager release rather than downloaded separately
- expose current DIRECT app/domain/network counts in the widget settings scaffold for future GUI editing

'''
if "## 0.2.7" not in changelog:
    changelog = changelog.replace("# Changelog\n\n", "# Changelog\n\n" + entry, 1)
    (ROOT / "CHANGELOG.md").write_text(changelog)

readme = (ROOT / "README.md").read_text()
readme = readme.replace("Current stable baseline: **0.2.6**.", "Current stable baseline: **0.2.7**.", 1)
readme = readme.replace("vpn off\nvpn status --ip", "vpn off\nvpn toggle\nvpn status --ip\nvpn status --json", 1)
readme = readme.replace("vpn app remove evgenium-waydroid-mapper\n", "vpn app remove evgenium-waydroid-mapper\nvpn widget install\nvpn widget remove\n", 1)
widget_docs = '''\n## KDE Plasma 6 widget\n\nVersion 0.2.7 includes a native Plasma 6 widget. Install it for the current desktop user with:\n\n```bash\nvpn widget install\n```\n\nThen right-click the desktop, choose **Add Widgets**, search for **Evgenium Network**, and place it on the desktop. The widget contains a single VPN ON/OFF switch and a settings gear. Turning the VPN back on uses the last successfully connected profile remembered by the manager. The settings area currently shows DIRECT application/domain/network counts and is intentionally reserved for the upcoming graphical exclusion editors.\n\nThe widget talks only to the local `vpn` command using `vpn status --json` and `vpn toggle`; it never receives or displays VLESS credentials.\n\n'''
if "## KDE Plasma 6 widget" not in readme:
    readme = readme.replace("## Update channel\n", widget_docs + "## Update channel\n", 1)
(ROOT / "README.md").write_text(readme)
