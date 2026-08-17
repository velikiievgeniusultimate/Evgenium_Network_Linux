#!/usr/bin/env python3
from pathlib import Path

p = Path("src/vpnctl.py")
s = p.read_text()

# Keep the last good profile even if a fresh activation attempt fails while VPN was off.
old = '''    RUNTIME_CONFIG.unlink(missing_ok=True)
    remove_guard()
    save_state({"active": None})
    fail(
        "VPN не прошёл реальную проверку; прямой интернет "
'''
new = '''    RUNTIME_CONFIG.unlink(missing_ok=True)
    remove_guard()
    save_state({
        "active": None,
        "last_active": old_state.get("last_active") or old_state.get("active"),
    })
    fail(
        "VPN не прошёл реальную проверку; прямой интернет "
'''
if old in s:
    s = s.replace(old, new, 1)
elif '"last_active": old_state.get("last_active") or old_state.get("active")' not in s:
    raise SystemExit("failed-activation state block not found")

# Cosmetic indentation fix in the IPv4-only success state.
s = s.replace(
    '                        "active": path.name,\n                    "last_active": path.name,\n',
    '                        "active": path.name,\n                        "last_active": path.name,\n',
    1,
)

# The settings control should be an unobtrusive gear immediately beside the switch.
s = s.replace(
    '''                PlasmaComponents3.ToolButton {
                    icon.name: "configure"
                    text: "Настройки"
                    onClicked: root.settingsVisible = !root.settingsVisible
                }
''',
    '''                PlasmaComponents3.ToolButton {
                    Layout.preferredWidth: 34
                    Layout.preferredHeight: 34
                    icon.name: "configure"
                    text: ""
                    onClicked: root.settingsVisible = !root.settingsVisible
                }
''',
    1,
)

# If the widget package is already installed, future manager updates refresh it in place.
old_after = '''    if args.cmd == "internal-after-update":
        sync_system_files()
        # Migrate an active 0.2.3 rule -> main without cycling the VPN.
'''
new_after = '''    if args.cmd == "internal-after-update":
        sync_system_files()
        if _widget_package_dir(settings).exists():
            cmd_widget_install(settings)
        # Migrate an active 0.2.3 rule -> main without cycling the VPN.
'''
if old_after in s:
    s = s.replace(old_after, new_after, 1)
elif 'if _widget_package_dir(settings).exists():' not in s:
    raise SystemExit("internal-after-update block not found")

# Strengthen the offline self-test around the local UI contract.
old_test = '''        assert "/usr/local/bin/vpn status --json" in PLASMOID_MAIN_QML
        assert "/usr/local/bin/vpn toggle" in PLASMOID_MAIN_QML
'''
new_test = '''        assert "/usr/local/bin/vpn status --json" in PLASMOID_MAIN_QML
        assert "/usr/local/bin/vpn toggle" in PLASMOID_MAIN_QML
        assert 'icon.name: "configure"' in PLASMOID_MAIN_QML
        assert 'text: ""' in PLASMOID_MAIN_QML
'''
if old_test in s and 'assert \'text: ""\' in PLASMOID_MAIN_QML' not in s:
    s = s.replace(old_test, new_test, 1)

p.write_text(s)
