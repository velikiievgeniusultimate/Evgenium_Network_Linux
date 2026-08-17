#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "vpnctl.py"
CHANGELOG = ROOT / "CHANGELOG.md"
VERSION = ROOT / "VERSION"

text = SRC.read_text()
text = text.replace('MANAGER_VERSION = "0.2.9"', 'MANAGER_VERSION = "0.2.10"', 1)
text = text.replace('"Version": "1.2"', '"Version": "1.3"', 1)

old = '''    Plasmoid.icon: "network-vpn"\n    toolTipMainText: "E-VPN"'''
new = '''    Plasmoid.icon: "network-vpn"\n    Plasmoid.hasConfigurationInterface: true\n    toolTipMainText: "E-VPN"'''
if old not in text:
    raise SystemExit("main QML insertion point not found")
text = text.replace(old, new, 1)

old = '''    function openSettings() {\n        const configureAction = plasmoid.action("configure")\n        if (configureAction)\n            configureAction.trigger()\n    }'''
new = '''    function openSettings() {\n        let configureAction = null\n        if (plasmoid && plasmoid.internalAction)\n            configureAction = plasmoid.internalAction("configure")\n        if (!configureAction && plasmoid && plasmoid.action)\n            configureAction = plasmoid.action("configure")\n        if (configureAction) {\n            configureAction.trigger()\n            return\n        }\n        root.errorText = "Plasma не создала действие настроек"\n    }'''
if old not in text:
    raise SystemExit("openSettings block not found")
text = text.replace(old, new, 1)

old = '''        assert 'plasmoid.action("configure")' in PLASMOID_MAIN_QML'''
new = '''        assert 'Plasmoid.hasConfigurationInterface: true' in PLASMOID_MAIN_QML\n        assert 'plasmoid.internalAction("configure")' in PLASMOID_MAIN_QML\n        assert 'plasmoid.action("configure")' in PLASMOID_MAIN_QML'''
if old not in text:
    raise SystemExit("self-test configure assertion not found")
text = text.replace(old, new, 1)

SRC.write_text(text)
VERSION.write_text("0.2.10\n")

changelog = CHANGELOG.read_text()
entry = '''## 0.2.10\n\n- fix the Plasma settings gear by explicitly enabling the configuration interface\n- trigger Plasma 6's shell-owned `configure` action through `Applet::internalAction()` with the older action API kept as a fallback\n- show a widget tooltip error if Plasma still fails to expose a configure action\n\n'''
needle = "# Changelog\n\n"
if entry not in changelog:
    if needle not in changelog:
        raise SystemExit("changelog header not found")
    changelog = changelog.replace(needle, needle + entry, 1)
CHANGELOG.write_text(changelog)
