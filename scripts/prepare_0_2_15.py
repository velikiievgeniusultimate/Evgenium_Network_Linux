#!/usr/bin/env python3
from __future__ import annotations

import base64
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUI = ROOT / "src" / "evgenium_gui.py"
VPNCTL = ROOT / "src" / "vpnctl.py"
VERSION = ROOT / "VERSION"
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "README.md"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        if new in text:
            return text
        raise SystemExit(f"{label}: expected source text not found")
    return text.replace(old, new, 1)


def python_b64_block(data: bytes) -> str:
    encoded = base64.b64encode(data).decode("ascii")
    chunks = [encoded[i:i + 100] for i in range(0, len(encoded), 100)]
    return "STANDALONE_GUI_PY_B64 = (\n" + "\n".join(f"    {chunk!r}" for chunk in chunks) + "\n)"


def main() -> None:
    VERSION.write_text("0.2.15\n")

    gui = GUI.read_text()
    old_candidates = '    for candidate in ("/usr/bin/qml6", "/usr/lib/qt6/bin/qml", "/usr/bin/qml"):\n'
    new_candidates = '''    for candidate in (\n        "/usr/bin/qml6",\n        "/usr/bin/qml-qt6",\n        "/usr/lib/qt6/bin/qml",\n        "/usr/lib64/qt6/bin/qml",\n        "/usr/bin/qml",\n    ):\n'''
    gui = replace_once(gui, old_candidates, new_candidates, "QML candidate list")
    gui = replace_once(
        gui,
        '    return shutil.which("qml6") or shutil.which("qml")\n',
        '    return shutil.which("qml6") or shutil.which("qml-qt6") or shutil.which("qml")\n',
        "QML PATH fallback",
    )
    old_error = 'Не найден qml6. Нужен Qt 6 QML runtime (qt6-declarative).'
    new_error = 'Не найден Qt 6 QML runtime (Arch: qt6-declarative; Fedora: qt6-qtdeclarative-devel).'
    if old_error in gui:
        gui = gui.replace(old_error, new_error)
    elif new_error not in gui:
        raise SystemExit("QML runtime error text not found")
    GUI.write_text(gui)

    vpnctl = VPNCTL.read_text()
    vpnctl = replace_once(
        vpnctl,
        'MANAGER_VERSION = "0.2.14"',
        'MANAGER_VERSION = "0.2.15"',
        "manager version",
    )
    block = python_b64_block(GUI.read_bytes())
    pattern = re.compile(
        r"STANDALONE_GUI_PY_B64 = \(\n.*?\n\)\nSTANDALONE_GUI_QML_B64 = \(",
        re.S,
    )
    if not pattern.search(vpnctl):
        raise SystemExit("embedded GUI Python block not found")
    vpnctl = pattern.sub(block + "\nSTANDALONE_GUI_QML_B64 = (", vpnctl, count=1)
    VPNCTL.write_text(vpnctl)

    changelog = CHANGELOG.read_text()
    entry = '''## 0.2.15\n\n- add clean-install support for Fedora Linux alongside Arch Linux\n- install only official distro dependencies with dnf on Fedora, including the Qt 6 QML runner used by the standalone KDE GUI\n- support Fedora's `qml-qt6` and `/usr/lib64/qt6/bin/qml` runtime locations\n- use `python3` portably instead of assuming an unversioned `python` command during installation\n- discover the distro `nologin` path and restore SELinux labels when `restorecon` is available\n- keep Xray 26.7.28, the fail-closed kill switch, Waydroid routing and existing VPN behavior unchanged\n\n'''
    if "## 0.2.15\n" not in changelog:
        changelog = changelog.replace("# Changelog\n\n", "# Changelog\n\n" + entry, 1)
    CHANGELOG.write_text(changelog)

    readme = README.read_text()
    readme = re.sub(r"Current stable baseline: \*\*[0-9.]+\*\*\.", "Current stable baseline: **0.2.15**.", readme, count=1)
    old_install = '''Fresh Arch Linux installation:\n\n```bash\ncurl -fsSL https://raw.githubusercontent.com/velikiievgeniusultimate/Evgenium_Network_Linux/main/install.sh | bash\n```\n\nThe installer runs as the normal desktop user, asks for `sudo` only for system changes, installs the required official Arch packages, creates the isolated `vpn-xray` service account, verifies the stable manager archive by SHA-256, runs compile/self-tests, installs the pinned compatible Xray-core, configures the GitHub stable update channel and creates the `vpn` command.\n'''
    new_install = '''Fresh **Arch Linux** or **Fedora Linux (KDE Plasma 6)** installation:\n\n```bash\ncurl -fsSL https://raw.githubusercontent.com/velikiievgeniusultimate/Evgenium_Network_Linux/main/install.sh | bash\n```\n\nThe installer runs as the normal desktop user, asks for `sudo` only for system changes, installs the required packages from the distribution's official repositories (`pacman` on Arch, `dnf` on Fedora), creates the isolated `vpn-xray` service account, verifies the stable manager archive by SHA-256, runs compile/self-tests, installs the pinned compatible Xray-core, configures the GitHub stable update channel and creates the `vpn` command plus the standalone Evgenium Network GUI. Fedora x86_64 and aarch64 are supported by the same installer; Xray's architecture-specific official asset is selected automatically.\n'''
    readme = replace_once(readme, old_install, new_install, "README install section")
    README.write_text(readme)

    subprocess.run([sys.executable, str(ROOT / "scripts" / "build_release.py"), "--channels", "stable", "testing"], check=True)
    print("prepared 0.2.15")


if __name__ == "__main__":
    main()
