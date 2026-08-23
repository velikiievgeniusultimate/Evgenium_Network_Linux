#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VPNCTL = ROOT / "src" / "vpnctl.py"
BUILDER = ROOT / "scripts" / "build_release.py"
CHANGELOG = ROOT / "CHANGELOG.md"
VERSION = ROOT / "VERSION"

OLD_MANAGER = 'MANAGER_VERSION = "0.2.13"'
NEW_MANAGER = 'MANAGER_VERSION = "0.2.14"'
OLD_XRAY = 'SAFE_XRAY_VERSION = "26.6.27"'
NEW_XRAY = 'SAFE_XRAY_VERSION = "26.7.28"'


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count == 0:
        if new in text:
            return
        raise SystemExit(f"{path}: expected marker not found: {old!r}")
    if count != 1:
        raise SystemExit(f"{path}: expected one marker, found {count}: {old!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    replace_once(VPNCTL, OLD_MANAGER, NEW_MANAGER)
    replace_once(VPNCTL, OLD_XRAY, NEW_XRAY)
    replace_once(BUILDER, OLD_XRAY, NEW_XRAY)

    text = VPNCTL.read_text(encoding="utf-8")
    text = text.replace(
        '# 26.6.27 принимает publicKey; в новых версиях это alias password.',
        '# Xray accepts publicKey here; newer builds also expose password as an alias.',
    )
    VPNCTL.write_text(text, encoding="utf-8")

    VERSION.write_text("0.2.14\n", encoding="utf-8")

    changelog = CHANGELOG.read_text(encoding="utf-8")
    if "## 0.2.14" not in changelog:
        marker = "# Changelog\n\n"
        entry = (
            "## 0.2.14\n\n"
            "- update the pinned official Xray core from 26.6.27 to 26.7.28\n"
            "- pick up upstream Linux TUN `autoOutboundsInterface` fix merged in Xray-core PR #6413\n"
            "- keep the existing fail-closed kill switch, DIRECT rules, Waydroid policy and profile behavior unchanged\n"
            "- preserve SHA-256 verification, config validation and automatic Xray binary rollback during core updates\n\n"
        )
        if not changelog.startswith(marker):
            raise SystemExit("unexpected CHANGELOG header")
        CHANGELOG.write_text(marker + entry + changelog[len(marker):], encoding="utf-8")

    subprocess.run(
        [sys.executable, str(BUILDER), "--channels", "stable", "testing"],
        cwd=ROOT,
        check=True,
    )

    # Release builder and runtime manager must advertise the same tested core.
    stable = (ROOT / "update" / "stable.json").read_text(encoding="utf-8")
    testing = (ROOT / "update" / "testing.json").read_text(encoding="utf-8")
    for name, manifest in (("stable", stable), ("testing", testing)):
        if '"version": "0.2.14"' not in manifest or '"xray_version": "26.7.28"' not in manifest:
            raise SystemExit(f"{name} manifest mismatch")


if __name__ == "__main__":
    main()
