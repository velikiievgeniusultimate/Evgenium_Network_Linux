#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
DIST = ROOT / "dist"
UPDATE = ROOT / "update"
REPO_RAW = "https://raw.githubusercontent.com/velikiievgeniusultimate/Evgenium_Network_Linux/main"
SAFE_XRAY_VERSION = "26.6.27"


def version() -> str:
    v = (ROOT / "VERSION").read_text().strip()
    if not re.fullmatch(r"[0-9A-Za-z._+-]+", v):
        raise SystemExit("bad VERSION")
    text = (SRC / "vpnctl.py").read_text()
    m = re.search(r'^MANAGER_VERSION\s*=\s*"([^"]+)"', text, re.M)
    if not m or m.group(1) != v:
        raise SystemExit(f"VERSION mismatch: file={v!r}, vpnctl={m.group(1) if m else None!r}")
    return v


def add_bytes(tf: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = mode
    ti.uid = 0
    ti.gid = 0
    ti.uname = "root"
    ti.gname = "root"
    ti.mtime = 0
    tf.addfile(ti, io.BytesIO(data))


def build_archive(v: str) -> tuple[Path, str]:
    DIST.mkdir(parents=True, exist_ok=True)
    out = DIST / f"vpn-manager-{v}.tar.gz"
    # Deterministic gzip/tar metadata so a rebuild of identical source has identical SHA-256.
    import gzip
    with out.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tf:
                add_bytes(tf, "vpnctl.py", (SRC / "vpnctl.py").read_bytes(), 0o755)
                add_bytes(tf, "vpnadmin.py", (SRC / "vpnadmin.py").read_bytes(), 0o755)
                add_bytes(tf, "VERSION", (ROOT / "VERSION").read_bytes(), 0o644)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    (DIST / f"vpn-manager-{v}.tar.gz.sha256").write_text(f"{digest}  {out.name}\n")
    return out, digest


def manifest(v: str, digest: str, channel: str) -> dict:
    return {
        "schema": 1,
        "channel": channel,
        "version": v,
        "url": f"{REPO_RAW}/dist/vpn-manager-{v}.tar.gz",
        "sha256": digest,
        "min_updater_version": "0.2.0",
        "xray_version": SAFE_XRAY_VERSION,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--channels", nargs="+", default=["stable"], choices=["stable", "testing"])
    args = ap.parse_args()
    v = version()
    archive, digest = build_archive(v)
    UPDATE.mkdir(parents=True, exist_ok=True)
    for channel in args.channels:
        (UPDATE / f"{channel}.json").write_text(
            json.dumps(manifest(v, digest, channel), indent=2) + "\n"
        )
    print(archive)
    print(digest)


if __name__ == "__main__":
    main()
