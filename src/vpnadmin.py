#!/usr/bin/env python3
from __future__ import annotations
import contextlib
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

SETTINGS = pathlib.Path("/etc/vpn-manager/settings.json")
RELEASES = pathlib.Path("/opt/vpn-manager/releases")
CURRENT = pathlib.Path("/opt/vpn-manager/current")
PREVIOUS = pathlib.Path("/opt/vpn-manager/previous")

def die(msg):
    print("ERROR:", msg, file=sys.stderr)
    raise SystemExit(1)

def load_settings():
    try:
        return json.loads(SETTINGS.read_text())
    except Exception as exc:
        die(f"settings: {exc}")

def save_settings(data):
    tmp = SETTINGS.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, SETTINGS)

def safe_extract(path, dest):
    allowed = {"vpnctl.py", "vpnadmin.py", "VERSION"}
    with tarfile.open(path, "r:gz") as tf:
        members = tf.getmembers()
        names = {m.name for m in members}
        if names != allowed:
            die(f"archive members: {sorted(names)}, expected {sorted(allowed)}")
        for m in members:
            pp = pathlib.PurePosixPath(m.name)
            if not m.isfile() or pp.is_absolute() or ".." in pp.parts:
                die("unsafe archive")
        tf.extractall(dest)
    ver = (dest / "VERSION").read_text().strip()
    if not re.fullmatch(r"[0-9A-Za-z._+-]+", ver):
        die("bad VERSION")
    os.chmod(dest / "vpnctl.py", 0o755)
    os.chmod(dest / "vpnadmin.py", 0o755)
    return ver

def local_update(path):
    path = pathlib.Path(path).resolve()
    sha = pathlib.Path(str(path) + ".sha256")
    if not path.is_file():
        die(f"нет файла {path}")
    if not sha.is_file():
        die(f"рядом должен лежать {sha.name}")

    expected = sha.read_text().split()[0].strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        die("bad sha256 file")
    got = hashlib.sha256(path.read_bytes()).hexdigest()
    if got != expected:
        die(f"SHA-256 mismatch: expected {expected}, got {got}")

    with tempfile.TemporaryDirectory(dir="/opt/vpn-manager/releases") as td:
        unpack = pathlib.Path(td) / "unpack"
        unpack.mkdir()
        version = safe_extract(path, unpack)
        cp = subprocess.run(
            [sys.executable, str(unpack / "vpnctl.py"), "--self-test"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if cp.returncode:
            die("self-test failed:\n" + cp.stderr + cp.stdout)

        dest = RELEASES / version
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(unpack, dest)

    old = pathlib.Path(os.path.realpath(CURRENT)) if CURRENT.exists() else None
    PREVIOUS.unlink(missing_ok=True)
    if old and old.exists():
        PREVIOUS.symlink_to(old)

    newlink = pathlib.Path("/opt/vpn-manager/.current.new")
    newlink.unlink(missing_ok=True)
    newlink.symlink_to(dest)
    os.replace(newlink, CURRENT)

    for target, src in (
        ("/usr/local/sbin/vpnctl", CURRENT / "vpnctl.py"),
        ("/usr/local/sbin/vpn-manager-admin", CURRENT / "vpnadmin.py"),
    ):
        tmp = target + ".new"
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        os.symlink(src, tmp)
        os.replace(tmp, target)

    subprocess.run(
        ["/usr/local/sbin/vpnctl", "internal-after-update"],
        check=True
    )
    print(f"VPN Manager updated locally -> {version}")

def set_source(url):
    if not url.startswith("https://"):
        die("source должен быть HTTPS")
    data = load_settings()
    data["manager_manifest_url"] = url
    save_settings(data)
    print("Manager update source saved.")

def rollback():
    subprocess.run(
        ["/usr/local/sbin/vpnctl", "manager-rollback"], check=True
    )

def legacy_cleanup():
    # Делать только после успешного vpn test на Xray.
    subprocess.run(
        ["/usr/bin/systemctl", "disable", "--now", "vpn-mihomo.service"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    for p in (
        "/etc/systemd/system/vpn-mihomo.service",
        "/opt/vpn-manager/bin/mihomo",
        "/opt/vpn-manager/bin/mihomo.previous",
    ):
        pathlib.Path(p).unlink(missing_ok=True)

    shutil.rmtree("/var/lib/vpn-manager/mihomo", ignore_errors=True)

    # Старые 0.1.x manager releases больше несовместимы с Xray edition.
    for p in RELEASES.glob("0.1.*"):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)

    # Старый системный пользователь.
    cp = subprocess.run(
        ["/usr/bin/id", "vpn-mihomo"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    if cp.returncode == 0:
        subprocess.run(
            ["/usr/sbin/userdel", "vpn-mihomo"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=False)
    subprocess.run(["/usr/bin/systemctl", "reset-failed"], check=False)
    print("Legacy Mihomo components removed.")

def main():
    if os.geteuid() != 0:
        die("используй sudo vpn-manager-admin ...")
    if len(sys.argv) < 2:
        print("""Usage:
  sudo vpn-manager-admin source HTTPS_MANIFEST
  sudo vpn-manager-admin local RELEASE.tar.gz
  sudo vpn-manager-admin rollback
  sudo vpn-manager-admin legacy-cleanup
""")
        return

    cmd = sys.argv[1]
    if cmd == "source" and len(sys.argv) == 3:
        set_source(sys.argv[2])
    elif cmd == "local" and len(sys.argv) == 3:
        local_update(sys.argv[2])
    elif cmd == "rollback" and len(sys.argv) == 2:
        rollback()
    elif cmd == "legacy-cleanup" and len(sys.argv) == 2:
        legacy_cleanup()
    else:
        die("неверные аргументы")

if __name__ == "__main__":
    main()