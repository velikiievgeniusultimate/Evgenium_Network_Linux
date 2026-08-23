#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VPNCTL = ROOT / "src" / "vpnctl.py"
INSTALL = ROOT / "install.sh"
VERSION = ROOT / "VERSION"
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "README.md"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        if new in text:
            return text
        raise SystemExit(f"{label}: expected source text not found")
    return text.replace(old, new, 1)


def main() -> None:
    VERSION.write_text("0.2.16\n")

    vpnctl = VPNCTL.read_text()
    vpnctl = replace_once(
        vpnctl,
        'MANAGER_VERSION = "0.2.15"',
        'MANAGER_VERSION = "0.2.16"',
        "manager version",
    )
    if "import urllib.error\n" not in vpnctl:
        vpnctl = replace_once(
            vpnctl,
            "import urllib.parse\nimport urllib.request\n",
            "import urllib.error\nimport urllib.parse\nimport urllib.request\n",
            "urllib imports",
        )

    new_http_get = r'''def http_get(url: str, max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        fail("Разрешены только HTTPS URL.")

    ctx = ssl.create_default_context()
    retryable_http = {408, 425, 429, 500, 502, 503, 504}
    attempts = 4
    last_error: Exception | None = None

    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": f"EvgeniusVPNManager/{MANAGER_VERSION}",
                "Accept": "application/vnd.github+json, application/json, text/plain, */*",
            },
        )
        retryable = False
        try:
            with urllib.request.urlopen(req, timeout=40, context=ctx) as r:
                out = bytearray()
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    out += chunk
                    if len(out) > max_bytes:
                        fail(f"Загрузка превысила лимит {max_bytes} bytes.")
                return bytes(out)
        except urllib.error.HTTPError as exc:
            last_error = exc
            retryable = int(exc.code) in retryable_http
        except urllib.error.URLError as exc:
            # Certificate verification failures are not transient and must never
            # be worked around by retries or weaker TLS settings.
            if isinstance(getattr(exc, "reason", None), ssl.SSLCertVerificationError):
                fail(f"HTTPS certificate verification failed: {exc}")
            last_error = exc
            retryable = True
        except (TimeoutError, socket.timeout, ConnectionResetError, BrokenPipeError) as exc:
            last_error = exc
            retryable = True
        except ssl.SSLCertVerificationError as exc:
            fail(f"HTTPS certificate verification failed: {exc}")
        except Exception as exc:
            fail(f"HTTPS download failed: {exc}")

        if not retryable or attempt >= attempts:
            fail(f"HTTPS download failed after {attempt} attempt(s): {last_error}")

        delay = min(8, 2 ** (attempt - 1))
        warn(
            f"Временная ошибка HTTPS ({last_error}); "
            f"повтор {attempt + 1}/{attempts} через {delay} с."
        )
        time.sleep(delay)

    fail(f"HTTPS download failed: {last_error}")
'''

    pattern = re.compile(
        r"def http_get\(url: str, max_bytes: int = MAX_DOWNLOAD_BYTES\) -> bytes:\n.*?\n\ndef list_config_paths",
        re.S,
    )
    match = pattern.search(vpnctl)
    if not match:
        if "retryable_http = {408, 425, 429, 500, 502, 503, 504}" not in vpnctl:
            raise SystemExit("http_get block not found")
    else:
        vpnctl = pattern.sub(new_http_get + "\n\ndef list_config_paths", vpnctl, count=1)
    VPNCTL.write_text(vpnctl)

    install = INSTALL.read_text()
    old_existing = '''is_existing_install() {
    [[ -x /usr/local/sbin/vpnctl ]] || return 1
    [[ -f /opt/vpn-manager/current/VERSION ]] || return 1
    [[ -x /opt/vpn-manager/bin/xray ]] || return 1
    return 0
}
'''
    new_existing = '''is_existing_install() {
    # Treat a manager+settings installation as recoverable even if the final
    # Xray download was interrupted. This lets rerunning install.sh repair a
    # partial installation instead of rebuilding it from scratch.
    [[ -x /usr/local/sbin/vpnctl ]] || return 1
    [[ -f /opt/vpn-manager/current/VERSION ]] || return 1
    [[ -f /etc/vpn-manager/settings.json ]] || return 1
    return 0
}
'''
    install = replace_once(install, old_existing, new_existing, "partial install detection")
    install = replace_once(
        install,
        '''    sudo /usr/local/sbin/vpnctl update
    ok "${APP_NAME} уже установлен. Ничего заново не переустанавливалось."
''',
        '''    sudo /usr/local/sbin/vpnctl update
    # `core-update` is idempotent. Calling it explicitly also repairs a previous
    # clean install that reached the manager/GUI stage but lost the Xray asset
    # download to a transient GitHub/CDN error.
    sudo /usr/local/sbin/vpnctl core-update
    ok "${APP_NAME} уже установлен. Ничего заново не переустанавливалось."
''',
        "existing install core repair",
    )
    INSTALL.write_text(install)

    changelog = CHANGELOG.read_text()
    entry = '''## 0.2.16\n\n- retry transient HTTPS failures (including HTTP 429/500/502/503/504) while downloading GitHub manifests, checksums and Xray assets\n- keep certificate verification fail-closed; TLS certificate errors are never retried with weaker security\n- retry the whole response read so interrupted release-asset transfers cannot leave a partial core download\n- make rerunning `install.sh` recover an installation where the manager/GUI were installed but the final Xray download failed\n- explicitly run the idempotent core repair step after updating an existing/partial installation\n- keep Xray 26.7.28 and all VPN routing, kill-switch, Waydroid and DIRECT behavior unchanged\n\n'''
    if "## 0.2.16\n" not in changelog:
        changelog = changelog.replace("# Changelog\n\n", "# Changelog\n\n" + entry, 1)
    CHANGELOG.write_text(changelog)

    readme = README.read_text()
    readme = re.sub(
        r"Current stable baseline: \*\*[0-9.]+\*\*\.",
        "Current stable baseline: **0.2.16**.",
        readme,
        count=1,
    )
    README.write_text(readme)

    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_release.py"), "--channels", "stable", "testing"],
        check=True,
    )
    print("prepared 0.2.16")


if __name__ == "__main__":
    main()
