#!/usr/bin/env python3
from __future__ import annotations

import base64
import http.server
import json
import os
import pathlib
import secrets
import shutil
import subprocess
import sys
import threading
import urllib.parse

APP_NAME = "Evgenium Network"
VPN = "/usr/local/bin/vpn"
HERE = pathlib.Path(__file__).resolve().parent
QML_FILE = HERE / "evgenium_gui.qml"
MAX_BODY = 64 * 1024


def find_qml_runtime() -> str | None:
    for candidate in ("/usr/bin/qml6", "/usr/lib/qt6/bin/qml", "/usr/bin/qml"):
        if pathlib.Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("qml6") or shutil.which("qml")


def run_vpn(args: list[str], timeout: int = 120) -> str:
    cp = subprocess.run(
        [VPN, *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if cp.returncode != 0:
        detail = (cp.stderr or cp.stdout or f"exit {cp.returncode}").strip()
        raise RuntimeError(detail)
    return (cp.stdout or "").strip()


def run_vpn_json(args: list[str]) -> dict:
    raw = run_vpn(args)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"VPN Manager вернул некорректный JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("VPN Manager вернул неожиданный ответ.")
    return data


def encode_ui_payload(payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    quoted = urllib.parse.quote(raw, safe="")
    return base64.b64encode(quoted.encode("ascii")).decode("ascii")


class ApiServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, handler, token: str):
        super().__init__(address, handler)
        self.token = token


class Handler(http.server.BaseHTTPRequestHandler):
    server: ApiServer

    def log_message(self, _format: str, *_args) -> None:
        return

    def _headers(self, status: int = 200, content_type: str = "application/json; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Evgenium-Token")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def _json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Evgenium-Token")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        return secrets.compare_digest(
            self.headers.get("X-Evgenium-Token", ""),
            self.server.token,
        )

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        self._json({"ok": False, "error": "unauthorized"}, 403)
        return False

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise RuntimeError("Некорректный Content-Length.") from exc
        if length < 0 or length > MAX_BODY:
            raise RuntimeError("Слишком большой запрос.")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8") if raw else "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Некорректный JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Ожидался JSON object.")
        return payload

    def do_OPTIONS(self) -> None:
        self._headers(204)

    def do_GET(self) -> None:
        if not self._require_auth():
            return
        try:
            if self.path == "/api/state":
                self._json({"ok": True, "state": run_vpn_json(["ui", "state"])})
                return
            if self.path == "/api/running":
                self._json({"ok": True, "running": run_vpn_json(["ui", "running"])})
                return
            if self.path == "/api/health":
                self._json({"ok": True, "app": APP_NAME})
                return
            self._json({"ok": False, "error": "not found"}, 404)
        except Exception as exc:
            self._json({"ok": False, "error": str(exc)}, 500)

    def do_POST(self) -> None:
        if not self._require_auth():
            return
        try:
            payload = self._read_json()
            if self.path == "/api/action":
                token = encode_ui_payload(payload)
                output = run_vpn(["ui", "action", token])
                self._json({"ok": True, "output": output})
                return
            if self.path == "/api/toggle":
                output = run_vpn(["toggle"])
                self._json({"ok": True, "output": output, "state": run_vpn_json(["ui", "state"])})
                return
            self._json({"ok": False, "error": "not found"}, 404)
        except Exception as exc:
            self._json({"ok": False, "error": str(exc)}, 500)


def state_log_path() -> pathlib.Path:
    root = pathlib.Path(os.environ.get("XDG_STATE_HOME", pathlib.Path.home() / ".local" / "state"))
    path = root / "evgenium-network" / "gui.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def launch_detached() -> int:
    if not QML_FILE.is_file():
        print(f"Не найден интерфейс: {QML_FILE}", file=sys.stderr)
        return 1
    if not find_qml_runtime():
        print("Не найден qml6. Нужен Qt 6 QML runtime (qt6-declarative).", file=sys.stderr)
        return 1
    log_path = state_log_path()
    with log_path.open("ab", buffering=0) as log:
        subprocess.Popen(
            [sys.executable, str(pathlib.Path(__file__).resolve())],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
            close_fds=True,
        )
    return 0


def run_gui() -> int:
    qml = find_qml_runtime()
    if not qml:
        print("Не найден qml6. Нужен Qt 6 QML runtime (qt6-declarative).", file=sys.stderr)
        return 1
    if not QML_FILE.is_file():
        print(f"Не найден интерфейс: {QML_FILE}", file=sys.stderr)
        return 1

    token = secrets.token_urlsafe(32)
    server = ApiServer(("127.0.0.1", 0), Handler, token)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, name="evgenium-gui-api", daemon=True)
    thread.start()

    env = os.environ.copy()
    env.setdefault("QT_QUICK_CONTROLS_STYLE", "Basic")
    env.setdefault("QML_DISABLE_DISK_CACHE", "0")

    try:
        cp = subprocess.run(
            [qml, str(QML_FILE), "--", str(port), token],
            env=env,
            check=False,
        )
        return int(cp.returncode)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def self_test() -> int:
    sample = {"action": "app_add", "target": "/opt/example/bin/app"}
    token = encode_ui_payload(sample)
    decoded = urllib.parse.unquote(base64.b64decode(token).decode("ascii"))
    assert json.loads(decoded) == sample
    assert MAX_BODY <= 1024 * 1024
    qml = HERE / "evgenium_gui.qml"
    if qml.exists():
        text = qml.read_text(encoding="utf-8")
        assert "Evgenium Network" in text
        assert "/api/running" in text
        assert "/api/action" in text
    print("evgenium-gui self-test OK")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    if "--detach" in sys.argv:
        return launch_detached()
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
