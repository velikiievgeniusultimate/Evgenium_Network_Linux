import contextlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import path_ranking
import vpn_tunnel as tunnel


SPAWN = subprocess.Popen
CHILD = """
import signal, sys
from pathlib import Path
root, role, mode = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
def on_term(*args):
    (root / (role + '.term')).touch()
    if mode != 'stubborn' or role != 'request':
        sys.exit(0)
signal.signal(signal.SIGTERM, on_term)
(root / (role + '.ready')).touch()
while True:
    signal.pause()
"""


def fixture_worker(root, mode):
    children = {}
    releases = []
    commands = []
    route = "ee-evgt-ru" if mode == "stubborn" else "ee-tls"
    candidate = next(c for c in tunnel.CANDIDATES if c["id"] == route)
    carrier_binary = root / "fixture-evgt"

    def spawn(role):
        if role in children:
            raise AssertionError("manual stop started another candidate")
        children[role] = SPAWN([sys.executable, "-I", "-c", CHILD, str(root), role, mode])
        return children[role]

    def foreground(args, **kwargs):
        if args == tunnel.swan_command("--initiate", "--child", tunnel.LAYOUT.ike + "-net"):
            return spawn("request")
        if route == "ee-tls" and args[-1] == "internal-tls-client":
            return spawn("carrier")
        if route == "ee-evgt-ru" and args[4:8] == [str(carrier_binary), "-mode", "client", "-server"]:
            if candidate["transport_port"] != 24579 or args[8] != candidate["transport_address"] + ":24579":
                raise AssertionError("unexpected HSVDS relay endpoint")
            return spawn("carrier")
        raise AssertionError("unexpected child command")

    def command(args, **kwargs):
        commands.append(list(args))
        listening = "127.0.0.1:24573" if args[-2:] == ["ss", "-anu"] else ""
        return subprocess.CompletedProcess(args, 0, listening, "")

    class Policy:
        def load(self):
            return {"mode": "full"}

        def inclusive(self, settings):
            return False

        def stop(self, release=False):
            releases.append(release)

    try:
        with contextlib.ExitStack() as stack:
            for name in ("ROOT", "RUNTIME"):
                stack.enter_context(patch.object(tunnel, name, root))
            stack.enter_context(patch.object(tunnel, "STATE", root / "state.json"))
            stack.enter_context(patch.object(tunnel, "rank_api", path_ranking))
            stack.enter_context(patch.object(tunnel, "policy", Policy()))
            stack.enter_context(patch.object(tunnel, "ensure_evgt_binary", return_value=carrier_binary))
            stack.enter_context(patch.object(tunnel, "command", side_effect=command))
            stack.enter_context(patch.object(tunnel.subprocess, "Popen", side_effect=foreground))
            stack.enter_context(patch.object(tunnel, "enroll", return_value=("fixture", None)))
            stack.enter_context(patch.object(tunnel, "uplink_ready", return_value=True))
            stack.enter_context(patch.object(tunnel, "start_daemon", side_effect=lambda env: spawn("daemon")))
            for name in ("refresh_retained_guard", "setup_network", "sync_device_name", "daemon_configs"):
                stack.enter_context(patch.object(tunnel, name))
            for name in ("installed", "prepare_data_plane", "egress_health"):
                stack.enter_context(patch.object(tunnel, name, side_effect=AssertionError("handshake advanced after stop")))
            tunnel.full_state().write_text('{"active": true}')
            (root / "full-guard.nft").write_text("fixture")
            if mode == "stubborn":
                (root / "panic.json").write_text('{"enabled":true}')
            tunnel.select_route(route)
            tunnel.worker()
            result = {
                "route": tunnel.selected_route(),
                "panic": tunnel.panic_enabled(),
                "returncodes": {role: child.returncode for role, child in children.items()},
                "phase": tunnel.saved()["phase"],
                "guard_retained": (root / "full-guard.nft").read_text() == "fixture" and tunnel.full_state().exists(),
                "guard_released": any(releases) or any(tunnel.GUARD_UNIT in args or tunnel.FULL_GUARD in args for args in commands),
            }
            (root / "result.json").write_text(json.dumps(result))
    finally:
        for child in children.values():
            if child.poll() is None:
                child.kill()
                child.wait()


class WorkerStopTests(unittest.TestCase):
    def exercise_stop(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = SPAWN([sys.executable, "-I", "-B", __file__, "--fixture-worker", directory, mode], start_new_session=True)
            try:
                deadline = time.monotonic() + 8
                while not all((root / (role + ".ready")).exists() for role in ("request", "daemon", "carrier")):
                    self.assertIsNone(worker.poll(), "worker exited before the fake IKE negotiation")
                    self.assertLess(time.monotonic(), deadline, "fixture did not reach IKE negotiation")
                    time.sleep(0.01)
                worker.terminate()  # systemd's KillMode=mixed sends TERM only to the worker.
                self.assertEqual(worker.wait(timeout=7), 0)
                result = json.loads((root / "result.json").read_text())
                self.assertEqual(result["route"], "ee-evgt-ru" if mode == "stubborn" else "ee-tls")
                self.assertEqual(result["panic"], mode == "stubborn")
                self.assertEqual(result["returncodes"], {"request": -signal.SIGKILL if mode == "stubborn" else 0, "daemon": 0, "carrier": 0})
                self.assertTrue(all((root / (role + ".term")).exists() for role in ("request", "daemon", "carrier")))
                self.assertEqual(result["phase"], "off")
                self.assertTrue(result["guard_retained"])
                self.assertFalse(result["guard_released"])
            finally:
                if worker.poll() is None:
                    os.killpg(worker.pid, signal.SIGKILL)
                    worker.wait()

    def test_worker_stops_during_ike_and_reaps_its_children(self):
        self.exercise_stop("cooperative")

    def test_worker_kills_only_a_stubborn_request_after_grace(self):
        self.exercise_stop("stubborn")

    def test_success_and_failure_preserve_the_normal_command_contract(self):
        for rc in (0, 3):
            with self.subTest(rc=rc):
                child = SPAWN([sys.executable, "-I", "-c", "import sys; sys.exit(" + str(rc) + ")"])
                with patch.object(tunnel.subprocess, "Popen", return_value=child) as spawn:
                    if rc:
                        with self.assertRaisesRegex(RuntimeError, "^command_failed$"):
                            tunnel.initiate_ike()
                    else:
                        tunnel.initiate_ike()
                self.assertEqual(spawn.call_args.args[0], tunnel.swan_command("--initiate", "--child", tunnel.LAYOUT.ike + "-net"))
                self.assertEqual(child.returncode, rc)

    def test_no_second_attempt_when_stopping_and_timeout_reaps(self):
        with patch.object(tunnel, "STOP", True), patch.object(tunnel.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(RuntimeError, "^cancelled$"):
                tunnel.initiate_ike()
            spawn.assert_not_called()
        child = SPAWN([sys.executable, "-I", "-c", "import time; time.sleep(30)"])
        with patch.object(tunnel.subprocess, "Popen", return_value=child):
            with self.assertRaises(subprocess.TimeoutExpired):
                tunnel.initiate_ike(timeout=0.1)
        self.assertEqual(child.returncode, -signal.SIGTERM)

    def test_disconnect_releases_only_after_stop_or_confirmed_missing_unit(self):
        OK = subprocess.CompletedProcess([], 0, "", "")
        refused = subprocess.CompletedProcess([], 1, "", "")
        for stop, state, releases in (
            (OK, None, True),
            (refused, subprocess.CompletedProcess([], 4, "LoadState=not-found\nActiveState=inactive\n", ""), True),
            (refused, subprocess.CompletedProcess([], 0, "LoadState=not-found\nActiveState=active\n", ""), False),
            (refused, subprocess.CompletedProcess([], 0, "LoadState=loaded\nActiveState=deactivating\n", ""), False),
            (refused, refused, False),
            (subprocess.TimeoutExpired("stop", 25), None, False),
        ):
            with self.subTest(stop=stop, state=state), patch.object(tunnel, "command", side_effect=[OK, stop, state]) as command, \
                    patch.object(tunnel, "cleanup") as cleanup, patch.object(tunnel, "cleanup_full") as full, patch.object(tunnel, "stage") as stage:
                if releases:
                    tunnel.disconnect()
                    cleanup.assert_called_once_with()
                    full.assert_called_once_with(release=True)
                    self.assertEqual(stage.call_args.args[0], "off")
                else:
                    with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)):
                        tunnel.disconnect()
                    cleanup.assert_not_called()
                    full.assert_not_called()
                    stage.assert_not_called()
                self.assertEqual(command.call_args_list[0].args[0], ["systemctl", "disable", tunnel.UNIT])
                self.assertEqual(command.call_args_list[1].args[0], ["systemctl", "stop", tunnel.UNIT])


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--fixture-worker":
        fixture_worker(Path(sys.argv[2]), sys.argv[3])
    else:
        unittest.main()
