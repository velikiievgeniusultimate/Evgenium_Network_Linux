"""Exercise the Linux worker through its normal entry point with no real network operations."""

from contextlib import ExitStack, redirect_stdout
from io import StringIO
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch


source = Path(os.environ.get("EVG_TEST_CLIENT_SRC", Path(__file__).parents[1] / "src"))
sys.path.insert(0, str(source))
import path_ranking
import vpn_tunnel as tunnel


def forbidden(*args, **kwargs):
    raise AssertionError(f"unexpected real operation: {args!r}")


class WorkerScenario:
    def __init__(self, stack):
        self.root = Path(stack.enter_context(TemporaryDirectory()))
        rank = path_ranking.Ranking(self.root / "ranking.json", [c["id"] for c in tunnel.CANDIDATES])
        rank.bootstrap()
        rank.save()
        self.order = rank.candidates()
        self.online = True
        self.suspended_seconds = 0.0
        self.sleep_calls = 0
        self.preparations = 0
        self.starts = []
        self.stop_calls = []
        self.health_calls = []
        self.events = []
        self.on_sleep = lambda: None
        self.on_setup = lambda: None
        self.on_start = lambda daemon: None
        self.on_health = lambda daemon: True
        self.on_stage = lambda phase, fields: None
        replacements = {
            "ROOT": self.root, "STOP": False, "rank_api": path_ranking, "policy": None,
            "command": forbidden, "inside": forbidden, "stage": self.stage,
            "cleanup": lambda: None, "refresh_retained_guard": lambda: None,
            "stop_candidate": self.stop_calls.append, "setup_network": self.setup,
            "start_candidate": self.start, "path_healthy": self.health,
            "suspend_offset": lambda: self.suspended_seconds, "uplink_ready": lambda: self.online,
            "physical_route": self.physical_route, "sync_device_name": lambda: None,
            "enroll": lambda: ("local-test", None), "activate_full": lambda address: None,
            "check_system_dns": lambda: None, "DNS_PROCESS": None,
            "start_namespace_dns": lambda: None, "traffic_total": lambda: 0,
        }
        for name, value in replacements.items():
            stack.enter_context(patch.object(tunnel, name, value))
        stack.enter_context(patch.object(tunnel.time, "sleep", self.sleep))
        stack.enter_context(patch.object(tunnel.signal, "signal"))

    @property
    def routes(self):
        return [daemon.route for daemon in self.starts]

    def sleep(self, seconds):
        self.sleep_calls += 1
        if self.sleep_calls > 2000:
            raise AssertionError(f"worker loop did not finish: {self.routes}")
        self.on_sleep()

    def physical_route(self):
        if not self.online:
            raise RuntimeError("no_physical_route")
        return {"dev": "evg-test-absent"}

    def setup(self):
        self.preparations += 1
        self.on_setup()
        if not self.online:
            raise RuntimeError("no_physical_route")

    def start(self, candidate, identity):
        if len(self.starts) >= 9:
            raise AssertionError(f"too many handshake attempts: {self.routes}")
        if not self.online:
            raise AssertionError("handshake started before the simulated uplink returned")
        daemon = SimpleNamespace(route=candidate["id"], index=len(self.starts))
        self.starts.append(daemon)
        self.on_start(daemon)
        return daemon

    def health(self, daemon):
        self.health_calls.append(daemon)
        return self.on_health(daemon)

    def stage(self, phase, message, progress, **fields):
        self.events.append((phase, fields))
        self.on_stage(phase, fields)

    def did_connect(self):
        return any(phase == "connected" for phase, _ in self.events)


class WorkerResumeTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.run_state = WorkerScenario(self.stack)

    def test_waits_until_a_route_appears_before_preparation(self):
        s = self.run_state
        s.online = False
        s.on_sleep = lambda: setattr(s, "online", True)
        s.on_stage = lambda phase, _: setattr(tunnel, "STOP", True) if phase == "connected" else None
        tunnel.worker()
        self.assertEqual(s.preparations, 1)
        self.assertEqual(s.routes, [s.order[0]])
        self.assertGreater(s.sleep_calls, 0)

    def test_route_lost_during_preparation_retries_normal_mode(self):
        s = self.run_state

        def drop_route_once():
            if s.preparations == 1:
                s.online = False

        s.on_setup = drop_route_once
        s.on_sleep = lambda: setattr(s, "online", True)
        s.on_stage = lambda phase, _: setattr(tunnel, "STOP", True) if phase == "connected" else None
        self.assertFalse(tunnel.panic_enabled())
        tunnel.worker()
        self.assertEqual(s.preparations, 2)
        self.assertEqual(s.routes, [s.order[0]])

    def test_resume_reuses_healthy_running_session(self):
        s = self.run_state

        def after_first_connection():
            if s.did_connect():
                s.suspended_seconds = 30

        def healthy(daemon):
            self.assertEqual(s.suspended_seconds, 30)
            self.assertIs(daemon, s.starts[0])
            self.assertNotIn(daemon, s.stop_calls)
            return True

        def after_health(phase, fields):
            if phase == "connected" and s.health_calls:
                tunnel.STOP = True

        s.on_sleep = after_first_connection
        s.on_health = healthy
        s.on_stage = after_health
        tunnel.worker()
        self.assertEqual(s.routes, [s.order[0]])
        self.assertEqual(s.health_calls, s.starts)
        preparation_pids = [fields["routing_worker_pid"] for phase, fields in s.events if phase == "prepare"]
        self.assertEqual(preparation_pids, [os.getpid()])

    def check_reconnect(self, ordinary_failure_afterward):
        s = self.run_state
        post_resume_checks = 0

        def first_route_fails(daemon):
            if daemon.index == 0:
                raise RuntimeError("simulated_transport_failure")

        def first_suspend():
            if s.did_connect() and not s.suspended_seconds:
                s.online = False
                s.suspended_seconds = 30
            elif s.suspended_seconds:
                s.online = True

        def health(daemon):
            nonlocal post_resume_checks
            if daemon.index == 1:
                self.assertEqual(s.suspended_seconds, 30)
                return False
            if daemon.index == 2:
                post_resume_checks += 1
                return post_resume_checks == 1
            return True

        def stop_after_confirmation(phase, fields):
            if phase == "connected" and ((ordinary_failure_afterward and len(s.starts) >= 4) or
                                         (not ordinary_failure_afterward and post_resume_checks)):
                tunnel.STOP = True

        s.on_start = first_route_fails
        s.on_sleep = first_suspend
        s.on_health = health
        s.on_stage = stop_after_confirmation
        tunnel.worker()
        self.assertGreater(post_resume_checks, 0)
        expected = [s.order[0], s.order[1], s.order[1]]
        if ordinary_failure_afterward:
            expected.append(s.order[2])
        self.assertEqual(s.routes, expected)
        self.assertEqual(tunnel.selected_route(), "auto")

    def test_unhealthy_wake_reconnects_previous_auto_route(self):
        self.check_reconnect(ordinary_failure_afterward=False)

    def test_later_awake_failure_resumes_ordinary_fallback(self):
        self.check_reconnect(ordinary_failure_afterward=True)

    def test_off_during_resume_wait_stops_worker_and_releases_guard_explicitly(self):
        s = self.run_state
        operations = []
        saw_lost_uplink = False

        def systemctl(args, **kwargs):
            operations.append(args)
            if args == ["systemctl", "stop", tunnel.UNIT]:
                tunnel.STOP = True
            return subprocess.CompletedProcess(args, 0)

        self.stack.enter_context(patch.object(tunnel, "command", side_effect=systemctl))
        release = self.stack.enter_context(patch.object(tunnel, "cleanup_full"))
        tunnel.select_route("ee-evgt")

        def uplink_ready():
            nonlocal saw_lost_uplink
            saw_lost_uplink = saw_lost_uplink or not s.online
            return s.online

        def during_resume():
            if s.did_connect() and not s.suspended_seconds:
                s.suspended_seconds = 30
                s.online = False
            elif saw_lost_uplink:
                with redirect_stdout(StringIO()):
                    tunnel.disconnect()

        self.stack.enter_context(patch.object(tunnel, "uplink_ready", side_effect=uplink_ready))
        s.on_sleep = during_resume
        tunnel.worker()
        self.assertTrue(saw_lost_uplink)
        self.assertEqual(operations, [["systemctl", "disable", tunnel.UNIT], ["systemctl", "stop", tunnel.UNIT]])
        release.assert_called_once_with(release=True)
        self.assertEqual(s.preparations, 1)
        self.assertEqual(s.routes, ["ee-evgt"])
        self.assertEqual(tunnel.selected_route(), "ee-evgt")


if __name__ == "__main__":
    unittest.main()
