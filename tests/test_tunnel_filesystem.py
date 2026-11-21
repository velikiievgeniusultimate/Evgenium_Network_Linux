"""Filesystem regressions for generated VPN units and migration from Linux 0.5.8."""
import contextlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import vpn_tunnel as tunnel


# Keep these release fixtures independent of the current template generator.
OLD_TUNNEL = """[Unit]
Description=Evgenium full-device Estonia VPN
After=network.target
StartLimitIntervalSec=180
StartLimitBurst=3
[Service]
Type=simple
ExecStart=/usr/local/sbin/vpnctl internal-starfive-tunnel
ExecStopPost=/usr/local/sbin/vpnctl internal-starfive-tunnel-cleanup
TimeoutStopSec=20
KillMode=mixed
UMask=0077
MemoryMax=256M
Restart=on-failure
RestartSec=3
"""
OLD_RECOVERY = """[Unit]
Description=Recover only interrupted Evgenium tunnel test resources
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target vpn-xray.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vpnctl internal-starfive-tunnel-cleanup
[Install]
WantedBy=multi-user.target
"""
OLD_GUARD = """[Unit]
Description=Evgenium full-device kill switch
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/nft -f {root}/full-guard.nft
[Install]
WantedBy=multi-user.target
"""


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


class TunnelFilesystemTests(unittest.TestCase):
    def setUp(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        self.directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        self.units = self.directory / "systemd" / "system"
        self.units.mkdir(parents=True)
        self.wants = self.units / "multi-user.target.wants"
        self.wants.mkdir()
        state_dir = self.directory / "state"
        state_dir.mkdir()
        self.transaction = state_dir / "tunnel-layout-transition"

        def under_fixture(layout):
            return layout._replace(root=self.directory / "etc" / layout.root.name,
                                   runtime=self.directory / "run" / layout.runtime.name,
                                   state=state_dir / layout.state.name)

        self.old = under_fixture(tunnel.LEGACY)
        self.new = under_fixture(tunnel.CURRENT)
        stack.callback(tunnel.use_layout, tunnel.LAYOUT)
        stack.enter_context(patch.multiple(tunnel, LEGACY=self.old, CURRENT=self.new,
                                           LAYOUT_TRANSACTION=self.transaction, UNIT_DIR=self.units))
        tunnel.use_layout(self.new)
        # This suite exercises the disk transaction for a quiescent client.
        stack.enter_context(patch.object(tunnel, "layout_in_use", return_value=False))
        stack.enter_context(patch.object(tunnel.shutil, "which", return_value="/usr/bin/nft"))
        self.command = stack.enter_context(patch.object(tunnel, "command", autospec=True,
                                                         return_value=subprocess.CompletedProcess([], 0, "")))
        old_umask = os.umask(0o077)
        stack.callback(os.umask, old_umask)

    def seed_old(self):
        self.old.root.mkdir(mode=0o700, parents=True)
        (self.old.root / "token").write_bytes(b"fixture credential\n")
        self.old.runtime.mkdir(parents=True)
        self.old.state.write_text('{"phase":"off"}\n')
        snapshots = {self.old.unit: OLD_TUNNEL, self.old.recovery: OLD_RECOVERY,
                     self.old.guard: OLD_GUARD.format(root=self.old.root)}
        for name, body in snapshots.items():
            (self.units / name).write_text(body)
        (self.wants / self.old.recovery).symlink_to("../" + self.old.recovery)
        tunnel.select_installed_layout()
        self.assertEqual(tunnel.LAYOUT, self.old)
        return snapshots

    def test_fresh_creation_and_rewrite_use_public_and_private_modes(self):
        tunnel.select_installed_layout()
        tunnel.finish_name_transition()
        self.assertEqual(tunnel.LAYOUT, self.new)
        self.command.assert_not_called()
        private_file = self.new.root / "full-guard.nft"
        with patch.object(tunnel, "ensure_dependencies"), \
             patch.object(tunnel, "token_status", return_value={"has_token": True}), \
             patch.object(tunnel, "stage"), contextlib.redirect_stdout(io.StringIO()):
            for iteration in range(2):
                with self.subTest(iteration=iteration):
                    tunnel.connect()
                    tunnel.persist_guard("fixture guard rules\n")
                    for name in (self.new.unit, self.new.recovery, self.new.guard):
                        self.assertEqual(mode(self.units / name), 0o644)
                    self.assertIn("internal-vpn-tunnel", (self.units / self.new.unit).read_text())
                    self.assertEqual(mode(private_file), 0o600)
                    if iteration == 0:
                        (self.units / self.new.unit).chmod(0o600)
                        private_file.chmod(0o644)

    def test_repair_only_changes_modes_of_exact_old_0600_templates(self):
        snapshots = self.seed_old()
        tunnel.migrate_unit_modes()
        for name, body in snapshots.items():
            self.assertEqual(mode(self.units / name), 0o644)
            self.assertEqual((self.units / name).read_text(), body)
        self.assertEqual(mode(self.old.root / "token"), 0o600)

        unit = self.units / self.old.unit
        unit.chmod(0o640)
        recovery = self.units / self.old.recovery
        recovery.write_text(OLD_RECOVERY + "# local variation\n")
        recovery.chmod(0o600)
        guard = self.units / self.old.guard
        guard.chmod(0o600)
        os.link(guard, self.directory / "admin-copy")
        tunnel.migrate_unit_modes()
        self.assertEqual(mode(unit), 0o640)
        self.assertEqual(mode(recovery), 0o600)
        self.assertEqual(mode(guard), 0o600)

    def test_idle_legacy_migration_preserves_identity_enablement_and_state(self):
        self.seed_old()
        token_inode = (self.old.root / "token").stat().st_ino
        (self.old.root / "strongswan.conf").write_text(f"socket = {self.old.runtime}/charon.vici\n")
        tunnel.finish_name_transition()
        self.assertEqual(tunnel.LAYOUT, self.new)
        token = self.new.root / "token"
        self.assertEqual(token.read_bytes(), b"fixture credential\n")
        self.assertEqual(token.stat().st_ino, token_inode)
        self.assertEqual(mode(token), 0o600)
        self.assertEqual((self.new.root / "strongswan.conf").read_text(),
                         f"socket = {self.new.runtime}/charon.vici\n")
        self.assertEqual(self.new.state.read_text(), '{"phase":"off"}\n')
        self.assertTrue(self.new.runtime.is_dir())
        for role in ("unit", "recovery", "guard"):
            self.assertFalse(os.path.lexists(self.units / getattr(self.old, role)))
            self.assertEqual(mode(self.units / getattr(self.new, role)), 0o644)
        self.assertFalse(os.path.lexists(self.wants / self.old.recovery))
        self.assertEqual((self.wants / self.new.recovery).resolve(), self.units / self.new.recovery)
        self.assertFalse((self.wants / self.new.guard).exists())
        self.assertFalse(self.transaction.exists())
        self.command.assert_called_once_with(["systemctl", "daemon-reload"])

    def test_interrupted_reload_is_retried_after_reentering_the_manager(self):
        self.seed_old()
        self.command.side_effect = [RuntimeError("test reload failed"), subprocess.CompletedProcess([], 0)]
        with self.assertRaisesRegex(RuntimeError, "test reload failed"):
            tunnel.finish_name_transition()
        self.assertEqual(self.transaction.read_text().strip(), "upgrade")
        self.assertEqual(mode(self.transaction), 0o600)
        self.assertFalse(self.old.root.exists())
        self.assertEqual((self.new.root / "token").read_bytes(), b"fixture credential\n")
        tunnel.select_installed_layout()
        tunnel.finish_name_transition()
        tunnel.finish_name_transition()
        self.assertFalse(self.transaction.exists())
        self.assertEqual(tunnel.LAYOUT, self.new)
        self.assertEqual((self.wants / self.new.recovery).resolve(), self.units / self.new.recovery)
        self.assertEqual(self.command.call_args_list, [call(["systemctl", "daemon-reload"])] * 2)

    def test_foreign_unit_symlink_blocks_migration_and_permission_repair(self):
        self.seed_old()
        external = self.directory / "local-file"
        external.write_text(OLD_TUNNEL)
        unit = self.units / self.old.unit
        unit.unlink()
        unit.symlink_to(external)
        tunnel.migrate_unit_modes()
        self.assertEqual(mode(external), 0o600)
        self.assertFalse(tunnel.move_idle_layout(self.old, self.new))
        self.assertTrue(unit.is_symlink())
        self.assertTrue(self.old.root.is_dir())
        self.assertFalse(self.new.root.exists())
        self.assertFalse(self.transaction.exists())
        self.command.assert_not_called()

    def test_existing_or_dangling_dropins_preserve_the_old_installation(self):
        self.seed_old()
        for name, dangling in ((self.old.unit, False), (self.new.recovery, True)):
            with self.subTest(name=name, dangling=dangling):
                dropin = self.units / (name + ".d")
                if dangling:
                    dropin.symlink_to(self.directory / "site-managed-dropins")
                else:
                    dropin.mkdir()
                    (dropin / "20-site.conf").write_text("[Service]\nPrivateTmp=yes\n")
                self.assertFalse(tunnel.move_idle_layout(self.old, self.new))
                self.assertTrue(os.path.lexists(dropin))
                self.assertTrue(self.old.root.is_dir())
                self.assertFalse(self.new.root.exists())
                self.assertFalse(self.transaction.exists())
                self.command.assert_not_called()
                if not dangling:
                    (dropin / "20-site.conf").unlink()
                    dropin.rmdir()


if __name__ == "__main__":
    unittest.main()
