from __future__ import annotations

from app.db.models.machine_update_run import UpgradeStrategy
from app.ssh.updates import build_update_command


def test_build_update_command_dist_upgrade():
    command = build_update_command(UpgradeStrategy.DIST_UPGRADE)

    assert "apt-get update -q" in command
    assert "dist-upgrade" in command
    assert "full-upgrade" not in command
    assert "autoremove" in command
    assert "autoclean" in command
    # Cleanup steps must run unconditionally (`;`-separated), never chained
    # with `&&` after the upgrade step, which could fail.
    assert "&&" not in command


def test_build_update_command_full_upgrade():
    command = build_update_command(UpgradeStrategy.FULL_UPGRADE)

    assert "full-upgrade" in command
    assert "dist-upgrade" not in command


def test_build_update_command_uses_noninteractive_sudo():
    command = build_update_command(UpgradeStrategy.DIST_UPGRADE)

    assert "sudo -n" in command
    assert "DEBIAN_FRONTEND=noninteractive" in command


def test_build_update_command_preserves_upgrade_exit_status():
    command = build_update_command(UpgradeStrategy.DIST_UPGRADE)

    assert 'exit "$status"' in command
    # Combined stdout+stderr capture for the whole script.
    assert command.strip().endswith("2>&1")
