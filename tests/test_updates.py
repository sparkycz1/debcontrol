from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from app.db.models.machine import Machine
from app.db.models.machine_update_run import UpgradeStrategy
from app.ssh import updates as updates_module
from app.ssh.updates import (
    build_update_command,
    parse_apt_upgradable_packages,
    parse_flatpak_upgradable_output,
    parse_flatpak_upgradable_packages,
    parse_snap_upgradable_output,
    parse_snap_upgradable_packages,
    parse_upgradable_output,
    run_system_update,
)


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


def test_build_update_command_includes_guarded_flatpak_and_snap():
    command = build_update_command(UpgradeStrategy.DIST_UPGRADE)

    assert "command -v flatpak" in command
    assert "flatpak update -y --noninteractive" in command
    assert "command -v snap" in command
    assert "snap refresh" in command


def test_build_update_command_falls_back_to_running_directly_as_root():
    """Every privileged step tries `sudo -n` first, then runs the plain
    command directly if that fails — the case that matters is an account
    that's already root and has no sudo grant (or password) at all. See
    `app.ssh.updates._with_root_fallback`."""
    command = build_update_command(UpgradeStrategy.DIST_UPGRADE)

    assert "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update -q" in command
    assert (
        "|| env DEBIAN_FRONTEND=noninteractive apt-get update -q" in command
    )
    assert "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -y -q autoremove" in command
    assert "|| env DEBIAN_FRONTEND=noninteractive apt-get -y -q autoremove" in command
    assert "sudo -n flatpak update -y --noninteractive" in command
    assert "|| flatpak update -y --noninteractive" in command
    assert "sudo -n snap refresh" in command
    assert "|| snap refresh" in command


def test_parse_upgradable_output_counts_packages_and_security():
    raw = (
        "Listing...\n"
        "===APT_UPGRADABLE===\n"
        "firefox-esr/bookworm-security 115.13.0esr-1~deb12u1 amd64 "
        "[upgradable from: 114.0esr-1~deb12u1]\n"
        "bash/stable 5.2.15-2 all [upgradable from: 5.2.15-1]\n"
        "===FLATPAK_UPGRADABLE===\n"
        "===SNAP_UPGRADABLE===\n"
    )

    upgradable, security = parse_upgradable_output(raw)

    assert upgradable == 2
    assert security == 1


def test_parse_upgradable_output_no_updates():
    raw = "===APT_UPGRADABLE===\n===FLATPAK_UPGRADABLE===\n===SNAP_UPGRADABLE===\n"

    upgradable, security = parse_upgradable_output(raw)

    assert upgradable == 0
    assert security == 0


def test_parse_upgradable_output_missing_marker():
    # e.g. apt-get update failed, so the marker never got echoed at all.
    upgradable, security = parse_upgradable_output("some unrelated error text")

    assert upgradable == 0
    assert security == 0


def test_parse_flatpak_upgradable_output_counts_and_dedupes():
    raw = (
        "===APT_UPGRADABLE===\n"
        "===FLATPAK_UPGRADABLE===\n"
        "org.mozilla.firefox\n"
        "org.gimp.GIMP\n"
        "org.mozilla.firefox\n"  # same app tracked from a second remote
        "===SNAP_UPGRADABLE===\n"
    )

    assert parse_flatpak_upgradable_output(raw) == 2


def test_parse_flatpak_upgradable_output_not_installed():
    raw = "===APT_UPGRADABLE===\n===FLATPAK_UPGRADABLE===\n===SNAP_UPGRADABLE===\n"

    assert parse_flatpak_upgradable_output(raw) == 0


def test_parse_snap_upgradable_output_counts():
    raw = (
        "===APT_UPGRADABLE===\n"
        "===FLATPAK_UPGRADABLE===\n"
        "===SNAP_UPGRADABLE===\n"
        "core22\n"
        "lxd\n"
    )

    assert parse_snap_upgradable_output(raw) == 2


def test_parse_snap_upgradable_output_not_installed():
    raw = "===APT_UPGRADABLE===\n===FLATPAK_UPGRADABLE===\n===SNAP_UPGRADABLE===\n"

    assert parse_snap_upgradable_output(raw) == 0


def test_parse_apt_upgradable_packages_extracts_names_and_versions():
    raw = (
        "===APT_UPGRADABLE===\n"
        "firefox-esr/bookworm-security 115.13.0esr-1~deb12u1 amd64 "
        "[upgradable from: 114.0esr-1~deb12u1]\n"
        "bash/stable 5.2.15-2 all [upgradable from: 5.2.15-1]\n"
        "===FLATPAK_UPGRADABLE===\n"
        "===SNAP_UPGRADABLE===\n"
    )

    packages = parse_apt_upgradable_packages(raw)

    assert packages == [
        {
            "name": "firefox-esr",
            "current_version": "114.0esr-1~deb12u1",
            "new_version": "115.13.0esr-1~deb12u1",
        },
        {"name": "bash", "current_version": "5.2.15-1", "new_version": "5.2.15-2"},
    ]


def test_parse_flatpak_upgradable_packages_extracts_names_and_versions():
    raw = (
        "===APT_UPGRADABLE===\n"
        "===FLATPAK_UPGRADABLE===\n"
        "org.mozilla.firefox\t128.0\n"
        "org.mozilla.firefox\t128.0\n"  # duplicate remote — de-duplicated
        "===SNAP_UPGRADABLE===\n"
    )

    packages = parse_flatpak_upgradable_packages(raw)

    assert packages == [
        {"name": "org.mozilla.firefox", "current_version": None, "new_version": "128.0"}
    ]


def test_parse_snap_upgradable_packages_extracts_names_and_versions():
    raw = (
        "===APT_UPGRADABLE===\n"
        "===FLATPAK_UPGRADABLE===\n"
        "===SNAP_UPGRADABLE===\n"
        "core22\t20240301\n"
        "lxd\t5.21\n"
    )

    packages = parse_snap_upgradable_packages(raw)

    assert packages == [
        {"name": "core22", "current_version": None, "new_version": "20240301"},
        {"name": "lxd", "current_version": None, "new_version": "5.21"},
    ]


# --- run_system_update: incremental output streaming ------------------------
#
# `run_system_update` reads stdout in chunks (rather than `conn.run()`'s
# buffer-it-all-and-return convenience) so a caller-supplied `on_output` can
# be told the output accumulated so far as it arrives — see
# `app.tasks.jobs._run_machine_update`, which uses this to make the
# update-run page show apt's output live. These fakes stand in for the
# AsyncSSH connection/process without touching the network at all.


class _FakeCompletedProcess:
    def __init__(self, exit_status: int) -> None:
        self.exit_status = exit_status


class _FakeUpdateProcess:
    def __init__(self, chunks: list[str], exit_status: int) -> None:
        self._chunks = list(chunks)
        self._exit_status = exit_status
        self.stdout = self

    async def read(self, n: int) -> str:
        if self._chunks:
            return self._chunks.pop(0)
        return ""

    async def wait(self) -> _FakeCompletedProcess:
        return _FakeCompletedProcess(self._exit_status)

    async def __aenter__(self) -> _FakeUpdateProcess:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


class _FakeUpdateConnection:
    def __init__(self, process: _FakeUpdateProcess) -> None:
        self._process = process

    async def create_process(self, script: str, stderr: object = None) -> _FakeUpdateProcess:
        return self._process

    async def __aenter__(self) -> _FakeUpdateConnection:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


async def test_run_system_update_streams_output_as_it_arrives(monkeypatch):
    process = _FakeUpdateProcess(["Reading package lists...\n", "0 upgraded.\n"], exit_status=0)
    connection = _FakeUpdateConnection(process)

    async def fake_open_connection(machine: object, secret: object, timeout_seconds: int) -> object:
        return connection

    monkeypatch.setattr(updates_module, "open_connection", fake_open_connection)

    seen: list[str] = []

    async def on_output(text: str) -> None:
        seen.append(text)

    result = await run_system_update(
        cast(Machine, SimpleNamespace()),
        None,
        UpgradeStrategy.DIST_UPGRADE,
        5,
        5,
        on_output=on_output,
    )

    assert result.exit_status == 0
    assert result.output == "Reading package lists...\n0 upgraded.\n"
    # Called once per chunk, each time with everything accumulated so far —
    # not just the new bytes — since that's what a DB write of "output so
    # far" needs.
    assert seen == [
        "Reading package lists...\n",
        "Reading package lists...\n0 upgraded.\n",
    ]


async def test_run_system_update_works_without_an_on_output_callback(monkeypatch):
    process = _FakeUpdateProcess(["ok\n"], exit_status=0)
    connection = _FakeUpdateConnection(process)

    async def fake_open_connection(machine: object, secret: object, timeout_seconds: int) -> object:
        return connection

    monkeypatch.setattr(updates_module, "open_connection", fake_open_connection)

    result = await run_system_update(
        cast(Machine, SimpleNamespace()), None, UpgradeStrategy.FULL_UPGRADE, 5, 5
    )

    assert result.exit_status == 0
    assert result.output == "ok\n"
