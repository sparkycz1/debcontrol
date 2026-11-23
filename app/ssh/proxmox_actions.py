"""Running a Proxmox VE guest command over SSH — the Proxmox tab's start /
shut down / reboot / stop buttons and a guest's notes (see `app.ssh.proxmox`
for the commands themselves)."""

from __future__ import annotations

from typing import Any

import asyncssh

from app.db.models.machine import Machine
from app.ssh.client import open_connection
from app.ssh.exceptions import SSHConnectionError
from app.ssh.proxmox import build_guest_action_command, build_guest_notes_command
from app.ssh.shell import with_root_shim


async def run_guest_action(
    machine: Machine, secret: str | None, guest: dict[str, Any], action: str, timeout_seconds: int
) -> tuple[int, str]:
    """(exit status, output). `pvesh create .../status/<action>` queues the
    task and returns straight away; the next monitoring sample shows the
    new state."""
    return await _run(machine, secret, build_guest_action_command(guest, action), action,
                      timeout_seconds)


async def run_guest_notes(
    machine: Machine, secret: str | None, guest: dict[str, Any], notes: str, timeout_seconds: int
) -> tuple[int, str]:
    """(exit status, output) of writing the guest's notes."""
    return await _run(machine, secret, build_guest_notes_command(guest, notes), "notes",
                      timeout_seconds)


async def _run(
    machine: Machine, secret: str | None, command: str, what: str, timeout_seconds: int
) -> tuple[int, str]:
    try:
        async with await open_connection(machine, secret, timeout_seconds) as conn:
            result = await conn.run(
                with_root_shim(command), check=False, timeout=timeout_seconds + 60
            )
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SSHConnectionError(f"{what} failed on {machine.name}: {exc}") from exc
    stdout = result.stdout or ""
    text = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
    status = result.exit_status if isinstance(result.exit_status, int) else -1
    return status, text.strip()[-1000:]
