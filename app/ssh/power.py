"""Reboot / shut down a machine over SSH.

Fire-and-forget by design: `shutdown` schedules the action and returns
almost immediately, but the SSH connection can legitimately be torn down
mid-response the moment the remote actually starts going down — that's
expected, not a failure, and is treated as such here. Unlike system
updates, there's no persistent run history for this — the existing
per-minute reachability check already shows a machine going offline and
(once it's back) online again, which is what actually matters afterwards.

Requires root — same as `app.ssh.updates`; see the wiki page "Managed
Machine Requirements" for the sudoers line (`shutdown` needs to be listed
alongside `apt-get`). Same root fallback too: `sudo -n` first, falling
back to running `shutdown` directly if that fails — the only case that
matters in practice is the machine's configured account already being
root, where no sudo grant exists (or is even possible, on a root account
with no usable sudo password) but the plain command works fine.

The confirmation step (typing the machine's/group's name before this is
even called) lives in the web layer — see `app.web.routes.machines` and
`app.web.routes.machine_groups`. This module has no opinion on that; it
just sends the command once asked to.
"""

from __future__ import annotations

import contextlib
import enum

import asyncssh

from app.db.models.machine import Machine
from app.ssh.client import open_connection

# The command itself returns almost immediately; this just bounds how long
# we wait for that acknowledgement, not the actual shutdown/reboot.
_COMMAND_TIMEOUT_SECONDS = 15


class PowerAction(enum.StrEnum):
    REBOOT = "reboot"
    SHUTDOWN = "shutdown"


_SHUTDOWN_FLAG = {
    PowerAction.REBOOT: "-r",
    PowerAction.SHUTDOWN: "-h",
}


def build_power_command(action: PowerAction) -> str:
    flag = _SHUTDOWN_FLAG[action]
    return f"(sudo -n shutdown {flag} now 2>/dev/null || shutdown {flag} now)"


async def send_power_command(
    machine: Machine, secret: str | None, action: PowerAction, connect_timeout_seconds: int
) -> None:
    """Connect (strict pinned host-key verification, as always) and issue
    the reboot/shutdown command."""
    command = build_power_command(action)
    conn = await open_connection(machine, secret, connect_timeout_seconds)
    try:
        await conn.run(command, check=False, timeout=_COMMAND_TIMEOUT_SECONDS)
    except (asyncssh.Error, OSError, TimeoutError):
        # Expected: the connection can legitimately drop mid-response once
        # the remote starts shutting down.
        pass
    finally:
        conn.close()
        with contextlib.suppress(Exception):
            await conn.wait_closed()
