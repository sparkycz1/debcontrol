"""List systemd service units on a managed machine — the Logs/Monitoring
tabs' "Services" modal. Read-only, no root needed: listing unit state is
allowed for any user under systemd's default polkit policy.

Requires `systemd`/`systemctl` — a container-like or otherwise systemd-less
managed machine simply gets an empty list rather than an error (same "not
every command is guaranteed present" convention `app.ssh.facts` and
`app.ssh.packages` already follow).
"""

from __future__ import annotations

from typing import TypedDict

from app.db.models.machine import Machine
from app.ssh.client import open_connection

# `--plain --no-legend --no-pager` for stable, script-friendly output (no
# ANSI, no header/footer, no pager prompt); `--all` so stopped/inactive
# units are included too, not just currently-running ones — a service that
# *should* be running but isn't is exactly what this list exists to surface.
SERVICES_COMMAND = (
    "if command -v systemctl >/dev/null 2>&1; then "
    "systemctl list-units --type=service --all --plain --no-legend --no-pager "
    "2>/dev/null; "
    "fi"
)


class ServiceEntry(TypedDict):
    unit: str
    load_state: str
    active_state: str
    sub_state: str
    description: str


def parse_services_output(raw: str) -> list[ServiceEntry]:
    """Parse `systemctl list-units --type=service --all --plain --no-legend`
    output. Each line: `UNIT LOAD ACTIVE SUB DESCRIPTION`, the first four
    fields whitespace-separated with no internal spaces, the description
    free text running to end of line. A line that doesn't even have four
    fields (never seen in practice, but the input is a remote command's
    output, not something to trust blindly) is skipped rather than raising.
    """
    services: list[ServiceEntry] = []
    for line in raw.splitlines():
        # A unit name marked `not-found`/`masked` can be prefixed with a
        # bullet ("● ") by some systemd versions even with `--plain` —
        # strip it defensively.
        fields = line.strip().lstrip("●").strip().split(None, 4)
        if len(fields) < 4:
            continue
        unit, load_state, active_state, sub_state = fields[:4]
        description = fields[4] if len(fields) > 4 else ""
        services.append(
            ServiceEntry(
                unit=unit,
                load_state=load_state,
                active_state=active_state,
                sub_state=sub_state,
                description=description,
            )
        )
    return services


async def gather_services(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> list[ServiceEntry]:
    """Connect to a machine and list its systemd service units. Requires a
    pinned host key."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(SERVICES_COMMAND, check=False, timeout=timeout_seconds)

    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_services_output(raw)
