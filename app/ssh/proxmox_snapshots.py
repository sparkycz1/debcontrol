"""Proxmox VE snapshots debcontrol takes of a guest before updating the
machine inside it (`app.services.update_snapshots`).

Everything goes through `pvesh` on the Proxmox host, like the guest power
actions (`app.ssh.proxmox_actions`). A snapshot has no RAM state: it is of
the disks only, which is quick and is what an "undo this update" needs.

debcontrol's snapshots are recognisable by name — `debcontrol-` and the
UTC time they were taken — so they can be told apart from a person's own
and their age can be read off without asking Proxmox.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

import asyncssh

from app.db.models.machine import Machine
from app.ssh.client import open_connection
from app.ssh.exceptions import SSHConnectionError
from app.ssh.shell import with_root_shim

SNAPSHOT_PREFIX = "debcontrol-"
_NAME_RE = re.compile(r"^debcontrol-(\d{8}-\d{6})$")
_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")

# How long a snapshot or a rollback task may take before debcontrol stops
# waiting for it (the task itself is left alone).
TASK_WAIT_SECONDS = 600
_POLL_SECONDS = 2


class SnapshotError(Exception):
    """Proxmox refused, or did not finish, a snapshot operation."""


def snapshot_name(now: datetime | None = None) -> str:
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    return SNAPSHOT_PREFIX + moment.strftime("%Y%m%d-%H%M%S")


def snapshot_taken_at(name: str) -> datetime | None:
    """When a `debcontrol-…` snapshot was taken, from its name; None for
    any other name."""
    match = _NAME_RE.match(name)
    if match is None:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y%m%d-%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def _guest_path(node: str, guest_type: str, vmid: int) -> str:
    """`/nodes/<node>/<qemu|lxc>/<vmid>`, every part checked before it
    reaches a shell."""
    if (
        guest_type not in ("qemu", "lxc")
        or isinstance(vmid, bool)
        or not isinstance(vmid, int)
        or vmid <= 0
        or not _NODE_RE.match(node)
    ):
        raise ValueError("Unknown guest.")
    return f"/nodes/{node}/{guest_type}/{vmid}"


def _wait_for_task(node: str) -> str:
    """Shell that follows a `pvesh create` whose output is in `$out`: when
    it printed a task id, wait for that task and fail unless it ended OK.
    (Whether `pvesh` waits by itself differs between versions; this works
    either way.)"""
    tries = TASK_WAIT_SECONDS // _POLL_SECONDS
    return (
        "upid=$(printf '%s' \"$out\" | grep -o 'UPID:[^\"[:space:]]*' | head -n 1); "
        'if [ -n "$upid" ]; then '
        "i=0; st=; "
        f"while [ $i -lt {tries} ]; do "
        f'st=$(sudo -n pvesh get "/nodes/{node}/tasks/$upid/status" '
        "--output-format json 2>/dev/null); "
        'if printf \'%s\' "$st" | grep -Eq \'"status" *: *"stopped"\'; then break; fi; '
        f"i=$((i+1)); sleep {_POLL_SECONDS}; "
        "done; "
        'if ! printf \'%s\' "$st" | grep -Eq \'"exitstatus" *: *"OK"\'; then '
        "printf '%s\\n' \"$st\"; exit 1; fi; "
        "fi"
    )


def build_create_command(node: str, guest_type: str, vmid: int, name: str) -> str:
    if _NAME_RE.match(name) is None:
        raise ValueError("Not a debcontrol snapshot name.")
    path = _guest_path(node, guest_type, vmid)
    return (
        f"out=$(sudo -n pvesh create {path}/snapshot --snapname {name} "
        "--description 'debcontrol: before a system update' 2>&1); rc=$?; "
        "printf '%s\\n' \"$out\"; "
        '[ "$rc" -eq 0 ] || exit "$rc"; '
        f"{_wait_for_task(node)}"
    )


def build_rollback_command(node: str, guest_type: str, vmid: int, name: str) -> str:
    """Roll the guest back to the snapshot, then start it again."""
    if _NAME_RE.match(name) is None:
        raise ValueError("Not a debcontrol snapshot name.")
    path = _guest_path(node, guest_type, vmid)
    return (
        f"out=$(sudo -n pvesh create {path}/snapshot/{name}/rollback 2>&1); rc=$?; "
        "printf '%s\\n' \"$out\"; "
        '[ "$rc" -eq 0 ] || exit "$rc"; '
        f"{_wait_for_task(node)}; "
        # A snapshot without RAM state leaves the guest stopped after a
        # rollback. Starting one that is already running is a harmless error.
        f"sudo -n pvesh create {path}/status/start >/dev/null 2>&1; exit 0"
    )


def build_list_command(guests: list[tuple[str, str, int]]) -> str:
    """One round trip listing the snapshots of several guests: a
    `===SNAP <type> <vmid>===` marker, then that guest's JSON list."""
    parts = []
    for node, guest_type, vmid in guests:
        path = _guest_path(node, guest_type, vmid)
        parts.append(
            f"echo '===SNAP {guest_type} {vmid}==='; "
            f"sudo -n pvesh get {path}/snapshot --output-format json 2>/dev/null; echo"
        )
    return "; ".join(parts) if parts else "true"


def parse_list_output(raw: str) -> dict[tuple[str, int], list[str] | None]:
    """`{(type, vmid): [debcontrol snapshot names]}`. None for a guest whose
    list could not be read (gone, moved to another node, no access) — which
    is not the same as "has none"."""
    found: dict[tuple[str, int], list[str] | None] = {}
    current: tuple[str, int] | None = None
    body: list[str] = []

    def flush() -> None:
        if current is None:
            return
        try:
            rows = json.loads("\n".join(body).strip() or "null")
        except ValueError:
            rows = None
        if not isinstance(rows, list):
            found[current] = None
            return
        found[current] = sorted(
            str(row.get("name"))
            for row in rows
            if isinstance(row, dict) and _NAME_RE.match(str(row.get("name") or ""))
        )

    for line in raw.splitlines():
        marker = re.fullmatch(r"===SNAP (qemu|lxc) (\d{1,10})===", line.strip())
        if marker is not None:
            flush()
            current = (marker.group(1), int(marker.group(2)))
            body = []
        else:
            body.append(line)
    flush()
    return found


async def _run(machine: Machine, secret: str | None, command: str, timeout_seconds: int) -> str:
    """Run `command` on the Proxmox host; its output, or `SnapshotError`
    with the output when it exits non-zero."""
    try:
        async with await open_connection(machine, secret, timeout_seconds) as conn:
            result = await conn.run(
                with_root_shim(command),
                check=False,
                timeout=timeout_seconds + TASK_WAIT_SECONDS + 60,
            )
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SSHConnectionError(f"Proxmox host {machine.name}: {exc}") from exc
    stdout = result.stdout or ""
    text = (stdout if isinstance(stdout, str) else stdout.decode(errors="replace")).strip()
    if result.exit_status != 0:
        raise SnapshotError(text[-1000:] or f"pvesh exited with status {result.exit_status}.")
    return text


async def create_snapshot(
    machine: Machine, secret: str | None, guest: dict[str, Any], name: str, timeout_seconds: int
) -> None:
    command = build_create_command(
        str(guest.get("node") or ""), str(guest.get("type") or ""), guest.get("vmid") or 0, name
    )
    await _run(machine, secret, command, timeout_seconds)


async def rollback_snapshot(
    machine: Machine,
    secret: str | None,
    node: str,
    guest_type: str,
    vmid: int,
    name: str,
    timeout_seconds: int,
) -> None:
    await _run(
        machine, secret, build_rollback_command(node, guest_type, vmid, name), timeout_seconds
    )


async def list_snapshots(
    machine: Machine, secret: str | None, guests: list[tuple[str, str, int]], timeout_seconds: int
) -> dict[tuple[str, int], list[str] | None]:
    if not guests:
        return {}
    try:
        async with await open_connection(machine, secret, timeout_seconds) as conn:
            result = await conn.run(
                with_root_shim(build_list_command(guests)),
                check=False,
                timeout=timeout_seconds + 60,
            )
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SSHConnectionError(f"Proxmox host {machine.name}: {exc}") from exc
    stdout = result.stdout or ""
    return parse_list_output(stdout if isinstance(stdout, str) else stdout.decode(errors="replace"))
