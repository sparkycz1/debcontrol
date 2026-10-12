"""A Proxmox snapshot of the guest before the machine inside it is updated.

An update that was asked to (`MachineUpdateRun.snapshot_before`) first has
the Proxmox host take a snapshot of the guest — only when debcontrol knows
which guest the machine is (`app.services.proxmox_guest_links`). A machine
that is not a recognised guest is simply updated without one, and the run
says so. A recognised guest whose snapshot fails is **not** updated: the
whole point was to have a way back.

Going back is a person's decision, never automatic: "Roll back to the
snapshot" on the run's page, confirmed by typing the machine's name.

debcontrol never deletes a snapshot. Each one it takes is noted on the
Proxmox host's record (`Machine.pve_debcontrol_snapshots`) and checked
against the host at its facts refresh, so the Proxmox tab can list the
ones that have been lying around and should be removed by hand.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_update_run import MachineUpdateRun
from app.services import proxmox_guest_links
from app.ssh import proxmox, proxmox_snapshots
from app.ssh.credentials import resolve_machine_credential
from app.ssh.exceptions import SSHConnectionError

logger = logging.getLogger(__name__)

# `MachineUpdateRun.snapshot_note` when a snapshot was asked for and none
# was taken.
NOTE_NOT_A_GUEST = "not_a_guest"

# A snapshot older than this is listed as one to clean up.
OLD_SNAPSHOT_DAYS = 7


class SnapshotFailedError(Exception):
    """The snapshot before an update could not be taken; the update must
    not run."""


def _note_on_host(host: Machine, entry: dict[str, Any]) -> None:
    current = [dict(item) for item in host.pve_debcontrol_snapshots or []]
    current.append(entry)
    host.pve_debcontrol_snapshots = current


async def take_before_update(
    session: AsyncSession, run: MachineUpdateRun, machine: Machine, timeout_seconds: int
) -> None:
    """Take the snapshot `run` asked for and record it on the run and on
    the Proxmox host. Returns quietly when the machine is not a recognised
    guest; raises `SnapshotFailedError` when it is and the snapshot failed."""
    found = await proxmox_guest_links.host_of(session, machine)
    host = await session.get(Machine, found.machine_id) if found is not None else None
    guest = proxmox.find_guest(host.pve_guests, found.vmid) if host and found else None
    if found is None or host is None or guest is None:
        run.snapshot_note = NOTE_NOT_A_GUEST
        await session.commit()
        return
    if not host.host_key_fingerprint:
        raise SnapshotFailedError(
            f'Snapshot before the update failed: the host key of Proxmox host "{host.name}" '
            "is not confirmed. Nothing was updated."
        )
    name = proxmox_snapshots.snapshot_name()
    secret = await resolve_machine_credential(host, session)
    try:
        await proxmox_snapshots.create_snapshot(host, secret, guest, name, timeout_seconds)
    except (
        SSHConnectionError,
        TimeoutError,
        ValueError,
        proxmox_snapshots.SnapshotError,
    ) as exc:
        raise SnapshotFailedError(
            f'Snapshot before the update failed on Proxmox host "{host.name}": {exc} '
            "Nothing was updated."
        ) from exc
    run.snapshot_name = name
    run.snapshot_host_id = host.id
    run.snapshot_node = str(guest.get("node") or "")
    run.snapshot_type = str(guest.get("type") or "")
    run.snapshot_vmid = found.vmid
    _note_on_host(
        host,
        {
            "vmid": found.vmid,
            "type": run.snapshot_type,
            "node": run.snapshot_node,
            "name": name,
            "machine_name": machine.name,
        },
    )
    await session.commit()


@dataclass(frozen=True)
class KeptSnapshot:
    vmid: int
    type: str
    name: str
    machine_name: str
    taken_at: datetime | None
    age_days: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "vmid": self.vmid,
            "type": self.type,
            "name": self.name,
            "machine_name": self.machine_name,
            "taken_at": self.taken_at.isoformat() if self.taken_at else None,
            "age_days": self.age_days,
        }


def kept_snapshots(host: Machine, now: datetime | None = None) -> list[KeptSnapshot]:
    """debcontrol's snapshots still on `host`, oldest first."""
    moment = now or datetime.now(UTC)
    kept = []
    for item in host.pve_debcontrol_snapshots or []:
        if not isinstance(item, dict) or not isinstance(item.get("vmid"), int):
            continue
        name = str(item.get("name") or "")
        taken_at = proxmox_snapshots.snapshot_taken_at(name)
        kept.append(
            KeptSnapshot(
                vmid=item["vmid"],
                type=str(item.get("type") or ""),
                name=name,
                machine_name=str(item.get("machine_name") or ""),
                taken_at=taken_at,
                age_days=(moment - taken_at).days if taken_at else None,
            )
        )
    kept.sort(key=lambda s: (s.taken_at or moment, s.vmid))
    return kept


def old_snapshots(host: Machine, now: datetime | None = None) -> list[KeptSnapshot]:
    """The ones worth a reminder: older than `OLD_SNAPSHOT_DAYS`."""
    return [
        s
        for s in kept_snapshots(host, now)
        if s.age_days is not None and s.age_days >= OLD_SNAPSHOT_DAYS
    ]


def reconcile(
    noted: list[dict[str, Any]] | None,
    listed: dict[tuple[str, int], list[str] | None],
) -> list[dict[str, Any]]:
    """What is noted on a host, corrected by what the host now lists: a
    snapshot gone from a guest whose list was read is dropped, one whose
    guest could not be read is kept (unknown is not "gone")."""
    result = []
    for item in noted or []:
        key = (str(item.get("type") or ""), item.get("vmid"))
        names = listed.get(key)  # type: ignore[arg-type]
        if names is None or item.get("name") in names:
            result.append(dict(item))
    return result


async def refresh_host(session: AsyncSession, host: Machine, timeout_seconds: int) -> int:
    """Check the snapshots noted on `host` against the host itself. Returns
    how many are left."""
    noted = [item for item in host.pve_debcontrol_snapshots or [] if isinstance(item, dict)]
    if not noted:
        return 0
    nodes = {g.get("vmid"): str(g.get("node") or "") for g in host.pve_guests or []}
    guests: list[tuple[str, str, int]] = []
    for item in noted:
        vmid = item.get("vmid")
        if not isinstance(vmid, int):
            continue
        entry = (nodes.get(vmid) or str(item.get("node") or ""), str(item.get("type") or ""), vmid)
        if entry not in guests:
            guests.append(entry)
    secret = await resolve_machine_credential(host, session)
    try:
        listed = await proxmox_snapshots.list_snapshots(host, secret, guests, timeout_seconds)
    except (SSHConnectionError, TimeoutError, ValueError) as exc:
        logger.warning("Snapshot check failed on %s: %s", host.name, exc)
        return len(noted)
    remaining = reconcile(noted, listed)
    if len(remaining) != len(noted):
        host.pve_debcontrol_snapshots = remaining or None
        await session.commit()
    return len(remaining)


async def roll_back(session: AsyncSession, run: MachineUpdateRun, timeout_seconds: int) -> None:
    """Roll the guest back to the snapshot `run` took. Raises
    `SnapshotFailedError` with the reason when that is not possible."""
    if not run.snapshot_name or run.snapshot_host_id is None or run.snapshot_vmid is None:
        raise SnapshotFailedError("This update run has no snapshot.")
    host = await session.get(Machine, run.snapshot_host_id)
    if host is None:
        raise SnapshotFailedError("The Proxmox host of this snapshot is no longer managed.")
    # The guest may have been migrated since: ask the latest sample.
    guest = proxmox.find_guest(host.pve_guests, run.snapshot_vmid)
    node = str((guest or {}).get("node") or run.snapshot_node or "")
    secret = await resolve_machine_credential(host, session)
    try:
        await proxmox_snapshots.rollback_snapshot(
            host,
            secret,
            node,
            run.snapshot_type or "",
            run.snapshot_vmid,
            run.snapshot_name,
            timeout_seconds,
        )
    except (
        SSHConnectionError,
        TimeoutError,
        ValueError,
        proxmox_snapshots.SnapshotError,
    ) as exc:
        raise SnapshotFailedError(f'Rollback failed on Proxmox host "{host.name}": {exc}') from exc
    run.snapshot_rolled_back_at = datetime.now(UTC)
    await session.commit()
