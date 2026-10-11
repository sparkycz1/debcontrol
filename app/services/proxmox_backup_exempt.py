"""Marking Proxmox guests as deliberately not backed up
(`Machine.pve_backup_exempt`) — templates and test VMs that would
otherwise sit in the "not in any backup job" warning forever. Shared by
the Proxmox tab (`app/web/routes/machines_detail.py`) and the REST API
(`app/web/routes/api_v1.py`), audited identically from both."""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.db.models.machine import Machine
from app.ssh import proxmox


class UnknownGuestError(ValueError):
    """None of the VMIDs is a guest Proxmox reports as not backed up."""


async def set_exempt(
    db: AsyncSession, request: Request, machine: Machine, vmids: list[int] | None, *, exempt: bool
) -> list[int]:
    """Mark `vmids` (None = every guest currently in the warning, or every
    marked one when un-marking) and return the VMIDs actually changed.

    Marking is limited to guests the last facts refresh reported as not
    backed up, so the list cannot fill with arbitrary numbers; un-marking
    takes any VMID that is on the list."""
    uncovered, signed_off = proxmox.split_not_backed_up(
        machine.pve_backups, machine.pve_backup_exempt
    )
    current = list(machine.pve_backup_exempt or [])
    if exempt:
        allowed = [g["vmid"] for g in uncovered]
        chosen = allowed if vmids is None else [v for v in vmids if v in allowed]
    else:
        chosen = current if vmids is None else [v for v in vmids if v in current]
    if not chosen:
        raise UnknownGuestError
    names = {g["vmid"]: g.get("name") or "" for g in uncovered + signed_off}
    machine.pve_backup_exempt = proxmox.with_backup_exempt(current, chosen, exempt=exempt)
    await db.commit()
    labels = ", ".join(f"{v} ({names[v]})" if names.get(v) else str(v) for v in chosen)
    await log_event(
        db,
        request=request,
        action=(
            "machine.proxmox.backup_exempt.add"
            if exempt
            else "machine.proxmox.backup_exempt.remove"
        ),
        summary=(
            f'Marked guest(s) {labels} on "{machine.name}" as deliberately not backed up'
            if exempt
            else f'Guest(s) {labels} on "{machine.name}" count as not backed up again'
        ),
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"vmids": chosen},
    )
    return chosen
