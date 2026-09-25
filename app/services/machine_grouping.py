"""Moving machines between machine groups in bulk — the machine list's
"Move to group" bulk action and `POST /api/v1/machines/bulk/group`, one
code path for both. Scope checks (which group the caller may pick, which
machines it may touch) stay with the callers, which already resolve both
through `app.services.access_scope`."""

from __future__ import annotations

from collections.abc import Iterable

from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup


def assign_machines_to_group(
    machines: Iterable[Machine], group: MachineGroup | None
) -> list[Machine]:
    """Set every machine's group to `group` (`None` = no group); the caller
    commits. Returns only the machines that actually changed, so the audit
    entry names what moved rather than what was merely selected."""
    target_id = group.id if group else None
    moved: list[Machine] = []
    for machine in machines:
        if machine.group_id != target_id:
            machine.group_id = target_id
            moved.append(machine)
    return moved
