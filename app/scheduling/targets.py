"""Resolving a `ScheduledTask`'s target into the actual list of machines it
applies to right now — shared by the job that executes a schedule
(`app.scheduling.jobs`) and the web UI (to show "applies to N machine(s)").

Also the single-`<select>` encoding used by the "New/edit scheduled task"
form (`encode_target`/`decode_target`) — one dropdown listing "All
machines", every group, and every machine is a much simpler form than a
target-type radio plus two conditionally-relevant selects, and needs no
client-side JS to keep the irrelevant one from being submitted too.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType

_ALL_MACHINES_VALUE = "all"
_GROUP_PREFIX = "group:"
_MACHINE_PREFIX = "machine:"


def encode_target(
    target_type: ScheduleTargetType,
    target_machine_id: uuid.UUID | None,
    target_group_id: uuid.UUID | None,
) -> str:
    if target_type == ScheduleTargetType.MACHINE and target_machine_id is not None:
        return f"{_MACHINE_PREFIX}{target_machine_id}"
    if target_type == ScheduleTargetType.GROUP and target_group_id is not None:
        return f"{_GROUP_PREFIX}{target_group_id}"
    return _ALL_MACHINES_VALUE


def decode_target(
    raw: str,
) -> tuple[ScheduleTargetType, uuid.UUID | None, uuid.UUID | None]:
    """Raises ValueError on anything malformed — the `<select>` this comes
    from is server-rendered, so a bad value here means a tampered request,
    not a normal user mistake."""
    if raw == _ALL_MACHINES_VALUE:
        return ScheduleTargetType.ALL_MACHINES, None, None
    if raw.startswith(_MACHINE_PREFIX):
        return ScheduleTargetType.MACHINE, uuid.UUID(raw[len(_MACHINE_PREFIX) :]), None
    if raw.startswith(_GROUP_PREFIX):
        return ScheduleTargetType.GROUP, None, uuid.UUID(raw[len(_GROUP_PREFIX) :])
    raise ValueError(f'Invalid target "{raw}".')


async def resolve_target_machines(db: AsyncSession, task: ScheduledTask) -> list[Machine]:
    """Every machine `task` currently targets. Resolved fresh each time
    (never cached on the task) — group/all-machines membership can change
    between schedule creation and the next time it fires."""
    if task.target_type == ScheduleTargetType.ALL_MACHINES:
        result = await db.execute(select(Machine))
        return list(result.scalars().all())

    if task.target_type == ScheduleTargetType.MACHINE:
        if task.target_machine_id is None:
            return []
        machine = await db.get(Machine, task.target_machine_id)
        return [machine] if machine is not None else []

    if task.target_type == ScheduleTargetType.GROUP:
        if task.target_group_id is None:
            return []
        result = await db.execute(select(Machine).where(Machine.group_id == task.target_group_id))
        return list(result.scalars().all())

    return []
