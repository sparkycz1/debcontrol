"""Add/delete a machine's history notes (`app.db.models.machine_note`) —
shared by the History tab (`app/web/routes/machines.py`) and the REST API
(`app/web/routes/api_v1.py`), audited identically from
both."""

from __future__ import annotations

import uuid

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.db.models.machine import Machine
from app.db.models.machine_note import MAX_NOTE_LENGTH, MachineNote
from app.db.models.user import User


class EmptyNoteError(ValueError):
    """The note has no text."""


async def add_note(
    db: AsyncSession, request: Request, machine: Machine, user: User, body: str
) -> MachineNote:
    text = body.strip()[:MAX_NOTE_LENGTH]
    if not text:
        raise EmptyNoteError
    note = MachineNote(machine_id=machine.id, author=user.username, body=text)
    db.add(note)
    await db.commit()
    await db.refresh(note)
    await log_event(
        db,
        request=request,
        action="machine.note.add",
        summary=f'Added a note to "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"note": text[:500]},
    )
    return note


async def delete_note(
    db: AsyncSession, request: Request, machine: Machine, note_id: uuid.UUID
) -> bool:
    """`True` when a note of *this* machine was deleted."""
    result = await db.execute(
        select(MachineNote).where(MachineNote.id == note_id, MachineNote.machine_id == machine.id)
    )
    note = result.scalar_one_or_none()
    if note is None:
        return False
    body = note.body
    await db.delete(note)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machine.note.delete",
        summary=f'Deleted a note from "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"note": body[:500]},
    )
    return True
