"""A machine's History tab — one time-ordered list of what happened to it,
merged from the records debcontrol already keeps:

- `note` — notes people added (`MachineNote`);
- `change` — detected configuration changes and newly pending security
  updates (`MachineChange`, see `app.services.config_drift`);
- `update_run` — system update runs and their outcome (`MachineUpdateRun`);
- `reachability` — the moments it stopped / started answering the
  reachability check (transitions in `MachineReachabilitySample`, found
  with a `LAG()` window, never by loading every per-minute sample);
- `audit` — what people and schedules did to it (`AuditLogEntry` rows
  targeting this machine), **only for a viewer with `audit.view`** — the
  History tab itself only needs `machine.view`, and the audit trail keeps
  its own permission. Read-only actions (`*.view`) are left out, and so
  are the note add/delete entries (the note itself is already there).

Used by `GET /machines/{id}/history`, `GET /api/v1/machines/{id}/timeline`
and the AI assistant's "summarize this machine's history" prompt
(`app/web/routes/ai.py`). Each event carries an English `summary` (API,
AI prompt) plus the structured fields the page renders in the viewer's
language.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, not_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.audit_log import AuditLogEntry, AuditOutcome
from app.db.models.machine import Machine
from app.db.models.machine_change import MachineChange
from app.db.models.machine_note import MachineNote
from app.db.models.machine_reachability_sample import MachineReachabilitySample
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus
from app.services.config_drift import SECURITY_FIELD, TRACKED_FIELDS, FieldChange

# The ranges the History tab offers, in days.
TIMELINE_RANGES = (1, 7, 30, 90, 365)
DEFAULT_RANGE_DAYS = 30
# Per source, and for the merged list — a page, not an export.
MAX_EVENTS = 300

TIMELINE_KINDS = ("note", "change", "update_run", "reachability", "audit")


@dataclass
class TimelineEvent:
    at: datetime
    kind: str
    summary: str
    # "ok" / "error" / "warn" / None — the page's badge colour.
    outcome: str | None = None
    actor: str | None = None
    detail: str | None = None
    link: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "at": self.at.isoformat(),
            "kind": self.kind,
            "summary": self.summary,
            "outcome": self.outcome,
            "actor": self.actor,
            "detail": self.detail,
            "link": self.link,
            "data": self.data,
        }


@dataclass
class Timeline:
    days: int
    since: datetime
    events: list[TimelineEvent]
    truncated: bool
    includes_audit: bool


def normalize_days(days: int | str | None) -> int:
    try:
        value = int(days) if days is not None else DEFAULT_RANGE_DAYS
    except (TypeError, ValueError):
        return DEFAULT_RANGE_DAYS
    return value if value in TIMELINE_RANGES else DEFAULT_RANGE_DAYS


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value


def _change_event(row: MachineChange) -> TimelineEvent:
    if row.field == SECURITY_FIELD:
        return TimelineEvent(
            at=_utc(row.detected_at),
            kind="change",
            summary=f"New security updates: {row.new_value or ''}",
            outcome="warn",
            detail=row.new_value,
            data={"field": row.field, "category": row.category, "new": row.new_value},
        )
    change = FieldChange(row.field, row.old_value, row.new_value)
    return TimelineEvent(
        at=_utc(row.detected_at),
        kind="change",
        summary=f"Changed — {change.describe()}",
        data={
            "field": row.field,
            "category": row.category,
            "label": TRACKED_FIELDS.get(row.field, (row.field, False))[0],
            "is_set": change.is_set,
            "old": row.old_value,
            "new": row.new_value,
        },
    )


def _update_run_event(machine: Machine, run: MachineUpdateRun) -> TimelineEvent:
    status = run.status.value
    outcome = {
        UpdateRunStatus.SUCCEEDED: "ok",
        UpdateRunStatus.FAILED: "error",
    }.get(run.status, "warn")
    at = run.finished_at or run.started_at or run.created_at
    return TimelineEvent(
        at=_utc(at),
        kind="update_run",
        summary=f"System update ({run.strategy.value}) {status}"
        + (f": {run.error}" if run.error else ""),
        outcome=outcome,
        detail=run.error,
        link=f"/machines/{machine.id}/updates/{run.id}",
        data={"status": status, "strategy": run.strategy.value, "run_id": str(run.id)},
    )


async def _reachability_transitions(
    db: AsyncSession, machine_id: uuid.UUID, since: datetime
) -> list[TimelineEvent]:
    previous = (
        func.lag(MachineReachabilitySample.reachable)
        .over(order_by=MachineReachabilitySample.checked_at)
        .label("previous")
    )
    ordered = (
        select(
            MachineReachabilitySample.checked_at,
            MachineReachabilitySample.reachable,
            previous,
        )
        .where(
            MachineReachabilitySample.machine_id == machine_id,
            MachineReachabilitySample.checked_at >= since,
        )
        .subquery()
    )
    result = await db.execute(
        select(ordered.c.checked_at, ordered.c.reachable)
        .where(ordered.c.previous.is_not(None), ordered.c.previous != ordered.c.reachable)
        .order_by(ordered.c.checked_at.desc())
        .limit(MAX_EVENTS)
    )
    return [
        TimelineEvent(
            at=_utc(checked_at),
            kind="reachability",
            summary="Reachable again" if reachable else "Stopped responding (unreachable)",
            outcome="ok" if reachable else "error",
            data={"reachable": bool(reachable)},
        )
        for checked_at, reachable in result.all()
    ]


async def load_timeline(
    db: AsyncSession,
    machine: Machine,
    *,
    days: int = DEFAULT_RANGE_DAYS,
    include_audit: bool,
    kinds: set[str] | None = None,
) -> Timeline:
    """`machine` must already be access-checked by the caller. `kinds`
    limits the sources (None = all)."""
    days = normalize_days(days)
    since = datetime.now(UTC) - timedelta(days=days)
    wanted = set(TIMELINE_KINDS) if not kinds else set(kinds) & set(TIMELINE_KINDS)
    events: list[TimelineEvent] = []

    if "note" in wanted:
        notes = await db.execute(
            select(MachineNote)
            .where(MachineNote.machine_id == machine.id, MachineNote.created_at >= since)
            .order_by(MachineNote.created_at.desc())
            .limit(MAX_EVENTS)
        )
        events.extend(
            TimelineEvent(
                at=_utc(note.created_at),
                kind="note",
                summary=f"Note by {note.author}: {note.body}",
                actor=note.author,
                detail=note.body,
                data={"note_id": str(note.id)},
            )
            for note in notes.scalars().all()
        )

    if "change" in wanted:
        changes = await db.execute(
            select(MachineChange)
            .where(MachineChange.machine_id == machine.id, MachineChange.detected_at >= since)
            .order_by(MachineChange.detected_at.desc())
            .limit(MAX_EVENTS)
        )
        events.extend(_change_event(row) for row in changes.scalars().all())

    if "update_run" in wanted:
        runs = await db.execute(
            select(MachineUpdateRun)
            .where(MachineUpdateRun.machine_id == machine.id, MachineUpdateRun.created_at >= since)
            .order_by(MachineUpdateRun.created_at.desc())
            .limit(MAX_EVENTS)
        )
        events.extend(_update_run_event(machine, run) for run in runs.scalars().all())

    if "reachability" in wanted:
        events.extend(await _reachability_transitions(db, machine.id, since))

    if include_audit and "audit" in wanted:
        entries = await db.execute(
            select(AuditLogEntry)
            .where(
                AuditLogEntry.target_id == str(machine.id),
                AuditLogEntry.target_type == "machine",
                AuditLogEntry.created_at >= since,
                not_(AuditLogEntry.action.like("%.view")),
                not_(AuditLogEntry.action.like("machine.note.%")),
            )
            .order_by(AuditLogEntry.created_at.desc())
            .limit(MAX_EVENTS)
        )
        events.extend(
            TimelineEvent(
                at=_utc(entry.created_at),
                kind="audit",
                summary=entry.summary,
                outcome="ok" if entry.outcome == AuditOutcome.SUCCESS else "error",
                actor=entry.actor,
                data={"action": entry.action, "outcome": entry.outcome.value},
            )
            for entry in entries.scalars().all()
        )

    events.sort(key=lambda e: e.at, reverse=True)
    return Timeline(
        days=days,
        since=since,
        events=events[:MAX_EVENTS],
        truncated=len(events) > MAX_EVENTS,
        includes_audit=include_audit,
    )


def timeline_as_text(machine: Machine, timeline: Timeline, limit: int = 120) -> str:
    """The timeline as plain English lines, oldest first — for the AI
    assistant's prompt (`app/web/routes/ai.py`). Bounded to the newest
    `limit` events so the prompt stays a fixed size."""
    lines = []
    for event in reversed(timeline.events[:limit]):
        who = f" [{event.actor}]" if event.actor and event.kind == "audit" else ""
        stamp = event.at.strftime("%Y-%m-%d %H:%M UTC")
        lines.append(f"{stamp} ({event.kind}){who}: {event.summary[:400]}")
    return "\n".join(lines)

