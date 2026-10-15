"""Lynis security audits (`app.db.models.security_audit`): which audits a
page shows, when a run counts as stuck, and the API's view of an audit.

Starting audits lives with the other machine actions
(`app.services.machine_actions.trigger_security_audits`, one code path for
the page, the API and a schedule); running one is
`app.tasks.jobs._run_security_audit`, the remote side `app.ssh.lynis`.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.security_audit import SecurityAudit, SecurityAuditStatus

# Audits kept per machine; older ones are removed when a new one finishes.
KEEP_PER_MACHINE = 10

# How long Lynis may take on one machine (it is usually one to five
# minutes), and the Celery hard limit on top of it.
RUN_TIMEOUT_SECONDS = 20 * 60
TASK_TIME_LIMIT_SECONDS = RUN_TIMEOUT_SECONDS + 5 * 60

# A pending or running audit older than this was cut off (the worker was
# restarted, or the machine debcontrol runs on was itself being upgraded)
# and will never finish: it is shown as interrupted and no longer blocks a
# new run.
STALE_AFTER = timedelta(seconds=TASK_TIME_LIMIT_SECONDS + 15 * 60)

INTERRUPTED = "interrupted"

# Each finding links to the Lynis control's own description.
CONTROL_URL = "https://cisofy.com/lynis/controls/{test}/"


def _aware(value: datetime) -> datetime:
    # SQLite (the test suite) hands timestamps back naive.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def is_active(audit: SecurityAudit, now: datetime | None = None) -> bool:
    """Pending or running, and not stuck."""
    if audit.status not in (SecurityAuditStatus.PENDING, SecurityAuditStatus.RUNNING):
        return False
    now = now or datetime.now(UTC)
    since = audit.started_at or audit.created_at
    return since is None or now - _aware(since) < STALE_AFTER


def display_status(audit: SecurityAudit, now: datetime | None = None) -> str:
    """The status a page shows: the stored one, or `interrupted` for a run
    that will never finish (see `STALE_AFTER`)."""
    if audit.status in (SecurityAuditStatus.PENDING, SecurityAuditStatus.RUNNING) and not (
        is_active(audit, now)
    ):
        return INTERRUPTED
    return audit.status.value


def _ranked(machine_ids: Select[Any], *, succeeded_only: bool) -> Select[Any]:
    rank = (
        func.row_number()
        .over(partition_by=SecurityAudit.machine_id, order_by=SecurityAudit.created_at.desc())
        .label("rank")
    )
    inner = select(SecurityAudit.id, rank).where(SecurityAudit.machine_id.in_(machine_ids))
    if succeeded_only:
        inner = inner.where(SecurityAudit.status == SecurityAuditStatus.SUCCEEDED)
    sub = inner.subquery()
    return select(SecurityAudit).join(sub, sub.c.id == SecurityAudit.id).where(sub.c.rank == 1)


async def latest_by_machine(
    db: AsyncSession, machine_ids: Select[Any], *, succeeded_only: bool = False
) -> dict[uuid.UUID, SecurityAudit]:
    """The newest audit of each machine in `machine_ids` (a select of
    machine ids), or the newest one that succeeded."""
    result = await db.execute(_ranked(machine_ids, succeeded_only=succeeded_only))
    return {audit.machine_id: audit for audit in result.scalars().all()}


async def history(db: AsyncSession, machine_id: uuid.UUID) -> list[SecurityAudit]:
    """The machine's kept audits, newest first."""
    result = await db.execute(
        select(SecurityAudit)
        .where(SecurityAudit.machine_id == machine_id)
        .order_by(SecurityAudit.created_at.desc())
        .limit(KEEP_PER_MACHINE + 5)
    )
    return list(result.scalars().all())


async def has_active(db: AsyncSession, machine_id: uuid.UUID) -> bool:
    result = await db.execute(
        select(SecurityAudit).where(
            SecurityAudit.machine_id == machine_id,
            SecurityAudit.status.in_((SecurityAuditStatus.PENDING, SecurityAuditStatus.RUNNING)),
        )
    )
    return any(is_active(audit) for audit in result.scalars().all())


async def prune(db: AsyncSession, machine_id: uuid.UUID) -> None:
    """Drop the machine's finished audits beyond `KEEP_PER_MACHINE`."""
    result = await db.execute(
        select(SecurityAudit)
        .where(SecurityAudit.machine_id == machine_id)
        .order_by(SecurityAudit.created_at.desc())
        .offset(KEEP_PER_MACHINE)
    )
    for audit in result.scalars().all():
        if not is_active(audit):
            await db.delete(audit)


def _iso(value: datetime | None) -> str | None:
    return _aware(value).isoformat() if value is not None else None


def audit_to_dict(audit: SecurityAudit, *, findings: bool = True) -> dict[str, Any]:
    """The REST API's view of one audit."""
    data: dict[str, Any] = {
        "id": str(audit.id),
        "machine_id": str(audit.machine_id),
        "status": display_status(audit),
        "lynis_version": audit.lynis_version,
        "privileged": audit.privileged,
        "hardening_index": audit.hardening_index,
        "tests_done": audit.tests_done,
        "warning_count": len(audit.warnings or []),
        "suggestion_count": len(audit.suggestions or []),
        "error": audit.error,
        "started_by": audit.started_by,
        "created_at": _iso(audit.created_at),
        "started_at": _iso(audit.started_at),
        "finished_at": _iso(audit.finished_at),
    }
    if findings:
        data["warnings"] = audit.warnings or []
        data["suggestions"] = audit.suggestions or []
    return data
