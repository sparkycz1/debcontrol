"""Security audits (`app.db.models.security_audit`): Lynis plus debcontrol's
own checks. Which audits a page shows, when a run counts as stuck, findings
marked "OK" on a machine, and the API's view of an audit.

**Findings marked OK.** Each finding has a stable key (`finding_key`): a
Lynis warning or suggestion by its test ID and text, a check by its id. A
`SecurityAuditSuppression` with that key on a machine moves the finding to
"Marked OK" on every audit of that machine, now and later, and takes it
out of the counts. Lynis's own hardening index is Lynis's and doesn't
change.

Starting audits lives with the other machine actions
(`app.services.machine_actions.trigger_security_audits`, one code path for
the page, the API and a schedule); running one is
`app.tasks.jobs._run_security_audit`, the remote side `app.ssh.lynis`.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.security_audit import (
    SecurityAudit,
    SecurityAuditStatus,
    SecurityAuditSuppression,
)
from app.ssh.security_checks import CHECK_IDS, FINDING_STATUSES

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


def audit_to_dict(
    audit: SecurityAudit, *, findings: bool = True, suppressed: set[str] | None = None
) -> dict[str, Any]:
    """The REST API's view of one audit; with `suppressed` (the machine's
    keys marked OK) also `active`, the counts of what still counts."""
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
        "failed_check_count": sum(1 for c in audit.checks or [] if c.get("status") == "fail"),
        "error": audit.error,
        "started_by": audit.started_by,
        "created_at": _iso(audit.created_at),
        "started_at": _iso(audit.started_at),
        "finished_at": _iso(audit.finished_at),
    }
    if suppressed is not None:
        c = counts(audit, suppressed)
        data["active"] = {
            "failed_checks": c.failed_checks,
            "warned_checks": c.warned_checks,
            "warnings": c.warnings,
            "suggestions": c.suggestions,
            "marked_ok": c.suppressed,
        }
    if findings:
        data["warnings"] = [
            {**f, "key": finding_key(LYNIS, f)} for f in audit.warnings or []
        ]
        data["suggestions"] = [
            {**f, "key": finding_key(LYNIS, f)} for f in audit.suggestions or []
        ]
        data["checks"] = [{**c, "key": finding_key(CHECK, c)} for c in audit.checks or []]
        data["details"] = audit.details or []
        data["facts"] = audit.facts or {}
    return data


# --- Findings marked OK --------------------------------------------------

LYNIS = "lynis"
CHECK = "check"
KEY_MAX = 128


def finding_key(kind: str, finding: dict[str, Any]) -> str:
    """The key a finding is marked OK by: `check:<id>`, or for Lynis
    `lynis:<TEST-ID>:<hash of text and detail>` (one test can report
    several different things, e.g. one per sshd option)."""
    if kind == CHECK:
        return f"{CHECK}:{finding.get('id', '')}"[:KEY_MAX]
    text = f"{finding.get('text', '')}|{finding.get('detail', '')}"
    digest = hashlib.sha256(text.encode()).hexdigest()[:16]
    return f"{LYNIS}:{finding.get('test', '')}:{digest}"[:KEY_MAX]


def valid_key(key: str) -> bool:
    """A key `finding_key` could have made (what a form or the API may send)."""
    if len(key) > KEY_MAX:
        return False
    kind, _, rest = key.partition(":")
    if kind == CHECK:
        return rest in CHECK_IDS
    if kind == LYNIS:
        test, _, digest = rest.partition(":")
        return bool(test) and len(digest) == 16 and all(c in "0123456789abcdef" for c in digest)
    return False


async def suppressions(
    db: AsyncSession, machine_id: uuid.UUID
) -> dict[str, SecurityAuditSuppression]:
    result = await db.execute(
        select(SecurityAuditSuppression)
        .where(SecurityAuditSuppression.machine_id == machine_id)
        .order_by(SecurityAuditSuppression.created_at)
    )
    return {s.key: s for s in result.scalars().all()}


async def suppressed_keys_by_machine(
    db: AsyncSession, machine_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, set[str]]:
    ids = list(machine_ids)
    keys: dict[uuid.UUID, set[str]] = {}
    if not ids:
        return keys
    result = await db.execute(
        select(SecurityAuditSuppression.machine_id, SecurityAuditSuppression.key).where(
            SecurityAuditSuppression.machine_id.in_(ids)
        )
    )
    for machine_id, key in result.all():
        keys.setdefault(machine_id, set()).add(key)
    return keys


async def suppress(
    db: AsyncSession,
    machine_id: uuid.UUID,
    key: str,
    *,
    label: str,
    note: str | None,
    created_by: str | None,
) -> bool:
    """Mark a finding OK on a machine; False when it already was. The
    caller commits."""
    existing = await db.execute(
        select(SecurityAuditSuppression).where(
            SecurityAuditSuppression.machine_id == machine_id,
            SecurityAuditSuppression.key == key,
        )
    )
    if existing.scalar_one_or_none() is not None:
        return False
    db.add(
        SecurityAuditSuppression(
            machine_id=machine_id,
            key=key,
            label=label.strip()[:500],
            note=(note or "").strip()[:500] or None,
            created_by=created_by,
        )
    )
    return True


async def unsuppress(db: AsyncSession, machine_id: uuid.UUID, key: str) -> bool:
    """Undo `suppress`; False when there was nothing to undo. The caller
    commits."""
    result = await db.execute(
        select(SecurityAuditSuppression).where(
            SecurityAuditSuppression.machine_id == machine_id,
            SecurityAuditSuppression.key == key,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        return False
    await db.delete(row)
    return True


@dataclass
class Counts:
    """An audit's findings that still count (not marked OK)."""

    failed_checks: int = 0
    warned_checks: int = 0
    warnings: int = 0
    suggestions: int = 0
    suppressed: int = 0


def counts(audit: SecurityAudit, suppressed: set[str]) -> Counts:
    c = Counts()
    for check in audit.checks or []:
        if check.get("status") not in FINDING_STATUSES:
            continue
        if finding_key(CHECK, check) in suppressed:
            c.suppressed += 1
        elif check.get("status") == "fail":
            c.failed_checks += 1
        else:
            c.warned_checks += 1
    for name in ("warnings", "suggestions"):
        for finding in getattr(audit, name) or []:
            if finding_key(LYNIS, finding) in suppressed:
                c.suppressed += 1
            else:
                setattr(c, name, getattr(c, name) + 1)
    return c


@dataclass
class FindingGroup:
    """Lynis findings of one category (the test ID's prefix: SSH, KRNL...)."""

    category: str
    findings: list[dict[str, Any]] = field(default_factory=list)


def lynis_category(test: str) -> str:
    return test.split("-", 1)[0].upper() if test else "OTHER"


def annotate(audit: SecurityAudit, suppressed: set[str]) -> dict[str, Any]:
    """What a page shows of one audit: checks, warnings and suggestions with
    their keys, split into those that count and those marked OK; Lynis
    findings grouped by category, each with the `details[]` of its test."""
    details_by_test: dict[str, list[dict[str, Any]]] = {}
    for detail in audit.details or []:
        details_by_test.setdefault(str(detail.get("test", "")), []).append(detail)

    checks: list[dict[str, Any]] = []
    marked: list[dict[str, Any]] = []
    for check in audit.checks or []:
        item = {**check, "key": finding_key(CHECK, check), "kind": CHECK}
        if item["key"] in suppressed and check.get("status") in FINDING_STATUSES:
            marked.append(item)
        else:
            checks.append(item)
    order = {"fail": 0, "warn": 1, "skip": 2, "info": 3, "pass": 4}
    checks.sort(key=lambda c: order.get(str(c.get("status")), 9))

    groups: dict[str, dict[str, FindingGroup]] = {"warnings": {}, "suggestions": {}}
    for name in ("warnings", "suggestions"):
        for finding in getattr(audit, name) or []:
            test = str(finding.get("test", ""))
            item = {
                **finding,
                "key": finding_key(LYNIS, finding),
                "kind": LYNIS,
                "severity": name,
                "details": details_by_test.get(test, []),
            }
            if item["key"] in suppressed:
                marked.append(item)
                continue
            category = lynis_category(test)
            groups[name].setdefault(category, FindingGroup(category)).findings.append(item)
    return {
        "checks": checks,
        "warnings": sorted(groups["warnings"].values(), key=lambda g: g.category),
        "suggestions": sorted(groups["suggestions"].values(), key=lambda g: g.category),
        "marked": marked,
        "counts": counts(audit, suppressed),
    }


def suppression_to_dict(row: SecurityAuditSuppression) -> dict[str, Any]:
    return {
        "key": row.key,
        "label": row.label,
        "note": row.note,
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
    }
