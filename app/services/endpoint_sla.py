"""The monthly SLA report for endpoint checks — `GET /checks/sla` (and its
CSV export) and `GET /api/v1/checks/sla`: per check, how many probes ran
in one calendar month (UTC), what share were up, an estimate of the
downtime, how many separate outages there were, and whether the check's
own `sla_target_percent` was met.

Built from the stored `EndpointCheckResult` history with two aggregate
queries over the month (both served by the `checked_at` index), never by
loading every row: a `GROUP BY` for the counts, and a `LAG()` window for
the outage count (a failed probe whose previous probe was up — or that is
the first probe of the month — starts an outage).

**The downtime is an estimate**: failed probes x the check's interval.
Probes are samples, not a continuous signal, so this is the same
resolution the check itself has. And the history only goes back as far
as the monitoring retention setting keeps it
(`AppSettings.monitoring_history_retention_days`) — `coverage_from` says
where a month's data actually starts, so a report for a partly purged
month says so rather than quietly looking better than it was.
"""

from __future__ import annotations

import csv
import io
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.endpoint_check_result import EndpointCheckResult

# How many past months the month selector offers.
SELECTABLE_MONTHS = 12


@dataclass
class SlaRow:
    check_id: uuid.UUID
    name: str
    kind: str
    target: str
    probes: int
    up: int
    # 0-100, None when the check has no probes in the month.
    uptime_percent: float | None
    downtime_seconds: int
    outages: int
    target_percent: float | None
    # None when there's no target or no data to judge it by.
    met: bool | None
    coverage_from: datetime | None

    def as_dict(self) -> dict[str, object]:
        return {
            "check_id": str(self.check_id),
            "name": self.name,
            "kind": self.kind,
            "target": self.target,
            "probes": self.probes,
            "up": self.up,
            "uptime_percent": self.uptime_percent,
            "downtime_seconds": self.downtime_seconds,
            "outages": self.outages,
            "sla_target_percent": self.target_percent,
            "met": self.met,
            "coverage_from": self.coverage_from.isoformat() if self.coverage_from else None,
        }


@dataclass
class SlaReport:
    month: str  # "YYYY-MM"
    start: datetime
    end: datetime
    rows: list[SlaRow]

    @property
    def is_current_month(self) -> bool:
        return self.start <= datetime.now(UTC) < self.end


def _add_months(year: int, month: int, delta: int) -> tuple[int, int]:
    index = year * 12 + (month - 1) + delta
    return index // 12, index % 12 + 1


def month_bounds(month: str | None, now: datetime | None = None) -> tuple[str, datetime, datetime]:
    """`("2026-09", start, end)` for a `YYYY-MM` string — the current month
    when `month` is empty, malformed or in the future."""
    now = now or datetime.now(UTC)
    year, mon = now.year, now.month
    if month:
        try:
            parsed = datetime.strptime(month.strip(), "%Y-%m")
        except ValueError:
            parsed = None
        if parsed is not None and (parsed.year, parsed.month) <= (now.year, now.month):
            year, mon = parsed.year, parsed.month
    start = datetime(year, mon, 1, tzinfo=UTC)
    end_year, end_month = _add_months(year, mon, 1)
    return f"{year:04d}-{mon:02d}", start, datetime(end_year, end_month, 1, tzinfo=UTC)


def selectable_months(now: datetime | None = None) -> list[str]:
    """The current month and the `SELECTABLE_MONTHS - 1` before it, newest first."""
    now = now or datetime.now(UTC)
    months = []
    for delta in range(SELECTABLE_MONTHS):
        year, mon = _add_months(now.year, now.month, -delta)
        months.append(f"{year:04d}-{mon:02d}")
    return months


def _as_utc(value: datetime | None) -> datetime | None:
    # SQLite (tests) hands back naive datetimes; Postgres aware ones.
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


async def load_sla_report(db: AsyncSession, month: str | None) -> SlaReport:
    key, start, end = month_bounds(month)
    in_month = and_(EndpointCheckResult.checked_at >= start, EndpointCheckResult.checked_at < end)

    counts_result = await db.execute(
        select(
            EndpointCheckResult.check_id,
            func.count(),
            func.sum(case((EndpointCheckResult.ok, 1), else_=0)),
            func.min(EndpointCheckResult.checked_at),
        )
        .where(in_month)
        .group_by(EndpointCheckResult.check_id)
    )
    counts = {
        row[0]: (int(row[1]), int(row[2] or 0), row[3]) for row in counts_result.all()
    }

    previous_ok = (
        func.lag(EndpointCheckResult.ok)
        .over(partition_by=EndpointCheckResult.check_id, order_by=EndpointCheckResult.checked_at)
        .label("previous_ok")
    )
    ordered = (
        select(EndpointCheckResult.check_id, EndpointCheckResult.ok, previous_ok)
        .where(in_month)
        .subquery()
    )
    outages_result = await db.execute(
        select(ordered.c.check_id, func.count())
        .where(
            ordered.c.ok.is_(False),
            or_(ordered.c.previous_ok.is_(None), ordered.c.previous_ok.is_(True)),
        )
        .group_by(ordered.c.check_id)
    )
    outages = {row[0]: int(row[1]) for row in outages_result.all()}

    checks_result = await db.execute(select(EndpointCheck).order_by(EndpointCheck.name))
    period_seconds = int((min(end, datetime.now(UTC)) - start).total_seconds())
    rows: list[SlaRow] = []
    for check in checks_result.scalars().all():
        probes, up, first = counts.get(check.id, (0, 0, None))
        uptime = round(up / probes * 100, 3) if probes else None
        downtime = min((probes - up) * check.interval_seconds, max(period_seconds, 0))
        target = check.sla_target_percent
        rows.append(
            SlaRow(
                check_id=check.id,
                name=check.name,
                kind=check.kind,
                target=check.target,
                probes=probes,
                up=up,
                uptime_percent=uptime,
                downtime_seconds=downtime,
                outages=outages.get(check.id, 0),
                target_percent=target,
                met=None if target is None or uptime is None else uptime >= target,
                coverage_from=_as_utc(first),
            )
        )
    return SlaReport(month=key, start=start, end=end, rows=rows)


def sla_report_csv(report: SlaReport) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "month", "check", "kind", "target", "probes", "up", "uptime_percent",
            "downtime_seconds", "outages", "sla_target_percent", "met", "coverage_from",
        ]
    )
    for row in report.rows:
        writer.writerow(
            [
                report.month,
                row.name,
                row.kind,
                row.target,
                row.probes,
                row.up,
                "" if row.uptime_percent is None else row.uptime_percent,
                row.downtime_seconds,
                row.outages,
                "" if row.target_percent is None else row.target_percent,
                "" if row.met is None else ("yes" if row.met else "no"),
                row.coverage_from.isoformat() if row.coverage_from else "",
            ]
        )
    return buffer.getvalue()
