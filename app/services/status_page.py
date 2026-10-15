"""A status page: whether chosen checks and machines are up, for people
without an account.

Off unless turned on (Checks -> Status page). It lives at
`/status/<token>` — an unguessable link, replaceable at any time — and is
the one page of this app that is served without signing in and outside
the network allowlist, so what it shows is deliberately little:

- a title, and for each chosen check or machine its **name**, whether it
  is up **now**, and the share of the last 30 days it was up;
- if turned on (`status_page_show_latency`), its **response time**: the
  latest one and the average over the last 24 hours;
- if turned on (`status_page_show_history`), a bar per **day** of the
  window with that day's share of successful probes (UTC days);
- a free-text notice the admin writes (`status_page_message`), e.g.
  planned maintenance;
- nothing else: no address, target, error text, version, or any item that
  was not chosen.

Only the names leave the app, so name the items for the readers you have
in mind before choosing them.
"""

from __future__ import annotations

import hmac
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.app_settings import AppSettings
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.endpoint_check_result import EndpointCheckResult
from app.db.models.machine import Machine
from app.db.models.machine_reachability_sample import MachineReachabilitySample

WINDOW_DAYS = 30
MAX_ITEMS = 100
DEFAULT_TITLE = "Service status"
# How long one rendering is reused: the page is public, and its numbers
# come from sample tables that are not small.
CACHE_SECONDS = 30.0

STATE_UP = "up"
STATE_DOWN = "down"
STATE_UNKNOWN = "unknown"

LATENCY_WINDOW_HOURS = 24


@dataclass(frozen=True)
class Day:
    day: date
    uptime_percent: float | None  # None = no samples that day

    @property
    def level(self) -> str:
        """The bar's colour: "ok" / "warn" / "down" / "none"."""
        if self.uptime_percent is None:
            return "none"
        if self.uptime_percent >= 99.5:
            return "ok"
        return "warn" if self.uptime_percent >= 95 else "down"


@dataclass(frozen=True)
class Item:
    kind: str  # "check" / "machine"
    name: str
    state: str
    uptime_percent: float | None
    # Only filled in when the page shows them (see the module docstring).
    latency_ms: float | None = None
    avg_latency_ms: float | None = None
    days: tuple[Day, ...] = field(default=())

    def as_dict(self, *, latency: bool = False, history: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "kind": self.kind,
            "name": self.name,
            "state": self.state,
            "uptime_percent": self.uptime_percent,
        }
        if latency:
            data["latency_ms"] = self.latency_ms
            data["avg_latency_ms_24h"] = self.avg_latency_ms
        if history:
            data["days"] = [
                {"date": d.day.isoformat(), "uptime_percent": d.uptime_percent}
                for d in self.days
            ]
        return data


@dataclass(frozen=True)
class Status:
    title: str
    items: tuple[Item, ...]
    generated_at: datetime
    message: str | None = None
    show_latency: bool = False
    show_history: bool = False

    @property
    def overall(self) -> str:
        """ "up" when everything known is up, "down" when anything is down,
        "unknown" when nothing is known yet."""
        states = {item.state for item in self.items}
        if STATE_DOWN in states:
            return STATE_DOWN
        return STATE_UP if STATE_UP in states else STATE_UNKNOWN

    @property
    def down_count(self) -> int:
        return sum(1 for item in self.items if item.state == STATE_DOWN)

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "overall": self.overall,
            "generated_at": self.generated_at.isoformat(),
            "window_days": WINDOW_DAYS,
            "message": self.message,
            "items": [
                item.as_dict(latency=self.show_latency, history=self.show_history)
                for item in self.items
            ],
        }


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_matches(app_settings: AppSettings, token: str) -> bool:
    """Whether `token` opens the page: it is turned on and the token is the
    current one (compared in constant time)."""
    stored = app_settings.status_page_token or ""
    return bool(
        app_settings.status_page_enabled
        and stored
        and hmac.compare_digest(stored.encode(), token.encode())
    )


def _ids(raw: Any) -> list[uuid.UUID]:
    found: list[uuid.UUID] = []
    for value in raw if isinstance(raw, list) else []:
        try:
            parsed = uuid.UUID(str(value))
        except ValueError:
            continue
        if parsed not in found:
            found.append(parsed)
    return found[:MAX_ITEMS]


def chosen_check_ids(app_settings: AppSettings) -> list[uuid.UUID]:
    return _ids(app_settings.status_page_check_ids)


def chosen_machine_ids(app_settings: AppSettings) -> list[uuid.UUID]:
    return _ids(app_settings.status_page_machine_ids)


def _percent(up: int, total: int) -> float | None:
    return round(up * 100.0 / total, 2) if total else None


def _day_of(value: Any) -> date | None:
    """`func.date(...)`'s value: a date on PostgreSQL, text on SQLite."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def _days(counts: dict[date, tuple[int, int]], today: date) -> tuple[Day, ...]:
    """One `Day` per day of the window, oldest first, ending today."""
    first = today - timedelta(days=WINDOW_DAYS - 1)
    return tuple(
        Day(day, _percent(*counts.get(day, (0, 0))))
        for day in (first + timedelta(days=offset) for offset in range(WINDOW_DAYS))
    )


def _rounded(value: Any) -> float | None:
    return None if value is None else round(float(value), 1)


async def build(db: AsyncSession, app_settings: AppSettings) -> Status:
    """The page's content, read fresh."""
    now = datetime.now(UTC)
    today = now.date()
    since = now - timedelta(days=WINDOW_DAYS)
    latency_since = now - timedelta(hours=LATENCY_WINDOW_HOURS)
    show_latency = bool(app_settings.status_page_show_latency)
    show_history = bool(app_settings.status_page_show_history)
    items: list[Item] = []

    check_ids = chosen_check_ids(app_settings)
    if check_ids:
        checks = await db.execute(
            select(EndpointCheck)
            .where(EndpointCheck.id.in_(check_ids))
            .order_by(EndpointCheck.name)
        )
        up = func.sum(case((EndpointCheckResult.ok.is_(True), 1), else_=0))
        counted = await db.execute(
            select(EndpointCheckResult.check_id, up, func.count())
            .where(
                EndpointCheckResult.check_id.in_(check_ids),
                EndpointCheckResult.checked_at >= since,
            )
            .group_by(EndpointCheckResult.check_id)
        )
        totals = {row[0]: (int(row[1] or 0), int(row[2] or 0)) for row in counted.all()}
        averages: dict[uuid.UUID, Any] = {}
        if show_latency:
            averaged = await db.execute(
                select(EndpointCheckResult.check_id, func.avg(EndpointCheckResult.latency_ms))
                .where(
                    EndpointCheckResult.check_id.in_(check_ids),
                    EndpointCheckResult.checked_at >= latency_since,
                    EndpointCheckResult.ok.is_(True),
                )
                .group_by(EndpointCheckResult.check_id)
            )
            averages = {row[0]: row[1] for row in averaged.all()}
        daily: dict[uuid.UUID, dict[date, tuple[int, int]]] = {}
        if show_history:
            day = func.date(EndpointCheckResult.checked_at)
            per_day = await db.execute(
                select(EndpointCheckResult.check_id, day, up, func.count())
                .where(
                    EndpointCheckResult.check_id.in_(check_ids),
                    EndpointCheckResult.checked_at >= since,
                )
                .group_by(EndpointCheckResult.check_id, day)
            )
            for check_id, raw_day, ups, total in per_day.all():
                parsed = _day_of(raw_day)
                if parsed is not None:
                    daily.setdefault(check_id, {})[parsed] = (int(ups or 0), int(total or 0))
        for check in checks.scalars().all():
            state = (
                STATE_UNKNOWN
                if check.last_ok is None or not check.enabled
                else (STATE_UP if check.last_ok else STATE_DOWN)
            )
            items.append(
                Item(
                    "check",
                    check.name,
                    state,
                    _percent(*totals.get(check.id, (0, 0))),
                    latency_ms=_rounded(check.last_latency_ms) if state == STATE_UP else None,
                    avg_latency_ms=_rounded(averages.get(check.id)),
                    days=_days(daily.get(check.id, {}), today) if show_history else (),
                )
            )

    machine_ids = chosen_machine_ids(app_settings)
    if machine_ids:
        machines = await db.execute(
            select(Machine.id, Machine.name, Machine.is_reachable)
            .where(Machine.id.in_(machine_ids))
            .order_by(Machine.name)
        )
        up = func.sum(case((MachineReachabilitySample.reachable.is_(True), 1), else_=0))
        counted = await db.execute(
            select(MachineReachabilitySample.machine_id, up, func.count())
            .where(
                MachineReachabilitySample.machine_id.in_(machine_ids),
                MachineReachabilitySample.checked_at >= since,
            )
            .group_by(MachineReachabilitySample.machine_id)
        )
        totals = {row[0]: (int(row[1] or 0), int(row[2] or 0)) for row in counted.all()}
        latest: dict[uuid.UUID, Any] = {}
        machine_averages: dict[uuid.UUID, Any] = {}
        if show_latency:
            sample = MachineReachabilitySample
            averaged = await db.execute(
                select(sample.machine_id, func.avg(sample.latency_ms))
                .where(
                    sample.machine_id.in_(machine_ids),
                    sample.checked_at >= latency_since,
                    sample.reachable.is_(True),
                )
                .group_by(sample.machine_id)
            )
            machine_averages = {row[0]: row[1] for row in averaged.all()}
            newest = (
                select(sample.machine_id, func.max(sample.checked_at).label("at"))
                .where(sample.machine_id.in_(machine_ids), sample.checked_at >= latency_since)
                .group_by(sample.machine_id)
                .subquery()
            )
            latest_rows = await db.execute(
                select(sample.machine_id, sample.latency_ms).join(
                    newest,
                    (sample.machine_id == newest.c.machine_id)
                    & (sample.checked_at == newest.c.at),
                )
            )
            latest = {row[0]: row[1] for row in latest_rows.all()}
        machine_daily: dict[uuid.UUID, dict[date, tuple[int, int]]] = {}
        if show_history:
            day = func.date(MachineReachabilitySample.checked_at)
            per_day = await db.execute(
                select(MachineReachabilitySample.machine_id, day, up, func.count())
                .where(
                    MachineReachabilitySample.machine_id.in_(machine_ids),
                    MachineReachabilitySample.checked_at >= since,
                )
                .group_by(MachineReachabilitySample.machine_id, day)
            )
            for machine_id, raw_day, ups, total in per_day.all():
                parsed = _day_of(raw_day)
                if parsed is not None:
                    machine_daily.setdefault(machine_id, {})[parsed] = (
                        int(ups or 0),
                        int(total or 0),
                    )
        for machine_id, name, reachable in machines.all():
            state = STATE_UNKNOWN if reachable is None else (STATE_UP if reachable else STATE_DOWN)
            items.append(
                Item(
                    "machine",
                    name,
                    state,
                    _percent(*totals.get(machine_id, (0, 0))),
                    latency_ms=_rounded(latest.get(machine_id)) if state == STATE_UP else None,
                    avg_latency_ms=_rounded(machine_averages.get(machine_id)),
                    days=(
                        _days(machine_daily.get(machine_id, {}), today) if show_history else ()
                    ),
                )
            )

    return Status(
        title=(app_settings.status_page_title or "").strip() or DEFAULT_TITLE,
        items=tuple(items),
        generated_at=now,
        message=(app_settings.status_page_message or "").strip() or None,
        show_latency=show_latency,
        show_history=show_history,
    )


# The last rendering, by the token it was made for: at most one entry.
_cache: dict[str, tuple[float, Status]] = {}


async def cached(db: AsyncSession, app_settings: AppSettings) -> Status:
    """`build`, reused for `CACHE_SECONDS` per token (a new link or a
    changed selection starts over — see `invalidate`)."""
    key = app_settings.status_page_token or ""
    now = time.monotonic()
    entry = _cache.get(key)
    if entry is not None and now - entry[0] < CACHE_SECONDS:
        return entry[1]
    status = await build(db, app_settings)
    _cache.clear()
    _cache[key] = (now, status)
    return status


def invalidate() -> None:
    _cache.clear()
