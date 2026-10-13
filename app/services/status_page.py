"""A status page: whether chosen checks and machines are up, for people
without an account.

Off unless turned on (Checks -> Status page). It lives at
`/status/<token>` — an unguessable link, replaceable at any time — and is
the one page of this app that is served without signing in and outside
the network allowlist, so what it shows is deliberately little:

- a title, and for each chosen check or machine its **name**, whether it
  is up **now**, and the share of the last 30 days it was up;
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
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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


@dataclass(frozen=True)
class Item:
    kind: str  # "check" / "machine"
    name: str
    state: str
    uptime_percent: float | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "state": self.state,
            "uptime_percent": self.uptime_percent,
        }


@dataclass(frozen=True)
class Status:
    title: str
    items: tuple[Item, ...]
    generated_at: datetime

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
            "items": [item.as_dict() for item in self.items],
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


async def build(db: AsyncSession, app_settings: AppSettings) -> Status:
    """The page's content, read fresh."""
    now = datetime.now(UTC)
    since = now - timedelta(days=WINDOW_DAYS)
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
        for check in checks.scalars().all():
            state = (
                STATE_UNKNOWN
                if check.last_ok is None or not check.enabled
                else (STATE_UP if check.last_ok else STATE_DOWN)
            )
            items.append(Item("check", check.name, state, _percent(*totals.get(check.id, (0, 0)))))

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
        for machine_id, name, reachable in machines.all():
            state = STATE_UNKNOWN if reachable is None else (STATE_UP if reachable else STATE_DOWN)
            items.append(Item("machine", name, state, _percent(*totals.get(machine_id, (0, 0)))))

    return Status(
        title=(app_settings.status_page_title or "").strip() or DEFAULT_TITLE,
        items=tuple(items),
        generated_at=now,
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
