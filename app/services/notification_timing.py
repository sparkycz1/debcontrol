"""When a rule's notification goes out: right away, or held for later.

A rule can have **quiet hours** (`quiet_hours_start`-`quiet_hours_end`,
may cross midnight) and a **daily summary** (`digest_time`), both in the
instance's time zone (`TZ`, `app.core.timezones.display_zone`).

- Inside quiet hours only an urgent event goes out (with
  `quiet_hours_urgent` on, the default); the rest are held.
- With a daily summary, an event that isn't urgent is held whatever the
  hour; an urgent one still goes out at once.
- Held events wait in `NotificationHeldItem`. With a daily summary they all
  go out in it; without one, as one message once the quiet hours end
  (`app.services.notification_digest`).

"Urgent" is a fixed set: a machine down, a failing disk or pool, a lost
cluster quorum, a UPS on battery, an endpoint down, and health turning
critical. Everything here is pure (no I/O), so it can be tested on its own.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, time, timedelta
from typing import Any

from app.core.timezones import display_zone
from app.db.models.notification_rule import NotificationEventType, NotificationRule

URGENT_EVENTS = frozenset(
    {
        NotificationEventType.MACHINE_UNREACHABLE,
        NotificationEventType.SMART_FAILED,
        NotificationEventType.ZFS_POOL_UNHEALTHY,
        NotificationEventType.CLUSTER_QUORUM_LOST,
        NotificationEventType.UPS_ON_BATTERY,
        NotificationEventType.ENDPOINT_DOWN,
    }
)

REASON_QUIET = "quiet"
REASON_DIGEST = "digest"

_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


def parse_hhmm(value: str | None) -> time | None:
    """"07:30" -> time(7, 30); None for anything else."""
    match = _HHMM_RE.match((value or "").strip())
    if match is None:
        return None
    return time(int(match.group(1)), int(match.group(2)))


def normalize_hhmm(value: str | None) -> str | None:
    """A valid "HH:MM" as stored ("7:05" is not accepted), else None;
    raises ValueError for text that is neither empty nor a time."""
    text = (value or "").strip()
    if not text:
        return None
    if parse_hhmm(text) is None:
        raise ValueError(f'"{text}" is not a time (HH:MM, 00:00-23:59).')
    return text


def is_urgent(event_type: NotificationEventType, context: dict[str, Any] | None) -> bool:
    if event_type in URGENT_EVENTS:
        return True
    return (
        event_type is NotificationEventType.HEALTH_DEGRADED
        and str((context or {}).get("status") or "") == "critical"
    )


def local_now(now: datetime) -> datetime:
    """`now` (aware) in the instance's time zone."""
    return now.astimezone(display_zone())


def in_quiet_hours(rule: NotificationRule, now: datetime) -> bool:
    start, end = parse_hhmm(rule.quiet_hours_start), parse_hhmm(rule.quiet_hours_end)
    if start is None or end is None or start == end:
        return False
    current = local_now(now).time().replace(second=0, microsecond=0)
    if start < end:
        return start <= current < end
    return current >= start or current < end


def hold_reason(
    rule: NotificationRule,
    event_type: NotificationEventType,
    context: dict[str, Any] | None,
    now: datetime,
) -> str | None:
    """Why this rule holds the event back now ("quiet" or "digest"), or
    None to send it at once."""
    urgent = is_urgent(event_type, context)
    if in_quiet_hours(rule, now) and not (urgent and rule.quiet_hours_urgent):
        return REASON_QUIET
    if parse_hhmm(rule.digest_time) is not None and not urgent:
        return REASON_DIGEST
    return None


def last_digest_slot(rule: NotificationRule, now: datetime) -> datetime | None:
    """The most recent moment (aware, instance zone) the rule's daily
    summary was due, at or before `now`; None without a summary time."""
    at = parse_hhmm(rule.digest_time)
    if at is None:
        return None
    local = local_now(now)
    slot = local.replace(hour=at.hour, minute=at.minute, second=0, microsecond=0)
    if slot > local:
        slot -= timedelta(days=1)
    return slot


def digest_due(rule: NotificationRule, now: datetime, has_items: bool) -> bool:
    """Whether the rule's held notifications (or daily summary) should go
    out now.

    With a summary time: once per day, at the first tick after it, when
    something was collected or the summary carries the fleet status.
    Without one: as soon as the quiet hours are over and anything waits."""
    slot = last_digest_slot(rule, now)
    if slot is None:
        return has_items and not in_quiet_hours(rule, now)
    if not (has_items or rule.digest_fleet_status):
        return False
    last = rule.digest_last_sent_at
    if last is None:
        return True
    if last.tzinfo is None:
        # SQLite (the tests) hands timestamps back without their zone.
        last = last.replace(tzinfo=UTC)
    return last < slot
