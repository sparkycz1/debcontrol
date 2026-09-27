"""Time zones: the instance's display zone (`TZ`) and validated IANA names
(a scheduled task's own zone)."""

from __future__ import annotations

from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from app.core.config import get_settings


@lru_cache
def zone(name: str) -> ZoneInfo:
    """The IANA zone `name`, falling back to UTC for an empty or unknown
    one. Cached — templates and parsers resolve the same few zones over
    and over."""
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def display_zone() -> ZoneInfo:
    """The zone every timestamp is shown in (`TZ`, default UTC)."""
    return zone(get_settings().tz)


def is_valid_timezone(name: str) -> bool:
    """True for a real IANA zone name (`Europe/Prague`, `UTC`)."""
    if not name or len(name) > 64:
        return False
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return False
    return True


@lru_cache(maxsize=1)
def timezone_names() -> list[str]:
    """Every IANA zone name this system knows, sorted — the schedule form's
    picker."""
    return sorted(n for n in available_timezones() if "/" in n or n == "UTC")
