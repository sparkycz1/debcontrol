"""Shared Jinja2 templates instance (kept separate from `app.main` so it can be
imported from routers without a circular dependency)."""

from __future__ import annotations

from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi.templating import Jinja2Templates

from app.core.config import get_settings
from app.web.os_logos import badge_for

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.autoescape = True


@lru_cache
def _display_zone(tz_name: str) -> ZoneInfo:
    """`lru_cache`d per zone name so a template rendering many timestamps
    in a loop doesn't re-resolve the zone database on every one. Falls
    back to UTC for an unset or unrecognized `TZ` — see `Settings.tz`."""
    try:
        return ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        return ZoneInfo("UTC")


def local_time(value: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    """Render a stored datetime in the configured `TZ` (default UTC).

    Every datetime this app writes to the DB is UTC, naive or not — a naive
    one is treated as UTC rather than local time. Include `%Z` in `fmt` to
    print the zone's abbreviation instead of hardcoding "UTC" in the
    template. Returns "—" for `None` so callers don't need their own
    `if value else "—"` ternary.
    """
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(_display_zone(get_settings().tz)).strftime(fmt)


templates.env.filters["local_time"] = local_time


def format_uptime(seconds: int | None) -> str:
    """Render a machine's uptime as e.g. "12d 3h 4m" — the DB only stores
    the raw second count (`Machine.uptime_seconds`, from `/proc/uptime`)."""
    if seconds is None:
        return "—"
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


templates.env.filters["format_uptime"] = format_uptime

templates.env.filters["os_badge"] = badge_for
