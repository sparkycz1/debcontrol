"""Shared Jinja2 templates instance (kept separate from `app.main` so it can be
imported from routers without a circular dependency)."""

from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.autoescape = True


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
