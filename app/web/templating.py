"""Shared Jinja2 templates instance (kept separate from `app.main` so it can be
imported from routers without a circular dependency)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import mistune
from fastapi import Request
from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from app.core.config import get_settings
from app.core.version import APP_VERSION, get_git_commit
from app.db.models.role import Permission
from app.i18n import DEFAULT_LOCALE_CODE, get_locale
from app.i18n import translate as _translate
from app.services import fleet_overview
from app.web import charts
from app.web.branding import favicon_href, logo_src
from app.web.flash import read_flash
from app.web.os_logos import badge_for

if TYPE_CHECKING:
    from app.db.models.user import User

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


def to_local_input(value: datetime | None) -> str:
    """A stored UTC timestamp as a `<input type="datetime-local">` value in
    the configured `TZ` (the zone every other timestamp is shown in)."""
    return local_time(value, "%Y-%m-%dT%H:%M") if value is not None else ""


def parse_local_input(raw: str) -> datetime:
    """The inverse of `to_local_input`: a `datetime-local` value, read in
    the configured `TZ`, as an aware UTC datetime. Raises `ValueError`."""
    naive = datetime.fromisoformat(raw.strip())
    if naive.tzinfo is not None:
        return naive.astimezone(UTC)
    return naive.replace(tzinfo=_display_zone(get_settings().tz)).astimezone(UTC)


templates.env.filters["local_input"] = to_local_input


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


def iso_list(timestamps: list[datetime]) -> list[str]:
    """`[t.isoformat() for t in timestamps]` — Jinja's `map` filter can read
    an attribute but not call a method, so this is the plain way to turn a
    list of datetimes into JS-parseable strings for `tojson` below (used by
    the Monitoring tab's hover-chart data attributes)."""
    return [t.isoformat() for t in timestamps]


templates.env.filters["iso_list"] = iso_list


def _chart(*args: Any, **kwargs: Any) -> charts.Chart:
    """`chart(...)` in a template: `app.web.charts.build_chart` with time
    labels rendered in the configured display zone."""
    kwargs.setdefault("time_label", local_time)
    return charts.build_chart(*args, **kwargs)


templates.env.globals["chart"] = _chart
templates.env.globals["level_for"] = fleet_overview.level_for


def _cert_days(expires_at: datetime) -> int:
    """Whole days until a certificate's `notAfter` (negative once expired)."""
    value = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=UTC)
    return int((value - datetime.now(UTC)).total_seconds() // 86400)


templates.env.globals["cert_days"] = _cert_days
templates.env.globals["chart_palette"] = charts.PALETTE
templates.env.filters["chart_value"] = charts.format_value
templates.env.filters["bytes"] = charts.format_bytes


def tojson_filter(value: object) -> Markup:
    """A minimal `tojson`, since plain `jinja2.Environment` (unlike Flask's)
    doesn't ship one. Escapes the characters that would otherwise break out
    of an HTML attribute or a `<script>` block — same character set Flask's
    own `tojson` escapes — so the result is safe to drop straight into a
    single- or double-quoted attribute, e.g. `data-series='{{ x | tojson }}'`.
    """
    raw = json.dumps(value, default=str)
    escaped = (
        raw.replace("&", "\\u0026")
        .replace("'", "\\u0027")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )
    return Markup(escaped)  # noqa: S704 - hand-escaped above, not raw interpolation


templates.env.filters["tojson"] = tojson_filter


# Deliberately NOT the `mistune.html` module-level convenience callable —
# that preset has `escape=False` (raw HTML in the source passes straight
# through unescaped), the opposite of what a stored-content renderer
# needs. `escape=True` here is what actually escapes a `<script>` in the
# source to inert text rather than executing it.
_markdown = mistune.create_markdown(escape=True)


def markdown_filter(text: str | None) -> Markup:
    """Renders `text` as Markdown to HTML — used for a machine's runbook
    (`Machine.runbook`). Raw HTML in the source is escaped to plain text,
    not passed through — a runbook is admin-authored (only
    `machine.manage` accounts can edit one) but there's no reason to trust
    it with markup injection just because of that; `javascript:`-scheme
    links are likewise stripped by mistune's own default link-safety
    check. `None`/empty renders as an empty string rather than an error,
    so a template can call this unconditionally."""
    if not text:
        return Markup("")
    html = _markdown(text)
    assert isinstance(html, str)
    return Markup(html)  # noqa: S704 - escape=True above, not raw interpolation


templates.env.filters["markdown"] = markdown_filter


def t(request: Request, key: str, **kwargs: object) -> str:
    """`{{ t(request, "nav.dashboard") }}` — the current request's language
    (`request.state.locale`, set by `app.auth.middleware` on every request,
    public or not) applied to `key`. See `app.i18n`'s module docstring for
    the lookup/fallback rules and the file format a new language file
    needs. `getattr(..., None)` rather than a direct attribute read: a
    handful of error-page renders (e.g. a raised `HTTPException` before the
    middleware runs, or a test hitting a route through a bare ASGI call)
    have no `request.state.locale` at all, and this should degrade to
    English then, not throw."""
    locale = getattr(request.state, "locale", None) or get_locale(None)
    return _translate(locale, key, **kwargs)


templates.env.globals["t"] = t


def audit_text(
    request: Request, action: str, summary: str, target_label: str | None = None
) -> str:
    """`{{ audit_text(request, entry.action, entry.summary) }}` — an audit
    entry's one-line description in the reader's language.

    `summary` is written in English when the event is recorded (it also
    goes to exports, syslog and the API, which stay English), so it's what
    an English reader sees — it's the more specific text. Any other
    language shows the translated label for the action code instead —
    `audit.action_label.<action>`, else the label of its parent code
    (`machine.power.reboot` -> `machine.power`), else the English summary
    when neither is translated. The label describes *what* happened; the
    table row still shows who and the outcome next to it; pass
    `target_label` where no separate target column shows it, and it's
    appended to a translated label (`Zobrazení journalu: prx`)."""
    locale = getattr(request.state, "locale", None) or get_locale(None)
    if locale.code == DEFAULT_LOCALE_CODE:
        return summary
    code = action
    while code:
        label = locale.strings.get(f"audit.action_label.{code}")
        if label is not None:
            return f"{label}: {target_label}" if target_label else label
        code = code.rpartition(".")[0]
    return summary


templates.env.globals["audit_text"] = audit_text


def smart_attr_label(request: Request, name: str) -> str:
    """A S.M.A.R.T. attribute's readable name in the reader's language —
    `smartctl` reports ATA attributes as `Reallocated_Sector_Ct` and the
    NVMe health log as `CriticalWarning` (see `app.ssh.smart`); both
    normalize to one `smart.attr.<lowercase letters and digits>` key. An
    attribute without a translation keeps its original name."""
    key = "smart.attr." + "".join(ch for ch in name.lower() if ch.isalnum())
    label = t(request, key)
    return name if label == key else label


templates.env.globals["smart_attr_label"] = smart_attr_label


def _permitted_for(permission: str, user: User) -> bool:
    """`{{ perms | select('permitted_for', user) }}` — Jinja test form of
    `User.has_permission`, for a nav link gated on any of several."""
    return user.has_permission(Permission(permission))


templates.env.tests["permitted_for"] = _permitted_for


STATIC_DIR = Path(__file__).resolve().parent / "static"


@lru_cache(maxsize=256)
def _static_fingerprint(path: str) -> str:
    try:
        return hashlib.sha256((STATIC_DIR / path).read_bytes()).hexdigest()[:12]
    except OSError:
        return "missing"


def static_url(path: str) -> str:
    """`/static/<path>?v=<content hash>` — every page references its CSS/JS
    through this, so a new release's files get a new URL and a browser
    never keeps rendering new HTML with a stale cached stylesheet (which
    silently breaks every layout added since). The hash is computed once per
    file per process, and `app.main` serves such versioned URLs as
    immutable."""
    return f"/static/{path}?v={_static_fingerprint(path)}"


templates.env.globals["static_url"] = static_url


def t_or(request: Request, key: str, fallback: str, **kwargs: object) -> str:
    """`t()`, but `fallback` (usually the English text a Python registry
    already carries, e.g. a scheduled action's `label`) instead of the bare
    key when no locale — English included — has `key`. For strings whose
    source of truth lives in code rather than `en.json`."""
    text = t(request, key, **kwargs)
    return fallback if text == key else text


templates.env.globals["t_or"] = t_or
templates.env.globals["flash"] = read_flash
templates.env.globals["logo_src"] = logo_src
templates.env.globals["favicon_href"] = favicon_href

# Footer (base.html) — same values settings/_general.html's "Version" panel
# used to show before that panel was removed in favor of the footer.
templates.env.globals["app_version"] = APP_VERSION
templates.env.globals["git_commit"] = get_git_commit
