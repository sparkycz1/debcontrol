"""The chart pages' time window, from and to a query string — the range
selector plus the custom from-to boxes (`partials/range_picker.html`) and
the drag-to-zoom in `monitoring-chart.js` all end up here. See
`app.services.monitoring_history.TimeWindow`."""

from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlencode

from app.services.monitoring_history import TimeWindow, resolve_window
from app.web.templating import parse_local_input


def _parse(raw: str) -> datetime | None:
    """A `datetime-local` value (read in the configured `TZ`) or an ISO
    timestamp with an offset; None for empty or unreadable input."""
    if not raw.strip():
        return None
    try:
        return parse_local_input(raw)
    except ValueError:
        return None


def window_from_query(range_key: str, start: str = "", end: str = "") -> TimeWindow:
    """`start` and `end` both readable → that custom window; anything else
    → the `range_key` preset (itself falling back to the default)."""
    return resolve_window(range_key, _parse(start), _parse(end))


def window_query(window: TimeWindow) -> str:
    """The query string that reproduces `window` — for links and redirects
    that must stay on the same view."""
    if window.is_custom and window.until is not None:
        return urlencode(
            {
                "start": window.since.astimezone(UTC).isoformat(),
                "end": window.until.astimezone(UTC).isoformat(),
            }
        )
    return urlencode({"range_key": window.range_key})
