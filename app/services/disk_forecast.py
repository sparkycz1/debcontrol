"""When will a filesystem fill up? A least-squares linear trend of each
mount's used bytes over the last `WINDOW` of monitoring samples,
extrapolated to its size.

Recomputed hourly per machine (`app.tasks.jobs.forecast_machine_disks`)
and stored on `Machine.disk_forecast`, so both the Monitoring tab and the
`monitoring.disk_full_days` notification condition read one small JSON
value instead of re-scanning a week of samples on every page load or
every condition-sweep tick.

Deliberately simple: a straight line over a week says "at this rate," not
"this will definitely happen" — a log rotation or a cleanup job resets it,
and the next recomputation picks that up.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta
from typing import Any

WINDOW = timedelta(days=7)
# Too few points, or too short a stretch of time, and a trend is noise.
MIN_POINTS = 6
MIN_SPAN = timedelta(hours=6)
# Beyond ~10 years the answer is "not in any meaningful sense".
MAX_DAYS = 3650.0


def _slope_per_day(points: list[tuple[float, float]]) -> float:
    """Least-squares slope of (days, bytes) points, in bytes/day."""
    n = len(points)
    mean_x = sum(x for x, _ in points) / n
    mean_y = sum(y for _, y in points) / n
    denominator = sum((x - mean_x) ** 2 for x, _ in points)
    if denominator == 0:
        return 0.0
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / denominator


def forecast_filesystems(
    samples: Iterable[tuple[datetime, list[dict[str, Any]] | None]], now: datetime
) -> dict[str, dict[str, Any]]:
    """`{mount: {"bytes_per_day", "days_until_full", "used_bytes",
    "size_bytes"}}` for every mount with enough history. `days_until_full`
    is None when the mount isn't growing (or wouldn't fill within
    `MAX_DAYS`); 0 when it's already full."""
    per_mount: dict[str, list[tuple[datetime, int, int]]] = {}
    for sampled_at, filesystems in samples:
        for fs in filesystems or []:
            mount = fs.get("mount")
            used, size = fs.get("used_bytes"), fs.get("size_bytes")
            if isinstance(mount, str) and isinstance(used, int) and isinstance(size, int) and size:
                per_mount.setdefault(mount, []).append((sampled_at, used, size))

    result: dict[str, dict[str, Any]] = {}
    for mount, rows in per_mount.items():
        rows.sort(key=lambda r: r[0])
        if len(rows) < MIN_POINTS or rows[-1][0] - rows[0][0] < MIN_SPAN:
            continue
        origin = rows[0][0]
        points = [((ts - origin).total_seconds() / 86400, float(used)) for ts, used, _ in rows]
        slope = _slope_per_day(points)
        _, used_now, size_now = rows[-1]
        days: float | None = None
        if used_now >= size_now:
            days = 0.0
        elif slope > 0:
            days = (size_now - used_now) / slope
            if days > MAX_DAYS:
                days = None
        result[mount] = {
            "bytes_per_day": round(slope),
            "days_until_full": round(days, 1) if days is not None else None,
            "used_bytes": used_now,
            "size_bytes": size_now,
        }
    return result


def soonest_full_days(forecast: dict[str, dict[str, Any]] | None) -> float | None:
    """The smallest `days_until_full` across mounts, or None if none is
    filling — the `monitoring.disk_full_days` condition field."""
    days = [
        float(entry["days_until_full"])
        for entry in (forecast or {}).values()
        if isinstance(entry, dict) and isinstance(entry.get("days_until_full"), (int, float))
    ]
    return min(days) if days else None
