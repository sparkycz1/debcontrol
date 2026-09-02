"""Turns a machine's raw `MachineMonitoringSample` history into the
downsampled series the Monitoring tab's graphs actually render.

A machine sampled every `MONITORING_INTERVAL_SECONDS` (2 minutes by
default) accumulates ~720 rows/day — a 90-day view is ~65,000 rows, far
more points than an SVG sparkline (or a human) can usefully show. Rather
than have Postgres or the ORM do time-bucketed aggregation (which would
need either a raw/dialect-specific query or pulling in a real
time-series-friendly extension neither this app nor its SQLite test
backend has), this fetches the raw rows in the requested window (capped —
see `MAX_RAW_SAMPLES`) and downsamples them in Python by simple
positional bucketing (every consecutive run of rows averaged into one
point) — not time-aligned buckets, just "spread evenly across however many
rows came back," which is good enough for a *trend* line and keeps this
portable and dependency-free.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.db.models.machine_monitoring_sample import MachineMonitoringSample

# Every option the Monitoring tab's range selector offers, and how far back
# each looks. Kept as an ordered dict-like tuple so the template can render
# the selector in this exact order.
TIME_RANGES: tuple[tuple[str, str, timedelta], ...] = (
    ("1h", "Last hour", timedelta(hours=1)),
    ("24h", "Last 24 hours", timedelta(hours=24)),
    ("7d", "Last 7 days", timedelta(days=7)),
    ("30d", "Last 30 days", timedelta(days=30)),
    ("90d", "Last 90 days", timedelta(days=90)),
)
DEFAULT_TIME_RANGE = "24h"

# A hard cap on how many raw rows one request will pull into memory before
# downsampling — protects against a machine whose interval override is much
# shorter than expected, or a retention override far longer than the
# selected range would normally imply.
MAX_RAW_SAMPLES = 20_000

# How many points a downsampled series targets — enough resolution for a
# ~560px-wide sparkline (see macros/charts.html) to look like a real trend
# line, not so many that the SVG itself gets heavy.
_TARGET_POINTS = 150


def time_range_delta(range_key: str) -> timedelta:
    by_key = {key: delta for key, _label, delta in TIME_RANGES}
    return by_key.get(range_key, by_key[DEFAULT_TIME_RANGE])


def _bucket_average(values: list[float | None], target_points: int) -> list[float | None]:
    """Averages `values` down to at most `target_points` entries, in order.
    A bucket that's entirely `None` (nothing measurable in that stretch)
    stays `None` rather than being silently treated as 0 — a real gap in
    the graph is more honest than a fake dip to zero."""
    n = len(values)
    if n <= target_points:
        return values
    bucket_size = -(-n // target_points)  # ceil division
    buckets: list[float | None] = []
    for i in range(0, n, bucket_size):
        chunk = [v for v in values[i : i + bucket_size] if v is not None]
        buckets.append(sum(chunk) / len(chunk) if chunk else None)
    return buckets


@dataclass
class MonitoringHistory:
    range_key: str
    sample_count: int
    truncated: bool  # True if MAX_RAW_SAMPLES was hit — the window shown is
    # actually shorter than the selected range implies.
    cpu_percent: list[float | None]
    ram_percent: list[float | None]
    # {mount: [percent, ...]} — one downsampled series per filesystem seen
    # anywhere in the window (a mount that only appears partway through the
    # window has `None` for buckets before it existed).
    disk_percent_by_mount: dict[str, list[float | None]]
    latest_cpu_percent: float | None
    latest_ram_used_bytes: int | None
    latest_ram_total_bytes: int | None
    latest_disks: list[dict[str, Any]]
    latest_failed_services_count: int | None
    latest_sampled_at: datetime | None


def build_monitoring_history(
    samples: list[MachineMonitoringSample], range_key: str
) -> MonitoringHistory:
    """Pure function, no I/O — the caller (`app.web.routes.machines`) does
    the DB query (oldest-first, capped at `MAX_RAW_SAMPLES`, within the
    requested window) and hands the rows here."""
    truncated = len(samples) >= MAX_RAW_SAMPLES
    cpu_series = _bucket_average([s.cpu_percent for s in samples], _TARGET_POINTS)

    ram_percent_raw: list[float | None] = []
    for s in samples:
        if s.ram_total_bytes and s.ram_used_bytes is not None and s.ram_total_bytes > 0:
            ram_percent_raw.append(s.ram_used_bytes / s.ram_total_bytes * 100)
        else:
            ram_percent_raw.append(None)
    ram_series = _bucket_average(ram_percent_raw, _TARGET_POINTS)

    mounts: list[str] = []
    for s in samples:
        for disk in s.disks or []:
            mount = disk.get("mount")
            if mount and mount not in mounts:
                mounts.append(mount)

    disk_series: dict[str, list[float | None]] = {}
    for mount in mounts:
        raw: list[float | None] = []
        for s in samples:
            value = None
            for disk in s.disks or []:
                if disk.get("mount") == mount:
                    value = disk.get("use_percent")
                    break
            raw.append(value)
        disk_series[mount] = _bucket_average(raw, _TARGET_POINTS)

    latest = samples[-1] if samples else None
    return MonitoringHistory(
        range_key=range_key,
        sample_count=len(samples),
        truncated=truncated,
        cpu_percent=cpu_series,
        ram_percent=ram_series,
        disk_percent_by_mount=disk_series,
        latest_cpu_percent=latest.cpu_percent if latest else None,
        latest_ram_used_bytes=latest.ram_used_bytes if latest else None,
        latest_ram_total_bytes=latest.ram_total_bytes if latest else None,
        latest_disks=latest.disks or [] if latest else [],
        latest_failed_services_count=latest.failed_services_count if latest else None,
        latest_sampled_at=latest.sampled_at if latest else None,
    )
