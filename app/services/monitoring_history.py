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

Network/disk I/O are stored as cumulative counters (bytes since boot —
see `app.ssh.monitoring`'s module docstring), so a *rate* (bytes/sec) is
computed here from the delta between each consecutive pair of samples,
before downsampling — a counter that went backwards (device/interface
reset, e.g. a reboot) or a non-positive time delta yields a gap (`None`)
for that point rather than a nonsensical negative or infinite rate.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_reachability_sample import MachineReachabilitySample

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
DEFAULT_TIME_RANGE = "1h"

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


def _bucket_timestamps(timestamps: list[datetime], target_points: int) -> list[datetime]:
    """The same positional bucketing `_bucket_average` does, but returning
    one representative timestamp (the bucket's middle sample) per bucket
    instead of an average — used to label the X axis / hover tooltip of
    every graph built from the same `samples` list, since they all bucket
    identically (bucketing depends only on `len(samples)`, never on the
    values themselves)."""
    n = len(timestamps)
    if n <= target_points:
        return timestamps
    bucket_size = -(-n // target_points)
    return [
        timestamps[i + len(timestamps[i : i + bucket_size]) // 2]
        for i in range(0, n, bucket_size)
    ]


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


def _cumulative_series(
    samples: list[MachineMonitoringSample],
    list_attr: str,
    key_field: str,
) -> tuple[list[str], dict[str, list[dict[str, Any] | None]]]:
    """`list_attr` is `"network_io"` or `"disk_io"` — each sample's JSON
    list of `{key_field: ..., <value fields>: ...}` dicts. Returns (keys in
    first-seen order, {key: [entry-or-None per sample]})."""
    keys: list[str] = []
    for s in samples:
        for entry in getattr(s, list_attr) or []:
            k = entry.get(key_field)
            if k and k not in keys:
                keys.append(k)

    per_key: dict[str, list[dict[str, Any] | None]] = {k: [] for k in keys}
    for s in samples:
        entries = {e.get(key_field): e for e in (getattr(s, list_attr) or [])}
        for k in keys:
            per_key[k].append(entries.get(k))
    return keys, per_key


def _filesystem_usage_series(
    samples: list[MachineMonitoringSample],
) -> tuple[list[str], dict[str, list[float | None]]]:
    """`{mount: [use_percent per sample]}` — one series per mount seen
    anywhere in the window, in first-seen order. Unlike network/disk I/O,
    `use_percent` is already a gauge (a snapshot value, not a cumulative
    counter), so this just reads it straight off each sample rather than
    computing a rate — a gap (`None`) is a sample where that mount wasn't
    reported at all (missing entirely, or unparseable), not zero usage."""
    keys: list[str] = []
    for s in samples:
        for entry in s.filesystems or []:
            mount = entry.get("mount")
            if mount and mount not in keys:
                keys.append(mount)

    per_key: dict[str, list[float | None]] = {k: [] for k in keys}
    for s in samples:
        entries: dict[Any, dict[str, Any]] = {
            e.get("mount"): e for e in (s.filesystems or [])
        }
        for mount in keys:
            matched = entries.get(mount)
            per_key[mount].append(matched.get("use_percent") if matched else None)
    return keys, per_key


def _combined_rate_series(
    entries: list[dict[str, Any] | None],
    timestamps: list[datetime],
    value_fields: tuple[str, str],
) -> list[float | None]:
    """The combined (summed) bytes/sec rate across `value_fields` (e.g.
    `("rx_bytes", "tx_bytes")` or `("read_bytes", "write_bytes")`) between
    each consecutive pair of cumulative-counter readings. The first point
    is always `None` — there's no prior sample to diff against yet."""
    rates: list[float | None] = [None]
    for i in range(1, len(entries)):
        prev, cur = entries[i - 1], entries[i]
        dt = (timestamps[i] - timestamps[i - 1]).total_seconds()
        if prev is None or cur is None or dt <= 0:
            rates.append(None)
            continue
        try:
            prev_total = sum(prev[f] for f in value_fields)
            cur_total = sum(cur[f] for f in value_fields)
        except (KeyError, TypeError):
            rates.append(None)
            continue
        if cur_total < prev_total:  # counter reset (reboot, interface replaced, ...)
            rates.append(None)
        else:
            rates.append((cur_total - prev_total) / dt)
    return rates


def _scalar_rate_series(
    values: list[int | None], timestamps: list[datetime], *, divisor: float = 1.0
) -> list[float | None]:
    """Same idea as `_combined_rate_series`, for a single cumulative
    counter (e.g. `cpu_energy_uj`) rather than a dict of named fields —
    `divisor` converts the counter's own unit into the rate's (microjoules
    per second / 1e6 = watts)."""
    rates: list[float | None] = [None]
    for i in range(1, len(values)):
        prev, cur = values[i - 1], values[i]
        dt = (timestamps[i] - timestamps[i - 1]).total_seconds()
        if prev is None or cur is None or dt <= 0 or cur < prev:  # counter reset
            rates.append(None)
        else:
            rates.append((cur - prev) / divisor / dt)
    return rates


@dataclass
class MonitoringHistory:
    range_key: str
    sample_count: int
    truncated: bool  # True if MAX_RAW_SAMPLES was hit — the window shown is
    # actually shorter than the selected range implies.
    # One timestamp per point in every series below — they all bucket
    # identically (see _bucket_timestamps), so this is shared rather than
    # repeated per graph. Rendered as data attributes for the hover
    # tooltip (see static/js/monitoring-chart.js).
    bucket_timestamps: list[datetime]
    cpu_percent: list[float | None]
    ram_percent: list[float | None]
    load1: list[float | None]
    load5: list[float | None]
    load15: list[float | None]
    # {iface: [combined rx+tx bytes/sec, ...]} — one downsampled series per
    # network interface seen anywhere in the window.
    network_rate_by_iface: dict[str, list[float | None]]
    # {device: [combined read+write bytes/sec, ...]} — one downsampled
    # series per whole disk seen anywhere in the window.
    disk_rate_by_device: dict[str, list[float | None]]
    # {mount: [use_percent, ...]} — one downsampled series per filesystem
    # mount seen anywhere in the window.
    filesystem_usage_by_mount: dict[str, list[float | None]]
    latest_cpu_percent: float | None
    latest_load1: float | None
    latest_load5: float | None
    latest_load15: float | None
    latest_ram_used_bytes: int | None
    latest_ram_total_bytes: int | None
    # {iface: {"rx_bytes": ..., "tx_bytes": ...}} — the most recent raw
    # cumulative reading per interface, for a "current" display alongside
    # the rate graph (the graph itself needs a rate, not a running total).
    latest_network_io: dict[str, dict[str, int]]
    latest_disk_io: dict[str, dict[str, int]]
    # {mount: {"size_bytes": ..., "used_bytes": ..., "avail_bytes": ...,
    # "use_percent": ...}} — the most recent raw reading per mount.
    latest_filesystems: dict[str, dict[str, Any]]
    latest_failed_services_count: int | None
    latest_sampled_at: datetime | None
    # --- Hardware (app.ssh.monitoring's _HARDWARE_COMMAND) — only ever
    # populated for a physical machine; empty/None throughout on a VM. ---
    # Average watts, computed from consecutive `cpu_energy_uj` readings —
    # a rate, same treatment as the network/disk-I/O series above, not a
    # "latest" gauge (a single instantaneous energy-counter reading means
    # nothing on its own).
    cpu_power_watts: list[float | None]
    latest_sensor_temps: list[dict[str, Any]]
    latest_sensor_fans: list[dict[str, Any]]
    latest_smart_disks: list[dict[str, Any]]
    latest_gpu_power_watts: float | None


def build_monitoring_history(
    samples: list[MachineMonitoringSample], range_key: str
) -> MonitoringHistory:
    """Pure function, no I/O — the caller (`app.web.routes.machines`) does
    the DB query (oldest-first, capped at `MAX_RAW_SAMPLES`, within the
    requested window) and hands the rows here."""
    truncated = len(samples) >= MAX_RAW_SAMPLES
    timestamps = [s.sampled_at for s in samples]
    bucket_timestamps = _bucket_timestamps(timestamps, _TARGET_POINTS)

    cpu_series = _bucket_average([s.cpu_percent for s in samples], _TARGET_POINTS)
    load1_series = _bucket_average([s.load1 for s in samples], _TARGET_POINTS)
    load5_series = _bucket_average([s.load5 for s in samples], _TARGET_POINTS)
    load15_series = _bucket_average([s.load15 for s in samples], _TARGET_POINTS)

    ram_percent_raw: list[float | None] = []
    for s in samples:
        if s.ram_total_bytes and s.ram_used_bytes is not None and s.ram_total_bytes > 0:
            ram_percent_raw.append(s.ram_used_bytes / s.ram_total_bytes * 100)
        else:
            ram_percent_raw.append(None)
    ram_series = _bucket_average(ram_percent_raw, _TARGET_POINTS)

    net_keys, net_by_key = _cumulative_series(samples, "network_io", "iface")
    network_rate_by_iface = {
        iface: _bucket_average(
            _combined_rate_series(net_by_key[iface], timestamps, ("rx_bytes", "tx_bytes")),
            _TARGET_POINTS,
        )
        for iface in net_keys
    }

    disk_keys, disk_by_key = _cumulative_series(samples, "disk_io", "device")
    disk_rate_by_device = {
        device: _bucket_average(
            _combined_rate_series(disk_by_key[device], timestamps, ("read_bytes", "write_bytes")),
            _TARGET_POINTS,
        )
        for device in disk_keys
    }

    fs_keys, fs_raw_by_mount = _filesystem_usage_series(samples)
    filesystem_usage_by_mount = {
        mount: _bucket_average(fs_raw_by_mount[mount], _TARGET_POINTS) for mount in fs_keys
    }

    cpu_power_watts = _bucket_average(
        _scalar_rate_series(
            [s.cpu_energy_uj for s in samples], timestamps, divisor=1_000_000.0
        ),
        _TARGET_POINTS,
    )

    latest = samples[-1] if samples else None
    latest_network_io = {
        iface: entries[-1] for iface, entries in net_by_key.items() if entries and entries[-1]
    }
    latest_disk_io = {
        device: entries[-1] for device, entries in disk_by_key.items() if entries and entries[-1]
    }
    latest_filesystems = {
        entry["mount"]: entry
        for entry in ((latest.filesystems or []) if latest else [])
        if entry.get("mount")
    }

    return MonitoringHistory(
        range_key=range_key,
        sample_count=len(samples),
        truncated=truncated,
        bucket_timestamps=bucket_timestamps,
        cpu_percent=cpu_series,
        ram_percent=ram_series,
        load1=load1_series,
        load5=load5_series,
        load15=load15_series,
        network_rate_by_iface=network_rate_by_iface,
        disk_rate_by_device=disk_rate_by_device,
        filesystem_usage_by_mount=filesystem_usage_by_mount,
        latest_cpu_percent=latest.cpu_percent if latest else None,
        latest_load1=latest.load1 if latest else None,
        latest_load5=latest.load5 if latest else None,
        latest_load15=latest.load15 if latest else None,
        latest_ram_used_bytes=latest.ram_used_bytes if latest else None,
        latest_ram_total_bytes=latest.ram_total_bytes if latest else None,
        latest_network_io=latest_network_io,
        latest_disk_io=latest_disk_io,
        latest_filesystems=latest_filesystems,
        latest_failed_services_count=latest.failed_services_count if latest else None,
        latest_sampled_at=latest.sampled_at if latest else None,
        cpu_power_watts=cpu_power_watts,
        latest_sensor_temps=(latest.sensor_temps or []) if latest else [],
        latest_sensor_fans=(latest.sensor_fans or []) if latest else [],
        latest_smart_disks=(latest.smart_disks or []) if latest else [],
        latest_gpu_power_watts=latest.gpu_power_watts if latest else None,
    )


@dataclass
class AvailabilityHistory:
    """The "Availability" category's own history, built from
    `MachineReachabilitySample` rows — a separate table and cadence from
    `MonitoringHistory` above (see that model's own docstring for why: a
    reachability check is written whether it succeeded or not, so it can
    actually show an outage; a monitoring sample is skipped entirely when
    SSH can't even connect)."""

    range_key: str
    sample_count: int
    truncated: bool
    bucket_timestamps: list[datetime]
    # 0-100 — the percentage of checks in each bucket that succeeded. A gap
    # (`None`) only happens if a bucket had zero samples at all, which
    # `_bucket_average` already never produces here since every bucket by
    # construction contains at least one row.
    uptime_percent: list[float | None]
    # Average connect latency of the *successful* checks in each bucket —
    # a failed check contributes no latency value to average (see
    # `ReachabilityResult.latency_ms`'s own docstring for why a failure
    # has no meaningful connect time at all).
    latency_ms: list[float | None]
    latest_reachable: bool | None
    latest_latency_ms: float | None
    latest_checked_at: datetime | None


def build_availability_history(
    samples: list[MachineReachabilitySample], range_key: str
) -> AvailabilityHistory:
    """Pure function, no I/O — same shape as `build_monitoring_history`:
    the caller does the DB query (oldest-first, capped at `MAX_RAW_SAMPLES`,
    within the requested window) and hands the rows here."""
    truncated = len(samples) >= MAX_RAW_SAMPLES
    timestamps = [s.checked_at for s in samples]
    bucket_timestamps = _bucket_timestamps(timestamps, _TARGET_POINTS)

    uptime_raw: list[float | None] = [100.0 if s.reachable else 0.0 for s in samples]
    uptime_series = _bucket_average(uptime_raw, _TARGET_POINTS)

    latency_raw: list[float | None] = [s.latency_ms for s in samples]
    latency_series = _bucket_average(latency_raw, _TARGET_POINTS)

    latest = samples[-1] if samples else None

    return AvailabilityHistory(
        range_key=range_key,
        sample_count=len(samples),
        truncated=truncated,
        bucket_timestamps=bucket_timestamps,
        uptime_percent=uptime_series,
        latency_ms=latency_series,
        latest_reachable=latest.reachable if latest else None,
        latest_latency_ms=latest.latency_ms if latest else None,
        latest_checked_at=latest.checked_at if latest else None,
    )
