"""An endpoint check's result history, summarized for its detail page
(`GET /checks/{id}`) and `GET /api/v1/checks/{id}/history`: uptime %,
latency statistics, downsampled uptime/latency series over a time range,
and the most recent failures.

Same approach as the machines' Monitoring tab
(`app.services.monitoring_history`): fetch the raw rows in the window
(capped at `MAX_RAW_SAMPLES`), downsample in Python, reuse its time ranges
so both pages offer the same selector.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.endpoint_check_result import EndpointCheckResult
from app.services.monitoring_history import (
    _TARGET_POINTS,
    MAX_RAW_SAMPLES,
    _bucket_average,
    _bucket_timestamps,
    time_range_delta,
)

# How many of the latest failed probes the detail page lists.
RECENT_FAILURES = 20


@dataclass
class CheckFailure:
    checked_at: datetime
    status_code: int | None
    error: str | None


@dataclass
class EndpointCheckHistory:
    range_key: str
    sample_count: int
    truncated: bool
    # Share of probes in the window that were up, 0-100; None with no data.
    uptime_percent: float | None
    failure_count: int
    avg_latency_ms: float | None
    p95_latency_ms: float | None
    bucket_timestamps: list[datetime]
    uptime_series: list[float | None]
    latency_series: list[float | None]
    recent_failures: list[CheckFailure] = field(default_factory=list)


def _percentile(values: list[float], percent: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(percent / 100 * len(ordered)) - 1))
    return round(ordered[index], 1)


def build_check_history(
    results: list[EndpointCheckResult], range_key: str
) -> EndpointCheckHistory:
    """Pure function — `results` oldest first, already limited to the window."""
    latencies = [r.latency_ms for r in results if r.latency_ms is not None]
    up = sum(1 for r in results if r.ok)
    failures = [r for r in results if not r.ok][-RECENT_FAILURES:]
    return EndpointCheckHistory(
        range_key=range_key,
        sample_count=len(results),
        truncated=len(results) >= MAX_RAW_SAMPLES,
        uptime_percent=round(up / len(results) * 100, 2) if results else None,
        failure_count=len(results) - up,
        avg_latency_ms=round(sum(latencies) / len(latencies), 1) if latencies else None,
        p95_latency_ms=_percentile(latencies, 95),
        bucket_timestamps=_bucket_timestamps([r.checked_at for r in results], _TARGET_POINTS),
        uptime_series=_bucket_average(
            [100.0 if r.ok else 0.0 for r in results], _TARGET_POINTS
        ),
        latency_series=_bucket_average([r.latency_ms for r in results], _TARGET_POINTS),
        recent_failures=[
            CheckFailure(checked_at=r.checked_at, status_code=r.status_code, error=r.error)
            for r in reversed(failures)
        ],
    )


async def load_check_history(
    db: AsyncSession, check_id: uuid.UUID, range_key: str
) -> EndpointCheckHistory:
    """`range_key` must already be normalized
    (`monitoring_history.normalize_range_key`). Served by the
    `(check_id, checked_at)` index."""
    since = datetime.now(UTC) - time_range_delta(range_key)
    result = await db.execute(
        select(EndpointCheckResult)
        .where(EndpointCheckResult.check_id == check_id, EndpointCheckResult.checked_at >= since)
        .order_by(EndpointCheckResult.checked_at)
        .limit(MAX_RAW_SAMPLES)
    )
    return build_check_history(list(result.scalars().all()), range_key)
