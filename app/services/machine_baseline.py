"""Each machine's **usual behavior**, and what is unusual against it.

A fixed threshold treats every machine the same: a backup server at 95 %
CPU every night at two is as alarming as a web server stuck at 95 % at
noon. Here each machine is compared with itself instead — with what its
CPU, memory, load, network traffic and internet latency normally are at
the same hour of the same weekday.

**Learning.** Every night (`app.tasks.baselines`) the last four weeks of a
machine's monitoring samples are put into 168 buckets, one per hour of the
week (UTC, so a bucket always means the same hour), each bucket also taking
the hour before and after so a job that drifts by a few minutes stays in.
A bucket keeps its median, its spread (the median absolute deviation,
scaled to a standard deviation, so a past incident barely moves it) and
its 5th and 95th percentile. One row per machine (`MachineBaseline`).

**Comparing** (`machine_health`, with every monitoring sample):

- *Unusual* — the reading is above the bucket's 95th percentile, more than
  `deviations` times the spread above the median, and more than a fixed
  minimum above it (`MIN_EXCESS`: 25 CPU points is a change, 3 is noise).
  Information; a warning when it is twice that far off. Network traffic
  that collapses (below a tenth of a busy machine's usual) is unusual too.
- *Usual* — a CPU or memory reading over the warning threshold that is no
  higher than the bucket's 95th percentile is shown as information, not a
  warning, when `AppSettings.health_anomaly_mute_usual` is on. A critical
  level always counts.

Nothing is compared until a machine has two weeks of history
(`MIN_HISTORY`) and the bucket at least `MIN_BUCKET_SAMPLES` readings.
"""

from __future__ import annotations

import statistics
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine_baseline import MachineBaseline
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.web.charts import noise_interfaces

Metric = Literal["cpu", "memory", "load", "network", "latency"]
METRICS: tuple[Metric, ...] = ("cpu", "memory", "load", "network", "latency")
HOURS = 7 * 24

# The history learned from, and how much of it is needed first.
WINDOW = timedelta(days=28)
MIN_HISTORY = timedelta(days=14)
MIN_BUCKET_SAMPLES = 8
# Consecutive samples further apart than this give no network rate.
MAX_RATE_GAP = timedelta(minutes=30)
# How many of the newest samples a reading is averaged over (as for CPU in
# machine_health), so one busy minute is not "unusual".
CURRENT_SAMPLES = 3

# The smallest spread taken: a machine idle at exactly 1 % CPU every hour
# has no spread at all, and 3 % would otherwise be "unusual".
SPREAD_FLOOR: dict[Metric, float] = {
    "cpu": 5.0,
    "memory": 2.0,
    "load": 0.5,
    "network": 64 * 1024.0,
    "latency": 5.0,
}
# How far above the usual median a reading must be, at least.
MIN_EXCESS: dict[Metric, float] = {
    "cpu": 25.0,
    "memory": 10.0,
    "load": 1.0,
    "network": 1024 * 1024.0,
    "latency": 30.0,
}
# Traffic counts as collapsed below this share of a usual median of at
# least LOW_TRAFFIC_MIN bytes/s.
LOW_TRAFFIC_SHARE = 0.1
LOW_TRAFFIC_MIN = 1024 * 1024.0

DEFAULT_DEVIATIONS = 4


def hour_of_week(moment: datetime) -> int:
    """0 = Monday 00:00-00:59 UTC ... 167 = Sunday 23:00-23:59 UTC."""
    moment = moment.astimezone(UTC) if moment.tzinfo else moment.replace(tzinfo=UTC)
    return moment.weekday() * 24 + moment.hour


@dataclass(frozen=True)
class Bucket:
    """One metric at one hour of the week."""

    samples: int
    median: float
    spread: float
    p5: float
    p95: float

    def as_list(self) -> list[float]:
        return [self.samples, round(self.median, 3), round(self.spread, 3),
                round(self.p5, 3), round(self.p95, 3)]

    @classmethod
    def from_list(cls, raw: Any) -> Bucket | None:
        if not isinstance(raw, list) or len(raw) != 5:
            return None
        if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in raw):
            return None
        return cls(int(raw[0]), float(raw[1]), float(raw[2]), float(raw[3]), float(raw[4]))


@dataclass(frozen=True)
class Baseline:
    since: datetime | None
    computed_at: datetime | None
    sample_count: int
    buckets: dict[str, list[Bucket | None]]

    def ready(self, now: datetime) -> bool:
        if self.since is None:
            return False
        since = self.since if self.since.tzinfo else self.since.replace(tzinfo=UTC)
        return now - since >= MIN_HISTORY

    def usual(self, metric: Metric, now: datetime) -> Bucket | None:
        """This hour's bucket, when there is enough of it to go by."""
        if not self.ready(now):
            return None
        row = self.buckets.get(metric) or []
        hour = hour_of_week(now)
        bucket = row[hour] if hour < len(row) else None
        return bucket if bucket is not None and bucket.samples >= MIN_BUCKET_SAMPLES else None

    def as_data(self) -> dict[str, Any]:
        return {
            "metrics": {
                metric: [b.as_list() if b else None for b in rows]
                for metric, rows in self.buckets.items()
            }
        }


def from_row(row: MachineBaseline | None) -> Baseline | None:
    if row is None:
        return None
    metrics = (row.data or {}).get("metrics") if isinstance(row.data, dict) else None
    buckets: dict[str, list[Bucket | None]] = {}
    for metric in METRICS:
        raw = metrics.get(metric) if isinstance(metrics, dict) else None
        if isinstance(raw, list) and len(raw) == HOURS:
            buckets[metric] = [Bucket.from_list(item) for item in raw]
    return Baseline(row.since, row.computed_at, row.sample_count, buckets)


async def load(db: AsyncSession, machine_id: uuid.UUID) -> Baseline | None:
    return from_row(await db.get(MachineBaseline, machine_id))


# --- Readings ----------------------------------------------------------------


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def memory_percent(used: Any, total: Any) -> float | None:
    used_n, total_n = _number(used), _number(total)
    if used_n is None or not total_n:
        return None
    return used_n / total_n * 100


def _counters(network_io: Any) -> dict[str, int]:
    """rx + tx bytes per interface, the noisy ones (veth, docker...) left out."""
    totals: dict[str, int] = {}
    for entry in network_io or []:
        if not isinstance(entry, dict):
            continue
        name, rx, tx = entry.get("iface"), entry.get("rx_bytes"), entry.get("tx_bytes")
        if isinstance(name, str) and isinstance(rx, int) and isinstance(tx, int):
            totals[name] = rx + tx
    noise = noise_interfaces(totals)
    return {name: value for name, value in totals.items() if name not in noise}


def network_rate(
    newer_at: datetime, newer_io: Any, older_at: datetime, older_io: Any
) -> float | None:
    """Bytes/second over the interfaces present in both samples, None across
    a gap, a reboot (a counter going back) or with nothing to compare."""
    seconds = (newer_at - older_at).total_seconds()
    if seconds <= 0 or seconds > MAX_RATE_GAP.total_seconds():
        return None
    newer, older = _counters(newer_io), _counters(older_io)
    total = 0
    shared = 0
    for name, value in newer.items():
        before = older.get(name)
        if before is None:
            continue
        if value < before:
            return None
        total += value - before
        shared += 1
    return total / seconds if shared else None


def _mean(values: Iterable[float | None]) -> float | None:
    known = [v for v in values if v is not None]
    return sum(known) / len(known) if known else None


def current(samples: Sequence[MachineMonitoringSample]) -> dict[Metric, float]:
    """The readings compared now, from the newest samples (newest first)."""
    newest = samples[:CURRENT_SAMPLES]
    readings: dict[Metric, float | None] = {
        "cpu": _mean(s.cpu_percent for s in newest),
        "memory": memory_percent(newest[0].ram_used_bytes, newest[0].ram_total_bytes)
        if newest
        else None,
        "load": _mean(s.load1 for s in newest),
        "network": network_rate(
            samples[0].sampled_at, samples[0].network_io,
            samples[1].sampled_at, samples[1].network_io,
        )
        if len(samples) >= 2
        else None,
        "latency": _mean(s.internet_latency_ms for s in newest),
    }
    return {metric: value for metric, value in readings.items() if value is not None}


# --- Learning ------------------------------------------------------------------


def _percentile(ordered: Sequence[float], share: float) -> float:
    if len(ordered) == 1:
        return ordered[0]
    position = share * (len(ordered) - 1)
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def bucket_of(values: Sequence[float]) -> Bucket | None:
    if not values:
        return None
    ordered = sorted(values)
    median = statistics.median(ordered)
    mad = statistics.median(abs(v - median) for v in ordered)
    return Bucket(
        samples=len(ordered),
        median=median,
        spread=1.4826 * mad,
        p5=_percentile(ordered, 0.05),
        p95=_percentile(ordered, 0.95),
    )


@dataclass(frozen=True)
class Reading:
    """What one sample contributes (the columns `compute` needs)."""

    sampled_at: datetime
    cpu: float | None
    memory: float | None
    load: float | None
    network_io: Any
    latency: float | None


def compute(readings: Sequence[Reading]) -> tuple[dict[str, list[Bucket | None]], int]:
    """The buckets from `readings` in time order, and how many readings
    went in. Each bucket takes its neighbouring hours as well."""
    per_hour: dict[str, list[list[float]]] = {m: [[] for _ in range(HOURS)] for m in METRICS}
    previous: Reading | None = None
    for reading in readings:
        hour = hour_of_week(reading.sampled_at)
        values: dict[str, float | None] = {
            "cpu": reading.cpu,
            "memory": reading.memory,
            "load": reading.load,
            "latency": reading.latency,
            "network": network_rate(
                reading.sampled_at, reading.network_io, previous.sampled_at, previous.network_io
            )
            if previous is not None
            else None,
        }
        for metric, value in values.items():
            if value is not None:
                per_hour[metric][hour].append(value)
        previous = reading
    buckets: dict[str, list[Bucket | None]] = {}
    for metric in METRICS:
        hours = per_hour[metric]
        buckets[metric] = [
            bucket_of(hours[(h - 1) % HOURS] + hours[h] + hours[(h + 1) % HOURS])
            for h in range(HOURS)
        ]
    return buckets, len(readings)


async def recompute(
    db: AsyncSession, machine_id: uuid.UUID, *, now: datetime | None = None
) -> Baseline | None:
    """Learn the machine's usual behavior from its last `WINDOW` of samples
    and store it (the caller commits). None, and nothing stored, without
    any history."""
    now = now or datetime.now(UTC)
    result = await db.execute(
        select(
            MachineMonitoringSample.sampled_at,
            MachineMonitoringSample.cpu_percent,
            MachineMonitoringSample.ram_used_bytes,
            MachineMonitoringSample.ram_total_bytes,
            MachineMonitoringSample.load1,
            MachineMonitoringSample.network_io,
            MachineMonitoringSample.internet_latency_ms,
        )
        .where(
            MachineMonitoringSample.machine_id == machine_id,
            MachineMonitoringSample.sampled_at >= now - WINDOW,
        )
        .order_by(MachineMonitoringSample.sampled_at)
    )
    readings = [
        Reading(
            sampled_at=row.sampled_at,
            cpu=row.cpu_percent,
            memory=memory_percent(row.ram_used_bytes, row.ram_total_bytes),
            load=row.load1,
            network_io=row.network_io,
            latency=row.internet_latency_ms,
        )
        for row in result.all()
    ]
    stored = await db.get(MachineBaseline, machine_id)
    if not readings:
        if stored is not None:
            await db.delete(stored)
        return None
    buckets, count = compute(readings)
    since = readings[0].sampled_at
    baseline = Baseline(since=since, computed_at=now, sample_count=count, buckets=buckets)
    if stored is None:
        stored = MachineBaseline(machine_id=machine_id)
        db.add(stored)
    stored.computed_at = now
    stored.since = since
    stored.sample_count = count
    stored.data = baseline.as_data()
    return baseline


# --- Comparing -------------------------------------------------------------------

Verdict = Literal["high", "very_high", "low"]


def unusual(
    metric: Metric, value: float, bucket: Bucket, deviations: int = DEFAULT_DEVIATIONS
) -> Verdict | None:
    """Whether `value` is unusual against `bucket` (see the module docstring)."""
    spread = max(bucket.spread, SPREAD_FLOOR[metric])
    excess = value - bucket.median
    if value > bucket.p95 and excess >= MIN_EXCESS[metric] and excess > deviations * spread:
        return "very_high" if excess > 2 * deviations * spread else "high"
    if (
        metric == "network"
        and bucket.median >= LOW_TRAFFIC_MIN
        and value < bucket.median * LOW_TRAFFIC_SHARE
        and value < bucket.p5
    ):
        return "low"
    return None


def is_usual(value: float, bucket: Bucket) -> bool:
    """A reading no higher than what the machine reaches at this hour anyway."""
    return value <= bucket.p95


@dataclass(frozen=True)
class Range:
    """What the Health panel and the API show for one metric now."""

    metric: Metric
    value: float | None
    median: float
    low: float
    high: float
    samples: int
    verdict: Verdict | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
            "value": None if self.value is None else round(self.value, 3),
            "usual_median": round(self.median, 3),
            "usual_low": round(self.low, 3),
            "usual_high": round(self.high, 3),
            "samples": self.samples,
            "verdict": self.verdict,
        }


def ranges_now(
    baseline: Baseline | None,
    samples: Sequence[MachineMonitoringSample],
    now: datetime,
    deviations: int = DEFAULT_DEVIATIONS,
) -> list[Range]:
    """Each metric's usual range at this hour and the reading now."""
    if baseline is None:
        return []
    readings = current(samples)
    found: list[Range] = []
    for metric in METRICS:
        bucket = baseline.usual(metric, now)
        if bucket is None:
            continue
        value = readings.get(metric)
        found.append(
            Range(
                metric=metric,
                value=value,
                median=bucket.median,
                low=bucket.p5,
                high=bucket.p95,
                samples=bucket.samples,
                verdict=unusual(metric, value, bucket, deviations) if value is not None else None,
            )
        )
    return found


def status_dict(baseline: Baseline | None, now: datetime) -> dict[str, Any]:
    """Whether a baseline exists and since when it is used (the API)."""
    if baseline is None:
        return {"learned": False, "ready": False, "since": None, "computed_at": None,
                "ready_at": None, "samples": 0}
    ready_at = None
    if baseline.since is not None:
        since = baseline.since if baseline.since.tzinfo else baseline.since.replace(tzinfo=UTC)
        ready_at = (since + MIN_HISTORY).isoformat()
    return {
        "learned": True,
        "ready": baseline.ready(now),
        "since": baseline.since.isoformat() if baseline.since else None,
        "computed_at": baseline.computed_at.isoformat() if baseline.computed_at else None,
        "ready_at": ready_at,
        "samples": baseline.sample_count,
    }
