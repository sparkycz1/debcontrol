"""The machine Overview's live cards and the Monitoring tab's network
interface table — built from the newest monitoring samples, no SSH.

The cards redraw when a new sample lands (`live_updates.KIND_MONITORING`)
or every two minutes at the latest; anything that needs a fresh reading
(the top processes, the connectivity test) is fetched on demand instead.

Pure functions over rows already loaded, apart from `load_recent`.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.web.charts import noise_interfaces, secondary_sensors

# How far back the cards' sparklines reach.
SPARK_WINDOW = timedelta(minutes=60)
# At most this many samples are read for them (newest first).
SPARK_MAX_SAMPLES = 60
SPARK_WIDTH = 100.0
SPARK_HEIGHT = 28.0
# A ring's circumference with r = 15.9155 (2πr = 100), so a percentage is
# the dash length as is.
RING_CIRCUMFERENCE = 100

LINK_GROUPS = ("physical", "wireless", "bond", "bridge", "vlan", "virtual")


async def load_recent(db: AsyncSession, machine_id: uuid.UUID) -> list[MachineMonitoringSample]:
    """The newest samples of the last hour, newest first (the
    `(machine_id, sampled_at)` index)."""
    since = datetime.now(UTC) - SPARK_WINDOW
    result = await db.execute(
        select(MachineMonitoringSample)
        .where(
            MachineMonitoringSample.machine_id == machine_id,
            MachineMonitoringSample.sampled_at >= since,
        )
        .order_by(MachineMonitoringSample.sampled_at.desc())
        .limit(SPARK_MAX_SAMPLES)
    )
    return list(result.scalars().all())


def sparkline(values: Sequence[float | None], *, top: float | None = None) -> str:
    """SVG polyline points (oldest left) in a SPARK_WIDTH x SPARK_HEIGHT box;
    empty when there are fewer than two readings. `top` fixes the scale
    (100 for a percentage), else it follows the highest value."""
    points = [(i, v) for i, v in enumerate(values) if v is not None]
    if len(points) < 2:
        return ""
    lowest = 0.0 if top is not None else min(v for _, v in points)
    highest = top if top is not None else max(v for _, v in points)
    span = (highest - lowest) or 1.0
    step = SPARK_WIDTH / max(len(values) - 1, 1)
    out = []
    for i, v in points:
        y = SPARK_HEIGHT - (min(max(v, lowest), highest) - lowest) / span * (SPARK_HEIGHT - 2) - 1
        out.append(f"{i * step:.1f},{y:.1f}")
    return " ".join(out)


def level(percent: float | None, warn: int, critical: int) -> str:
    """CSS level for a ring/value: ok, warn or critical."""
    if percent is None:
        return "none"
    if percent >= critical:
        return "critical"
    if percent >= warn:
        return "warn"
    return "ok"


def _rates(
    newest: MachineMonitoringSample, previous: MachineMonitoringSample | None, column: str,
    key: str, fields: tuple[str, str],
) -> dict[str, tuple[float | None, float | None]]:
    """Per key (interface, disk): both counters' rate in bytes/second
    between the two newest samples; None across a counter reset."""
    if previous is None:
        return {}
    seconds = (newest.sampled_at - previous.sampled_at).total_seconds()
    if seconds <= 0:
        return {}
    before = {e.get(key): e for e in getattr(previous, column) or [] if isinstance(e, dict)}
    rates: dict[str, tuple[float | None, float | None]] = {}
    for entry in getattr(newest, column) or []:
        if not isinstance(entry, dict) or entry.get(key) not in before:
            continue
        old = before[entry[key]]
        pair: list[float | None] = []
        for name in fields:
            now_value, old_value = entry.get(name), old.get(name)
            if isinstance(now_value, int) and isinstance(old_value, int) and now_value >= old_value:
                pair.append((now_value - old_value) / seconds)
            else:
                pair.append(None)
        rates[str(entry[key])] = (pair[0], pair[1])
    return rates


def _sum(values: Sequence[float | None]) -> float | None:
    known = [v for v in values if v is not None]
    return sum(known) if known else None


@dataclass
class LiveCards:
    sampled_at: datetime | None = None
    cpu: dict[str, Any] = field(default_factory=dict)
    memory: dict[str, Any] = field(default_factory=dict)
    storage: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    temperature: dict[str, Any] | None = None


def _hottest(sample: MachineMonitoringSample) -> tuple[float, str] | None:
    temps = [t for t in sample.sensor_temps or [] if isinstance(t, dict)]
    names = [str(t.get("name") or "") for t in temps]
    minor = secondary_sensors(names)
    best: tuple[float, str] | None = None
    for temp, name in zip(temps, names, strict=True):
        celsius = temp.get("celsius")
        if name in minor or not isinstance(celsius, (int, float)):
            continue
        if best is None or celsius > best[0]:
            best = (float(celsius), name)
    return best


def link_summary(links: Sequence[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """[{"kind", "up", "total"}] per kind present, in LINK_GROUPS order."""
    counts: dict[str, list[int]] = {}
    for link in links or []:
        kind = str(link.get("kind") or "virtual")
        up, total = counts.setdefault(kind, [0, 0])
        counts[kind] = [up + (link.get("state") == "up"), total + 1]
    return [
        {"kind": kind, "up": counts[kind][0], "total": counts[kind][1]}
        for kind in LINK_GROUPS
        if kind in counts
    ]


def build_cards(machine: Machine, samples: Sequence[MachineMonitoringSample]) -> LiveCards:
    """The Overview's cards from `samples` (newest first)."""
    cards = LiveCards()
    if not samples:
        return cards
    newest = samples[0]
    previous = samples[1] if len(samples) > 1 else None
    oldest_first = list(reversed(samples))
    cards.sampled_at = newest.sampled_at

    cards.cpu = {
        "percent": newest.cpu_percent,
        "user": newest.cpu_user_percent,
        "system": newest.cpu_system_percent,
        "iowait": newest.cpu_iowait_percent,
        "load": (newest.load1, newest.load5, newest.load15),
        "cores": machine.cpu_cores,
        "spark": sparkline([s.cpu_percent for s in oldest_first], top=100),
    }

    used, total = newest.ram_used_bytes, newest.ram_total_bytes
    cards.memory = {
        "used": used,
        "total": total,
        "percent": used / total * 100 if used is not None and total else None,
        "cache": newest.ram_cache_bytes,
        "arc": newest.ram_arc_bytes,
        "spark": sparkline(
            [
                s.ram_used_bytes / s.ram_total_bytes * 100
                if s.ram_used_bytes is not None and s.ram_total_bytes
                else None
                for s in oldest_first
            ],
            top=100,
        ),
    }

    filesystems = [f for f in newest.filesystems or [] if isinstance(f, dict)]
    fullest = max(
        (f for f in filesystems if isinstance(f.get("use_percent"), int)),
        key=lambda f: f["use_percent"],
        default=None,
    )
    disk_rates = _rates(newest, previous, "disk_io", "device", ("read_bytes", "write_bytes"))
    cards.storage = {
        "fullest": fullest,
        "mounts": len(filesystems),
        "used": _sum([f.get("used_bytes") for f in filesystems]),
        "size": _sum([f.get("size_bytes") for f in filesystems]),
        "read": _sum([r for r, _w in disk_rates.values()]),
        "write": _sum([w for _r, w in disk_rates.values()]),
    }

    net_rates = _rates(newest, previous, "network_io", "iface", ("rx_bytes", "tx_bytes"))
    # The host's own traffic: no taps, veths or firewall bridges, and a
    # port that belongs to a bridge or bond is counted once, at the top.
    enslaved = {
        str(link.get("name")) for link in machine.network_links or [] if link.get("master")
    }
    counted = {
        name: rate
        for name, rate in net_rates.items()
        if name not in noise_interfaces([name]) and name not in enslaved
    }
    cards.network = {
        "rx": _sum([rx for rx, _tx in counted.values()]),
        "tx": _sum([tx for _rx, tx in counted.values()]),
        "links": link_summary(machine.network_links),
        "gateway": machine.default_gateway,
        "gateway_latency": newest.gateway_latency_ms,
        "gateway_loss": newest.gateway_loss_percent,
        "internet_latency": newest.internet_latency_ms,
        "internet_loss": newest.internet_loss_percent,
        "dns_ok": newest.dns_ok,
        "dns_ms": newest.dns_ms,
        "ntp_synced": newest.ntp_synced,
        "ntp_offset": newest.ntp_offset_ms,
        "spark": sparkline([s.internet_latency_ms for s in oldest_first]),
    }

    hottest = _hottest(newest)
    if hottest is not None:
        series = []
        for sample in oldest_first:
            reading = _hottest(sample)
            series.append(reading[0] if reading else None)
        cards.temperature = {
            "celsius": hottest[0],
            "sensor": hottest[1],
            "spark": sparkline(series),
        }
    return cards


# --- the Monitoring tab's interface table -------------------------------------


def interface_table(
    machine: Machine,
    newest: MachineMonitoringSample | None,
    previous: MachineMonitoringSample | None,
) -> list[dict[str, Any]]:
    """[{"kind", "up", "total", "links": [...]}] — every interface the
    newest sample saw, grouped by kind, each with its addresses (facts),
    members (for a bridge or bond), current rates and error/drop counters."""
    links = [link for link in machine.network_links or [] if isinstance(link, dict)]
    if not links:
        return []
    addresses: dict[str, list[str]] = {}
    for entry in machine.network_interfaces or []:
        name, address = entry.get("interface"), entry.get("address")
        if name and address:
            addresses.setdefault(str(name), []).append(str(address))
    counters = {
        str(e.get("iface")): e
        for e in (newest.network_io or [] if newest else [])
        if isinstance(e, dict)
    }
    rates = (
        _rates(newest, previous, "network_io", "iface", ("rx_bytes", "tx_bytes"))
        if newest
        else {}
    )
    members: dict[str, list[str]] = {}
    for link in links:
        if link.get("master"):
            members.setdefault(str(link["master"]), []).append(str(link["name"]))

    groups: dict[str, list[dict[str, Any]]] = {}
    for link in links:
        name = str(link.get("name"))
        counter = counters.get(name, {})
        rx, tx = rates.get(name, (None, None))
        errors = [counter.get(k) for k in ("rx_errors", "tx_errors")]
        drops = [counter.get(k) for k in ("rx_dropped", "tx_dropped")]
        groups.setdefault(str(link.get("kind") or "virtual"), []).append(
            {
                **link,
                "addresses": addresses.get(name, []),
                "members": sorted(members.get(name, [])),
                "rx": rx,
                "tx": tx,
                "errors": _sum([e for e in errors if isinstance(e, int)]),
                "drops": _sum([d for d in drops if isinstance(d, int)]),
            }
        )
    return [
        {
            "kind": kind,
            "up": sum(1 for link in groups[kind] if link.get("state") == "up"),
            "total": len(groups[kind]),
            "links": groups[kind],
        }
        for kind in LINK_GROUPS
        if kind in groups
    ]
