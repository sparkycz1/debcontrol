"""History of things a machine no longer has: removed after a day.

A monitoring sample carries per-item lists — a sensor, disk, interface,
mount, GPU or container per entry (`SERIES`). When an item stops showing
up (a swapped graphics card, an unmounted disk, a deleted container), the
charts stop drawing it within minutes (`monitoring_history.CURRENT_WINDOW`),
and once it has been gone for `VANISHED_AFTER` its entries are deleted
from every stored sample, so nothing of it lingers until retention.

`Machine.monitoring_series_seen` remembers when each item was last seen:
`{list name: {item key: unix seconds}}`, updated by every sample (`note`).
`None` means "not built yet" (a machine from before 0.152.0): the first
sweep then reads the machine's history once to build it (`bootstrap`).

A container that only stopped still exists: it is kept for as long as
Docker still lists it (`Machine.docker_containers`), however long ago it
last ran.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample

logger = logging.getLogger(__name__)

# Sample list -> the field that names an item in it.
SERIES: dict[str, str] = {
    "network_io": "iface",
    "disk_io": "device",
    "filesystems": "mount",
    "sensor_temps": "name",
    "sensor_fans": "name",
    "gpus": "id",
    "docker_stats": "name",
    "smart_disks": "device",
}

VANISHED_AFTER = timedelta(hours=24)
# Rows read (and rewritten) per round trip.
BATCH_SIZE = 500


def _keys(entries: Any, field: str) -> set[str]:
    return {
        str(entry[field])
        for entry in entries or []
        if isinstance(entry, dict) and entry.get(field)
    }


def note(machine: Machine, sample: MachineMonitoringSample, now: datetime) -> None:
    """Record that every item in `sample` was seen at `now`. A machine
    without a record yet keeps `None` (the sweep builds it from history);
    a new dict is assigned so the JSON column is written."""
    if machine.monitoring_series_seen is None:
        return
    stamp = int(now.timestamp())
    seen: dict[str, dict[str, int]] = {
        name: dict(items) for name, items in machine.monitoring_series_seen.items()
    }
    for name, field in SERIES.items():
        keys = _keys(getattr(sample, name, None), field)
        if keys:
            bucket = seen.setdefault(name, {})
            for key in keys:
                bucket[key] = stamp
    machine.monitoring_series_seen = seen


def merge(seen: dict[str, dict[str, int]], name: str, key: str, stamp: int) -> None:
    bucket = seen.setdefault(name, {})
    if stamp > bucket.get(key, 0):
        bucket[key] = stamp


def _existing_containers(machine: Machine) -> set[str]:
    return {
        str(c.get("name"))
        for c in machine.docker_containers or []
        if isinstance(c, dict) and c.get("name")
    }


def vanished(
    machine: Machine, seen: dict[str, dict[str, int]], now: datetime
) -> dict[str, dict[str, int]]:
    """`{list name: {key: last seen}}` of the items gone for longer than
    `VANISHED_AFTER` (see the module docstring for containers)."""
    cutoff = int((now - VANISHED_AFTER).timestamp())
    containers = _existing_containers(machine)
    gone: dict[str, dict[str, int]] = {}
    for name, items in seen.items():
        if name not in SERIES:
            continue
        for key, stamp in items.items():
            if stamp >= cutoff:
                continue
            if name == "docker_stats" and key in containers:
                continue
            gone.setdefault(name, {})[key] = stamp
    return gone


def strip(entries: Any, field: str, keys: set[str]) -> list[Any] | None:
    """`entries` without the items in `keys`, or None when none was in it."""
    if not isinstance(entries, list):
        return None
    kept = [
        e for e in entries if not (isinstance(e, dict) and str(e.get(field) or "") in keys)
    ]
    return kept if len(kept) != len(entries) else None


async def _rows(
    db: AsyncSession, machine_id: uuid.UUID, columns: Iterable[str], until: datetime | None
) -> Any:
    """The machine's samples (id, time and `columns`), oldest first, in
    batches, without holding them all at once."""
    cols = [getattr(MachineMonitoringSample, c) for c in columns]
    after: tuple[datetime, uuid.UUID] | None = None
    while True:
        query = select(
            MachineMonitoringSample.id, MachineMonitoringSample.sampled_at, *cols
        ).where(MachineMonitoringSample.machine_id == machine_id)
        if until is not None:
            query = query.where(MachineMonitoringSample.sampled_at <= until)
        if after is not None:
            query = query.where(
                (MachineMonitoringSample.sampled_at > after[0])
                | (
                    (MachineMonitoringSample.sampled_at == after[0])
                    & (MachineMonitoringSample.id > after[1])
                )
            )
        query = query.order_by(
            MachineMonitoringSample.sampled_at, MachineMonitoringSample.id
        ).limit(BATCH_SIZE)
        batch = (await db.execute(query)).all()
        if not batch:
            return
        yield batch
        after = (batch[-1][1], batch[-1][0])
        if len(batch) < BATCH_SIZE:
            return


def _stamp(when: datetime) -> int:
    return int((when if when.tzinfo else when.replace(tzinfo=UTC)).timestamp())


async def bootstrap(db: AsyncSession, machine: Machine) -> dict[str, dict[str, int]]:
    """When each item was last seen, read from the machine's whole stored
    history (once, for a machine that has no record yet)."""
    seen: dict[str, dict[str, int]] = {}
    names = list(SERIES)
    async for batch in _rows(db, machine.id, names, None):
        for row in batch:
            stamp = _stamp(row[1])
            for i, name in enumerate(names):
                for key in _keys(row[2 + i], SERIES[name]):
                    merge(seen, name, key, stamp)
    return seen


async def purge_machine(db: AsyncSession, machine: Machine, now: datetime) -> int:
    """Delete the entries of `machine`'s vanished items from its stored
    samples and forget them. Returns how many samples were rewritten.
    Commits."""
    seen = machine.monitoring_series_seen
    if seen is None:
        seen = await bootstrap(db, machine)
        # Whatever a sample noted meanwhile is newer.
        await db.refresh(machine)
        for name, items in (machine.monitoring_series_seen or {}).items():
            for key, stamp in items.items():
                merge(seen, name, key, stamp)
    else:
        seen = {name: dict(items) for name, items in seen.items()}
    gone = vanished(machine, seen, now)
    rewritten = 0
    if gone:
        names = list(gone)
        newest = max(stamp for items in gone.values() for stamp in items.values())
        # Stamps are whole seconds: the last row with it is up to 1 s later.
        until = datetime.fromtimestamp(newest + 1, UTC)
        async for batch in _rows(db, machine.id, names, until):
            for row in batch:
                values: dict[str, Any] = {}
                for i, name in enumerate(names):
                    kept = strip(row[2 + i], SERIES[name], set(gone[name]))
                    if kept is not None:
                        values[name] = kept
                if values:
                    await db.execute(
                        update(MachineMonitoringSample)
                        .where(MachineMonitoringSample.id == row[0])
                        .values(**values)
                    )
                    rewritten += 1
            await db.commit()
        for name, items in gone.items():
            for key in items:
                seen.get(name, {}).pop(key, None)
    await db.refresh(machine)
    # Keep what samples noted while this ran; drop only what was purged.
    current = machine.monitoring_series_seen or {}
    for name, items in current.items():
        for key, stamp in items.items():
            if key not in gone.get(name, {}) or stamp > gone[name][key]:
                merge(seen, name, key, stamp)
    machine.monitoring_series_seen = {name: items for name, items in seen.items() if items}
    await db.commit()
    if rewritten:
        logger.info(
            "Removed %d vanished item(s) from %d sample(s) of %s",
            sum(len(v) for v in gone.values()),
            rewritten,
            machine.name,
        )
    return rewritten
