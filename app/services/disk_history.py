"""A physical disk's life, followed by its serial number: readings, events
and a failure prediction (`app.db.models.disk`).

Fed from every facts refresh (`app.tasks.jobs._refresh_machine_facts`)
with the machine's S.M.A.R.T. summaries (`app.ssh.smart`) and its ZFS
pools' device tree (`app.ssh.proxmox.parse_zfs_pools`):

- the disk is found by (model, serial) — or created — wherever it sits, so
  a disk moved to another machine keeps its history (and gets a "moved"
  event);
- a reading goes to `DiskSample` at most once an hour, or at once when an
  error counter changed;
- what changed since the previous reading becomes a `DiskEvent`: S.M.A.R.T.
  failed (or passed again), an error counter that grew (reallocated or
  pending sectors, CRC, NVMe media errors, the kernel's I/O errors, ZFS
  read/write/checksum errors), the disk's ZFS state, a wear or
  temperature level crossed upwards (thresholds by disk kind, in
  Settings), a disk that dropped out of its machine or came back;
- `predict` reads the recent samples into a risk ("low", "elevated",
  "high", "failing") with its reasons, and when wear will reach 100 %.

Each machine's `smart_devices` entries get the disk's `disk_id` and
`prediction`, so the Monitoring tab can link the disk and the machine's
health (`app.services.machine_health`) can count it.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.app_settings import AppSettings
from app.db.models.disk import Disk, DiskEvent, DiskSample
from app.db.models.machine import Machine
from app.db.models.user import User
from app.i18n import DEFAULT_LOCALE_CODE, get_locale, translate
from app.services.access_scope import allowed_group_ids
from app.services.disk_forecast import _slope_per_day

logger = logging.getLogger(__name__)

SAMPLE_EVERY = timedelta(hours=1)
PREDICTION_WINDOW = timedelta(days=90)
# A counter that grew within this window counts towards the risk.
RECENT = timedelta(days=30)
# Wear is predicted only from this much history.
MIN_WEAR_SPAN = timedelta(days=7)

EVENT_KINDS = (
    "first_seen",
    "moved",
    "missing",
    "back",
    "smart_failed",
    "smart_passed",
    "counter",
    "wear",
    "temperature",
    "zfs_errors",
    "zfs_state",
)

# Counters whose growth means the disk itself is wearing out.
MEDIA_COUNTERS = (
    "reallocated",
    "pending",
    "uncorrectable",
    "uncorrectable_reported",
    "media_errors",
)
# Counters worth an event, with its severity. `unsafe_shutdowns` only
# says the power went, not that the disk is bad: kept, never an event.
COUNTER_SEVERITY = {
    "reallocated": "warning",
    "pending": "warning",
    "uncorrectable": "warning",
    "uncorrectable_reported": "warning",
    "media_errors": "warning",
    "crc_errors": "warning",
    "io_errors": "warning",
    "zfs_read": "warning",
    "zfs_write": "warning",
    "zfs_cksum": "warning",
    "error_log_entries": "info",
}
# Counters that start again from zero (since boot, or `zpool clear`): a
# drop is a new baseline, not a change worth an event.
RESETTING_COUNTERS = ("io_errors", "zfs_read", "zfs_write", "zfs_cksum")

RISKS = ("low", "elevated", "high", "failing")


@dataclass(frozen=True)
class DiskThresholds:
    temp: dict[str, tuple[int, int]]
    wear_warn: int
    wear_critical: int

    @classmethod
    def from_settings(cls, settings: AppSettings) -> DiskThresholds:
        return cls(
            temp={
                "hdd": (
                    settings.health_disk_temp_hdd_warn_celsius,
                    settings.health_disk_temp_hdd_critical_celsius,
                ),
                "ssd": (
                    settings.health_disk_temp_ssd_warn_celsius,
                    settings.health_disk_temp_ssd_critical_celsius,
                ),
                "nvme": (
                    settings.health_disk_temp_nvme_warn_celsius,
                    settings.health_disk_temp_nvme_critical_celsius,
                ),
            },
            wear_warn=settings.health_disk_wear_warn_percent,
            wear_critical=settings.health_disk_wear_critical_percent,
        )


DEFAULT_THRESHOLDS = DiskThresholds(
    temp={"hdd": (50, 60), "ssd": (60, 70), "nvme": (70, 80)}, wear_warn=80, wear_critical=95
)


def temperature_class(device: dict[str, Any]) -> str:
    """"hdd", "ssd" or "nvme" — which temperature thresholds apply."""
    if str(device.get("type") or "") == "nvme":
        return "nvme"
    rpm = device.get("rotation_rpm")
    if isinstance(rpm, (int, float)) and rpm > 0:
        return "hdd"
    return "ssd"


Level = Literal["warning", "critical"]


def _level(value: Any, warn: int, critical: int) -> Level | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    if value >= critical:
        return "critical"
    if value >= warn:
        return "warning"
    return None


def temperature_level(device: dict[str, Any], th: DiskThresholds) -> Level | None:
    warn, critical = th.temp[temperature_class(device)]
    return _level(device.get("temperature_c"), warn, critical)


def wear_level(device: dict[str, Any], th: DiskThresholds) -> Level | None:
    return _level(device.get("wear_percent"), th.wear_warn, th.wear_critical)


_RANK = {None: 0, "info": 0, "warning": 1, "critical": 2}


def _rises(before: str | None, after: str | None) -> bool:
    return _RANK[after] > _RANK[before]


# --- ZFS -------------------------------------------------------------------

_PARTITION_RE = re.compile(r"^(.*?)(?:p?\d+)?$")


def _zfs_matches(name: str, device: dict[str, Any]) -> bool:
    """Is the pool member `name` (as `zpool status` shows it) this disk?
    By-id names carry the serial; a plain `sda`/`sda1`/`nvme0n1p3` is
    matched by the device name."""
    serial = str(device.get("serial") or "").strip()
    if len(serial) >= 4 and serial.lower() in name.lower():
        return True
    path = str(device.get("device") or "")
    base = path.rsplit("/", 1)[-1]
    if not base:
        return False
    leaf = name.rsplit("/", 1)[-1]
    if leaf == base:
        return True
    if base.startswith("nvme"):
        return leaf.startswith(base + "p") and leaf[len(base) + 1 :].isdecimal()
    return leaf.startswith(base) and leaf[len(base) :].isdecimal()


def zfs_membership(
    device: dict[str, Any], zfs_pools: Sequence[dict[str, Any]] | None
) -> dict[str, Any] | None:
    """`{"pool", "name", "state", "read", "write", "cksum"}` of the pool
    member that is this disk (its partitions summed), or None."""
    found: dict[str, Any] | None = None
    for pool in zfs_pools or []:
        for member in pool.get("devices") or []:
            name = str(member.get("name") or "")
            if not name or not _zfs_matches(name, device):
                continue
            if found is None:
                found = {
                    "pool": str(pool.get("name") or ""),
                    "name": name,
                    "state": str(member.get("state") or ""),
                    "read": 0,
                    "write": 0,
                    "cksum": 0,
                }
            elif member.get("state") != "ONLINE":
                found["state"] = str(member.get("state") or "")
            for key in ("read", "write", "cksum"):
                value = member.get(key)
                if isinstance(value, int):
                    found[key] += value
    return found


# --- Prediction ------------------------------------------------------------


def predict(
    samples: Sequence[tuple[datetime, float | None, dict[str, int] | None]],
    latest: dict[str, Any],
    now: datetime,
    th: DiskThresholds = DEFAULT_THRESHOLDS,
) -> dict[str, Any]:
    """`{"risk", "reasons": [{"key", ...}], "wear_days_left"}` from the
    disk's samples (`(sampled_at, wear_percent, counters)`, any order) and
    its newest reading.

    - "failing": S.M.A.R.T. says FAILED, or a ZFS pool faulted the disk.
    - "high": media errors (reallocated/pending/uncorrectable sectors, NVMe
      media errors) grew more than once in the last 30 days, or wear is at
      its critical level or will reach 100 % within 30 days.
    - "elevated": media errors grew once in the last 30 days, other errors
      (CRC, I/O, ZFS) grew, or wear is at its warning level or will reach
      100 % within 180 days.
    - "low": none of that.

    Deliberately plain: a trend says "at this rate", not a date the disk
    will die."""
    reasons: list[dict[str, Any]] = []
    risk = "low"

    def raise_to(level: str) -> None:
        nonlocal risk
        if RISKS.index(level) > RISKS.index(risk):
            risk = level

    if latest.get("passed") is False:
        raise_to("failing")
        reasons.append({"key": "smart_failed"})
    zfs = latest.get("zfs") or {}
    if str(zfs.get("state") or "") in ("FAULTED", "UNAVAIL", "REMOVED"):
        raise_to("failing")
        reasons.append({"key": "zfs_faulted", "state": zfs.get("state"), "pool": zfs.get("pool")})

    ordered = sorted(
        (
            (ts if ts.tzinfo else ts.replace(tzinfo=UTC), wear, counters or {})
            for ts, wear, counters in samples
        ),
        key=lambda row: row[0],
    )
    recent_start = now - RECENT
    growth: dict[str, int] = {}
    rises: dict[str, int] = {}
    previous: dict[str, int] | None = None
    for ts, _wear, counters in ordered:
        if previous is not None and ts >= recent_start:
            for name, value in counters.items():
                before = previous.get(name)
                if isinstance(before, int) and isinstance(value, int) and value > before:
                    growth[name] = growth.get(name, 0) + value - before
                    rises[name] = rises.get(name, 0) + 1
        previous = counters
    media_rises = sum(rises.get(name, 0) for name in MEDIA_COUNTERS)
    if media_rises:
        raise_to("high" if media_rises > 1 else "elevated")
        reasons.append(
            {
                "key": "media_errors_growing",
                "count": sum(growth.get(name, 0) for name in MEDIA_COUNTERS),
            }
        )
    other = sum(
        growth.get(name, 0)
        for name in ("crc_errors", "io_errors", "zfs_read", "zfs_write", "zfs_cksum")
    )
    if other:
        raise_to("elevated")
        reasons.append({"key": "errors_growing", "count": other})

    wear_now = latest.get("wear_percent")
    wear_days: float | None = None
    wear_points = [(ts, w) for ts, w, _c in ordered if isinstance(w, (int, float))]
    if (
        isinstance(wear_now, (int, float))
        and len(wear_points) >= 3
        and wear_points[-1][0] - wear_points[0][0] >= MIN_WEAR_SPAN
    ):
        origin = wear_points[0][0]
        slope = _slope_per_day(
            [((ts - origin).total_seconds() / 86400, float(w)) for ts, w in wear_points]
        )
        if wear_now >= 100:
            wear_days = 0.0
        elif slope > 0:
            wear_days = min((100 - float(wear_now)) / slope, 3650.0)
    level = wear_level({"wear_percent": wear_now}, th)
    if level == "critical" or (wear_days is not None and wear_days <= 30):
        raise_to("high")
    elif level == "warning" or (wear_days is not None and wear_days <= 180):
        raise_to("elevated")
    if level is not None or (wear_days is not None and wear_days <= 180):
        reasons.append(
            {
                "key": "wear",
                "percent": (
                    round(float(wear_now), 1) if isinstance(wear_now, (int, float)) else None
                ),
                "days": round(wear_days) if wear_days is not None else None,
            }
        )
    return {
        "risk": risk,
        "reasons": reasons,
        "wear_days_left": round(wear_days) if wear_days is not None else None,
    }


# --- Recording -------------------------------------------------------------


def _event(
    disk: Disk,
    machine: Machine | None,
    now: datetime,
    kind: str,
    severity: str,
    detail: dict[str, Any] | None = None,
) -> DiskEvent:
    return DiskEvent(
        disk_id=disk.id,
        machine_id=machine.id if machine else None,
        machine_name=machine.name if machine else disk.machine_name,
        occurred_at=now,
        kind=kind,
        severity=severity,
        detail=detail or {},
    )


def _counters_of(device: dict[str, Any], zfs: dict[str, Any] | None) -> dict[str, int]:
    counters = {
        str(k): int(v)
        for k, v in (device.get("counters") or {}).items()
        if isinstance(v, int) and not isinstance(v, bool)
    }
    if zfs is not None:
        counters["zfs_read"] = int(zfs["read"])
        counters["zfs_write"] = int(zfs["write"])
        counters["zfs_cksum"] = int(zfs["cksum"])
    return counters


def changes(
    previous: dict[str, Any] | None,
    current: dict[str, Any],
    th: DiskThresholds,
) -> list[tuple[str, str, dict[str, Any]]]:
    """`(kind, severity, detail)` for what changed between two readings of
    one disk (`Disk.latest` shapes). No previous reading: only a failing
    S.M.A.R.T. or a ZFS fault is worth saying on first sight."""
    found: list[tuple[str, str, dict[str, Any]]] = []
    before = previous or {}
    if current.get("passed") is False and before.get("passed") is not False:
        found.append(("smart_failed", "critical", {}))
    elif previous and current.get("passed") is True and before.get("passed") is False:
        found.append(("smart_passed", "info", {}))

    zfs_now = current.get("zfs") or {}
    zfs_before = before.get("zfs") or {}
    state_now = str(zfs_now.get("state") or "")
    state_before = str(zfs_before.get("state") or "")
    if state_now and state_now != (state_before or "ONLINE"):
        severity = "warning" if state_now == "DEGRADED" else "critical"
        if state_now == "ONLINE":
            severity = "info"
        found.append(
            ("zfs_state", severity,
             {"pool": zfs_now.get("pool"), "from": state_before or None, "to": state_now})
        )
    if previous is None:
        return found

    counters_now = current.get("counters") or {}
    counters_before = before.get("counters") or {}
    zfs_changes: dict[str, tuple[int, int]] = {}
    for name, value in sorted(counters_now.items()):
        old = counters_before.get(name)
        severity_of = COUNTER_SEVERITY.get(name)
        if severity_of is None or not isinstance(old, int) or not isinstance(value, int):
            continue
        if value <= old:
            continue
        if name.startswith("zfs_"):
            zfs_changes[name] = (old, value)
            continue
        found.append(("counter", severity_of, {"counter": name, "from": old, "to": value}))
    if zfs_changes:
        found.append(
            (
                "zfs_errors",
                "warning",
                {
                    "pool": zfs_now.get("pool"),
                    **{name[4:]: value for name, (_old, value) in zfs_changes.items()},
                },
            )
        )

    temp_before = temperature_level(before, th) if before.get("temperature_c") is not None else None
    temp_now = temperature_level(current, th)
    if temp_now and _rises(temp_before, temp_now):
        found.append(
            ("temperature", temp_now,
             {"celsius": current.get("temperature_c"), "class": temperature_class(current)})
        )
    wear_before = wear_level(before, th)
    wear_now = wear_level(current, th)
    if wear_now and _rises(wear_before, wear_now):
        found.append(("wear", wear_now, {"percent": current.get("wear_percent")}))
    return found


async def _recent_samples(
    db: AsyncSession, disk_id: uuid.UUID, now: datetime
) -> list[tuple[datetime, float | None, dict[str, int] | None]]:
    rows = (
        await db.execute(
            select(DiskSample.sampled_at, DiskSample.wear_percent, DiskSample.counters)
            .where(
                DiskSample.disk_id == disk_id,
                DiskSample.sampled_at >= now - PREDICTION_WINDOW,
            )
            .order_by(DiskSample.sampled_at)
        )
    ).all()
    return [(row[0], row[1], row[2]) for row in rows]


def _as_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def record(
    db: AsyncSession,
    machine: Machine,
    th: DiskThresholds,
    now: datetime | None = None,
) -> list[DiskEvent]:
    """Take `machine.smart_devices` (and `machine.zfs_pools`) into the disk
    history: disks, samples, events, predictions. Returns the new events;
    the caller commits. A machine without S.M.A.R.T. data (a VM, no
    smartctl) is left alone."""
    devices = machine.smart_devices
    if devices is None:
        return []
    now = now or datetime.now(UTC)
    new_events: list[DiskEvent] = []
    annotated: list[dict[str, Any]] = []
    seen: set[uuid.UUID] = set()

    for device in devices:
        entry = dict(device)
        serial = str(device.get("serial") or "").strip()
        model = str(device.get("model") or "").strip()
        if not serial:
            annotated.append(entry)
            continue
        disk = (
            await db.execute(select(Disk).where(Disk.model == model, Disk.serial == serial))
        ).scalar_one_or_none()
        zfs = zfs_membership(device, machine.zfs_pools)
        current = {
            key: value for key, value in device.items() if key not in ("counters",)
        }
        current["counters"] = _counters_of(device, zfs)
        current["zfs"] = zfs
        events: list[DiskEvent] = []
        if disk is None:
            disk = Disk(id=uuid.uuid7(), model=model, serial=serial, first_seen_at=now)
            db.add(disk)
            events.append(_event(disk, machine, now, "first_seen", "info",
                                 {"device": device.get("device")}))
            previous = None
        else:
            previous = disk.latest
            if disk.machine_id is not None and disk.machine_id != machine.id:
                events.append(
                    _event(disk, machine, now, "moved", "info",
                           {"from_machine": disk.machine_name, "to_machine": machine.name})
                )
            elif (previous or {}).get("missing"):
                events.append(_event(disk, machine, now, "back", "info", {}))
        for kind, severity, detail in changes(previous, current, th):
            events.append(_event(disk, machine, now, kind, severity, detail))

        disk.kind = str(device.get("type") or "") or None
        rpm = device.get("rotation_rpm")
        disk.rotation_rpm = int(rpm) if isinstance(rpm, (int, float)) and rpm else None
        capacity = device.get("capacity_bytes")
        disk.capacity_bytes = int(capacity) if isinstance(capacity, (int, float)) else None
        disk.firmware = str(device.get("firmware") or "") or None
        disk.machine_id = machine.id
        disk.machine_name = machine.name
        disk.device = str(device.get("device") or "") or None
        disk.last_seen_at = now
        disk.latest = current
        seen.add(disk.id)

        last_sample = (
            await db.execute(
                select(DiskSample.sampled_at, DiskSample.counters)
                .where(DiskSample.disk_id == disk.id)
                .order_by(DiskSample.sampled_at.desc())
                .limit(1)
            )
        ).first()
        last_at = _as_aware(last_sample[0]) if last_sample else None
        counters_changed = last_sample is None or (last_sample[1] or {}) != current["counters"]
        if last_at is None or now - last_at >= SAMPLE_EVERY or counters_changed:
            temp = device.get("temperature_c")
            hours = device.get("power_on_hours")
            wear = device.get("wear_percent")
            written = device.get("written_bytes")
            db.add(
                DiskSample(
                    disk_id=disk.id,
                    sampled_at=now,
                    temperature_c=float(temp) if isinstance(temp, (int, float)) else None,
                    power_on_hours=int(hours) if isinstance(hours, (int, float)) else None,
                    wear_percent=float(wear) if isinstance(wear, (int, float)) else None,
                    written_bytes=int(written) if isinstance(written, (int, float)) else None,
                    counters=current["counters"],
                )
            )
            await db.flush()
            disk.prediction = predict(await _recent_samples(db, disk.id, now), current, now, th)
        elif disk.prediction is None:
            disk.prediction = predict([], current, now, th)

        for event in events:
            db.add(event)
        disk.event_count = (disk.event_count or 0) + len(events)
        new_events += events
        entry["disk_id"] = str(disk.id)
        entry["prediction"] = disk.prediction
        entry["event_count"] = disk.event_count
        annotated.append(entry)

    # A disk this machine had and no longer shows: it dropped out (or was
    # pulled). Said once; "back" when it shows up again.
    if devices:
        query = select(Disk).where(Disk.machine_id == machine.id)
        if seen:
            query = query.where(Disk.id.not_in(seen))
        gone = (await db.execute(query)).scalars().all()
        for disk in gone:
            if (disk.latest or {}).get("missing"):
                continue
            disk.latest = {**(disk.latest or {}), "missing": True}
            event = _event(disk, machine, now, "missing", "warning",
                           {"device": disk.device})
            db.add(event)
            disk.event_count = (disk.event_count or 0) + 1
            new_events.append(event)

    machine.smart_devices = annotated
    return new_events


def event_text(event: DiskEvent, locale_code: str | None = None) -> str:
    """What `event` says, in `locale_code` (default language otherwise)."""
    locale = get_locale(locale_code or DEFAULT_LOCALE_CODE)
    detail = dict(event.detail or {})
    if event.kind == "counter":
        name = str(detail.get("counter") or "")
        detail["counter"] = translate(locale, f"disks.counter.{name}")
    params = {k: ("—" if v is None else v) for k, v in detail.items()}
    return translate(locale, f"disks.event.{event.kind}", **params)


# --- Reading, scoped to what an account may see ------------------------------


async def visible_disks_query(db: AsyncSession, user: User) -> Select[Disk]:
    """Disks whose machine `user` can see. A disk whose machine is gone is
    only listed for an account that sees every machine."""
    group_ids = await allowed_group_ids(db, user)
    query = select(Disk)
    if group_ids is not None:
        query = query.join(Machine, Machine.id == Disk.machine_id).where(
            Machine.group_id.in_(group_ids)
        )
    return query


async def visible_disk(db: AsyncSession, user: User, disk_id: uuid.UUID) -> Disk | None:
    query = await visible_disks_query(db, user)
    return (await db.execute(query.where(Disk.id == disk_id))).scalar_one_or_none()


async def samples_since(
    db: AsyncSession, disk_id: uuid.UUID, since: datetime
) -> list[DiskSample]:
    return list(
        (
            await db.execute(
                select(DiskSample)
                .where(DiskSample.disk_id == disk_id, DiskSample.sampled_at >= since)
                .order_by(DiskSample.sampled_at)
            )
        ).scalars().all()
    )


async def events_of(db: AsyncSession, disk_id: uuid.UUID, limit: int = 500) -> list[DiskEvent]:
    return list(
        (
            await db.execute(
                select(DiskEvent)
                .where(DiskEvent.disk_id == disk_id)
                .order_by(DiskEvent.occurred_at.desc(), DiskEvent.id.desc())
                .limit(limit)
            )
        ).scalars().all()
    )


def disk_summary(disk: Disk) -> dict[str, Any]:
    """The REST API's (and the list's) shape of one disk."""
    latest = disk.latest or {}
    return {
        "id": str(disk.id),
        "model": disk.model,
        "serial": disk.serial,
        "kind": disk.kind,
        "temperature_class": temperature_class(latest) if latest else None,
        "rotation_rpm": disk.rotation_rpm,
        "capacity_bytes": disk.capacity_bytes,
        "firmware": disk.firmware,
        "machine_id": str(disk.machine_id) if disk.machine_id else None,
        "machine_name": disk.machine_name,
        "device": disk.device,
        "missing": bool(latest.get("missing")),
        "first_seen_at": disk.first_seen_at.isoformat() if disk.first_seen_at else None,
        "last_seen_at": disk.last_seen_at.isoformat() if disk.last_seen_at else None,
        "smart_passed": latest.get("passed"),
        "temperature_c": latest.get("temperature_c"),
        "power_on_hours": latest.get("power_on_hours"),
        "power_cycles": latest.get("power_cycles"),
        "wear_percent": latest.get("wear_percent"),
        "written_bytes": latest.get("written_bytes"),
        "read_bytes": latest.get("read_bytes"),
        "counters": latest.get("counters") or {},
        "zfs": latest.get("zfs"),
        "prediction": disk.prediction,
        "event_count": disk.event_count,
    }


def event_dict(event: DiskEvent, locale_code: str | None = None) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "occurred_at": event.occurred_at.isoformat(),
        "kind": event.kind,
        "severity": event.severity,
        "machine_id": str(event.machine_id) if event.machine_id else None,
        "machine_name": event.machine_name,
        "detail": event.detail or {},
        "text": event_text(event, locale_code),
    }


_LATEST_DEFAULTS: dict[str, Any] = {
    "device": None,
    "passed": None,
    "power_on_hours": None,
    "power_cycles": None,
    "temperature_c": None,
    "wear_percent": None,
    "written_bytes": None,
    "read_bytes": None,
    "counters": {},
    "zfs": None,
    "attributes": [],
    "missing": False,
}
_PREDICTION_DEFAULTS: dict[str, Any] = {"risk": "low", "reasons": [], "wear_days_left": None}


def latest_view(disk: Disk) -> dict[str, Any]:
    """`Disk.latest` with every key a page reads (older or partial
    readings lack some)."""
    return {**_LATEST_DEFAULTS, **(disk.latest or {})}


def prediction_view(disk: Disk) -> dict[str, Any]:
    return {**_PREDICTION_DEFAULTS, **(disk.prediction or {})}
