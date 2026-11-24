"""The data behind the Dashboard's widgets (`dashboard_layout.OPTIONAL`):
machines behaving unusually, the busiest machines, the worst internet
latency, and the web interfaces of the containers. Shared by the Dashboard
(`app/web/routes/dashboard.py`, only for the widgets an account shows) and
`GET /api/v1/dashboard/widgets`.

Every function takes the groups a restricted account may see
(`access_scope.allowed_group_ids`, None = the whole fleet), and only what
is already stored is read — no SSH.
"""

from __future__ import annotations

import uuid
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_health_snooze import MachineHealthSnooze
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.services import container_links, machine_baseline, machine_health

# Readings older than this are not "now" any more.
FRESH = timedelta(minutes=15)
TOP = 5
MAX_UNUSUAL = 10
MAX_LINKS = 60


def _scoped(query: Any, group_ids: AbstractSet[uuid.UUID] | None) -> Any:
    query = query.where(Machine.is_active)
    if group_ids is not None:
        query = query.where(Machine.group_id.in_(group_ids))
    return query


async def unusual_machines(
    db: AsyncSession, group_ids: AbstractSet[uuid.UUID] | None = None, limit: int = MAX_UNUSUAL
) -> list[tuple[Machine, list[machine_health.Finding]]]:
    """Machines with an unusual-behavior finding that is not snoozed,
    the ones with a warning first."""
    machines = list(
        (
            await db.execute(
                _scoped(select(Machine), group_ids).where(
                    Machine.health_status.in_(("info", "warning", "critical"))
                )
            )
        )
        .scalars()
        .all()
    )
    candidates = [
        m for m in machines
        if any(f.key in machine_health.UNUSUAL_KEYS for f in machine_health.stored_findings(m))
    ]
    if not candidates:
        return []
    snoozes: dict[uuid.UUID, list[MachineHealthSnooze]] = {}
    for row in (
        await db.execute(
            select(MachineHealthSnooze).where(
                MachineHealthSnooze.machine_id.in_([m.id for m in candidates])
            )
        )
    ).scalars():
        snoozes.setdefault(row.machine_id, []).append(row)
    found: list[tuple[Machine, list[machine_health.Finding]]] = []
    for machine in candidates:
        view = machine_health.build_view(machine, snoozes.get(machine.id, []))
        unusual = [f for f in view.active if f.key in machine_health.UNUSUAL_KEYS]
        if unusual:
            found.append((machine, unusual))
    found.sort(
        key=lambda item: (
            -max(machine_health.rank(f.severity) for f in item[1]),
            item[0].name.lower(),
        )
    )
    return found[:limit]


@dataclass(frozen=True)
class Reading:
    machine_id: uuid.UUID
    name: str
    cpu_percent: float | None
    memory_percent: float | None
    load1: float | None
    cpu_cores: int | None
    internet_latency_ms: float | None
    internet_loss_percent: float | None
    gateway_latency_ms: float | None

    def as_dict(self) -> dict[str, Any]:
        def r(value: float | None) -> float | None:
            return None if value is None else round(value, 1)

        return {
            "id": str(self.machine_id),
            "name": self.name,
            "cpu_percent": r(self.cpu_percent),
            "memory_percent": r(self.memory_percent),
            "load1": r(self.load1),
            "cpu_cores": self.cpu_cores,
            "internet_latency_ms": r(self.internet_latency_ms),
            "internet_loss_percent": r(self.internet_loss_percent),
            "gateway_latency_ms": r(self.gateway_latency_ms),
        }


async def latest_readings(
    db: AsyncSession, group_ids: AbstractSet[uuid.UUID] | None = None
) -> list[Reading]:
    """Each visible machine's newest sample of the last `FRESH` minutes —
    only the few columns the widgets show, in one windowed query."""
    since = datetime.now(UTC) - FRESH
    ranked = (
        select(
            MachineMonitoringSample.machine_id,
            MachineMonitoringSample.cpu_percent,
            MachineMonitoringSample.ram_used_bytes,
            MachineMonitoringSample.ram_total_bytes,
            MachineMonitoringSample.load1,
            MachineMonitoringSample.internet_latency_ms,
            MachineMonitoringSample.internet_loss_percent,
            MachineMonitoringSample.gateway_latency_ms,
            func.row_number()
            .over(
                partition_by=MachineMonitoringSample.machine_id,
                order_by=MachineMonitoringSample.sampled_at.desc(),
            )
            .label("rn"),
        )
        .where(MachineMonitoringSample.sampled_at >= since)
        .subquery()
    )
    query = _scoped(
        select(ranked, Machine.name, Machine.cpu_cores).join(
            Machine, Machine.id == ranked.c.machine_id
        ),
        group_ids,
    ).where(ranked.c.rn == 1)
    return [
        Reading(
            machine_id=row.machine_id,
            name=row.name,
            cpu_percent=row.cpu_percent,
            memory_percent=machine_baseline.memory_percent(row.ram_used_bytes, row.ram_total_bytes),
            load1=row.load1,
            cpu_cores=row.cpu_cores,
            internet_latency_ms=row.internet_latency_ms,
            internet_loss_percent=row.internet_loss_percent,
            gateway_latency_ms=row.gateway_latency_ms,
        )
        for row in (await db.execute(query)).all()
    ]


def _top(readings: list[Reading], attribute: str, limit: int = TOP) -> list[Reading]:
    known = [r for r in readings if getattr(r, attribute) is not None]
    return sorted(known, key=lambda r: (-getattr(r, attribute), r.name.lower()))[:limit]


@dataclass(frozen=True)
class TopMachines:
    cpu: list[Reading]
    memory: list[Reading]

    def as_dict(self) -> dict[str, Any]:
        return {"cpu": [r.as_dict() for r in self.cpu],
                "memory": [r.as_dict() for r in self.memory]}


def top_machines(readings: list[Reading], limit: int = TOP) -> TopMachines:
    return TopMachines(cpu=_top(readings, "cpu_percent", limit),
                       memory=_top(readings, "memory_percent", limit))


@dataclass(frozen=True)
class Latency:
    worst: list[Reading]
    measured: int
    average_ms: float | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "worst": [r.as_dict() for r in self.worst],
            "measured": self.measured,
            "average_ms": None if self.average_ms is None else round(self.average_ms, 1),
        }


def latency(readings: list[Reading], limit: int = TOP) -> Latency:
    """The worst internet round trips (packet loss first) and the average."""
    measured = [r for r in readings if r.internet_latency_ms is not None]
    worst = sorted(
        measured,
        key=lambda r: (-(r.internet_loss_percent or 0), -(r.internet_latency_ms or 0),
                       r.name.lower()),
    )[:limit]
    average = (
        sum(r.internet_latency_ms or 0 for r in measured) / len(measured) if measured else None
    )
    return Latency(worst=worst, measured=len(measured), average_ms=average)


@dataclass(frozen=True)
class AppLink:
    machine_id: uuid.UUID
    machine_name: str
    container: str
    stack: str
    url: str
    label: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "machine_id": str(self.machine_id),
            "machine_name": self.machine_name,
            "container": self.container,
            "stack": self.stack,
            "url": self.url,
            "label": self.label,
        }


async def app_links(
    db: AsyncSession, group_ids: AbstractSet[uuid.UUID] | None = None, limit: int = MAX_LINKS
) -> tuple[list[AppLink], int]:
    """The best web link of every running container (what the Docker tab
    and the map show, `container_links`), by stack, and how many there are
    in all."""
    machines = (
        await db.execute(
            _scoped(select(Machine), group_ids)
            .where(Machine.docker_status == "ok")
            .order_by(Machine.name)
        )
    ).scalars()
    links: list[AppLink] = []
    for machine in machines:
        for row in machine.docker_containers or []:
            if not isinstance(row, dict) or row.get("state") != "running" or not row.get("name"):
                continue
            found = container_links.web_links(row, machine.ip_address)
            if found:
                links.append(
                    AppLink(
                        machine_id=machine.id,
                        machine_name=machine.name,
                        container=str(row["name"]),
                        stack=str(row.get("compose_project") or ""),
                        url=found[0].url,
                        label=found[0].label,
                    )
                )
    links.sort(key=lambda link: ((link.stack or link.container).lower(), link.container.lower(),
                                 link.machine_name.lower()))
    return links[:limit], len(links)
