"""The Fleet page (`/fleet`) and its REST twin: every visible machine as one
compact row of its latest readings — status, CPU, RAM, fullest disk,
hottest sensor, load, containers, pending updates — built from each machine's single most
recent monitoring sample (one batched window query, see
`latest_monitoring_samples`) plus a few columns already on `Machine`.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.db.models.machine import Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.services.disk_forecast import soonest_full_days

Level = Literal["ok", "warn", "danger", "unknown"]

# Percent thresholds for coloring (warn, danger) — the same idea as a
# traffic light, not an alerting rule (those are Notifications).
_PERCENT_LEVELS = (75.0, 90.0)
_TEMP_LEVELS = (70.0, 85.0)


async def latest_monitoring_samples(
    db: AsyncSession, machine_ids: list[uuid.UUID]
) -> dict[uuid.UUID, MachineMonitoringSample]:
    """The single most recent monitoring sample for each machine in
    `machine_ids` — one `row_number() OVER (PARTITION BY machine_id ...)`
    query filtered to rank 1, not one query per machine."""
    if not machine_ids:
        return {}
    ranked = (
        select(
            MachineMonitoringSample,
            func.row_number()
            .over(
                partition_by=MachineMonitoringSample.machine_id,
                order_by=MachineMonitoringSample.sampled_at.desc(),
            )
            .label("rn"),
        )
        .where(MachineMonitoringSample.machine_id.in_(machine_ids))
        .subquery()
    )
    latest = aliased(MachineMonitoringSample, ranked)
    result = await db.execute(select(latest).where(ranked.c.rn == 1))
    return {sample.machine_id: sample for sample in result.scalars().all()}


def level_for(value: float | None, levels: tuple[float, float] = _PERCENT_LEVELS) -> Level:
    if value is None:
        return "unknown"
    if value >= levels[1]:
        return "danger"
    if value >= levels[0]:
        return "warn"
    return "ok"


@dataclass
class FleetRow:
    machine_id: str
    name: str
    os_id: str | None
    is_reachable: bool | None
    is_physical: bool | None
    cpu_percent: float | None
    ram_percent: float | None
    disk_percent: float | None
    disk_mount: str | None
    temperature_c: float | None
    load1: float | None
    cpu_cores: int | None
    uptime_seconds: int | None
    containers_running: int | None
    containers_total: int | None
    containers_problem: int | None
    disk_full_days: float | None
    upgradable_count: int | None
    security_upgradable_count: int | None
    reboot_required: bool | None
    sampled_at: datetime | None
    # The worst of the colored metrics — drives the card's accent.
    level: Level
    # Counted by the page's "needs attention" tile: a danger-level reading,
    # or something an operator has to act on even while every gauge is
    # green — pending security updates, a pending reboot.
    needs_attention: bool

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["sampled_at"] = self.sampled_at.isoformat() if self.sampled_at else None
        return data


def build_fleet_row(machine: Machine, sample: MachineMonitoringSample | None) -> FleetRow:
    ram_percent = (
        sample.ram_used_bytes / sample.ram_total_bytes * 100
        if sample and sample.ram_used_bytes is not None and sample.ram_total_bytes
        else None
    )
    disk_percent: float | None = None
    disk_mount: str | None = None
    for fs in (sample.filesystems or []) if sample else []:
        percent = fs.get("use_percent")
        if isinstance(percent, (int, float)) and (disk_percent is None or percent > disk_percent):
            disk_percent, disk_mount = float(percent), fs.get("mount")
    temps = [
        float(t["celsius"])
        for t in ((sample.sensor_temps or []) if sample else [])
        if isinstance(t, dict) and isinstance(t.get("celsius"), (int, float))
    ]
    containers = machine.docker_containers if machine.docker_status == "ok" else None
    containers_running = containers_total = containers_problem = None
    if containers is not None:
        containers_total = len(containers)
        containers_running = sum(1 for c in containers if c.get("state") == "running")
        containers_problem = sum(
            1
            for c in containers
            if c.get("health") == "unhealthy" or c.get("state") == "restarting"
        )

    temperature = max(temps) if temps else None
    levels = [
        level_for(sample.cpu_percent if sample else None),
        level_for(ram_percent),
        level_for(disk_percent),
        level_for(temperature, _TEMP_LEVELS),
    ]
    level: Level = "unknown"
    if machine.is_reachable is False or containers_problem or "danger" in levels:
        level = "danger"
    elif "warn" in levels or machine.security_upgradable_count or machine.reboot_required:
        level = "warn"
    elif "ok" in levels:
        level = "ok"
    needs_attention = bool(
        level == "danger" or machine.security_upgradable_count or machine.reboot_required
    )

    return FleetRow(
        machine_id=str(machine.id),
        name=machine.name,
        os_id=machine.os_id,
        is_reachable=machine.is_reachable,
        is_physical=machine.is_physical,
        cpu_percent=sample.cpu_percent if sample else None,
        ram_percent=ram_percent,
        disk_percent=disk_percent,
        disk_mount=disk_mount,
        temperature_c=temperature,
        load1=sample.load1 if sample else None,
        cpu_cores=machine.cpu_cores,
        uptime_seconds=machine.uptime_seconds,
        containers_running=containers_running,
        containers_total=containers_total,
        containers_problem=containers_problem,
        disk_full_days=soonest_full_days(machine.disk_forecast),
        upgradable_count=machine.upgradable_count,
        security_upgradable_count=machine.security_upgradable_count,
        reboot_required=machine.reboot_required,
        sampled_at=sample.sampled_at if sample else None,
        level=level,
        needs_attention=needs_attention,
    )


async def build_fleet_overview(db: AsyncSession, machines: list[Machine]) -> list[FleetRow]:
    samples = await latest_monitoring_samples(db, [m.id for m in machines])
    return [build_fleet_row(m, samples.get(m.id)) for m in machines]
