"""Autoheal: restart a container whose health check reports unhealthy.

Docker itself never restarts an unhealthy container (its restart policy
only acts when the container exits), so this is opt-in per container
(the container's page, `DockerContainerSetting.autoheal`). Each
monitoring sample lists every container's health; for an unhealthy one
with autoheal on, debcontrol queues `docker restart` (the same task as the
Restart button) and records it.

Limits, so a container that never gets well isn't restarted forever:
- at most `autoheal_max_per_hour` restarts in any hour (3 by default);
  after that debcontrol gives up, sends one "autoheal gave up"
  notification and leaves the container alone until the oldest of those
  restarts is an hour old;
- no restart within `MIN_GAP` of the previous one (a restarted container
  needs time for its health check to pass);
- debcontrol's own containers are never restarted.

Every restart and every give-up is audited (actor "autoheal (automatic)")
and sent as the `docker.container.autoheal` notification event.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.db.models.audit_log import AuditOutcome
from app.db.models.docker import DockerContainerSetting
from app.db.models.machine import Machine
from app.db.models.notification_rule import NotificationEventType
from app.services import docker_jobs
from app.services.notifications import notify

ACTOR = "autoheal (automatic)"
WINDOW = timedelta(hours=1)
MIN_GAP = timedelta(minutes=3)
MIN_PER_HOUR = 1
MAX_PER_HOUR = 10
DEFAULT_PER_HOUR = 3


@dataclass
class AutohealOutcome:
    restarted: list[str] = field(default_factory=list)
    gave_up: list[str] = field(default_factory=list)


def _times(raw: list[str] | None, now: datetime) -> list[datetime]:
    """The restarts in the last `WINDOW`, oldest first."""
    kept: list[datetime] = []
    for value in raw or []:
        with contextlib.suppress(TypeError, ValueError):
            when = datetime.fromisoformat(str(value))
            when = when if when.tzinfo else when.replace(tzinfo=UTC)
            if now - when < WINDOW:
                kept.append(when)
    return sorted(kept)


def decide(setting: DockerContainerSetting, now: datetime) -> str:
    """"restart", "give_up" or "wait" for an unhealthy container."""
    recent = _times(setting.autoheal_restarts, now)
    if recent and now - recent[-1] < MIN_GAP:
        return "wait"
    limit = setting.autoheal_max_per_hour or DEFAULT_PER_HOUR
    if len(recent) >= limit:
        return "wait" if setting.autoheal_gave_up_at is not None else "give_up"
    return "restart"


def unhealthy_containers(containers: list[dict[str, Any]] | None) -> list[str]:
    return [
        str(c["name"])
        for c in containers or []
        if isinstance(c, dict)
        and c.get("name")
        and c.get("health") == "unhealthy"
        and c.get("state") == "running"
    ]


async def apply(db: AsyncSession, machine: Machine) -> AutohealOutcome:
    """Act on the machine's latest sample (`Machine.docker_containers`).
    Called after the sample is committed; reads nothing from the database
    unless a container is unhealthy."""
    outcome = AutohealOutcome()
    unhealthy = set(unhealthy_containers(machine.docker_containers))
    if not unhealthy:
        return outcome
    rows = (
        (
            await db.execute(
                select(DockerContainerSetting).where(
                    DockerContainerSetting.machine_id == machine.id,
                    DockerContainerSetting.autoheal.is_(True),
                    DockerContainerSetting.name.in_(unhealthy),
                )
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        return outcome
    now = datetime.now(UTC)
    protected = await docker_jobs.protected_project(db, machine)
    to_restart: list[DockerContainerSetting] = []
    for setting in rows:
        if protected and docker_jobs.container_project(machine, setting.name) == protected:
            continue
        decision = decide(setting, now)
        if decision == "restart":
            recent = _times(setting.autoheal_restarts, now)
            setting.autoheal_restarts = [w.isoformat() for w in [*recent, now]]
            setting.autoheal_gave_up_at = None
            to_restart.append(setting)
            outcome.restarted.append(setting.name)
        elif decision == "give_up":
            setting.autoheal_gave_up_at = now
            outcome.gave_up.append(setting.name)
    if not (outcome.restarted or outcome.gave_up):
        return outcome
    await db.commit()

    if outcome.restarted:
        # Imported here: app.tasks.jobs imports this module.
        from app.tasks import jobs as tasks

        tasks.run_container_action_task.delay(
            str(machine.id), action="restart", containers=outcome.restarted
        )
    details: list[str] = []
    for setting in to_restart:
        count = len(setting.autoheal_restarts or [])
        details.append(
            f"{setting.name}: restarted ({count} of {setting.autoheal_max_per_hour} this hour)"
        )
    details.extend(
        f"{name}: still unhealthy after the restarts allowed this hour; gave up"
        for name in outcome.gave_up
    )
    for name in outcome.restarted:
        await _audit(db, machine, name, "restart")
    for name in outcome.gave_up:
        await _audit(db, machine, name, "give_up")
    await notify(
        db,
        NotificationEventType.DOCKER_CONTAINER_AUTOHEAL,
        machine=machine,
        context={
            "containers": ", ".join([*outcome.restarted, *outcome.gave_up]),
            "details": "\n".join(details),
        },
    )
    return outcome


async def _audit(db: AsyncSession, machine: Machine, name: str, what: str) -> None:
    restarted = what == "restart"
    await log_event(
        db,
        actor=ACTOR,
        action="machine.docker.container.autoheal",
        summary=(
            f'Autoheal restarted the unhealthy container "{name}" on "{machine.name}"'
            if restarted
            else f'Autoheal gave up on the unhealthy container "{name}" on "{machine.name}"'
        ),
        outcome=AuditOutcome.SUCCESS if restarted else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"container": name, "result": "restarted" if restarted else "gave_up"},
    )


async def save(
    db: AsyncSession,
    machine_id: Any,
    name: str,
    *,
    enabled: bool,
    max_per_hour: int,
    actor: str,
) -> DockerContainerSetting:
    """Turn autoheal on or off for one container (keeps its other settings)."""
    setting = (
        await db.execute(
            select(DockerContainerSetting).where(
                DockerContainerSetting.machine_id == machine_id,
                DockerContainerSetting.name == name,
            )
        )
    ).scalar_one_or_none()
    if setting is None:
        setting = DockerContainerSetting(
            machine_id=machine_id,
            name=name,
            auto_update=False,
            vulnerability_gate="off",
            update_policy="any",
        )
        db.add(setting)
    setting.autoheal = enabled
    setting.autoheal_max_per_hour = max(MIN_PER_HOUR, min(MAX_PER_HOUR, max_per_hour))
    if not enabled:
        setting.autoheal_restarts = None
        setting.autoheal_gave_up_at = None
    setting.updated_by = actor
    setting.updated_at = datetime.now(UTC)
    await db.flush()
    return setting
