"""What the Docker tab needs from the database, besides the job runner
itself (`app.tasks.docker_jobs`): the jobs of a machine, a container's
settings, and which containers debcontrol must not replace because it
runs in them.

**debcontrol's own containers.** On the machine debcontrol itself runs
on (`app.services.self_host`), the Compose project its containers belong
to is protected: updating, rolling back, recreating or taking down any
container of that project, and restoring onto its volumes, would stop
debcontrol in the middle of the job — with its database possibly
half-restored. Those are refused with a pointer to Settings → Update
(the host-side self-update, see `app.services.app_update`). Starting,
stopping and restarting a single container stay possible, as before.
"""

from __future__ import annotations

import socket
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.docker import (
    DockerContainerSetting,
    DockerJob,
    DockerJobStatus,
    VulnerabilityGate,
)
from app.db.models.machine import Machine
from app.services import self_host

# How long finished jobs are kept.
KEEP_DAYS = 90
# The tail of a job's output that is stored.
MAX_OUTPUT_CHARS = 200_000
# Jobs listed on a page.
LIST_LIMIT = 100

ACTIVE_STATUSES = (DockerJobStatus.PENDING.value, DockerJobStatus.RUNNING.value)
FINAL_STATUSES = tuple(s.value for s in DockerJobStatus if s.value not in ACTIVE_STATUSES)

# Compose's default project name in debcontrol's own docker-compose.yml.
_DEFAULT_OWN_PROJECT = "debcontrol"


PROTECTED_MESSAGE = (
    "debcontrol itself runs in this Compose project, so it is not changed from here: "
    "update debcontrol from Settings → Update instead."
)


class ProtectedError(Exception):
    """The action would replace a container debcontrol runs in."""


def truncate_output(text: str) -> str:
    return text if len(text) <= MAX_OUTPUT_CHARS else text[-MAX_OUTPUT_CHARS:]


def own_project(machine: Machine, own: self_host.SelfHost) -> str | None:
    """The Compose project debcontrol's containers belong to on `machine`,
    when `machine` is the one debcontrol runs on; else None."""
    if machine.id not in own.hosts:
        return None
    containers = [c for c in machine.docker_containers or [] if isinstance(c, dict)]
    hostname = socket.gethostname().lower()
    for container in containers:
        container_id = str(container.get("id") or "").lower()
        if len(hostname) >= 12 and container_id.startswith(hostname):
            return str(container.get("compose_project") or "") or None
    # A hostname set in the compose file hides the id; Compose's default
    # project name for debcontrol is the next best answer.
    if any(c.get("compose_project") == _DEFAULT_OWN_PROJECT for c in containers):
        return _DEFAULT_OWN_PROJECT
    return None


async def protected_project(db: AsyncSession, machine: Machine) -> str | None:
    return own_project(machine, await self_host.find(db))


def container_project(machine: Machine, name: str) -> str:
    for container in machine.docker_containers or []:
        if isinstance(container, dict) and container.get("name") == name:
            return str(container.get("compose_project") or "")
    return ""


async def check_container(db: AsyncSession, machine: Machine, name: str) -> None:
    """Raise `ProtectedError` when `name` is one of debcontrol's own."""
    project = await protected_project(db, machine)
    if project and container_project(machine, name) == project:
        raise ProtectedError(name)


async def check_project(db: AsyncSession, machine: Machine, project: str) -> None:
    protected = await protected_project(db, machine)
    if protected and project == protected:
        raise ProtectedError(project)


async def check_volumes(db: AsyncSession, machine: Machine, volumes: list[str]) -> None:
    """Compose names a project's volumes `<project>_<volume>`."""
    protected = await protected_project(db, machine)
    if not protected:
        return
    for volume in volumes:
        if volume.startswith(protected + "_"):
            raise ProtectedError(volume)


# --- Container settings ------------------------------------------------------


async def container_settings(
    db: AsyncSession, machine_id: uuid.UUID
) -> dict[str, DockerContainerSetting]:
    rows = await db.execute(
        select(DockerContainerSetting).where(DockerContainerSetting.machine_id == machine_id)
    )
    return {row.name: row for row in rows.scalars().all()}


async def save_container_setting(
    db: AsyncSession,
    machine_id: uuid.UUID,
    name: str,
    *,
    auto_update: bool,
    gate: str,
    actor: str | None,
) -> DockerContainerSetting:
    result = await db.execute(
        select(DockerContainerSetting).where(
            DockerContainerSetting.machine_id == machine_id,
            DockerContainerSetting.name == name,
        )
    )
    setting = result.scalar_one_or_none()
    if setting is None:
        setting = DockerContainerSetting(machine_id=machine_id, name=name)
        db.add(setting)
    setting.auto_update = auto_update
    setting.vulnerability_gate = gate if gate in VulnerabilityGate else VulnerabilityGate.OFF
    setting.updated_by = actor
    setting.updated_at = datetime.now(UTC)
    await db.flush()
    return setting


# --- Jobs -------------------------------------------------------------------


async def list_jobs(
    db: AsyncSession,
    machine_id: uuid.UUID,
    *,
    limit: int = LIST_LIMIT,
    kinds: tuple[str, ...] | None = None,
    target: str | None = None,
    ref_id: uuid.UUID | None = None,
) -> list[DockerJob]:
    query = select(DockerJob).where(DockerJob.machine_id == machine_id)
    if kinds:
        query = query.where(DockerJob.kind.in_(kinds))
    if target is not None:
        query = query.where(DockerJob.target == target)
    if ref_id is not None:
        query = query.where(DockerJob.ref_id == ref_id)
    result = await db.execute(query.order_by(DockerJob.created_at.desc()).limit(limit))
    return list(result.scalars().all())


async def get_job(db: AsyncSession, machine_id: uuid.UUID, job_id: uuid.UUID) -> DockerJob | None:
    job = await db.get(DockerJob, job_id, populate_existing=True)
    return job if job is not None and job.machine_id == machine_id else None


async def active_job(
    db: AsyncSession, machine_id: uuid.UUID, kind: str, target: str
) -> DockerJob | None:
    """A pending or running job of this kind on this target, if any — the
    same thing is never queued twice."""
    result = await db.execute(
        select(DockerJob)
        .where(
            DockerJob.machine_id == machine_id,
            DockerJob.kind == kind,
            DockerJob.target == target,
            DockerJob.status.in_(ACTIVE_STATUSES),
        )
        .limit(1)
    )
    return result.scalar_one_or_none()


async def has_active_jobs(db: AsyncSession, machine_id: uuid.UUID) -> bool:
    result = await db.execute(
        select(DockerJob.id)
        .where(DockerJob.machine_id == machine_id, DockerJob.status.in_(ACTIVE_STATUSES))
        .limit(1)
    )
    return result.first() is not None


def last_update(jobs: list[DockerJob], name: str) -> DockerJob | None:
    """The newest successful update or rollback of container `name` — what
    "Roll back" goes back from."""
    for job in jobs:
        if (
            job.target == name
            and job.kind in ("container_update", "container_rollback")
            and job.status == DockerJobStatus.SUCCEEDED
        ):
            return job
    return None


def rollback_image(job: DockerJob | None) -> str | None:
    """The image a rollback after `job` would go back to."""
    if job is None:
        return None
    result: dict[str, Any] = job.result or {}
    previous = result.get("previous_image_id")
    return str(previous) if previous else None


async def purge_old(db: AsyncSession) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=KEEP_DAYS)
    result = await db.execute(
        delete(DockerJob).where(
            DockerJob.created_at < cutoff, DockerJob.status.in_(FINAL_STATUSES)
        )
    )
    await db.commit()
    return int(getattr(result, "rowcount", 0) or 0)
