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

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.docker import (
    DockerContainerSetting,
    DockerJob,
    DockerJobKind,
    DockerJobStatus,
    UpdatePolicy,
    VulnerabilityGate,
)
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.services import self_host
from app.ssh.docker_cli import is_image_id_valid, is_image_ref_valid

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
    update_policy: str | None = None,
) -> DockerContainerSetting:
    """`update_policy` None keeps the stored one (a caller that doesn't
    know about it, e.g. an older API client)."""
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
    if update_policy is not None:
        setting.update_policy = update_policy if update_policy in UpdatePolicy else "any"
    elif setting.update_policy is None:
        setting.update_policy = UpdatePolicy.ANY.value
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


def output_hidden(job: DockerJob, user: User) -> bool:
    """A stack check's output shows the compose file's changes (and a Git
    repository's): only for whoever may read the compose file itself."""
    return job.kind == DockerJobKind.STACK_CHECK and not user.has_permission(
        Permission.ACTION_TERMINAL
    )


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
    previous = str(result.get("previous_image_id") or "")
    # Only a full image id can be gone back to (anything else came from a
    # broken or hostile answer and would be refused anyway).
    return previous if is_image_id_valid(previous) else None


def rollback_ref(job: DockerJob | None) -> str | None:
    """The tag a rollback after `job` goes back to, when `job` moved the
    container to another one (the update policy's tag bump)."""
    if job is None:
        return None
    previous = str((job.result or {}).get("previous_ref") or "")
    if not previous or "@" in previous or not is_image_ref_valid(previous):
        return None
    return previous


async def purge_old(db: AsyncSession) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=KEEP_DAYS)
    result = await db.execute(
        delete(DockerJob).where(
            DockerJob.created_at < cutoff, DockerJob.status.in_(FINAL_STATUSES)
        )
    )
    await db.commit()
    return int(getattr(result, "rowcount", 0) or 0)


# --- Cancelling ----------------------------------------------------------------

# Running jobs that stop cleanly when signalled: nothing they do is left
# half-done in a way that breaks what runs (a scan, a pull, restic, which
# keeps its repository consistent when interrupted). A container update
# only while it pulls, before anything is recreated; a stack deploy or a
# start/stop of a stack never once it runs. A restore can be stopped too —
# its volumes are then left partly restored, which the page warns about.
CANCELLABLE_RUNNING_KINDS = frozenset(
    {
        DockerJobKind.IMAGE_SCAN.value,
        DockerJobKind.PRUNE.value,
        DockerJobKind.STACK_CHECK.value,
        DockerJobKind.BACKUP_RUN.value,
        DockerJobKind.BACKUP_CHECK.value,
        DockerJobKind.BACKUP_FORGET.value,
        DockerJobKind.BACKUP_RESTORE.value,
        DockerJobKind.BACKUP_VERIFY.value,
    }
)
# (kind, phase) pairs that may be stopped although the kind as a whole can't.
_CANCELLABLE_PHASES = frozenset({(DockerJobKind.CONTAINER_UPDATE.value, "pull")})


def cancel_permission(kind: str) -> Permission:
    """The permission that cancels a job: the one that starts that kind."""
    if kind == DockerJobKind.STACK_ACTION:
        return Permission.ACTION_POWER
    if kind in (
        DockerJobKind.STACK_CHECK,
        DockerJobKind.STACK_DEPLOY,
        DockerJobKind.BACKUP_RESTORE,
    ):
        return Permission.ACTION_TERMINAL
    return Permission.ACTION_UPDATES


def phase_cancellable(kind: str, phase: str | None) -> bool:
    """Whether a running job of `kind` in `phase` may be signalled to stop."""
    return kind in CANCELLABLE_RUNNING_KINDS or (kind, phase or "") in _CANCELLABLE_PHASES


def can_cancel(job: DockerJob) -> bool:
    """Whether the job can be cancelled now: any job still waiting, a
    running one only in a phase that stops cleanly, and only once."""
    if job.status == DockerJobStatus.PENDING:
        return True
    if job.status != DockerJobStatus.RUNNING or job.cancel_requested_at is not None:
        return False
    return phase_cancellable(job.kind, str((job.result or {}).get("phase") or ""))


def may_cancel(job: DockerJob, user: User) -> bool:
    return can_cancel(job) and user.has_permission(cancel_permission(job.kind))


async def request_cancel(db: AsyncSession, job: DockerJob, actor: str) -> str | None:
    """Cancel a waiting job at once ("cancelled"), or ask the worker
    following a running one to stop it ("requested"); None when it can't be
    cancelled (any more). Commits."""
    if not can_cancel(job):
        return None
    now = datetime.now(UTC)
    if job.status == DockerJobStatus.PENDING:
        done = await db.execute(
            update(DockerJob)
            .where(DockerJob.id == job.id, DockerJob.status == DockerJobStatus.PENDING)
            .values(
                status=DockerJobStatus.CANCELLED,
                cancel_requested_by=actor[:255],
                cancel_requested_at=now,
                error=f"Cancelled by {actor} before it started."[:1024],
                finished_at=now,
            )
            .execution_options(synchronize_session=False)
        )
        await db.commit()
        if getattr(done, "rowcount", 0) == 1:
            await db.refresh(job)
            return "cancelled"
        await db.refresh(job)
        # Claimed meanwhile: ask the running job instead.
        if not can_cancel(job):
            return None
    asked = await db.execute(
        update(DockerJob)
        .where(
            DockerJob.id == job.id,
            DockerJob.status == DockerJobStatus.RUNNING,
            DockerJob.cancel_requested_at.is_(None),
        )
        .values(cancel_requested_by=actor[:255], cancel_requested_at=now)
        .execution_options(synchronize_session=False)
    )
    await db.commit()
    await db.refresh(job)
    return "requested" if getattr(asked, "rowcount", 0) == 1 else None


async def next_pending(db: AsyncSession, machine_id: uuid.UUID) -> uuid.UUID | None:
    """The machine's oldest waiting job, when none of its jobs runs."""
    running = await db.execute(
        select(DockerJob.id)
        .where(DockerJob.machine_id == machine_id, DockerJob.status == DockerJobStatus.RUNNING)
        .limit(1)
    )
    if running.first() is not None:
        return None
    found = await db.execute(
        select(DockerJob.id)
        .where(DockerJob.machine_id == machine_id, DockerJob.status == DockerJobStatus.PENDING)
        .order_by(DockerJob.created_at, DockerJob.id)
        .limit(1)
    )
    row = found.first()
    return row[0] if row is not None else None
