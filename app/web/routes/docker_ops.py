"""One Docker action on one machine, audited: shared by a machine's own
Docker pages, the fleet-wide Docker pages (`docker_fleet_pages`) and the
REST API, so the three run the same code with the same checks.

Each function assumes the caller checked the permission and that the
machine is visible to the account; it returns an `Op` with the job it
queued (or `done` for an action that finished inline) or an error to
show. Nothing here redirects.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.core.app_settings import get_or_create_app_settings
from app.db.models.audit_log import AuditOutcome
from app.db.models.docker import DockerBackup, DockerJob
from app.db.models.machine import Machine
from app.db.models.user import User
from app.services import docker_actions, docker_daemon, docker_jobs, docker_stacks, self_host
from app.services import docker_inventory_snapshot as inventory_snapshot
from app.ssh.docker_cli import (
    DockerCommandError,
    is_image_id_valid,
    is_image_valid,
    is_project_name_valid,
)
from app.ssh.docker_compose import STACK_ACTIONS
from app.ssh.docker_prune import PruneOptions
from app.tasks import docker_jobs as docker_tasks
from app.tasks import jobs as machine_tasks
from app.web.messages import LocalizedText
from app.web.routes.machines_docker_common import wait_task

_WAIT_EXTRA = 90


@dataclass
class Op:
    job: DockerJob | None = None
    error: str | None = None
    done: bool = False
    # The request itself was bad (a 400 for the caller), not the machine.
    invalid: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and (self.done or self.job is not None)


async def audit(
    db: AsyncSession,
    request: Request,
    machine: Machine,
    action: str,
    summary: str,
    *,
    ok: bool = True,
    denied: bool = False,
    details: dict[str, Any] | None = None,
) -> None:
    await log_event(
        db,
        request=request,
        action=action,
        summary=summary,
        outcome=(
            AuditOutcome.DENIED
            if denied
            else AuditOutcome.SUCCESS
            if ok
            else AuditOutcome.FAILURE
        ),
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details=details,
    )


def _queued(request: Request) -> str:
    return LocalizedText(request, "docker.job.already_queued")


# --- Stacks / Compose projects -------------------------------------------------


async def _live_project(
    request: Request, db: AsyncSession, machine: Machine, project: str
) -> tuple[dict[str, Any] | None, str | None]:
    app_settings = await get_or_create_app_settings(db)
    result, error = await wait_task(
        request,
        docker_tasks.docker_inventory.delay(str(machine.id), ["compose", "inspect"]),
        app_settings.ssh_connect_timeout + _WAIT_EXTRA,
    )
    if error is not None or result is None:
        return None, error
    inventory = result.get("inventory") or {}
    found = inventory_snapshot.projects_of(
        inventory.get("compose") or [], inventory.get("containers") or []
    )
    return next((p for p in found if p["name"] == project), None), None


async def project_action(
    request: Request, db: AsyncSession, machine: Machine, user: User, project: str, action: str
) -> Op:
    """start / stop / restart / down / up / update (pull & recreate) of one
    Compose project. A project debcontrol doesn't manage needs its files
    for up / update: from the stored inventory, else read live."""
    if action not in STACK_ACTIONS or not is_project_name_valid(project):
        return Op(error="Invalid request.", invalid=True)
    managed = next(
        (s for s in await docker_stacks.list_stacks(db, machine.id) if s.name == project), None
    )
    working_dir = ""
    files: list[str] = []
    if action in ("up", "update") and managed is None:
        found = inventory_snapshot.project(machine, project)
        if found is None or not found.get("config_files") or not found.get("working_dir"):
            found, error = await _live_project(request, db, machine, project)
            if error is not None:
                return Op(error=error)
        if found is None or not found.get("config_files"):
            return Op(error=LocalizedText(request, "docker.stack.files_unknown"))
        working_dir = str(found.get("working_dir") or "")
        files = [str(f) for f in found["config_files"]]
    try:
        job = await docker_actions.stack_action(
            db,
            machine,
            project,
            action,
            started_by=user.username,
            working_dir=working_dir,
            files=files,
            stack=managed,
        )
    except docker_jobs.ProtectedError:
        await audit(
            db,
            request,
            machine,
            "machine.docker.stack.action",
            f'Refused "{action}" of Compose project "{project}" on "{machine.name}": '
            "debcontrol runs in it",
            denied=True,
            details={"project": project, "action": action},
        )
        return Op(error=LocalizedText(request, "docker.protected"))
    except DockerCommandError as exc:
        return Op(error=str(exc))
    if job is None:
        return Op(error=_queued(request))
    await audit(
        db,
        request,
        machine,
        "machine.docker.stack.action",
        f'Started "{action}" of Compose project "{project}" on "{machine.name}"',
        details={"project": project, "action": action},
    )
    return Op(job=job)


# --- Images ------------------------------------------------------------------------


async def image_pull(
    request: Request, db: AsyncSession, machine: Machine, user: User, ref: str
) -> Op:
    try:
        job = await docker_actions.pull_image(db, machine, ref, started_by=user.username)
    except DockerCommandError:
        return Op(error=LocalizedText(request, "docker.image.invalid_ref"))
    if job is None:
        return Op(error=_queued(request))
    await audit(
        db,
        request,
        machine,
        "machine.docker.image.pull",
        f'Started pulling {job.target} on "{machine.name}"',
        details={"image": job.target},
    )
    return Op(job=job)


async def image_remove(
    request: Request, db: AsyncSession, machine: Machine, image: str
) -> Op:
    """`docker image rm`, never forced: Docker refuses an image in use."""
    if not is_image_valid(image):
        return Op(error="Invalid image.", invalid=True)
    app_settings = await get_or_create_app_settings(db)
    _result, error = await wait_task(
        request,
        docker_tasks.docker_image_op.delay(str(machine.id), "remove", image, ""),
        app_settings.ssh_connect_timeout + _WAIT_EXTRA,
    )
    await audit(
        db,
        request,
        machine,
        "machine.docker.image.remove",
        f'Removed image {image} on "{machine.name}"'
        if error is None
        else f'Could not remove image {image} on "{machine.name}"',
        ok=error is None,
        details={"image": image, **({"error": str(error)[:300]} if error else {})},
    )
    if error is not None:
        return Op(error=error)
    snapshot = dict(machine.docker_inventory or {})
    if snapshot.get("images"):
        snapshot["images"] = [
            i
            for i in snapshot["images"]
            if i.get("ref") != image and i.get("id") != image
        ]
        machine.docker_inventory = snapshot
        await db.commit()
    return Op(done=True)


async def image_scan(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    user: User,
    *,
    images: dict[str, str] | None = None,
    refs: list[str] | None = None,
    scope: str = "",
) -> Op:
    """Scan images with Trivy and Grype: `images` ({ref: id}), `refs`, or a
    `scope` of the machine's images."""
    try:
        if images:
            if not all(is_image_valid(r) and is_image_id_valid(i) for r, i in images.items()):
                raise DockerCommandError("Invalid image.")
            job = await docker_actions.scan_images(
                db, machine, started_by=user.username, images=images
            )
        elif refs:
            job = await docker_actions.scan_images(
                db, machine, started_by=user.username, refs=refs
            )
        else:
            job = await docker_actions.scan_images(
                db, machine, started_by=user.username, scope=scope
            )
    except DockerCommandError as exc:
        return Op(error=str(exc), invalid=True)
    if job is None:
        return Op(error=_queued(request))
    await audit(
        db,
        request,
        machine,
        "machine.docker.images.scan",
        f'Started a vulnerability scan ({job.target}) on "{machine.name}"',
        details={"target": job.target},
    )
    return Op(job=job)


async def prune(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    user: User,
    options: PruneOptions,
    *,
    confirm_name: str = "",
) -> Op:
    """Clean up what `options` select. Removing every unused named volume
    also needs the machine's name typed."""
    if not options.anything:
        return Op(error=LocalizedText(request, "docker.prune.nothing"))
    if options.all_volumes and (not options.volumes or confirm_name.strip() != machine.name):
        await audit(
            db,
            request,
            machine,
            "machine.docker.prune",
            f'Refused to remove all unused volumes on "{machine.name}": name not confirmed',
            denied=True,
            details=options.as_dict(),
        )
        return Op(error=LocalizedText(request, "docker.prune.confirm_mismatch"))
    job = await docker_actions.prune(db, machine, options, started_by=user.username)
    if job is None:
        return Op(error=_queued(request))
    await audit(
        db,
        request,
        machine,
        "machine.docker.prune",
        f'Started a Docker clean-up on "{machine.name}"',
        details=options.as_dict(),
    )
    return Op(job=job)


# --- Backups -----------------------------------------------------------------------


async def backup_job(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    user: User,
    backup: DockerBackup,
    what: str,
    *,
    read_data_percent: int = 0,
) -> Op:
    """Run a backup now, check its repository, prune it to its retention or
    test a restore (`docker_actions.BACKUP_JOB_KINDS`)."""
    if what not in docker_actions.BACKUP_JOB_KINDS:
        return Op(error="Unknown backup job.", invalid=True)
    try:
        job = await docker_actions.backup_job(
            db,
            machine,
            backup,
            what,
            started_by=user.username,
            read_data_percent=read_data_percent,
        )
    except docker_jobs.ProtectedError:
        return Op(error=LocalizedText(request, "docker.protected"))
    except DockerCommandError as exc:
        return Op(error=str(exc))
    if job is None:
        return Op(error=_queued(request))
    await audit(
        db,
        request,
        machine,
        f"machine.docker.backup.{what}",
        f'Started Docker backup job "{what}" of "{backup.name}" on "{machine.name}"',
        details={"backup": backup.name},
    )
    return Op(job=job)


# --- The Docker host -----------------------------------------------------------------


async def daemon_apply(request: Request, db: AsyncSession, machine: Machine, user: User) -> Op:
    """Write Docker → Settings into the machine's daemon.json (no restart)."""
    app_settings = await get_or_create_app_settings(db)
    if not docker_daemon.machine_status(machine, app_settings)["in_scope"]:
        return Op(error=LocalizedText(request, "docker.settings.not_in_scope"))
    job = await docker_daemon.queue_apply(db, machine, actor=user.username)
    if job is None:
        return Op(error=_queued(request))
    await audit(
        db,
        request,
        machine,
        "machine.docker.daemon.apply",
        f'Docker settings: daemon.json queued for "{machine.name}"',
        details={"job": str(job.id)},
    )
    return Op(job=job)


async def daemon_restart(request: Request, db: AsyncSession, machine: Machine, user: User) -> Op:
    """Restart Docker so it reads daemon.json. Never on the machine
    debcontrol runs on."""
    if machine.id in (await self_host.find(db)).hosts:
        return Op(error=LocalizedText(request, "docker.settings.restart_self"))
    job = await docker_daemon.queue_restart(db, machine, actor=user.username)
    if job is None:
        return Op(error=_queued(request))
    await audit(
        db,
        request,
        machine,
        "machine.docker.daemon.restart",
        f'Docker daemon restart queued on "{machine.name}"',
        details={"job": str(job.id)},
    )
    return Op(job=job)


async def check_now(request: Request, db: AsyncSession, machine: Machine) -> Op:
    """Queue the image update check, which also refreshes the host check
    and the stored inventory (the fleet pages don't wait for it)."""
    if not machine.host_key_fingerprint:
        return Op(error=LocalizedText(request, "docker.no_host_key"))
    machine_tasks.check_machine_image_updates.delay(str(machine.id))
    await audit(
        db,
        request,
        machine,
        "machine.docker.check_images",
        f'Checked Docker image updates on "{machine.name}"',
        details={"queued": True},
    )
    return Op(done=True)


def refresh_inventory(machine: Machine) -> bool:
    """Queue a read of the machine's images, volumes, networks and projects
    for the fleet pages (read-only, not audited). False without a host key."""
    if not machine.host_key_fingerprint:
        return False
    docker_tasks.refresh_docker_inventory.delay(str(machine.id))
    return True


# A machine read this recently isn't read again by the fleet's *Refresh*.
REFRESH_MIN_AGE = timedelta(seconds=60)


def refresh_fleet(machines: list[Machine]) -> int:
    """The fleet pages' *Refresh*: queue `refresh_inventory` for each
    machine not read in the last minute; how many were queued."""
    cutoff = datetime.now(UTC) - REFRESH_MIN_AGE
    queued = 0
    for machine in machines:
        read = inventory_snapshot.read_at(machine)
        if read is not None and read > cutoff:
            continue
        queued += 1 if refresh_inventory(machine) else 0
    return queued
