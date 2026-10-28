"""Starting Docker jobs — the one code path behind a button on the Docker
tab, the REST API and a scheduled task, like `app.services.machine_actions`
is for the rest of a machine's actions.

Every function here creates `DockerJob` rows, commits, then queues them
(`app.tasks.docker_jobs.run_docker_job`); the jobs of one machine run one
after another. The one exception is `run_bulk_action` (start, stop,
restart or remove the selected containers), which is quick and waits for
the answer like a single container's start/stop does. None of them
checks permissions — the callers do, with the same `Permission` on the
web and the API side.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any

from celery.exceptions import TimeoutError as CeleryTimeoutError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.docker import (
    DockerBackup,
    DockerJob,
    DockerJobKind,
    DockerStack,
    VulnerabilityGate,
)
from app.db.models.machine import Machine
from app.services import docker_backups, docker_jobs
from app.services.docker_gate import normalize_gate
from app.ssh.containers import BULK_ACTIONS, MAX_BULK_CONTAINERS
from app.ssh.docker_cli import (
    DockerCommandError,
    is_container_name_valid,
    is_image_id_valid,
    is_image_valid,
    is_project_name_valid,
    is_volume_name_valid,
)
from app.ssh.docker_compose import STACK_ACTIONS
from app.ssh.docker_prune import PruneOptions
from app.ssh.restic import is_snapshot_valid, normalize_host_path, normalize_snapshot_path
from app.tasks.docker_jobs import run_docker_job

SCAN_SCOPES = ("in_use", "unscanned", "all")
UPDATE_SCOPES = ("auto", "with_update", "all")
MAX_SCAN_REFS = 100
BACKUP_JOB_KINDS = {
    "run": DockerJobKind.BACKUP_RUN,
    "check": DockerJobKind.BACKUP_CHECK,
    "forget": DockerJobKind.BACKUP_FORGET,
}


@dataclass
class Queued:
    """What a request queued: the new jobs, and what it left out and why
    (`{name: reason}` — "protected", "already_queued", "invalid")."""

    jobs: list[DockerJob] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)


def _eligible(machine: Machine) -> bool:
    return bool(machine.host_key_fingerprint) and machine.docker_status == "ok"


async def _queue(db: AsyncSession, jobs: list[DockerJob]) -> None:
    """Commit, then queue: a worker must find the rows when it starts.
    Only the first job per machine is queued now; the rest start in turn
    (`app.tasks.docker_jobs._start_next`)."""
    db.add_all(jobs)
    await db.commit()
    seen: set[uuid.UUID] = set()
    for job in jobs:
        if job.machine_id in seen:
            continue
        seen.add(job.machine_id)
        run_docker_job.delay(str(job.id))


async def queue_job(
    db: AsyncSession,
    machine: Machine,
    kind: DockerJobKind,
    target: str,
    *,
    started_by: str | None,
    params: dict[str, Any] | None = None,
    ref_id: uuid.UUID | None = None,
) -> DockerJob | None:
    """One job; None when the same job is already waiting or running."""
    target = target[:255]  # the column's length, for the lookup too
    if await docker_jobs.active_job(db, machine.id, kind, target):
        return None
    job = DockerJob(
        machine_id=machine.id,
        kind=kind,
        target=target,
        params=params or {},
        started_by=started_by,
        ref_id=ref_id,
    )
    await _queue(db, [job])
    return job


# --- Containers --------------------------------------------------------------


@dataclass
class BulkResult:
    """What a start/stop/restart/remove of the selected containers did:
    the names it ran for, those it left out (`{name: reason}`), and the
    error docker or the connection reported (None = it worked)."""

    names: list[str] = field(default_factory=list)
    skipped: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    output: str = ""


async def run_bulk_action(
    db: AsyncSession,
    machine: Machine,
    action: str,
    names: list[str],
    *,
    timeout: float,  # noqa: ASYNC109 - Celery's result timeout, not a deadline here
) -> BulkResult:
    """Start/stop/restart/remove the given containers in one docker command
    on the machine and wait for its answer (`app.ssh.containers`).
    debcontrol's own containers are left out of everything but `start`."""
    # Imported here: app.tasks.jobs imports the scheduler, which imports
    # this module.
    from app.tasks import jobs as tasks

    if action not in BULK_ACTIONS:
        raise DockerCommandError("Unknown container action.")
    result = BulkResult()
    protected = await docker_jobs.protected_project(db, machine)
    for name in dict.fromkeys(names):
        if not is_container_name_valid(name):
            result.skipped[name] = "invalid"
        elif (
            action != "start"
            and protected
            and docker_jobs.container_project(machine, name) == protected
        ):
            result.skipped[name] = "protected"
        else:
            result.names.append(name)
    result.names = result.names[:MAX_BULK_CONTAINERS]
    if not result.names:
        return result
    try:
        async_result = tasks.run_container_action_task.delay(
            str(machine.id), action=action, containers=result.names
        )
        answer = await asyncio.to_thread(async_result.get, timeout=timeout)
    except CeleryTimeoutError:
        result.error = "The command did not finish in time."
        return result
    except Exception as exc:
        result.error = str(exc) or type(exc).__name__
        return result
    if isinstance(answer, dict) and answer.get("ok"):
        result.output = str(answer.get("output") or "")
    else:
        result.error = str((answer or {}).get("error") or "Unknown error.")
    return result


async def update_containers(
    db: AsyncSession,
    machine: Machine,
    names: list[str],
    *,
    started_by: str | None,
    gate: str | None = None,
) -> Queued:
    """Update each container to the newest image of its tag. `gate` None =
    each container's own setting."""
    queued = Queued()
    settings = await docker_jobs.container_settings(db, machine.id)
    protected = await docker_jobs.protected_project(db, machine)
    batch_id = uuid.uuid4()
    jobs: list[DockerJob] = []
    for name in dict.fromkeys(names):
        if not is_container_name_valid(name):
            queued.skipped[name] = "invalid"
            continue
        if protected and docker_jobs.container_project(machine, name) == protected:
            queued.skipped[name] = "protected"
            continue
        if await docker_jobs.active_job(db, machine.id, DockerJobKind.CONTAINER_UPDATE, name):
            queued.skipped[name] = "already_queued"
            continue
        setting = settings.get(name)
        policy = normalize_gate(
            gate if gate is not None else (setting.vulnerability_gate if setting else None)
        )
        jobs.append(
            DockerJob(
                machine_id=machine.id,
                kind=DockerJobKind.CONTAINER_UPDATE,
                target=name,
                params={"gate": policy},
                started_by=started_by,
                batch_id=batch_id,
            )
        )
    if jobs:
        await _queue(db, jobs)
    queued.jobs = jobs
    return queued


async def rollback_container(
    db: AsyncSession, machine: Machine, name: str, image_id: str, *, started_by: str | None
) -> DockerJob | None:
    if not is_container_name_valid(name) or not is_image_id_valid(image_id):
        raise DockerCommandError("Nothing to roll back to.")
    await docker_jobs.check_container(db, machine, name)
    return await queue_job(
        db,
        machine,
        DockerJobKind.CONTAINER_ROLLBACK,
        name,
        started_by=started_by,
        params={"image_id": image_id},
    )


# --- Images -------------------------------------------------------------------


async def scan_images(
    db: AsyncSession,
    machine: Machine,
    *,
    started_by: str | None,
    images: dict[str, str] | None = None,
    scope: str | None = None,
    refs: list[str] | None = None,
) -> DockerJob | None:
    """Scan the given images (`{name: image id}`), the images of the given
    references (`refs`, e.g. the selected containers' images — resolved to
    ids on the machine when the job runs) or those of a scope
    (`SCAN_SCOPES`)."""
    params: dict[str, Any] = {}
    if refs is not None:
        clean_refs = sorted({ref for ref in refs if is_image_valid(ref)})[:MAX_SCAN_REFS]
        if not clean_refs:
            raise DockerCommandError("No valid image to scan.")
        params["refs"] = clean_refs
        target = clean_refs[0] if len(clean_refs) == 1 else f"{len(clean_refs)} images"
    elif images:
        clean = {
            name: image_id
            for name, image_id in images.items()
            if is_image_valid(name) and is_image_id_valid(image_id)
        }
        if not clean:
            raise DockerCommandError("No valid image to scan.")
        params["images"] = clean
        target = next(iter(clean)) if len(clean) == 1 else f"{len(clean)} images"
    else:
        if scope not in SCAN_SCOPES:
            raise DockerCommandError("Unknown scan scope.")
        params["scope"] = scope
        target = f"scope:{scope}"
    return await queue_job(
        db, machine, DockerJobKind.IMAGE_SCAN, target, started_by=started_by, params=params
    )


async def prune(
    db: AsyncSession, machine: Machine, options: PruneOptions, *, started_by: str | None
) -> DockerJob | None:
    if not options.anything:
        raise DockerCommandError("Nothing selected to clean up.")
    return await queue_job(
        db, machine, DockerJobKind.PRUNE, "prune", started_by=started_by, params=options.as_dict()
    )


# --- Stacks -------------------------------------------------------------------


async def deploy_stack(
    db: AsyncSession,
    machine: Machine,
    stack: DockerStack,
    *,
    started_by: str | None,
    pull: bool,
    commit: str = "",
) -> DockerJob | None:
    """Queue a deploy of `stack` as stored (a Git stack at `commit` when
    given: a rollback)."""
    await docker_jobs.check_project(db, machine, stack.name)
    params: dict[str, Any] = {"pull": pull}
    if commit:
        params["commit"] = commit
    return await queue_job(
        db,
        machine,
        DockerJobKind.STACK_DEPLOY,
        stack.name,
        started_by=started_by,
        params=params,
        ref_id=stack.id,
    )


async def check_stack(
    db: AsyncSession, machine: Machine, stack: DockerStack, *, started_by: str | None
) -> DockerJob | None:
    """Queue the check before a deploy (`docker_jobs.STACK_CHECK`)."""
    return await queue_job(
        db,
        machine,
        DockerJobKind.STACK_CHECK,
        stack.name,
        started_by=started_by,
        params={},
        ref_id=stack.id,
    )


async def stack_action(
    db: AsyncSession,
    machine: Machine,
    project: str,
    action: str,
    *,
    started_by: str | None,
    working_dir: str = "",
    files: list[str] | None = None,
    stack: DockerStack | None = None,
    remove_volumes: bool = False,
) -> DockerJob | None:
    """start/stop/restart/down/up/update of any Compose project, or
    "remove" of a managed stack (down + delete its files)."""
    if not is_project_name_valid(project):
        raise DockerCommandError("Invalid Compose project.")
    if action not in (*STACK_ACTIONS, "remove") or (action == "remove" and stack is None):
        raise DockerCommandError("Unknown stack action.")
    if action not in ("start",):
        await docker_jobs.check_project(db, machine, project)
    if stack is not None and action in ("up", "update"):
        pull = action == "update"
        return await deploy_stack(db, machine, stack, started_by=started_by, pull=pull)
    params: dict[str, Any] = {"action": action}
    if action in ("up", "update"):
        params.update({"working_dir": working_dir, "files": list(files or [])})
    if action == "remove":
        params["volumes"] = remove_volumes
    return await queue_job(
        db,
        machine,
        DockerJobKind.STACK_ACTION,
        project,
        started_by=started_by,
        params=params,
        ref_id=stack.id if stack is not None else None,
    )


# --- Backups ------------------------------------------------------------------


async def backup_job(
    db: AsyncSession,
    machine: Machine,
    backup: DockerBackup,
    what: str,
    *,
    started_by: str | None,
    read_data_percent: int = 0,
) -> DockerJob | None:
    kind = BACKUP_JOB_KINDS.get(what)
    if kind is None:
        raise DockerCommandError("Unknown backup job.")
    if what == "forget" and not docker_backups.has_retention(backup):
        raise DockerCommandError("This backup keeps every snapshot; set a retention first.")
    if what == "run" and backup.stop_containers:
        await docker_jobs.check_volumes(db, machine, list(backup.volumes or []))
    params: dict[str, Any] = {}
    if what == "check":
        params["read_data_percent"] = max(0, min(int(read_data_percent), 100))
    return await queue_job(
        db, machine, kind, backup.name, started_by=started_by, params=params, ref_id=backup.id
    )


async def restore_backup(
    db: AsyncSession,
    machine: Machine,
    backup: DockerBackup,
    snapshot: str,
    *,
    started_by: str | None,
    volumes: list[str],
    paths: list[str],
    delete: bool,
) -> DockerJob | None:
    if not is_snapshot_valid(snapshot):
        raise DockerCommandError("Invalid snapshot.")
    volumes = [v for v in volumes if v in (backup.volumes or [])]
    paths = [p for p in paths if p in (backup.paths or [])]
    if not volumes and not paths:
        raise DockerCommandError("Nothing selected to restore.")
    await docker_jobs.check_volumes(db, machine, volumes)
    return await queue_job(
        db,
        machine,
        DockerJobKind.BACKUP_RESTORE,
        backup.name,
        started_by=started_by,
        params={"snapshot": snapshot, "volumes": volumes, "paths": paths, "delete": delete},
        ref_id=backup.id,
    )


async def restore_backup_to(
    db: AsyncSession,
    machine: Machine,
    backup: DockerBackup,
    snapshot: str,
    *,
    started_by: str | None,
    source: str,
    volume: str = "",
    path: str = "",
    delete: bool,
) -> DockerJob | None:
    """Restore `source` of any snapshot in the backup's repository into one
    volume or host directory (`restic.build_restore_to_script`)."""
    if not is_snapshot_valid(snapshot):
        raise DockerCommandError("Invalid snapshot.")
    checked_source = normalize_snapshot_path(source)
    if checked_source is None:
        raise DockerCommandError("Invalid path inside the snapshot.")
    volume, path = volume.strip(), path.strip()
    if bool(volume) == bool(path):
        raise DockerCommandError("Restore into one volume or one directory.")
    if volume and not is_volume_name_valid(volume):
        raise DockerCommandError(f'"{volume}" is not a valid volume name.')
    checked_path = normalize_host_path(path) if path else ""
    if checked_path is None:
        raise DockerCommandError(f'"{path}" can\'t be restored into.')
    await docker_jobs.check_volumes(db, machine, [volume] if volume else [])
    return await queue_job(
        db,
        machine,
        DockerJobKind.BACKUP_RESTORE,
        backup.name,
        started_by=started_by,
        params={
            "mode": "to",
            "snapshot": snapshot,
            "source": checked_source,
            "volume": volume,
            "path": checked_path,
            "delete": delete,
        },
        ref_id=backup.id,
    )


# --- Across machines (scheduled tasks) ---------------------------------------


async def trigger_container_updates(
    db: AsyncSession,
    machines: list[Machine],
    *,
    scope: str,
    gate: str | None,
    started_by: str,
) -> tuple[int, int]:
    """Update containers on each machine: those with automatic updates on
    ("auto"), those with a newer image found by the image check
    ("with_update"), or every one ("all"). Returns (machines with jobs,
    machines skipped)."""
    attempted = skipped = 0
    for machine in machines:
        if not _eligible(machine):
            skipped += 1
            continue
        settings = await docker_jobs.container_settings(db, machine.id)
        updates = machine.docker_image_updates or {}
        names: list[str] = []
        for container in machine.docker_containers or []:
            if not isinstance(container, dict) or not container.get("name"):
                continue
            name = str(container["name"])
            if scope == "auto" and not (settings.get(name) and settings[name].auto_update):
                continue
            if scope == "with_update" and updates.get(str(container.get("image"))) != "update":
                continue
            names.append(name)
        if not names:
            continue
        queued = await update_containers(
            db, machine, names, started_by=started_by, gate=gate if gate else None
        )
        attempted += 1 if queued.jobs else 0
    return attempted, skipped


async def trigger_scans(
    db: AsyncSession, machines: list[Machine], *, scope: str, started_by: str
) -> tuple[int, int]:
    attempted = skipped = 0
    for machine in machines:
        if not _eligible(machine):
            skipped += 1
            continue
        if await scan_images(db, machine, started_by=started_by, scope=scope):
            attempted += 1
    return attempted, skipped


async def trigger_prune(
    db: AsyncSession, machines: list[Machine], options: PruneOptions, *, started_by: str
) -> tuple[int, int]:
    attempted = skipped = 0
    for machine in machines:
        if not _eligible(machine):
            skipped += 1
            continue
        if await prune(db, machine, options, started_by=started_by):
            attempted += 1
    return attempted, skipped


async def trigger_backups(
    db: AsyncSession, machines: list[Machine], what: str, *, started_by: str
) -> tuple[int, int]:
    """Run, check or prune every enabled backup of each machine. Counted
    per machine, like the other actions: attempted when at least one of its
    backups was queued, skipped otherwise."""
    attempted = skipped = 0
    for machine in machines:
        queued = 0
        if _eligible(machine):
            for backup in await docker_backups.list_backups(db, machine.id):
                if not backup.enabled:
                    continue
                if what == "forget" and not docker_backups.has_retention(backup):
                    continue
                try:
                    if await backup_job(db, machine, backup, what, started_by=started_by):
                        queued += 1
                except (DockerCommandError, docker_jobs.ProtectedError):
                    continue
        if queued:
            attempted += 1
        else:
            skipped += 1
    return attempted, skipped


DEFAULT_GATE = VulnerabilityGate.OFF.value
