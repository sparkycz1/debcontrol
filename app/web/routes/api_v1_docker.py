"""REST API for a machine's Docker tab — the same pages, permissions and
service calls as `machines_docker*.py` (see `machines_docker_common` for
who may do what): `machine.view` reads everything that isn't a secret,
`action.power` starts/stops containers and Compose projects,
`action.updates` updates, rolls back, scans, cleans up, deploys and runs
backups, `action.terminal` edits stacks, backups and files.

Long operations answer `202` with the queued job (`GET .../docker/jobs/
{id}` follows it), exactly like the web pages redirect to the job's page.
What the web UI guards with a typed name (removing named volumes,
restoring a backup, deleting a stack with its volumes) needs the same name
in `confirm` here.

Deliberately web-only: the container shell (an interactive WebSocket, like
the machine terminal — see `api_v1.py`'s module docstring). Secrets never
come back: a stack's Git token and a backup's password, repository and
environment are write-only; a stack's compose file and `.env` are returned
only to `action.terminal`, who may edit them anyway.
"""

from __future__ import annotations

import base64
import posixpath
import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.core.app_settings import get_or_create_app_settings
from app.db.models.audit_log import AuditOutcome
from app.db.models.docker import (
    DockerBackup,
    DockerImageScan,
    DockerJob,
    DockerJobKind,
    DockerStack,
    StackSource,
)
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_actions, docker_backups, docker_jobs, docker_scans, docker_stacks
from app.services.docker_gate import GATES
from app.ssh import docker_files
from app.ssh.docker_cli import (
    DockerCommandError,
    is_container_name_valid,
    is_image_id_valid,
    is_image_valid,
    is_network_name_valid,
    is_project_name_valid,
    is_volume_name_valid,
)
from app.ssh.docker_compose import MAX_FILE_BYTES, STACK_ACTIONS
from app.ssh.docker_prune import PruneOptions
from app.tasks import docker_jobs as docker_tasks
from app.web.routes.api_v1 import _get_machine_or_404
from app.web.routes.machines_docker_common import wait_task

router = APIRouter(prefix="/api/v1/machines/{machine_id}/docker")
_view = Depends(require_api_permission(Permission.MACHINE_VIEW))
_updates = Depends(require_api_permission(Permission.ACTION_UPDATES))
_terminal = Depends(require_api_permission(Permission.ACTION_TERMINAL))

_PROJECT_PERMISSION = {
    "start": Permission.ACTION_POWER,
    "stop": Permission.ACTION_POWER,
    "restart": Permission.ACTION_POWER,
    "down": Permission.ACTION_POWER,
    "up": Permission.ACTION_UPDATES,
    "update": Permission.ACTION_UPDATES,
}


# --- Shapes -----------------------------------------------------------------


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def _job(job: DockerJob, *, output: bool = False) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": str(job.id),
        "kind": job.kind,
        "status": job.status,
        "target": job.target,
        "params": job.params or {},
        "result": job.result or {},
        "error": job.error,
        "started_by": job.started_by,
        "batch_id": str(job.batch_id) if job.batch_id else None,
        "created_at": _iso(job.created_at),
        "started_at": _iso(job.started_at),
        "finished_at": _iso(job.finished_at),
    }
    if output:
        data["output"] = job.output or ""
    return data


def _scan(scan: DockerImageScan, *, findings: bool = False) -> dict[str, Any]:
    data: dict[str, Any] = {
        "image_id": scan.image_id,
        "image_ref": scan.image_ref,
        "scanners": scan.scanners or {},
        "counts": scan.counts or {},
        "errors": scan.errors or {},
        "scanned_at": _iso(scan.scanned_at),
    }
    if findings:
        data["vulnerabilities"] = scan.vulnerabilities or []
    return data


def _stack(stack: DockerStack, *, secrets: bool) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": str(stack.id),
        "name": stack.name,
        "source": stack.source,
        # None = the default ~/.local/share/debcontrol/stacks/<name>.
        "directory": stack.directory,
        "git_url": stack.git_url,
        "git_branch": stack.git_branch,
        "git_compose_path": stack.git_compose_path,
        "has_git_token": stack.git_token_encrypted is not None,
        "auto_sync": stack.auto_sync,
        "has_webhook": stack.webhook_token_hash is not None,
        "webhook_last_at": _iso(stack.webhook_last_at),
        "deployed_commit": stack.deployed_commit,
        "deployed_at": _iso(stack.deployed_at),
        "changed_since_deploy": docker_stacks.is_changed(stack),
        "last_status": stack.last_status,
        "last_error": stack.last_error,
        "last_checked_at": _iso(stack.last_checked_at),
        "created_by": stack.created_by,
        "created_at": _iso(stack.created_at),
    }
    if secrets:
        data["compose"] = stack.compose_content or ""
        data["env"] = docker_stacks.env_text(stack)
    return data


def _backup(backup: DockerBackup) -> dict[str, Any]:
    return {
        "id": str(backup.id),
        "name": backup.name,
        "enabled": backup.enabled,
        "repository": backup.repository_display,
        "volumes": list(backup.volumes or []),
        "paths": list(backup.paths or []),
        "excludes": list(backup.excludes or []),
        "stop_containers": backup.stop_containers,
        "all_snapshots": backup.all_snapshots,
        "keep_last": backup.keep_last,
        "keep_daily": backup.keep_daily,
        "keep_weekly": backup.keep_weekly,
        "keep_monthly": backup.keep_monthly,
        "last_backup_at": _iso(backup.last_backup_at),
        "last_backup_status": backup.last_backup_status,
        "last_success_at": _iso(backup.last_success_at),
        "last_snapshot_id": backup.last_snapshot_id,
        "last_backup_bytes": backup.last_backup_bytes,
        "last_error": backup.last_error,
        "last_check_at": _iso(backup.last_check_at),
        "last_check_status": backup.last_check_status,
        "created_by": backup.created_by,
        "created_at": _iso(backup.created_at),
    }


# --- Helpers ----------------------------------------------------------------


async def _audit(
    db: AsyncSession,
    request: Request,
    machine: Machine,
    action: str,
    summary: str,
    details: dict[str, Any] | None = None,
    *,
    ok: bool = True,
    denied: bool = False,
) -> None:
    await log_event(
        db,
        request=request,
        action=action,
        summary=summary,
        # A safeguard that blocked the request (typed confirmation, debcontrol's
        # own) is DENIED, like elsewhere in the app; a failed attempt is FAILURE.
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


def _bad(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _conflict(detail: str = "The same job is already waiting or running.") -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)


_PROTECTED = "debcontrol itself runs in this; update debcontrol from Settings -> Update instead."


def _protected() -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=_PROTECTED)


def _ready(machine: Machine) -> None:
    if not machine.host_key_fingerprint:
        raise _bad("Confirm the machine's host key fingerprint first.")


async def _wait(
    request: Request, db: AsyncSession, async_result: Any, extra: int
) -> dict[str, Any]:
    app_settings = await get_or_create_app_settings(db)
    result, error = await wait_task(request, async_result, app_settings.ssh_connect_timeout + extra)
    if error is not None or result is None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(error or "?"))
    return result


async def _inventory(
    request: Request, db: AsyncSession, machine: Machine, sections: list[str]
) -> dict[str, Any]:
    extra = 200 if "volume_sizes" in sections else 90
    result = await _wait(
        request, db, docker_tasks.docker_inventory.delay(str(machine.id), sections), extra
    )
    inventory: dict[str, Any] = result.get("inventory") or {}
    return inventory


def _queued(job: DockerJob | None) -> dict[str, Any]:
    if job is None:
        raise _conflict()
    return {"job": _job(job)}


# --- Containers ---------------------------------------------------------------


@router.get("", dependencies=[_view])
async def docker_overview_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """The containers of the latest monitoring sample, with their update,
    auto-update and scan state."""
    machine = await _get_machine_or_404(machine_id, db, user)
    settings = await docker_jobs.container_settings(db, machine.id)
    scans = await docker_scans.scans_by_image(db, machine.id)
    by_ref = {scan.image_ref: scan for scan in scans.values() if scan.image_ref}
    containers = []
    for container in machine.docker_containers or []:
        if not isinstance(container, dict):
            continue
        setting = settings.get(str(container.get("name")))
        scan = by_ref.get(str(container.get("image")))
        containers.append(
            {
                **container,
                "image_update": (machine.docker_image_updates or {}).get(
                    str(container.get("image"))
                ),
                "auto_update": bool(setting and setting.auto_update),
                "vulnerability_gate": setting.vulnerability_gate if setting else "off",
                "vulnerabilities": (scan.counts or {}) if scan else None,
            }
        )
    return {
        "status": machine.docker_status,
        "protected_project": await docker_jobs.protected_project(db, machine),
        "images_checked_at": _iso(machine.docker_images_checked_at),
        "vulnerabilities": machine.docker_vulnerabilities,
        "last_backup_ok_at": _iso(machine.docker_backup_ok_at),
        "containers": containers,
    }


@router.get("/containers/{name}", dependencies=[_view])
async def docker_container_api(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """The container as `docker inspect` describes it now (environment
    variable names only), its settings, rollback target and recent jobs."""
    if not is_container_name_valid(name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such container.")
    machine = await _get_machine_or_404(machine_id, db, user)
    inventory = await _inventory(request, db, machine, ["inspect"])
    container = next(
        (c for c in inventory.get("containers") or [] if c.get("name") == name), None
    )
    if container is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such container.")
    setting = (await docker_jobs.container_settings(db, machine.id)).get(name)
    jobs = await docker_jobs.list_jobs(db, machine.id, limit=20, target=name)
    scan = (
        await docker_scans.get_scan(db, machine.id, str(container["image_id"]))
        if container.get("image_id")
        else None
    )
    return {
        "container": container,
        "auto_update": bool(setting and setting.auto_update),
        "vulnerability_gate": setting.vulnerability_gate if setting else "off",
        "rollback_image_id": docker_jobs.rollback_image(docker_jobs.last_update(jobs, name)),
        "scan": _scan(scan) if scan else None,
        "jobs": [_job(job) for job in jobs],
    }


class _ContainerSettings(BaseModel):
    auto_update: bool = False
    vulnerability_gate: str = "off"


@router.put("/containers/{name}/settings", dependencies=[_updates])
async def docker_container_settings_api(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    body: _ContainerSettings,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    if not is_container_name_valid(name) or body.vulnerability_gate not in GATES:
        raise _bad("Invalid container name or vulnerability gate.")
    machine = await _get_machine_or_404(machine_id, db, user)
    await docker_jobs.save_container_setting(
        db,
        machine.id,
        name,
        auto_update=body.auto_update,
        gate=body.vulnerability_gate,
        actor=user.username,
    )
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.container.settings",
        f'Changed update settings of container "{name}" on "{machine.name}"',
        {"container": name, "auto_update": body.auto_update, "gate": body.vulnerability_gate},
    )
    return {"ok": True}


class _UpdateRequest(BaseModel):
    # Names, or scope "with_update" (what the image check found newer).
    containers: list[str] = Field(default_factory=list, max_length=500)
    scope: Literal["", "with_update"] = ""
    # Empty: each container's own setting.
    vulnerability_gate: str = ""


async def _update(
    request: Request, db: AsyncSession, machine: Machine, user: User, names: list[str], gate: str
) -> dict[str, Any]:
    if gate and gate not in GATES:
        raise _bad("Unknown vulnerability gate.")
    _ready(machine)
    queued = await docker_actions.update_containers(
        db, machine, names, started_by=user.username, gate=gate or None
    )
    for job in queued.jobs:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.container.update",
            f'Started updating container "{job.target}" on "{machine.name}"',
            {"container": job.target, "gate": (job.params or {}).get("gate")},
        )
    for name, reason in queued.skipped.items():
        if reason == "protected":
            await _audit(
                db,
                request,
                machine,
                "machine.docker.container.update",
                f'Refused to update container "{name}" on "{machine.name}": debcontrol runs in it',
                {"container": name, "reason": reason},
                denied=True,
            )
    return {"jobs": [_job(job) for job in queued.jobs], "skipped": queued.skipped}


@router.post(
    "/containers/{name}/update", dependencies=[_updates], status_code=status.HTTP_202_ACCEPTED
)
async def docker_container_update_api(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    body: _UpdateRequest | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Pull the container's newest image and recreate it (put back if it
    doesn't stay up), optionally behind a vulnerability gate."""
    if not is_container_name_valid(name):
        raise _bad("Invalid container name.")
    machine = await _get_machine_or_404(machine_id, db, user)
    gate = body.vulnerability_gate if body else ""
    return await _update(request, db, machine, user, [name], gate)


@router.post("/update", dependencies=[_updates], status_code=status.HTTP_202_ACCEPTED)
async def docker_update_many_api(
    request: Request,
    machine_id: uuid.UUID,
    body: _UpdateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Update several containers, one after another."""
    machine = await _get_machine_or_404(machine_id, db, user)
    names = [n for n in body.containers if is_container_name_valid(n)]
    if body.scope == "with_update":
        updates = machine.docker_image_updates or {}
        names = [
            str(c.get("name"))
            for c in machine.docker_containers or []
            if isinstance(c, dict) and updates.get(str(c.get("image"))) == "update"
        ]
    if not names:
        raise _bad("No containers to update.")
    return await _update(request, db, machine, user, names, body.vulnerability_gate)


@router.post(
    "/containers/{name}/rollback", dependencies=[_updates], status_code=status.HTTP_202_ACCEPTED
)
async def docker_container_rollback_api(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Recreate the container from the image it ran before its last update."""
    if not is_container_name_valid(name):
        raise _bad("Invalid container name.")
    machine = await _get_machine_or_404(machine_id, db, user)
    _ready(machine)
    jobs = await docker_jobs.list_jobs(db, machine.id, limit=20, target=name)
    image_id = docker_jobs.rollback_image(docker_jobs.last_update(jobs, name))
    if image_id is None:
        raise _bad("There's no earlier image to go back to.")
    try:
        job = await docker_actions.rollback_container(
            db, machine, name, image_id, started_by=user.username
        )
    except docker_jobs.ProtectedError as exc:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.container.rollback",
            f'Refused to roll back container "{name}" on "{machine.name}": debcontrol runs in it',
            {"container": name},
            denied=True,
        )
        raise _protected() from exc
    except DockerCommandError as exc:
        raise _bad(str(exc)) from exc
    answer = _queued(job)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.container.rollback",
        f'Started rolling back container "{name}" on "{machine.name}"',
        {"container": name, "image_id": image_id},
    )
    return answer


# --- Images, scans, clean-up ----------------------------------------------------


@router.get("/images", dependencies=[_view])
async def docker_images_api(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    inventory = await _inventory(request, db, machine, ["images", "inspect", "df"])
    scans = await docker_scans.scans_by_image(db, machine.id)
    images = []
    for image in inventory.get("images") or []:
        scan = scans.get(str(image.get("id")))
        images.append({**image, "vulnerabilities": (scan.counts or {}) if scan else None})
    return {"images": images, "disk_usage": inventory.get("df") or {}}


class _ScanRequest(BaseModel):
    # One image (ref + id), or a scope: in_use / unscanned / all.
    image: str = ""
    image_id: str = ""
    scope: str = ""


@router.post("/images/scan", dependencies=[_updates], status_code=status.HTTP_202_ACCEPTED)
async def docker_images_scan_api(
    request: Request,
    machine_id: uuid.UUID,
    body: _ScanRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Scan with Trivy and Grype, both pulled fresh."""
    machine = await _get_machine_or_404(machine_id, db, user)
    _ready(machine)
    try:
        if body.image or body.image_id:
            if not is_image_valid(body.image) or not is_image_id_valid(body.image_id):
                raise DockerCommandError("Invalid image.")
            job = await docker_actions.scan_images(
                db, machine, started_by=user.username, images={body.image: body.image_id}
            )
        else:
            job = await docker_actions.scan_images(
                db, machine, started_by=user.username, scope=body.scope or "in_use"
            )
    except DockerCommandError as exc:
        raise _bad(str(exc)) from exc
    answer = _queued(job)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.images.scan",
        f'Started a vulnerability scan ({answer["job"]["target"]}) on "{machine.name}"',
        {"target": answer["job"]["target"]},
    )
    return answer


@router.get("/images/{image_id}/vulnerabilities", dependencies=[_view])
async def docker_image_vulnerabilities_api(
    machine_id: uuid.UUID,
    image_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    scan = (
        await docker_scans.get_scan(db, machine.id, image_id)
        if is_image_id_valid(image_id)
        else None
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No scan of this image.")
    return _scan(scan, findings=True)


class _PruneRequest(BaseModel):
    containers: bool = False
    images: bool = False
    all_images: bool = False
    networks: bool = False
    volumes: bool = False
    all_volumes: bool = False
    build_cache: bool = False
    # The machine's name, for `all_volumes` (named volumes hold data).
    confirm: str = ""


@router.post("/prune", dependencies=[_updates], status_code=status.HTTP_202_ACCEPTED)
async def docker_prune_api(
    request: Request,
    machine_id: uuid.UUID,
    body: _PruneRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    _ready(machine)
    options = PruneOptions(**body.model_dump(exclude={"confirm"}))
    if not options.anything:
        raise _bad("Nothing selected to clean up.")
    if options.all_volumes and (not options.volumes or body.confirm.strip() != machine.name):
        await _audit(
            db,
            request,
            machine,
            "machine.docker.prune",
            f'Refused to remove all unused volumes on "{machine.name}": name not confirmed',
            options.as_dict(),
            denied=True,
        )
        raise _bad('all_volumes needs volumes too and the machine\'s name in "confirm".')
    answer = _queued(await docker_actions.prune(db, machine, options, started_by=user.username))
    await _audit(
        db,
        request,
        machine,
        "machine.docker.prune",
        f'Started a Docker clean-up on "{machine.name}"',
        options.as_dict(),
    )
    return answer


@router.get("/volumes", dependencies=[_view])
async def docker_volumes_api(
    request: Request,
    machine_id: uuid.UUID,
    sizes: bool = False,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    sections = ["volumes", "inspect"] + (["volume_sizes"] if sizes else [])
    inventory = await _inventory(request, db, machine, sections)
    return {"volumes": inventory.get("volumes") or []}


@router.get("/networks", dependencies=[_view])
async def docker_networks_api(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    inventory = await _inventory(request, db, machine, ["networks", "inspect"])
    return {"networks": inventory.get("networks") or []}


@router.get("/networks/{name}", dependencies=[_view])
async def docker_network_api(
    request: Request,
    machine_id: uuid.UUID,
    name: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """One network as `docker network inspect` describes it: addressing,
    options, labels and the attached containers with their addresses."""
    machine = await _get_machine_or_404(machine_id, db, user)
    if not is_network_name_valid(name):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such network.")
    inventory = await _inventory(request, db, machine, ["network_inspect"])
    for network in inventory.get("network_details") or []:
        if network.get("name") == name:
            return {"network": network}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such network.")


# --- Jobs -----------------------------------------------------------------------


@router.get("/jobs", dependencies=[_view])
async def docker_jobs_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    machine = await _get_machine_or_404(machine_id, db, user)
    return [_job(job) for job in await docker_jobs.list_jobs(db, machine.id)]


@router.get("/jobs/{job_id}", dependencies=[_view])
async def docker_job_api(
    machine_id: uuid.UUID,
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    job = await docker_jobs.get_job(db, machine.id, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
    return _job(job, output=True)


# --- Stacks and Compose projects --------------------------------------------------


async def _stack_or_404(db: AsyncSession, machine: Machine, stack_id: uuid.UUID) -> DockerStack:
    stack = await docker_stacks.get_stack(db, machine.id, stack_id)
    if stack is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stack not found.")
    return stack


@router.get("/stacks", dependencies=[_view])
async def docker_stacks_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    machine = await _get_machine_or_404(machine_id, db, user)
    secrets = user.has_permission(Permission.ACTION_TERMINAL)
    return [
        _stack(stack, secrets=secrets)
        for stack in await docker_stacks.list_stacks(db, machine.id)
    ]


class _StackSave(BaseModel):
    name: str = Field(default="", max_length=64)
    source: Literal["editor", "git"] = "editor"
    compose: str = ""
    # None keeps the stored .env.
    env: str | None = None
    git_url: str = ""
    git_branch: str = docker_stacks.DEFAULT_BRANCH
    git_compose_path: str = docker_stacks.DEFAULT_COMPOSE_PATH
    # None keeps the stored token, "" removes it.
    git_token: str | None = None
    auto_sync: bool = False
    # Where the files go on the machine (absolute or ~/...), chosen on
    # create only; None/"" = the default directory.
    directory: str | None = Field(default=None, max_length=1024)
    deploy: bool = False


def _stack_form(body: _StackSave) -> docker_stacks.StackForm:
    return docker_stacks.StackForm(
        name=body.name,
        source=body.source,
        compose=body.compose.replace("\r\n", "\n"),
        env=body.env.replace("\r\n", "\n") if body.env is not None else None,
        git_url=body.git_url,
        git_branch=body.git_branch,
        git_compose_path=body.git_compose_path,
        git_token=body.git_token,
        auto_sync=body.auto_sync,
        directory=body.directory,
    )


async def _deploy(
    request: Request, db: AsyncSession, machine: Machine, user: User, stack: DockerStack, pull: bool
) -> dict[str, Any]:
    _ready(machine)
    try:
        job = await docker_actions.deploy_stack(
            db, machine, stack, started_by=user.username, pull=pull
        )
    except docker_jobs.ProtectedError as exc:
        raise _protected() from exc
    answer = _queued(job)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.deploy",
        f'Started deploying Docker stack "{stack.name}" on "{machine.name}"',
        {"stack": stack.name, "pull": pull},
    )
    return answer


def _check_deploy(body: _StackSave, user: User, machine: Machine) -> None:
    """`deploy: true` is checked before anything is saved, so a refused
    deploy leaves no half-done change behind."""
    if body.deploy:
        if not user.has_permission(Permission.ACTION_UPDATES):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
        _ready(machine)


@router.post("/stacks", dependencies=[_terminal], status_code=status.HTTP_201_CREATED)
async def docker_stack_create_api(
    request: Request,
    machine_id: uuid.UUID,
    body: _StackSave,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Create a stack; `deploy: true` also deploys it (needs `action.updates`)."""
    machine = await _get_machine_or_404(machine_id, db, user)
    _check_deploy(body, user, machine)
    form = _stack_form(body)
    form.directory = form.directory or ""
    errors = form.validate()
    if not errors and await docker_stacks.name_taken(db, machine.id, form.name):
        errors.append("docker.stack.error.name_taken")
    if not errors and await docker_stacks.directory_taken(db, machine.id, form.directory or ""):
        errors.append("docker.stack.error.directory_taken")
    if not errors:
        try:
            await docker_jobs.check_project(db, machine, form.name)
        except docker_jobs.ProtectedError:
            errors.append("docker.stack.error.protected")
    if errors:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=errors)
    stack = DockerStack(machine_id=machine.id, created_by=user.username)
    form.apply(stack)
    db.add(stack)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.create",
        f'Created Docker stack "{stack.name}" on "{machine.name}"',
        {
            "stack": stack.name,
            "source": stack.source,
            "git_url": stack.git_url,
            "directory": stack.directory,
        },
    )
    answer: dict[str, Any] = {"stack": _stack(stack, secrets=True)}
    if body.deploy:
        answer.update(await _deploy(request, db, machine, user, stack, True))
    return answer


@router.get("/stacks/{stack_id}", dependencies=[_view])
async def docker_stack_api(
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    stack = await _stack_or_404(db, machine, stack_id)
    jobs = await docker_jobs.list_jobs(db, machine.id, limit=20, ref_id=stack.id)
    return {
        **_stack(stack, secrets=user.has_permission(Permission.ACTION_TERMINAL)),
        "jobs": [_job(job) for job in jobs],
    }


@router.put("/stacks/{stack_id}", dependencies=[_terminal])
async def docker_stack_save_api(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    body: _StackSave,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Change a stack (its name stays: it is the Compose project's name).
    Saving does not deploy unless `deploy: true`."""
    machine = await _get_machine_or_404(machine_id, db, user)
    stack = await _stack_or_404(db, machine, stack_id)
    _check_deploy(body, user, machine)
    form = _stack_form(body)
    form.name = stack.name
    # The directory is chosen once, when the stack is made.
    if (body.directory or None) not in (None, stack.directory):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=["docker.stack.error.directory_fixed"],
        )
    form.directory = None
    errors = form.validate()
    if errors:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=errors)
    form.apply(stack)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.edit",
        f'Edited Docker stack "{stack.name}" on "{machine.name}"',
        {"stack": stack.name, "source": stack.source, "git_url": stack.git_url},
    )
    answer: dict[str, Any] = {"stack": _stack(stack, secrets=True)}
    if body.deploy:
        answer.update(await _deploy(request, db, machine, user, stack, True))
    return answer


class _DeployRequest(BaseModel):
    pull: bool = True


@router.post(
    "/stacks/{stack_id}/deploy", dependencies=[_updates], status_code=status.HTTP_202_ACCEPTED
)
async def docker_stack_deploy_api(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    body: _DeployRequest | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    stack = await _stack_or_404(db, machine, stack_id)
    return await _deploy(request, db, machine, user, stack, body.pull if body else True)


@router.post("/stacks/{stack_id}/sync", dependencies=[_updates])
async def docker_stack_sync_api(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Check the Git branch now and deploy a new commit."""
    machine = await _get_machine_or_404(machine_id, db, user)
    stack = await _stack_or_404(db, machine, stack_id)
    if stack.source != StackSource.GIT:
        raise _bad("Not a Git stack.")
    _ready(machine)
    try:
        await docker_jobs.check_project(db, machine, stack.name)
    except docker_jobs.ProtectedError as exc:
        raise _protected() from exc
    app_settings = await get_or_create_app_settings(db)
    result, error = await wait_task(
        request,
        docker_tasks.sync_git_stack.delay(str(stack.id), user.username),
        app_settings.ssh_connect_timeout + 150,
    )
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.sync",
        f'Checked Git for Docker stack "{stack.name}" on "{machine.name}"',
        {"stack": stack.name, "error": error} if error else {"stack": stack.name},
        ok=error is None,
    )
    if error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(error))
    return {"deployed": bool(result and result.get("deployed")), **(result or {})}


class _WebhookRequest(BaseModel):
    remove: bool = False


@router.post("/stacks/{stack_id}/webhook", dependencies=[_terminal])
async def docker_stack_webhook_api(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    body: _WebhookRequest | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """A new webhook URL (returned only in this answer) or none."""
    machine = await _get_machine_or_404(machine_id, db, user)
    stack = await _stack_or_404(db, machine, stack_id)
    if stack.source != StackSource.GIT:
        raise _bad("Not a Git stack.")
    url: str | None = None
    if body is not None and body.remove:
        stack.webhook_token_hash = None
    else:
        token, digest = docker_stacks.new_webhook_token()
        stack.webhook_token_hash = digest
        url = str(request.base_url).rstrip("/") + docker_stacks.WEBHOOK_PREFIX + token
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.webhook",
        f'{"Removed" if url is None else "Created a new"} webhook of Docker stack '
        f'"{stack.name}" on "{machine.name}"',
        {"stack": stack.name, "removed": url is None},
    )
    return {"webhook_url": url}


@router.delete("/stacks/{stack_id}", dependencies=[_terminal])
async def docker_stack_delete_api(
    request: Request,
    machine_id: uuid.UUID,
    stack_id: uuid.UUID,
    remove_volumes: bool = False,
    confirm: str = "",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Take the stack down, delete its files and forget it; its named
    volumes too with `remove_volumes=true&confirm=<stack name>`."""
    machine = await _get_machine_or_404(machine_id, db, user)
    stack = await _stack_or_404(db, machine, stack_id)
    if remove_volumes and confirm.strip() != stack.name:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.stack.delete",
            f'Refused to delete Docker stack "{stack.name}" with its volumes: name not confirmed',
            {"stack": stack.name},
            denied=True,
        )
        raise _bad('Removing volumes needs the stack\'s name in "confirm".')
    if stack.deployed_at is None and stack.last_status is None:
        name = stack.name
        await db.delete(stack)
        await db.commit()
        await _audit(
            db,
            request,
            machine,
            "machine.docker.stack.delete",
            f'Deleted Docker stack "{name}" (never deployed) on "{machine.name}"',
            {"stack": name},
        )
        return {"deleted": True, "job": None}
    _ready(machine)
    try:
        job = await docker_actions.stack_action(
            db,
            machine,
            stack.name,
            "remove",
            started_by=user.username,
            stack=stack,
            remove_volumes=remove_volumes,
        )
    except docker_jobs.ProtectedError as exc:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.stack.delete",
            f'Refused to delete Docker stack "{stack.name}": debcontrol runs in it',
            {"stack": stack.name},
            denied=True,
        )
        raise _protected() from exc
    answer = _queued(job)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.delete",
        f'Started deleting Docker stack "{stack.name}" on "{machine.name}"'
        + (" with its volumes" if remove_volumes else ""),
        {"stack": stack.name, "volumes": remove_volumes},
    )
    return {"deleted": False, **answer}


async def _projects(request: Request, db: AsyncSession, machine: Machine) -> list[dict[str, Any]]:
    inventory = await _inventory(request, db, machine, ["compose", "inspect"])
    projects: dict[str, dict[str, Any]] = {}
    for row in inventory.get("compose") or []:
        projects[row["name"]] = {
            "name": row["name"],
            "status": row.get("status") or "",
            "config_files": list(row.get("config_files") or []),
            "working_dir": "",
            "containers": [],
        }
    for container in inventory.get("containers") or []:
        name = container.get("compose_project")
        if not name:
            continue
        project = projects.setdefault(
            name,
            {"name": name, "status": "", "config_files": [], "working_dir": "", "containers": []},
        )
        project["containers"].append(container.get("name"))
        if not project["working_dir"]:
            project["working_dir"] = container.get("compose_working_dir") or ""
        if not project["config_files"]:
            project["config_files"] = list(container.get("compose_config_files") or [])
    return sorted(projects.values(), key=lambda p: str(p["name"]))


@router.get("/projects", dependencies=[_view])
async def docker_projects_api(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    """Every Compose project on the machine now, deployed by debcontrol or not."""
    machine = await _get_machine_or_404(machine_id, db, user)
    managed = {s.name: s for s in await docker_stacks.list_stacks(db, machine.id)}
    return [
        {**p, "stack_id": str(managed[p["name"]].id) if p["name"] in managed else None}
        for p in await _projects(request, db, machine)
    ]


@router.post("/projects/{project}/{action}", status_code=status.HTTP_202_ACCEPTED)
async def docker_project_action_api(
    request: Request,
    machine_id: uuid.UUID,
    project: str,
    action: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """start / stop / restart / down (`action.power`), up / update
    (`action.updates`) of a Compose project."""
    if action not in STACK_ACTIONS or not is_project_name_valid(project):
        raise _bad("Invalid request.")
    if not user.has_permission(_PROJECT_PERMISSION[action]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    machine = await _get_machine_or_404(machine_id, db, user)
    _ready(machine)
    managed = next(
        (s for s in await docker_stacks.list_stacks(db, machine.id) if s.name == project), None
    )
    working_dir = ""
    files: list[str] = []
    if action in ("up", "update") and managed is None:
        projects = await _projects(request, db, machine)
        found = next((p for p in projects if p["name"] == project), None)
        if found is None or not found["config_files"]:
            raise _bad("This project's compose files aren't known.")
        working_dir = str(found["working_dir"] or "")
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
    except docker_jobs.ProtectedError as exc:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.stack.action",
            f'Refused "{action}" of Compose project "{project}" on "{machine.name}": '
            "debcontrol runs in it",
            {"project": project, "action": action},
            denied=True,
        )
        raise _protected() from exc
    except DockerCommandError as exc:
        raise _bad(str(exc)) from exc
    answer = _queued(job)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.stack.action",
        f'Started "{action}" of Compose project "{project}" on "{machine.name}"',
        {"project": project, "action": action},
    )
    return answer


@router.get("/projects/{project}/compose", dependencies=[_terminal])
async def docker_project_compose_api(
    request: Request,
    machine_id: uuid.UUID,
    project: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """The compose file(s) a project on the machine was started from."""
    if not is_project_name_valid(project):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such project.")
    machine = await _get_machine_or_404(machine_id, db, user)
    found = next((p for p in await _projects(request, db, machine) if p["name"] == project), None)
    if found is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such project.")
    app_settings = await get_or_create_app_settings(db)
    files = []
    for path in found["config_files"][:10]:
        result, error = await wait_task(
            request,
            docker_tasks.docker_compose_file.delay(str(machine.id), str(path)),
            app_settings.ssh_connect_timeout + 90,
        )
        files.append(
            {
                "path": path,
                "content": (result or {}).get("content") if error is None else None,
                "error": str(error) if error is not None else None,
            }
        )
    return {"project": project, "working_dir": found["working_dir"], "files": files}


class _ComposeFileSave(BaseModel):
    # One of the project's compose files, as GET .../compose lists them.
    path: str = Field(max_length=1024)
    content: str
    # Also run `docker compose up -d` afterwards (needs `action.updates`).
    up: bool = False


@router.put("/projects/{project}/compose", dependencies=[_terminal])
async def docker_project_compose_save_api(
    request: Request,
    machine_id: uuid.UUID,
    project: str,
    body: _ComposeFileSave,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Replace one compose file of a project found on the machine. The
    whole project is checked with `docker compose config` and the old
    text put back when it fails (422). Not for stacks debcontrol deploys:
    change those with PUT /stacks/{id}."""
    if not is_project_name_valid(project):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such project.")
    if body.up and not user.has_permission(Permission.ACTION_UPDATES):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    machine = await _get_machine_or_404(machine_id, db, user)
    _ready(machine)
    content = body.content.replace("\r\n", "\n")
    if len(content.encode()) > MAX_FILE_BYTES or "\0" in content:
        raise _bad("The compose file is too large (at most 512 KiB) or contains a NUL byte.")
    if any(s.name == project for s in await docker_stacks.list_stacks(db, machine.id)):
        raise _bad("This is a stack debcontrol deploys; change it with PUT /stacks/{id}.")
    try:
        await docker_jobs.check_project(db, machine, project)
    except docker_jobs.ProtectedError as exc:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.project.compose_edit",
            f'Refused editing a compose file of "{project}" on "{machine.name}": '
            "debcontrol runs in it",
            {"project": project, "path": body.path},
            denied=True,
        )
        raise _protected() from exc
    found = next((p for p in await _projects(request, db, machine) if p["name"] == project), None)
    files = [str(f) for f in (found or {}).get("config_files") or []]
    if found is None or body.path not in files:
        raise _bad("That file is not one of this project's compose files.")
    working_dir = str(found["working_dir"] or "")
    app_settings = await get_or_create_app_settings(db)
    result, error = await wait_task(
        request,
        docker_tasks.docker_write_compose_file.delay(
            str(machine.id), project, body.path, content, working_dir, files
        ),
        app_settings.ssh_connect_timeout + 150,
    )
    if error is not None or result is None:
        step = str((result or {}).get("step") or "")
        await _audit(
            db,
            request,
            machine,
            "machine.docker.project.compose_edit",
            f'Editing compose file "{body.path}" of "{project}" on "{machine.name}" failed'
            + (f" ({step})" if step else ""),
            {"project": project, "path": body.path, "step": step or None},
            ok=False,
        )
        code = (
            status.HTTP_422_UNPROCESSABLE_CONTENT
            if step == "config"
            else status.HTTP_502_BAD_GATEWAY
        )
        raise HTTPException(status_code=code, detail=str(error or "?"))
    await _audit(
        db,
        request,
        machine,
        "machine.docker.project.compose_edit",
        f'Edited compose file "{body.path}" of "{project}" on "{machine.name}"',
        {"project": project, "path": body.path, "up": body.up},
    )
    answer: dict[str, Any] = {"saved": True, "path": body.path}
    if body.up:
        try:
            job = await docker_actions.stack_action(
                db,
                machine,
                project,
                "up",
                started_by=user.username,
                working_dir=working_dir,
                files=files,
            )
        except DockerCommandError as exc:
            raise _bad(str(exc)) from exc
        answer.update(_queued(job))
        await _audit(
            db,
            request,
            machine,
            "machine.docker.stack.action",
            f'Started "up" of Compose project "{project}" on "{machine.name}"',
            {"project": project, "action": "up"},
        )
    return answer


# --- Backups ----------------------------------------------------------------------


async def _backup_or_404(
    db: AsyncSession, machine: Machine, backup_id: uuid.UUID
) -> DockerBackup:
    backup = await docker_backups.get_backup(db, machine.id, backup_id)
    if backup is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Backup not found.")
    return backup


class _BackupSave(BaseModel):
    name: str = Field(max_length=64)
    # Empty on PUT: keep the stored one.
    repository: str = ""
    password: str = ""
    env: str = ""
    # On edit: true removes the stored variables (an empty `env` keeps them).
    clear_env: bool = False
    volumes: list[str] = Field(default_factory=list, max_length=100)
    paths: list[str] = Field(default_factory=list, max_length=100)
    excludes: list[str] = Field(default_factory=list, max_length=200)
    stop_containers: bool = False
    # List every snapshot in the repository (other machines' too).
    all_snapshots: bool = False
    enabled: bool = True
    keep_last: int | None = None
    keep_daily: int | None = None
    keep_weekly: int | None = None
    keep_monthly: int | None = None


def _backup_form(body: _BackupSave) -> docker_backups.BackupForm:
    def keep(value: int | None) -> str:
        return "" if value is None else str(value)

    return docker_backups.BackupForm(
        name=body.name,
        repository=body.repository,
        password=body.password,
        env=body.env.replace("\r\n", "\n"),
        clear_env=body.clear_env,
        volumes="\n".join(body.volumes),
        paths="\n".join(body.paths),
        excludes="\n".join(body.excludes),
        stop_containers=body.stop_containers,
        all_snapshots=body.all_snapshots,
        enabled=body.enabled,
        keep_last=keep(body.keep_last),
        keep_daily=keep(body.keep_daily),
        keep_weekly=keep(body.keep_weekly),
        keep_monthly=keep(body.keep_monthly),
    )


def _backup_details(backup: DockerBackup) -> dict[str, Any]:
    return {
        "backup": backup.name,
        "repository": backup.repository_display,
        "volumes": backup.volumes,
        "paths": backup.paths,
    }


@router.get("/backups", dependencies=[_view])
async def docker_backups_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    machine = await _get_machine_or_404(machine_id, db, user)
    return [_backup(b) for b in await docker_backups.list_backups(db, machine.id)]


@router.post("/backups", dependencies=[_terminal], status_code=status.HTTP_201_CREATED)
async def docker_backup_create_api(
    request: Request,
    machine_id: uuid.UUID,
    body: _BackupSave,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    form = _backup_form(body)
    errors = form.validate(existing=None)
    if not errors and await docker_backups.name_taken(db, machine.id, form.name):
        errors.append("docker.backup.error.name_taken")
    if errors:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=errors)
    backup = DockerBackup(machine_id=machine.id, created_by=user.username)
    form.apply(backup)
    db.add(backup)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.backup.create",
        f'Created Docker backup "{backup.name}" on "{machine.name}"',
        _backup_details(backup),
    )
    return _backup(backup)


@router.get("/backups/export", dependencies=[_terminal])
async def docker_backups_export_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Every backup's settings without secrets, as the web page's Export
    file. To import one, POST /backups with its fields plus `password`
    (and the repository when it came back as null: it had credentials)."""
    machine = await _get_machine_or_404(machine_id, db, user)
    backups = await docker_backups.list_backups(db, machine.id)
    return docker_backups.export_definitions(backups, machine)


@router.get("/backups/{backup_id}", dependencies=[_view])
async def docker_backup_api(
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    backup = await _backup_or_404(db, machine, backup_id)
    jobs = await docker_jobs.list_jobs(db, machine.id, limit=20, ref_id=backup.id)
    return {**_backup(backup), "jobs": [_job(job) for job in jobs]}


@router.put("/backups/{backup_id}", dependencies=[_terminal])
async def docker_backup_save_api(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    body: _BackupSave,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Change a backup; an empty repository, password or env keeps the stored one."""
    machine = await _get_machine_or_404(machine_id, db, user)
    backup = await _backup_or_404(db, machine, backup_id)
    form = _backup_form(body)
    errors = form.validate(existing=backup)
    if not errors and await docker_backups.name_taken(
        db, machine.id, form.name, exclude=backup.id
    ):
        errors.append("docker.backup.error.name_taken")
    if errors:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=errors)
    form.apply(backup)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.backup.edit",
        f'Edited Docker backup "{backup.name}" on "{machine.name}"',
        _backup_details(backup),
    )
    return _backup(backup)


@router.delete("/backups/{backup_id}", dependencies=[_terminal])
async def docker_backup_delete_api(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Forget the backup here; the repository and its snapshots stay."""
    machine = await _get_machine_or_404(machine_id, db, user)
    backup = await _backup_or_404(db, machine, backup_id)
    name = backup.name
    await db.delete(backup)
    await db.commit()
    await _audit(
        db,
        request,
        machine,
        "machine.docker.backup.delete",
        f'Deleted Docker backup "{name}" on "{machine.name}"',
        {"backup": name},
    )
    return {"ok": True}


@router.get("/backups/{backup_id}/snapshots", dependencies=[_view])
async def docker_backup_snapshots_api(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    machine = await _get_machine_or_404(machine_id, db, user)
    backup = await _backup_or_404(db, machine, backup_id)
    task = docker_tasks.docker_backup_snapshots.delay(str(backup.id))
    result = await _wait(request, db, task, 330)
    snapshots: list[dict[str, Any]] = result.get("snapshots") or []
    return snapshots


class _RestoreRequest(BaseModel):
    snapshot: str = Field(max_length=64)
    # Empty: every volume / path of the backup.
    volumes: list[str] | None = None
    paths: list[str] | None = None
    delete: bool = False
    # The machine's name: a restore overwrites live data.
    confirm: str = ""


@router.post(
    "/backups/{backup_id}/restore", dependencies=[_terminal], status_code=status.HTTP_202_ACCEPTED
)
async def docker_backup_restore_api(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    body: _RestoreRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    backup = await _backup_or_404(db, machine, backup_id)
    if body.confirm.strip() != machine.name:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.backup.restore",
            f'Refused to restore Docker backup "{backup.name}": machine name not confirmed',
            {"backup": backup.name, "snapshot": body.snapshot},
            denied=True,
        )
        raise _bad('A restore needs the machine\'s name in "confirm".')
    _ready(machine)
    volumes = list(backup.volumes or []) if body.volumes is None else body.volumes
    paths = list(backup.paths or []) if body.paths is None else body.paths
    try:
        job = await docker_actions.restore_backup(
            db,
            machine,
            backup,
            body.snapshot,
            started_by=user.username,
            volumes=volumes,
            paths=paths,
            delete=body.delete,
        )
    except docker_jobs.ProtectedError as exc:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.backup.restore",
            f'Refused to restore Docker backup "{backup.name}": debcontrol uses those volumes',
            {"backup": backup.name, "snapshot": body.snapshot},
            denied=True,
        )
        raise _protected() from exc
    except DockerCommandError as exc:
        raise _bad(str(exc)) from exc
    answer = _queued(job)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.backup.restore",
        f'Started restoring snapshot {body.snapshot[:12]} of Docker backup "{backup.name}" '
        f'on "{machine.name}"',
        {
            "backup": backup.name,
            "snapshot": body.snapshot,
            "volumes": volumes,
            "paths": paths,
            "delete": body.delete,
        },
    )
    return answer


@router.get("/backups/{backup_id}/export", dependencies=[_terminal])
async def docker_backup_export_api(
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    backup = await _backup_or_404(db, machine, backup_id)
    return docker_backups.export_definitions([backup], machine)


class _RestoreToRequest(BaseModel):
    snapshot: str = Field(max_length=64)
    # A directory inside the snapshot; "/" = all of it.
    source: str = Field(default="/", max_length=1024)
    # Exactly one of the two.
    volume: str = Field(default="", max_length=255)
    path: str = Field(default="", max_length=1024)
    delete: bool = False
    # The machine's name: a restore overwrites what is there.
    confirm: str = ""


@router.post(
    "/backups/{backup_id}/restore-to",
    dependencies=[_terminal],
    status_code=status.HTTP_202_ACCEPTED,
)
async def docker_backup_restore_to_api(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    body: _RestoreToRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Restore `source` of any snapshot in the repository (another
    machine's too) into one volume or host directory."""
    machine = await _get_machine_or_404(machine_id, db, user)
    backup = await _backup_or_404(db, machine, backup_id)
    details = {
        "backup": backup.name,
        "snapshot": body.snapshot,
        "source": body.source,
        "volume": body.volume or None,
        "path": body.path or None,
        "delete": body.delete,
    }
    if body.confirm.strip() != machine.name:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.backup.restore",
            f'Refused to restore from Docker backup "{backup.name}": machine name not confirmed',
            details,
            denied=True,
        )
        raise _bad('A restore needs the machine\'s name in "confirm".')
    _ready(machine)
    try:
        job = await docker_actions.restore_backup_to(
            db,
            machine,
            backup,
            body.snapshot,
            started_by=user.username,
            source=body.source,
            volume=body.volume,
            path=body.path,
            delete=body.delete,
        )
    except docker_jobs.ProtectedError as exc:
        await _audit(
            db,
            request,
            machine,
            "machine.docker.backup.restore",
            f'Refused to restore from Docker backup "{backup.name}": debcontrol uses that volume',
            details,
            denied=True,
        )
        raise _protected() from exc
    except DockerCommandError as exc:
        raise _bad(str(exc)) from exc
    answer = _queued(job)
    target = f"volume {body.volume}" if body.volume else body.path
    await _audit(
        db,
        request,
        machine,
        "machine.docker.backup.restore",
        f'Started restoring {body.source} of snapshot {body.snapshot[:12]} '
        f'(Docker backup "{backup.name}") into {target} on "{machine.name}"',
        details,
    )
    return answer


class _BackupJobRequest(BaseModel):
    # check only: also read this share of the data (0-100).
    read_data_percent: int = Field(default=0, ge=0, le=100)


@router.post(
    "/backups/{backup_id}/{what}", dependencies=[_updates], status_code=status.HTTP_202_ACCEPTED
)
async def docker_backup_job_api(
    request: Request,
    machine_id: uuid.UUID,
    backup_id: uuid.UUID,
    what: Literal["run", "check", "forget"],
    body: _BackupJobRequest | None = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Back up now, check the repository, or prune it to the retention."""
    machine = await _get_machine_or_404(machine_id, db, user)
    backup = await _backup_or_404(db, machine, backup_id)
    _ready(machine)
    try:
        job = await docker_actions.backup_job(
            db,
            machine,
            backup,
            what,
            started_by=user.username,
            read_data_percent=body.read_data_percent if body else 0,
        )
    except docker_jobs.ProtectedError as exc:
        raise _protected() from exc
    except DockerCommandError as exc:
        raise _bad(str(exc)) from exc
    answer = _queued(job)
    await _audit(
        db,
        request,
        machine,
        f"machine.docker.backup.{what}",
        f'Started Docker backup job "{what}" of "{backup.name}" on "{machine.name}"',
        {"backup": backup.name},
    )
    return answer


# --- Files --------------------------------------------------------------------------

_KINDS = {"containers": "container", "volumes": "volume"}


def _target(kind: str, name: str) -> docker_files.Target:
    target_kind = _KINDS.get(kind)
    valid = (
        is_container_name_valid(name) if target_kind == "container" else is_volume_name_valid(name)
    )
    if target_kind is None or not valid:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    return docker_files.Target(target_kind, name)  # type: ignore[arg-type]


def _path(path: str) -> str:
    try:
        return docker_files.normalize_path(path or "/")
    except DockerCommandError as exc:
        raise _bad("Invalid path.") from exc


async def _files(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    op: str,
    target: docker_files.Target,
    path: str,
    **extra: str,
) -> tuple[dict[str, Any] | None, str | None]:
    _ready(machine)
    app_settings = await get_or_create_app_settings(db)
    result, error = await wait_task(
        request,
        docker_tasks.docker_files_task.delay(
            str(machine.id), op, target.kind, target.name, path, **extra
        ),
        app_settings.ssh_connect_timeout + 330,
    )
    return result, str(error) if error is not None else None


def _file_error(error: str) -> HTTPException:
    if error in ("too_large", "The file is too large for this."):
        return HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail=error)
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=error)


@router.get("/{kind}/{name}/files", dependencies=[_terminal])
async def docker_files_list_api(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str = "/",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """A folder in a container or volume (`kind`: containers / volumes)."""
    target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, user)
    path = _path(path)
    result, error = await _files(request, db, machine, "list", target, path)
    if error is not None:
        raise _file_error(error)
    return {"path": path, "entries": (result or {}).get("entries") or []}


@router.get("/{kind}/{name}/files/content", dependencies=[_terminal])
async def docker_file_read_api(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """One file, base64-encoded, with its mode and owner. Audited like a
    download."""
    target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, user)
    path = _path(path)
    result, error = await _files(request, db, machine, "download", target, path)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.download",
        f'Downloaded {path} from {target.kind} "{name}" on "{machine.name}"',
        {"kind": target.kind, "name": name, "path": path, **({"error": error} if error else {})},
        ok=error is None,
    )
    if error is not None or result is None:
        raise _file_error(error or "?")
    return {
        "path": path,
        "size": result.get("size"),
        "mode": result.get("mode"),
        "uid": result.get("uid"),
        "gid": result.get("gid"),
        "content_b64": result.get("data_b64") or "",
    }


class _FileWrite(BaseModel):
    path: str = Field(max_length=4096)
    content_b64: str


@router.put("/{kind}/{name}/files/content", dependencies=[_terminal])
async def docker_file_write_api(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    body: _FileWrite,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Write (create or replace) one file; an existing file keeps its owner
    and mode."""
    target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, user)
    path = _path(body.path)
    if path == "/" or path.endswith("/"):
        raise _bad("Give a file path.")
    if len(body.content_b64) > (docker_files.MAX_UPLOAD_BYTES * 4) // 3 + 8:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="too_large")
    try:
        data = base64.b64decode(body.content_b64, validate=True)
    except ValueError as exc:
        raise _bad("content_b64 isn't valid base64.") from exc
    if len(data) > docker_files.MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="too_large")
    _result, error = await _files(
        request, db, machine, "write", target, path, data_b64=base64.b64encode(data).decode()
    )
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.write",
        f'Saved {path} in {target.kind} "{name}" on "{machine.name}"',
        {"kind": target.kind, "name": name, "path": path, "bytes": len(data)},
        ok=error is None,
    )
    if error is not None:
        raise _file_error(error)
    return {"ok": True, "path": path, "bytes": len(data)}


class _Mkdir(BaseModel):
    path: str = Field(max_length=4096)


@router.post("/{kind}/{name}/files/mkdir", dependencies=[_terminal])
async def docker_file_mkdir_api(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    body: _Mkdir,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, user)
    path = _path(body.path)
    folder = posixpath.basename(path)
    if path == "/" or folder in ("", ".", ".."):
        raise _bad("Give the new folder's path.")
    _result, error = await _files(request, db, machine, "mkdir", target, path)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.mkdir",
        f'Created folder {path} in {target.kind} "{name}" on "{machine.name}"',
        {"kind": target.kind, "name": name, "path": path},
        ok=error is None,
    )
    if error is not None:
        raise _file_error(error)
    return {"ok": True, "path": path}


@router.delete("/{kind}/{name}/files", dependencies=[_terminal])
async def docker_file_delete_api(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Delete a file or a folder with everything in it."""
    target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, user)
    path = _path(path)
    if path == "/":
        raise _bad("Refusing to delete the root.")
    _result, error = await _files(request, db, machine, "delete", target, path)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.delete",
        f'Deleted {path} in {target.kind} "{name}" on "{machine.name}"',
        {"kind": target.kind, "name": name, "path": path},
        ok=error is None,
    )
    if error is not None:
        raise _file_error(error)
    return {"ok": True}


# Keep `DockerJobKind` importable from here for scripts reading job kinds.
JOB_KINDS = tuple(kind.value for kind in DockerJobKind)
