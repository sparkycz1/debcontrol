"""REST API for Docker → Settings (`app.services.docker_daemon`): the
daemon.json keys debcontrol keeps the same across the fleet, the defaults
for new containers and stacks, and writing / restarting per machine.

The same rules as the web page (`app.web.routes.docker_settings`):
`settings.view` to read, `settings.manage` (and a token not limited to
some machine groups) to change, `settings.manage` + `action.terminal` to
write daemon.json on the machines, `action.power` to restart Docker.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.core.app_settings import get_or_create_app_settings
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_daemon, self_host
from app.services.access_scope import is_restricted
from app.web.routes.api_v1 import _get_machine_or_404
from app.web.routes.docker_settings import clean_defaults, parse_group_ids, store

router = APIRouter(tags=["docker"])
_view = Depends(require_api_permission(Permission.SETTINGS_VIEW))
_manage = Depends(require_api_permission(Permission.SETTINGS_MANAGE))
_terminal = Depends(require_api_permission(Permission.ACTION_TERMINAL))
_power = Depends(require_api_permission(Permission.ACTION_POWER))
_machine_view = Depends(require_api_permission(Permission.MACHINE_VIEW))


class _Daemon(BaseModel):
    """Leave a field out (or empty) and debcontrol leaves that key alone."""

    log_driver: str | None = Field(default=None, max_length=20)
    log_max_size: str | None = Field(default=None, max_length=10)
    log_max_file: int | None = Field(default=None, ge=1, le=100)
    live_restore: bool | None = None
    address_pools: list[str] = Field(default_factory=list, max_length=docker_daemon.MAX_POOLS)
    registry_mirrors: list[str] = Field(
        default_factory=list, max_length=docker_daemon.MAX_MIRRORS
    )
    dns: list[str] = Field(default_factory=list, max_length=docker_daemon.MAX_DNS)
    no_new_privileges: bool | None = None
    builder_keep_storage: str | None = Field(default=None, max_length=10)


class _Defaults(BaseModel):
    update_policy: str | None = Field(default=None, max_length=8)
    vulnerability_gate: str | None = Field(default=None, max_length=16)
    autoheal: bool = False


class _SettingsIn(BaseModel):
    daemon: _Daemon = Field(default_factory=_Daemon)
    group_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    defaults: _Defaults = Field(default_factory=_Defaults)


def _out(settings: Any) -> dict[str, Any]:
    return {
        "daemon": settings.docker_daemon_config or {},
        "group_ids": list(settings.docker_daemon_group_ids or []),
        "defaults": {
            "update_policy": settings.docker_default_update_policy,
            "vulnerability_gate": settings.docker_default_vulnerability_gate,
            "autoheal": bool(settings.docker_default_autoheal),
        },
    }


@router.get("/api/v1/docker/settings", dependencies=[_view])
async def docker_settings_api(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    """The managed daemon.json keys (only those set), the machine groups
    they are for (empty = every machine) and the defaults."""
    return _out(await get_or_create_app_settings(db))


@router.put("/api/v1/docker/settings", dependencies=[_manage])
async def docker_settings_save_api(
    request: Request,
    body: _SettingsIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Replace the settings (a field left out stops being managed). 422
    with `{"field", "error"}` for an invalid value."""
    if await is_restricted(db, user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    raw = body.daemon.model_dump()
    raw["live_restore"] = {None: "", True: "on", False: "off"}[raw["live_restore"]]
    raw["no_new_privileges"] = {None: "", True: "on", False: "off"}[raw["no_new_privileges"]]
    raw["log_max_file"] = "" if raw["log_max_file"] is None else str(raw["log_max_file"])
    try:
        config = docker_daemon.clean(raw)
        defaults = clean_defaults(
            {
                "update_policy": body.defaults.update_policy or "",
                "vulnerability_gate": body.defaults.vulnerability_gate or "",
                "autoheal": body.defaults.autoheal,
            }
        )
    except docker_daemon.DaemonSettingsError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"field": exc.field, "error": exc.key},
        ) from None
    settings = await get_or_create_app_settings(db)
    group_ids = await parse_group_ids(db, user, [str(g) for g in body.group_ids])
    changed = store(settings, config, group_ids, defaults)
    await db.commit()
    if changed:
        await log_event(
            db,
            request=request,
            action="docker.settings.update",
            summary="Docker settings changed: " + ", ".join(changed),
            target_type="settings",
            target_label="Docker",
            details={"changed": changed, "daemon": config, "defaults": defaults},
        )
    return {**_out(settings), "changed": changed}


@router.get("/api/v1/docker/settings/machines", dependencies=[_view, _machine_view])
async def docker_settings_machines_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Each visible machine in scope: what differs from the settings and
    whether a Docker restart is waiting."""
    settings = await get_or_create_app_settings(db)
    machines = await docker_daemon.target_machines(db, user, settings)
    return {
        "machines": [
            {"id": str(m.id), "name": m.name, **docker_daemon.machine_status(m, settings)}
            for m in machines
        ]
    }


@router.post("/api/v1/docker/settings/apply", dependencies=[_manage, _terminal])
async def docker_settings_apply_api(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Write the managed keys into daemon.json on every visible machine in
    scope (one job each; Docker is not restarted)."""
    settings = await get_or_create_app_settings(db)
    if not settings.docker_daemon_config:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Nothing is managed.")
    jobs: dict[str, str] = {}
    for machine in await docker_daemon.target_machines(db, user, settings):
        job = await docker_daemon.queue_apply(db, machine, actor=user.username)
        if job is not None:
            jobs[str(machine.id)] = str(job.id)
    await log_event(
        db,
        request=request,
        action="docker.settings.apply",
        summary=f"Docker settings: daemon.json queued for {len(jobs)} machine(s)",
        target_type="settings",
        target_label="Docker",
        details={"count": len(jobs)},
    )
    return {"queued": len(jobs), "jobs": jobs}


async def _restart(request: Request, db: AsyncSession, user: User, machine: Any) -> str | None:
    job = await docker_daemon.queue_restart(db, machine, actor=user.username)
    if job is None:
        return None
    await log_event(
        db,
        request=request,
        action="machine.docker.daemon.restart",
        summary=f'Docker daemon restart queued on "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"job": str(job.id)},
    )
    return str(job.id)


@router.post("/api/v1/docker/settings/restart", dependencies=[_power])
async def docker_settings_restart_api(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Restart Docker on every visible machine whose daemon.json was
    written but not yet read (debcontrol's own host is left out)."""
    own = (await self_host.find(db)).hosts
    jobs: dict[str, str] = {}
    for machine in await docker_daemon.pending_restart(db, user):
        if machine.id in own:
            continue
        job_id = await _restart(request, db, user, machine)
        if job_id:
            jobs[str(machine.id)] = job_id
    return {"queued": len(jobs), "jobs": jobs}


@router.post(
    "/api/v1/machines/{machine_id}/docker/daemon/apply", dependencies=[_machine_view, _terminal]
)
async def docker_daemon_apply_api(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Write the settings into this machine's daemon.json (202-style: the
    job). 409 when the machine is not in the settings' scope."""
    machine = await _get_machine_or_404(machine_id, db, user)
    settings = await get_or_create_app_settings(db)
    if not docker_daemon.machine_status(machine, settings)["in_scope"]:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Not in scope.")
    job = await docker_daemon.queue_apply(db, machine, actor=user.username)
    if job is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Already queued.")
    await log_event(
        db,
        request=request,
        action="machine.docker.daemon.apply",
        summary=f'Docker settings: daemon.json queued for "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"job": str(job.id)},
    )
    return {"job": str(job.id)}


@router.post(
    "/api/v1/machines/{machine_id}/docker/daemon/restart", dependencies=[_machine_view, _power]
)
async def docker_daemon_restart_api(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Restart Docker so it reads daemon.json (the job). 409 on the machine
    debcontrol runs on."""
    machine = await _get_machine_or_404(machine_id, db, user)
    if machine.id in (await self_host.find(db)).hosts:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="debcontrol runs on this machine."
        )
    job_id = await _restart(request, db, user, machine)
    if job_id is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Already queued.")
    return {"job": job_id}
