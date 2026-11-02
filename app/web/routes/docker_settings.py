"""Docker → Settings (`/docker/settings`): the daemon.json keys debcontrol
keeps the same across the fleet, and the defaults for containers and
stacks it sees for the first time (`app.services.docker_daemon`).

- seeing the page: `settings.view`;
- saving: `settings.manage`, and an account not limited to some machine
  groups (the settings are for the whole fleet);
- "Apply to machines" (writes daemon.json, as root, on every machine in
  scope it can see): `settings.manage` + `action.terminal`;
- "Restart Docker where waiting": `action.power`.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.app_settings import AppSettings
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_daemon, self_host
from app.services.access_scope import groups_visible_to, is_restricted
from app.web.messages import LocalizedText
from app.web.routes.docker_fleet import tabs
from app.web.routes.machines_docker_common import actor, redirect
from app.web.templating import t, templates

router = APIRouter(
    prefix="/docker/settings",
    dependencies=[Depends(require_permission(Permission.SETTINGS_VIEW))],
)
_manage = Depends(require_permission(Permission.SETTINGS_MANAGE))
_terminal = Depends(require_permission(Permission.ACTION_TERMINAL))
_power = Depends(require_permission(Permission.ACTION_POWER))


def defaults_of(settings: AppSettings) -> dict[str, Any]:
    return {
        "update_policy": settings.docker_default_update_policy or "",
        "vulnerability_gate": settings.docker_default_vulnerability_gate or "",
        "autoheal": bool(settings.docker_default_autoheal),
    }


def clean_defaults(raw: dict[str, Any]) -> dict[str, Any]:
    """Validated defaults; raises `DaemonSettingsError`."""
    policy = str(raw.get("update_policy") or "")
    gate = str(raw.get("vulnerability_gate") or "")
    if policy and policy not in docker_daemon.UPDATE_POLICIES:
        raise docker_daemon.DaemonSettingsError("update_policy", "docker.settings.error.choice")
    if gate and gate not in docker_daemon.GATES:
        raise docker_daemon.DaemonSettingsError(
            "vulnerability_gate", "docker.settings.error.choice"
        )
    return {
        "update_policy": policy or None,
        "vulnerability_gate": gate or None,
        "autoheal": raw.get("autoheal") in (True, "1", "on", "true"),
    }


def store(
    settings: AppSettings,
    config: dict[str, Any],
    group_ids: list[uuid.UUID],
    defaults: dict[str, Any],
) -> list[str]:
    """Save everything; returns the names of what changed (for the audit)."""
    changed: list[str] = []
    old = settings.docker_daemon_config or {}
    changed += sorted(k for k in set(old) | set(config) if old.get(k) != config.get(k))
    new_groups = [str(g) for g in group_ids] or None
    if (settings.docker_daemon_group_ids or None) != new_groups:
        changed.append("groups")
    for name, value in defaults.items():
        if defaults_of(settings)[name] != (value if value is not None else ""):
            changed.append(f"default_{name}")
    settings.docker_daemon_config = config or None
    settings.docker_daemon_group_ids = new_groups
    settings.docker_default_update_policy = defaults["update_policy"]
    settings.docker_default_vulnerability_gate = defaults["vulnerability_gate"]
    settings.docker_default_autoheal = defaults["autoheal"]
    return changed


async def _page(
    request: Request,
    db: AsyncSession,
    user: User,
    settings: AppSettings,
    *,
    values: dict[str, str] | None = None,
    defaults: dict[str, Any] | None = None,
    group_ids: list[str] | None = None,
    error: str | None = None,
    error_field: str | None = None,
) -> Response:
    groups = (await db.execute(await groups_visible_to(db, user))).scalars().all()
    targets = await docker_daemon.target_machines(db, user, settings)
    own = (await self_host.find(db)).hosts
    pending = [m for m in await docker_daemon.pending_restart(db, user) if m.id not in own]
    status_rows = [(m, docker_daemon.machine_status(m, settings)) for m in targets]
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "docker/settings.html",
        {
            "tabs": tabs(request, user),
            "active_tab": "settings",
            "csrf_token": csrf_token,
            "values": values or docker_daemon.form_values(settings.docker_daemon_config),
            "defaults": defaults or defaults_of(settings),
            "groups": sorted(groups, key=lambda g: g.name.lower()),
            "group_ids": group_ids
            if group_ids is not None
            else [str(g) for g in settings.docker_daemon_group_ids or []],
            "configured": bool(settings.docker_daemon_config),
            "status_rows": status_rows,
            "differing": sum(1 for _m, s in status_rows if s["differences"]),
            "pending": pending,
            "log_drivers": docker_daemon.LOG_DRIVERS,
            "policies": docker_daemon.UPDATE_POLICIES,
            "gates": docker_daemon.GATES,
            "can_manage": user.has_permission(Permission.SETTINGS_MANAGE)
            and not await is_restricted(db, user),
            "can_apply": user.has_permission(Permission.SETTINGS_MANAGE)
            and user.has_permission(Permission.ACTION_TERMINAL),
            "can_restart": user.has_permission(Permission.ACTION_POWER),
            "error": error,
            "error_field": error_field,
        },
        status_code=status.HTTP_400_BAD_REQUEST if error else status.HTTP_200_OK,
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("")
async def docker_settings_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    settings = await get_or_create_app_settings(db)
    return await _page(request, db, current_user, settings)


async def parse_group_ids(db: AsyncSession, user: User, raw: list[str]) -> list[uuid.UUID]:
    visible = {g.id for g in (await db.execute(await groups_visible_to(db, user))).scalars()}
    ids: list[uuid.UUID] = []
    for value in raw:
        try:
            group_id = uuid.UUID(value)
        except ValueError:
            continue
        if group_id in visible and group_id not in ids:
            ids.append(group_id)
    return ids


@router.post("", dependencies=[_manage, Depends(verify_csrf)])
async def docker_settings_save(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if await is_restricted(db, current_user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    form = await request.form()
    raw = {name: str(form.get(name) or "") for name in docker_daemon.FIELDS}
    raw_defaults = {
        "update_policy": str(form.get("default_update_policy") or ""),
        "vulnerability_gate": str(form.get("default_vulnerability_gate") or ""),
        "autoheal": str(form.get("default_autoheal") or ""),
    }
    raw_groups = [str(v) for v in form.getlist("group")]
    settings = await get_or_create_app_settings(db)
    try:
        config = docker_daemon.clean(raw)
        defaults = clean_defaults(raw_defaults)
    except docker_daemon.DaemonSettingsError as exc:
        return await _page(
            request,
            db,
            current_user,
            settings,
            values=raw,
            defaults={**raw_defaults, "autoheal": raw_defaults["autoheal"] == "1"},
            group_ids=raw_groups,
            error=t(request, exc.key),
            error_field=exc.field,
        )
    group_ids = await parse_group_ids(db, current_user, raw_groups)
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
    return redirect("/docker/settings", notice=LocalizedText(request, "docker.settings.saved"))


@router.post("/apply", dependencies=[_manage, _terminal, Depends(verify_csrf)])
async def docker_settings_apply(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Write the daemon.json keys on every machine in scope this account
    can see: one job each (no restart)."""
    settings = await get_or_create_app_settings(db)
    if not settings.docker_daemon_config:
        return redirect(
            "/docker/settings", error=LocalizedText(request, "docker.settings.nothing_managed")
        )
    machines = await docker_daemon.target_machines(db, current_user, settings)
    who = actor(current_user)
    queued = [m for m in machines if await docker_daemon.queue_apply(db, m, actor=who)]
    await log_event(
        db,
        request=request,
        action="docker.settings.apply",
        summary=f"Docker settings: daemon.json queued for {len(queued)} machine(s)",
        target_type="settings",
        target_label="Docker",
        details={"machines": [m.name for m in queued][:200], "count": len(queued)},
    )
    return redirect(
        "/docker/settings",
        notice=LocalizedText(request, "docker.settings.apply_queued", count=len(queued)),
    )


@router.post("/restart", dependencies=[_power, Depends(verify_csrf)])
async def docker_settings_restart(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Restart Docker on every visible machine with a written daemon.json
    that Docker has not read yet — never the machine debcontrol runs on.
    Each restart is audited."""
    machines = await docker_daemon.pending_restart(db, current_user)
    own = (await self_host.find(db)).hosts
    count = 0
    for machine in machines:
        if machine.id in own:
            continue
        job = await docker_daemon.queue_restart(db, machine, actor=actor(current_user))
        if job is None:
            continue
        count += 1
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
    return redirect(
        "/docker/settings",
        notice=LocalizedText(request, "docker.settings.restart_queued", count=count),
    )
