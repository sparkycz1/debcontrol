"""Docker → Registries and Docker → Variables: private registry logins and
shared variables/secrets for stacks, fleet-wide, per machine group or per
machine (`app.services.docker_registries`, `app.services.docker_variables`,
scopes in `app.services.docker_scopes`).

Both need `action.terminal` — a registry login lands in the machines'
Docker configuration and a shared secret in stacks' `.env`, both
readable by anyone with a shell there. An account limited to some groups
manages only its groups' and machines' entries and sees the fleet-wide
ones without being able to change them.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.docker import DockerRegistry, DockerVariable
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_registries, docker_scopes, docker_variables
from app.services.access_scope import groups_visible_to, is_restricted, machines_visible_to
from app.tasks import docker_extras
from app.web.messages import LocalizedText
from app.web.routes.docker_fleet import tabs
from app.web.routes.machines_docker_common import redirect
from app.web.templating import templates

router = APIRouter(
    prefix="/docker",
    dependencies=[Depends(require_permission(Permission.ACTION_TERMINAL))],
)


async def scope_options(db: AsyncSession, user: User) -> dict[str, Any]:
    """What the scope picker offers: the whole fleet (unrestricted accounts
    only), the visible groups and the visible machines."""
    groups = (await db.execute(await groups_visible_to(db, user))).scalars().all()
    machines = (
        await db.execute((await machines_visible_to(db, user)).order_by(Machine.name))
    ).scalars().all()
    return {
        "allow_all": not await is_restricted(db, user),
        "groups": sorted(groups, key=lambda g: g.name.lower()),
        "machines": machines,
    }


async def scope_labels(db: AsyncSession, items: list[Any]) -> dict[uuid.UUID, str]:
    labels: dict[uuid.UUID, str] = {}
    for item in items:
        labels[item.id] = await docker_scopes.label(
            db, docker_scopes.Scope.of(item.group_id, item.machine_id)
        )
    return labels


def _page(
    request: Request, template: str, user: User, active: str, context: dict[str, Any],
    *, status_code: int = 200,
) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        template,
        {"tabs": tabs(request, user), "active_tab": active, "csrf_token": csrf_token, **context},
        status_code=status_code,
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


async def _audit(
    db: AsyncSession,
    request: Request,
    action: str,
    summary: str,
    target_type: str,
    item: DockerRegistry | DockerVariable,
    label: str,
    details: dict[str, Any],
) -> None:
    await log_event(
        db,
        request=request,
        action=action,
        summary=summary,
        target_type=target_type,
        target_id=item.id,
        target_label=label,
        details=details,
    )


# --- Registries -----------------------------------------------------------------


async def _registry_or_404(db: AsyncSession, user: User, registry_id: uuid.UUID) -> DockerRegistry:
    registry = await db.get(DockerRegistry, registry_id)
    visible = {r.id for r in await docker_registries.visible_registries(db, user)}
    if registry is None or registry.id not in visible:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such registry.")
    return registry


@router.get("/registries")
async def registries_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    registries = await docker_registries.visible_registries(db, current_user)
    manageable = {
        r.id for r in registries if await docker_registries.can_manage(db, current_user, r)
    }
    return _page(
        request,
        "docker/registries.html",
        current_user,
        "registries",
        {
            "registries": registries,
            "logins": await docker_registries.logins_of(db, registries, current_user),
            "labels": await scope_labels(db, registries),
            "manageable": manageable,
        },
    )


async def _registry_form_page(
    request: Request,
    db: AsyncSession,
    user: User,
    registry: DockerRegistry | None,
    form: docker_registries.RegistryForm | None = None,
    *,
    status_code: int = 200,
) -> Response:
    return _page(
        request,
        "docker/registry_form.html",
        user,
        "registries",
        {
            "registry": registry,
            "form": form,
            "errors": form.errors if form else [],
            "scope_value": (
                form.scope
                if form
                else docker_registries.scope_of(registry).value
                if registry
                else ""
            ),
            **(await scope_options(db, user)),
        },
        status_code=status_code,
    )


@router.get("/registries/new")
async def registry_new(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    return await _registry_form_page(request, db, current_user, None)


def _registry_form(raw: Any, *, editing: bool) -> docker_registries.RegistryForm:
    password = str(raw.get("password") or "")
    return docker_registries.RegistryForm(
        server=str(raw.get("server") or ""),
        username=str(raw.get("username") or ""),
        # An empty password field keeps the stored one when editing.
        password=None if editing and not password else password,
        description=str(raw.get("description") or ""),
        scope=str(raw.get("scope") or "all"),
    )


async def store_registry(
    request: Request,
    db: AsyncSession,
    user: User,
    registry: DockerRegistry | None,
    form: docker_registries.RegistryForm,
) -> tuple[DockerRegistry, int]:
    """Save a checked form, queue the logins it changes and audit it (the
    web page and the API both end here): (registry, machines queued)."""
    old_scope = docker_registries.scope_of(registry) if registry is not None else None
    old_server = registry.server if registry is not None else ""
    creating = registry is None
    if registry is None:
        registry = DockerRegistry(created_by=user.username)
        db.add(registry)
    form.apply(registry)
    await db.commit()
    await db.refresh(registry)
    scope = docker_registries.scope_of(registry)
    affected = await docker_registries.machine_ids_in_scope(db, scope)
    if old_scope is not None:
        affected += await docker_registries.machine_ids_in_scope(db, old_scope)
        affected += await docker_registries.machine_ids_logged_in(db, old_server)
    queued = docker_extras.queue_registry_sync(affected)
    label = await docker_scopes.label(db, scope)
    await _audit(
        db,
        request,
        "docker.registry.create" if creating else "docker.registry.edit",
        f'{"Added" if creating else "Changed"} the Docker registry login "{registry.server}" '
        f"({registry.username}) for {label}",
        "docker_registry",
        registry,
        registry.server,
        {
            "server": registry.server,
            "username": registry.username,
            "scope": label,
            "password_changed": form.password is not None,
            "machines": queued,
        },
    )
    return registry, queued


async def relogin_registry(request: Request, db: AsyncSession, registry: DockerRegistry) -> int:
    """Log every machine in scope in again; returns how many were queued."""
    scope = docker_registries.scope_of(registry)
    queued = docker_extras.queue_registry_sync(
        await docker_registries.machine_ids_in_scope(db, scope), force=True
    )
    label = await docker_scopes.label(db, scope)
    await _audit(
        db,
        request,
        "docker.registry.login",
        f'Started logging {queued} machine(s) in to the Docker registry "{registry.server}" again',
        "docker_registry",
        registry,
        registry.server,
        {"server": registry.server, "scope": label, "machines": queued},
    )
    return queued


async def remove_registry(request: Request, db: AsyncSession, registry: DockerRegistry) -> int:
    """Forget the login; the machines that used it log out (or switch to a
    broader entry for the same server)."""
    registry_id = registry.id
    label = await docker_scopes.label(db, docker_registries.scope_of(registry))
    server = registry.server
    affected = await docker_registries.machine_ids_logged_in(db, server)
    await db.delete(registry)
    await db.commit()
    queued = docker_extras.queue_registry_sync(affected)
    await log_event(
        db,
        request=request,
        action="docker.registry.delete",
        summary=f'Removed the Docker registry login "{server}" for {label}',
        target_type="docker_registry",
        target_id=registry_id,
        target_label=server,
        details={"server": server, "scope": label, "machines": queued},
    )
    return queued


async def _save_registry(
    request: Request,
    db: AsyncSession,
    user: User,
    registry: DockerRegistry | None,
) -> Response:
    raw = await request.form()
    form = _registry_form(raw, editing=registry is not None)
    if await form.validate(db, user, registry):
        return await _registry_form_page(
            request, db, user, registry, form, status_code=status.HTTP_400_BAD_REQUEST
        )
    _registry, queued = await store_registry(request, db, user, registry, form)
    return redirect(
        "/docker/registries",
        notice=LocalizedText(request, "docker.registry.saved", machines=queued),
    )


@router.post("/registries", dependencies=[Depends(verify_csrf)])
async def registry_create(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    return await _save_registry(request, db, current_user, None)


@router.get("/registries/{registry_id}")
async def registry_edit(
    request: Request,
    registry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    registry = await _registry_or_404(db, current_user, registry_id)
    if not await docker_registries.can_manage(db, current_user, registry):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    return await _registry_form_page(request, db, current_user, registry)


@router.post("/registries/{registry_id}", dependencies=[Depends(verify_csrf)])
async def registry_save(
    request: Request,
    registry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    registry = await _registry_or_404(db, current_user, registry_id)
    if not await docker_registries.can_manage(db, current_user, registry):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    return await _save_registry(request, db, current_user, registry)


@router.post("/registries/{registry_id}/login", dependencies=[Depends(verify_csrf)])
async def registry_login(
    request: Request,
    registry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Log every machine in scope in again (after a token was rotated at
    the registry, or a machine came back)."""
    registry = await _registry_or_404(db, current_user, registry_id)
    if not await docker_registries.can_manage(db, current_user, registry):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    queued = await relogin_registry(request, db, registry)
    return redirect(
        "/docker/registries",
        notice=LocalizedText(request, "docker.registry.login_queued", machines=queued),
    )


@router.post("/registries/{registry_id}/delete", dependencies=[Depends(verify_csrf)])
async def registry_delete(
    request: Request,
    registry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Forget the login; the machines that used it log out (or switch to a
    broader entry for the same server)."""
    registry = await _registry_or_404(db, current_user, registry_id)
    if not await docker_registries.can_manage(db, current_user, registry):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    await remove_registry(request, db, registry)
    return redirect("/docker/registries", notice=LocalizedText(request, "docker.registry.deleted"))


# --- Variables ------------------------------------------------------------------


async def _variable_or_404(db: AsyncSession, user: User, variable_id: uuid.UUID) -> DockerVariable:
    variable = await db.get(DockerVariable, variable_id)
    visible = {v.id for v in await docker_variables.visible_variables(db, user)}
    if variable is None or variable.id not in visible:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such variable.")
    return variable


@router.get("/variables")
async def variables_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    variables = await docker_variables.visible_variables(db, current_user)
    manageable = {
        v.id for v in variables if await docker_variables.can_manage(db, current_user, v)
    }
    using = await docker_variables.stacks_using(db, {v.name for v in variables}, current_user)
    return _page(
        request,
        "docker/variables.html",
        current_user,
        "variables",
        {
            "variables": variables,
            "labels": await scope_labels(db, variables),
            "manageable": manageable,
            "using": {name: len(stacks) for name, stacks in using.items()},
            "shown": {v.id: docker_variables.shown_value(v) for v in variables},
        },
    )


async def _variable_form_page(
    request: Request,
    db: AsyncSession,
    user: User,
    variable: DockerVariable | None,
    form: docker_variables.VariableForm | None = None,
    *,
    status_code: int = 200,
) -> Response:
    return _page(
        request,
        "docker/variable_form.html",
        user,
        "variables",
        {
            "variable": variable,
            "form": form,
            "errors": form.errors if form else [],
            "value": (
                docker_variables.shown_value(variable) if variable is not None else None
            ),
            "scope_value": (
                form.scope
                if form
                else docker_variables.scope_of(variable).value
                if variable
                else ""
            ),
            **(await scope_options(db, user)),
        },
        status_code=status_code,
    )


@router.get("/variables/new")
async def variable_new(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    return await _variable_form_page(request, db, current_user, None)


async def store_variable(
    request: Request,
    db: AsyncSession,
    user: User,
    variable: DockerVariable | None,
    form: docker_variables.VariableForm,
) -> DockerVariable:
    """Save a checked form and audit it (the web page and the API)."""
    creating = variable is None
    if variable is None:
        variable = DockerVariable(created_by=user.username)
        db.add(variable)
    form.apply(variable)
    variable.updated_by = user.username
    await db.commit()
    await db.refresh(variable)
    label = await docker_scopes.label(db, docker_variables.scope_of(variable))
    await _audit(
        db,
        request,
        "docker.variable.create" if creating else "docker.variable.edit",
        f'{"Added" if creating else "Changed"} the shared Docker variable "{variable.name}" '
        f"for {label}",
        "docker_variable",
        variable,
        variable.name,
        {
            "name": variable.name,
            "scope": label,
            "secret": variable.secret,
            "value_changed": form.value is not None,
        },
    )
    return variable


async def remove_variable(request: Request, db: AsyncSession, variable: DockerVariable) -> None:
    variable_id = variable.id
    label = await docker_scopes.label(db, docker_variables.scope_of(variable))
    name = variable.name
    await db.delete(variable)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="docker.variable.delete",
        summary=f'Removed the shared Docker variable "{name}" for {label}',
        target_type="docker_variable",
        target_id=variable_id,
        target_label=name,
        details={"name": name, "scope": label},
    )


async def _save_variable(
    request: Request, db: AsyncSession, user: User, variable: DockerVariable | None
) -> Response:
    raw = await request.form()
    keep = variable is not None and raw.get("value_action") == "keep"
    form = docker_variables.VariableForm(
        name=str(raw.get("name") or ""),
        value=None if keep else str(raw.get("value") or ""),
        secret=raw.get("secret") == "1",
        description=str(raw.get("description") or ""),
        scope=str(raw.get("scope") or "all"),
    )
    if await form.validate(db, user, variable):
        return await _variable_form_page(
            request, db, user, variable, form, status_code=status.HTTP_400_BAD_REQUEST
        )
    await store_variable(request, db, user, variable, form)
    return redirect("/docker/variables", notice=LocalizedText(request, "docker.variable.saved"))


@router.post("/variables", dependencies=[Depends(verify_csrf)])
async def variable_create(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    return await _save_variable(request, db, current_user, None)


@router.get("/variables/{variable_id}")
async def variable_edit(
    request: Request,
    variable_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    variable = await _variable_or_404(db, current_user, variable_id)
    if not await docker_variables.can_manage(db, current_user, variable):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    return await _variable_form_page(request, db, current_user, variable)


@router.post("/variables/{variable_id}", dependencies=[Depends(verify_csrf)])
async def variable_save(
    request: Request,
    variable_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    variable = await _variable_or_404(db, current_user, variable_id)
    if not await docker_variables.can_manage(db, current_user, variable):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    return await _save_variable(request, db, current_user, variable)


@router.post("/variables/{variable_id}/delete", dependencies=[Depends(verify_csrf)])
async def variable_delete(
    request: Request,
    variable_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    variable = await _variable_or_404(db, current_user, variable_id)
    if not await docker_variables.can_manage(db, current_user, variable):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")
    await remove_variable(request, db, variable)
    return redirect("/docker/variables", notice=LocalizedText(request, "docker.variable.deleted"))
