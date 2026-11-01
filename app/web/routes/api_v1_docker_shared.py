"""REST API for Docker → Registries and Docker → Variables: private
registry logins and shared variables/secrets for stacks
(`app.services.docker_registries`, `app.services.docker_variables`).

The same rules as the web pages (`app.web.routes.docker_shared`, whose
store/remove functions these call): `action.terminal` for everything; an
account (or token) limited to some machine groups manages only its
groups' and machines' entries (`scope`: "all", "group:<id>",
"machine:<id>"), and sees fleet-wide ones read-only. A registry password
and a secret variable's value are never returned.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.docker import DockerRegistry, DockerVariable
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import docker_registries, docker_scopes, docker_variables
from app.web.routes.docker_shared import (
    relogin_registry,
    remove_registry,
    remove_variable,
    store_registry,
    store_variable,
)

router = APIRouter(prefix="/api/v1/docker", tags=["docker"])
_terminal = Depends(require_api_permission(Permission.ACTION_TERMINAL))


def _invalid(errors: list[str]) -> HTTPException:
    return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=errors)


def _forbidden() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="This entry's scope is outside the machine groups this account may manage.",
    )


# --- Registries -----------------------------------------------------------------


class _RegistryIn(BaseModel):
    server: str = Field(max_length=300)
    username: str = Field(max_length=255)
    # Required on create; None keeps the stored one on change.
    password: str | None = Field(default=None, max_length=4096)
    description: str = Field(default="", max_length=255)
    scope: str = Field(default="all", max_length=64)


async def _registry(db: AsyncSession, user: User, registry_id: uuid.UUID) -> DockerRegistry:
    for registry in await docker_registries.visible_registries(db, user):
        if registry.id == registry_id:
            return registry
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such registry.")


async def _registry_out(
    db: AsyncSession, user: User, registry: DockerRegistry
) -> dict[str, Any]:
    logins = await docker_registries.logins_of(db, [registry], user)
    label = await docker_scopes.label(db, docker_registries.scope_of(registry))
    return docker_registries.as_api(registry, logins.get(registry.id, []), label)


@router.get("/registries", dependencies=[_terminal])
async def registries_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, Any]]:
    """Every registry login the account may see, with each machine's login
    status (`ok` / `failed` and docker's message)."""
    registries = await docker_registries.visible_registries(db, user)
    logins = await docker_registries.logins_of(db, registries, user)
    out: list[dict[str, Any]] = []
    for registry in registries:
        label = await docker_scopes.label(db, docker_registries.scope_of(registry))
        out.append(docker_registries.as_api(registry, logins.get(registry.id, []), label))
    return out


@router.post("/registries", dependencies=[_terminal], status_code=status.HTTP_201_CREATED)
async def registry_create_api(
    request: Request,
    body: _RegistryIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Add a registry login; every machine in its scope logs in (queued)."""
    form = docker_registries.RegistryForm(
        server=body.server,
        username=body.username,
        password=body.password or None,
        description=body.description,
        scope=body.scope,
    )
    if errors := await form.validate(db, user):
        raise _invalid(errors)
    registry, queued = await store_registry(request, db, user, None, form)
    return {"registry": await _registry_out(db, user, registry), "machines_queued": queued}


@router.get("/registries/{registry_id}", dependencies=[_terminal])
async def registry_api(
    registry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    return await _registry_out(db, user, await _registry(db, user, registry_id))


@router.put("/registries/{registry_id}", dependencies=[_terminal])
async def registry_save_api(
    request: Request,
    registry_id: uuid.UUID,
    body: _RegistryIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Change a registry login (`password` omitted keeps it); the machines
    it touches log in again."""
    registry = await _registry(db, user, registry_id)
    if not await docker_registries.can_manage(db, user, registry):
        raise _forbidden()
    form = docker_registries.RegistryForm(
        server=body.server,
        username=body.username,
        password=body.password or None,
        description=body.description,
        scope=body.scope,
    )
    if errors := await form.validate(db, user, registry):
        raise _invalid(errors)
    registry, queued = await store_registry(request, db, user, registry, form)
    return {"registry": await _registry_out(db, user, registry), "machines_queued": queued}


@router.post("/registries/{registry_id}/login", dependencies=[_terminal])
async def registry_login_api(
    request: Request,
    registry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Log every machine in scope in again."""
    registry = await _registry(db, user, registry_id)
    if not await docker_registries.can_manage(db, user, registry):
        raise _forbidden()
    return {"machines_queued": await relogin_registry(request, db, registry)}


@router.delete(
    "/registries/{registry_id}",
    dependencies=[_terminal],
    status_code=status.HTTP_204_NO_CONTENT,
)
async def registry_delete_api(
    request: Request,
    registry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    """Remove a registry login; the machines that used it log out."""
    registry = await _registry(db, user, registry_id)
    if not await docker_registries.can_manage(db, user, registry):
        raise _forbidden()
    await remove_registry(request, db, registry)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Variables ------------------------------------------------------------------


class _VariableIn(BaseModel):
    name: str = Field(max_length=128)
    # Required on create; None keeps the stored value on change.
    value: str | None = Field(default=None, max_length=16384)
    secret: bool = False
    description: str = Field(default="", max_length=255)
    scope: str = Field(default="all", max_length=64)


async def _variable(db: AsyncSession, user: User, variable_id: uuid.UUID) -> DockerVariable:
    for variable in await docker_variables.visible_variables(db, user):
        if variable.id == variable_id:
            return variable
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such variable.")


async def _variable_out(
    db: AsyncSession, user: User, variable: DockerVariable
) -> dict[str, Any]:
    label = await docker_scopes.label(db, docker_variables.scope_of(variable))
    using = await docker_variables.stacks_using(db, {variable.name}, user)
    return docker_variables.as_api(variable, label, len(using.get(variable.name, [])))


@router.get("/variables", dependencies=[_terminal])
async def variables_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, Any]]:
    """Every shared variable the account may see (a secret one without
    its value), with how many stacks pick it by name."""
    variables = await docker_variables.visible_variables(db, user)
    using = await docker_variables.stacks_using(db, {v.name for v in variables}, user)
    out: list[dict[str, Any]] = []
    for variable in variables:
        label = await docker_scopes.label(db, docker_variables.scope_of(variable))
        out.append(docker_variables.as_api(variable, label, len(using.get(variable.name, []))))
    return out


@router.post("/variables", dependencies=[_terminal], status_code=status.HTTP_201_CREATED)
async def variable_create_api(
    request: Request,
    body: _VariableIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    form = docker_variables.VariableForm(
        name=body.name,
        value=body.value,
        secret=body.secret,
        description=body.description,
        scope=body.scope,
    )
    if errors := await form.validate(db, user):
        raise _invalid(errors)
    variable = await store_variable(request, db, user, None, form)
    return await _variable_out(db, user, variable)


@router.get("/variables/{variable_id}", dependencies=[_terminal])
async def variable_api(
    variable_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    return await _variable_out(db, user, await _variable(db, user, variable_id))


@router.put("/variables/{variable_id}", dependencies=[_terminal])
async def variable_save_api(
    request: Request,
    variable_id: uuid.UUID,
    body: _VariableIn,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Change a variable (`value` omitted keeps it); stacks using it show
    as changed since their deploy until deployed again."""
    variable = await _variable(db, user, variable_id)
    if not await docker_variables.can_manage(db, user, variable):
        raise _forbidden()
    form = docker_variables.VariableForm(
        name=body.name,
        value=body.value,
        secret=body.secret,
        description=body.description,
        scope=body.scope,
    )
    if errors := await form.validate(db, user, variable):
        raise _invalid(errors)
    variable = await store_variable(request, db, user, variable, form)
    return await _variable_out(db, user, variable)


@router.delete(
    "/variables/{variable_id}",
    dependencies=[_terminal],
    status_code=status.HTTP_204_NO_CONTENT,
)
async def variable_delete_api(
    request: Request,
    variable_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    variable = await _variable(db, user, variable_id)
    if not await docker_variables.can_manage(db, user, variable):
        raise _forbidden()
    await remove_variable(request, db, variable)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
