"""Private registries (`DockerRegistry`): which login applies to which
machine, the form that creates or edits one, and whether `docker login`
worked on each machine (`DockerRegistryLogin`).

Saving or removing a registry queues `sync_registry_logins` for every
machine it touches (one Celery task per machine, never awaited inline);
each machine's image update check logs in first where a login is still
missing, so a machine added to a group later picks its logins up by
itself. The password is stored encrypted and never shown again.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import encrypt_secret
from app.db.models.docker import DockerRegistry, DockerRegistryLogin
from app.db.models.machine import Machine
from app.db.models.user import User
from app.services.access_scope import allowed_group_ids
from app.services.docker_scopes import Scope, check_scope
from app.ssh.docker_registry import is_password_valid, is_username_valid, normalize_server

MAX_REGISTRIES = 500


@dataclass
class RegistryForm:
    """What the registry form (or the API) sends, checked."""

    server: str
    username: str
    # None = keep the stored password.
    password: str | None
    description: str = ""
    scope: str = "all"
    parsed_scope: Scope | None = None
    errors: list[str] = field(default_factory=list)

    async def validate(
        self, db: AsyncSession, user: User, stored: DockerRegistry | None = None
    ) -> list[str]:
        errors: list[str] = []
        server = normalize_server(self.server)
        if server is None:
            errors.append("docker.registry.error.server")
        else:
            self.server = server
        self.username = self.username.strip()
        if not is_username_valid(self.username):
            errors.append("docker.registry.error.username")
        # A password is never sent to another server than it was given for.
        moved = stored is not None and server is not None and server != stored.server
        missing = self.password is None and (stored is None or moved)
        if missing or (self.password is not None and not is_password_valid(self.password)):
            errors.append("docker.registry.error.password")
        self.description = self.description.strip()[:255]
        self.parsed_scope = Scope.parse(self.scope)
        if self.parsed_scope is None or not await check_scope(db, user, self.parsed_scope):
            errors.append("docker.scope.error")
        if not errors and self.parsed_scope is not None:
            query = select(DockerRegistry.id).where(
                DockerRegistry.server == self.server,
                DockerRegistry.scope_key == self.parsed_scope.key,
            )
            if stored is not None:
                query = query.where(DockerRegistry.id != stored.id)
            if (await db.execute(query.limit(1))).first() is not None:
                errors.append("docker.registry.error.taken")
        self.errors = errors
        return errors

    def apply(self, registry: DockerRegistry) -> None:
        assert self.parsed_scope is not None
        registry.server = self.server
        registry.username = self.username
        registry.description = self.description
        registry.group_id = self.parsed_scope.group_id
        registry.machine_id = self.parsed_scope.machine_id
        registry.scope_key = self.parsed_scope.key
        if self.password is not None:
            registry.password_encrypted = encrypt_secret(self.password)


def scope_of(registry: DockerRegistry) -> Scope:
    return Scope.of(registry.group_id, registry.machine_id)


async def visible_registries(db: AsyncSession, user: User) -> list[DockerRegistry]:
    """The registries `user` may see: every fleet-wide one, and those of
    the groups and machines the account may see."""
    query = select(DockerRegistry).order_by(DockerRegistry.server, DockerRegistry.scope_key)
    allowed = await allowed_group_ids(db, user)
    if allowed is not None:
        visible_machines = select(Machine.id).where(Machine.group_id.in_(allowed))
        query = query.where(
            or_(
                DockerRegistry.scope_key == "",
                DockerRegistry.group_id.in_(allowed),
                DockerRegistry.machine_id.in_(visible_machines),
            )
        )
    return list((await db.execute(query.limit(MAX_REGISTRIES))).scalars().all())


async def can_manage(db: AsyncSession, user: User, registry: DockerRegistry) -> bool:
    return await check_scope(db, user, scope_of(registry))


def _most_specific(
    rows: Iterable[DockerRegistry], machine: Machine
) -> dict[str, DockerRegistry]:
    chosen: dict[str, DockerRegistry] = {}
    for row in rows:
        scope = scope_of(row)
        if not scope.applies_to(machine):
            continue
        current = chosen.get(row.server)
        if current is None or scope.rank > scope_of(current).rank:
            chosen[row.server] = row
    return chosen


async def applicable(db: AsyncSession, machine: Machine) -> dict[str, DockerRegistry]:
    """{server: the registry login that applies to `machine`}."""
    conditions = [DockerRegistry.scope_key == "", DockerRegistry.machine_id == machine.id]
    if machine.group_id is not None:
        conditions.append(DockerRegistry.group_id == machine.group_id)
    rows = (await db.execute(select(DockerRegistry).where(or_(*conditions)))).scalars().all()
    return _most_specific(rows, machine)


async def machine_ids_in_scope(db: AsyncSession, scope: Scope) -> list[uuid.UUID]:
    """Active machines with a pinned host key and readable Docker in `scope`."""
    query = select(Machine.id).where(
        Machine.is_active,
        Machine.host_key_fingerprint.is_not(None),
        Machine.docker_status == "ok",
    )
    if scope.machine_id is not None:
        query = query.where(Machine.id == scope.machine_id)
    elif scope.group_id is not None:
        query = query.where(Machine.group_id == scope.group_id)
    return list((await db.execute(query)).scalars().all())


async def machine_ids_logged_in(db: AsyncSession, server: str) -> list[uuid.UUID]:
    result = await db.execute(
        select(DockerRegistryLogin.machine_id).where(DockerRegistryLogin.server == server)
    )
    return list(result.scalars().all())


async def logins_of(
    db: AsyncSession, registries: list[DockerRegistry], user: User
) -> dict[uuid.UUID, list[tuple[DockerRegistryLogin, str]]]:
    """{registry id: [(login, machine name)]}, failed first — only the
    machines `user` may see (a fleet-wide login covers every machine)."""
    ids = [r.id for r in registries]
    out: dict[uuid.UUID, list[tuple[DockerRegistryLogin, str]]] = {i: [] for i in ids}
    if not ids:
        return out
    query = (
        select(DockerRegistryLogin, Machine.name)
        .join(Machine, Machine.id == DockerRegistryLogin.machine_id)
        .where(DockerRegistryLogin.registry_id.in_(ids))
    )
    allowed = await allowed_group_ids(db, user)
    if allowed is not None:
        query = query.where(Machine.group_id.in_(allowed))
    result = await db.execute(query)
    for login, name in result.all():
        if login.registry_id is not None:
            out[login.registry_id].append((login, name))
    for rows in out.values():
        rows.sort(key=lambda pair: (pair[0].status == "ok", pair[1].lower()))
    return out


def as_api(
    registry: DockerRegistry, logins: list[tuple[DockerRegistryLogin, str]], scope_label: str
) -> dict[str, object]:
    """The API's view of a registry: never the password."""
    return {
        "id": str(registry.id),
        "server": registry.server,
        "username": registry.username,
        "description": registry.description,
        "scope": scope_of(registry).value,
        "scope_label": scope_label,
        "created_by": registry.created_by,
        "created_at": registry.created_at.isoformat() if registry.created_at else None,
        "updated_at": registry.updated_at.isoformat() if registry.updated_at else None,
        "logins": [
            {
                "machine_id": str(login.machine_id),
                "machine": name,
                "status": login.status,
                "message": login.message,
                "checked_at": login.checked_at.isoformat(),
            }
            for login, name in logins
        ],
    }
