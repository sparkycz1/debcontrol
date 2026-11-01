"""Shared variables and secrets for stacks (`DockerVariable`).

A stack picks variables by name (`DockerStack.shared_variables`); each is
resolved for the stack's machine when the stack is deployed or checked —
the machine's own definition, then its group's, then the fleet-wide one
— and added to the `.env` debcontrol writes. A variable the stack's own
`.env` already sets keeps the stack's value. Nothing is shared with a
stack that didn't pick it, so a secret reaches only the stacks named.

Every value is stored encrypted; a secret one is never shown again, only
replaced. Changing a value marks the stacks using it as changed since
their deploy (the deployed `.env` no longer matches).
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.docker import DockerStack, DockerVariable
from app.db.models.machine import Machine
from app.db.models.user import User
from app.services.access_scope import allowed_group_ids
from app.services.docker_scopes import Scope, check_scope

NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
MAX_VALUE_BYTES = 16 * 1024
MAX_VARIABLES = 2000
# Names a stack may pick at most.
MAX_PER_STACK = 100


def is_name_valid(name: str) -> bool:
    return bool(NAME_RE.match(name))


def is_value_valid(value: str) -> bool:
    return len(value.encode()) <= MAX_VALUE_BYTES and not any(c in value for c in "\n\r\0")


def parse_names(raw: Iterable[str]) -> list[str] | None:
    """Picked names, de-duplicated in order; None when one is not a name."""
    names: list[str] = []
    for item in raw:
        name = item.strip()
        if not name:
            continue
        if not is_name_valid(name):
            return None
        if name not in names:
            names.append(name)
    return names if len(names) <= MAX_PER_STACK else None


@dataclass
class VariableForm:
    name: str
    # None = keep the stored value.
    value: str | None
    secret: bool = False
    description: str = ""
    scope: str = "all"
    parsed_scope: Scope | None = None
    errors: list[str] = field(default_factory=list)

    async def validate(
        self, db: AsyncSession, user: User, stored: DockerVariable | None = None
    ) -> list[str]:
        errors: list[str] = []
        self.name = self.name.strip()
        if not is_name_valid(self.name):
            errors.append("docker.variable.error.name")
        missing = self.value is None and stored is None
        if missing or (self.value is not None and not is_value_valid(self.value)):
            errors.append("docker.variable.error.value")
        self.description = self.description.strip()[:255]
        self.parsed_scope = Scope.parse(self.scope)
        if self.parsed_scope is None or not await check_scope(db, user, self.parsed_scope):
            errors.append("docker.scope.error")
        if not errors and self.parsed_scope is not None:
            query = select(DockerVariable.id).where(
                DockerVariable.name == self.name,
                DockerVariable.scope_key == self.parsed_scope.key,
            )
            if stored is not None:
                query = query.where(DockerVariable.id != stored.id)
            if (await db.execute(query.limit(1))).first() is not None:
                errors.append("docker.variable.error.taken")
        self.errors = errors
        return errors

    def apply(self, variable: DockerVariable) -> None:
        assert self.parsed_scope is not None
        variable.name = self.name
        # A secret stays secret unless it gets a new value: its stored value
        # is never shown again.
        variable.secret = self.secret or (bool(variable.secret) and self.value is None)
        variable.description = self.description
        variable.group_id = self.parsed_scope.group_id
        variable.machine_id = self.parsed_scope.machine_id
        variable.scope_key = self.parsed_scope.key
        if self.value is not None:
            variable.value_encrypted = encrypt_secret(self.value)


def scope_of(variable: DockerVariable) -> Scope:
    return Scope.of(variable.group_id, variable.machine_id)


def shown_value(variable: DockerVariable) -> str | None:
    """The value to show, or None for a secret."""
    return None if variable.secret else decrypt_secret(variable.value_encrypted)


async def visible_variables(db: AsyncSession, user: User) -> list[DockerVariable]:
    query = select(DockerVariable).order_by(DockerVariable.name, DockerVariable.scope_key)
    allowed = await allowed_group_ids(db, user)
    if allowed is not None:
        visible_machines = select(Machine.id).where(Machine.group_id.in_(allowed))
        query = query.where(
            or_(
                DockerVariable.scope_key == "",
                DockerVariable.group_id.in_(allowed),
                DockerVariable.machine_id.in_(visible_machines),
            )
        )
    return list((await db.execute(query.limit(MAX_VARIABLES))).scalars().all())


async def can_manage(db: AsyncSession, user: User, variable: DockerVariable) -> bool:
    return await check_scope(db, user, scope_of(variable))


async def for_machine(db: AsyncSession, machine: Machine) -> dict[str, DockerVariable]:
    """{name: the definition that applies to `machine`}."""
    conditions = [DockerVariable.scope_key == "", DockerVariable.machine_id == machine.id]
    if machine.group_id is not None:
        conditions.append(DockerVariable.group_id == machine.group_id)
    rows = (await db.execute(select(DockerVariable).where(or_(*conditions)))).scalars().all()
    chosen: dict[str, DockerVariable] = {}
    for row in rows:
        current = chosen.get(row.name)
        if current is None or scope_of(row).rank > scope_of(current).rank:
            chosen[row.name] = row
    return chosen


async def resolve(db: AsyncSession, stack: DockerStack) -> dict[str, str]:
    """{name: value} of the variables `stack` picked, for its machine; a
    name defined nowhere is left out (`missing` lists those)."""
    names = list(stack.shared_variables or [])
    if not names:
        return {}
    machine = await db.get(Machine, stack.machine_id)
    if machine is None:
        return {}
    defined = await for_machine(db, machine)
    return {
        name: decrypt_secret(defined[name].value_encrypted) for name in names if name in defined
    }


async def resolve_many(
    db: AsyncSession, stacks: list[DockerStack]
) -> dict[uuid.UUID, dict[str, str]]:
    """`resolve` for several stacks of one page."""
    out: dict[uuid.UUID, dict[str, str]] = {}
    for stack in stacks:
        out[stack.id] = await resolve(db, stack) if stack.shared_variables else {}
    return out


def missing(stack: DockerStack, resolved: Mapping[str, str]) -> list[str]:
    return [name for name in stack.shared_variables or [] if name not in resolved]


async def stacks_using(
    db: AsyncSession, names: set[str], user: User
) -> dict[str, list[DockerStack]]:
    """{name: stacks that picked it}, on the machines `user` may see — the
    stacks table is small (a few per machine), and JSON containment isn't
    portable, so filtered here."""
    query = select(DockerStack)
    allowed = await allowed_group_ids(db, user)
    if allowed is not None:
        query = query.join(Machine, Machine.id == DockerStack.machine_id).where(
            Machine.group_id.in_(allowed)
        )
    result = await db.execute(query)
    out: dict[str, list[DockerStack]] = {name: [] for name in names}
    for stack in result.scalars().all():
        for name in stack.shared_variables or []:
            if name in out:
                out[name].append(stack)
    return out


def as_api(variable: DockerVariable, scope_label: str, used_by: int = 0) -> dict[str, object]:
    return {
        "id": str(variable.id),
        "name": variable.name,
        "secret": variable.secret,
        # A secret's value is never returned.
        "value": shown_value(variable),
        "description": variable.description,
        "scope": scope_of(variable).value,
        "scope_label": scope_label,
        "used_by_stacks": used_by,
        "created_by": variable.created_by,
        "updated_by": variable.updated_by,
        "updated_at": variable.updated_at.isoformat() if variable.updated_at else None,
    }
