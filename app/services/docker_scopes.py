"""Where a registry login or a shared variable applies: the whole fleet,
one machine group, or one machine (`DockerRegistry`, `DockerVariable`).

For a machine the most specific definition wins: its own, then its
group's, then the fleet-wide one.

**Who may manage which scope.** An account limited to some machine groups
may manage only definitions for those groups and their machines; one for
the whole fleet needs an account (and API token) without such a limit,
like accepting a vulnerability for every image.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.docker import scope_key
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.user import User
from app.services.access_scope import allowed_group_ids

# How specific each kind of scope is (higher wins).
_RANK = {"machine": 2, "group": 1, "all": 0}


@dataclass(frozen=True)
class Scope:
    """One scope: kind "all", "group" or "machine"."""

    kind: str
    group_id: uuid.UUID | None = None
    machine_id: uuid.UUID | None = None

    @property
    def key(self) -> str:
        return scope_key(self.group_id, self.machine_id)

    @property
    def value(self) -> str:
        """The form value: "all", "group:<id>" or "machine:<id>"."""
        if self.machine_id is not None:
            return f"machine:{self.machine_id}"
        if self.group_id is not None:
            return f"group:{self.group_id}"
        return "all"

    @property
    def rank(self) -> int:
        return _RANK[self.kind]

    @classmethod
    def parse(cls, value: str) -> Scope | None:
        """`value` as the form (or API) sends it; None when it is not one."""
        value = (value or "").strip()
        if value in ("", "all"):
            return cls("all")
        kind, _, raw_id = value.partition(":")
        if kind not in ("group", "machine"):
            return None
        try:
            parsed = uuid.UUID(raw_id)
        except ValueError:
            return None
        if kind == "group":
            return cls("group", group_id=parsed)
        return cls("machine", machine_id=parsed)

    @classmethod
    def of(cls, group_id: uuid.UUID | None, machine_id: uuid.UUID | None) -> Scope:
        if machine_id is not None:
            return cls("machine", machine_id=machine_id)
        if group_id is not None:
            return cls("group", group_id=group_id)
        return cls("all")

    def applies_to(self, machine: Machine) -> bool:
        if self.machine_id is not None:
            return self.machine_id == machine.id
        if self.group_id is not None:
            return self.group_id == machine.group_id
        return True


async def check_scope(db: AsyncSession, user: User, scope: Scope) -> bool:
    """Whether `user` may manage definitions in `scope` (it exists, and
    is within the groups the account is limited to)."""
    allowed = await allowed_group_ids(db, user)
    if scope.machine_id is not None:
        machine = await db.get(Machine, scope.machine_id)
        if machine is None:
            return False
        return allowed is None or (machine.group_id is not None and machine.group_id in allowed)
    if scope.group_id is not None:
        if await db.get(MachineGroup, scope.group_id) is None:
            return False
        return allowed is None or scope.group_id in allowed
    return allowed is None


async def label(db: AsyncSession, scope: Scope) -> str:
    """A short English label for audit entries and the API."""
    if scope.machine_id is not None:
        machine = await db.get(Machine, scope.machine_id)
        return f"machine {machine.name}" if machine is not None else "a deleted machine"
    if scope.group_id is not None:
        group = await db.get(MachineGroup, scope.group_id)
        return f"group {group.name}" if group is not None else "a deleted group"
    return "all machines"
