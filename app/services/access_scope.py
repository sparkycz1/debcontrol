"""The single implementation of per-user machine-group visibility scoping.

See `app.db.models.user_machine_group_access` for the data model and the
"empty means unrestricted" rule this enforces. Everything that lists or
resolves a `Machine` or a `MachineGroup` for a *specific user* goes through
this module — the web routes, the REST API, and the AI assistant's tools
alike — so there is exactly one definition of "may this account see this",
not one per call site.

Two shapes are offered, because call sites come in two shapes:

- `machines_visible_to` / `groups_visible_to` return a `Select` that is
  already scope-filtered and still fully composable (`.where(...)`,
  `.order_by(...)`, `.options(...)`, pagination) — for the many places that
  build a listing query themselves.
- `can_see_machine` / `can_see_group_id` / `visible_machines_by_ids`
  answer the same question about one row or a client-submitted id list —
  for detail routes (which then raise the usual 404, never a 403: see
  `app/web/routes/ai.py`'s `_get_conversation` for the same reasoning) and
  for bulk endpoints, which must never trust a client-submitted list of
  machine ids: out-of-scope ids are dropped silently rather than rejected
  with an error naming them (that would confirm they exist).

What is deliberately **not** scoped: the audit log. `audit.view` stays a
single global permission with no group filtering — the audit trail is a
security control over the whole deployment, not a per-operator convenience
view, and a partial one would be worse than none. See wiki/Architecture.md.

Background jobs are not scoped either, and can't be: a Celery task has no
"current user" (the daily fleet snapshot really is fleet-wide, and a
scheduled task fires on its cron expression regardless of who is logged
in). Scope on scheduled tasks is therefore enforced when one is *created or
edited*, by whoever is doing that — never at execution time.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence

from sqlalchemy import Select, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.user import User
from app.db.models.user_machine_group_access import UserMachineGroupAccess


async def allowed_group_ids(db: AsyncSession, user: User) -> set[uuid.UUID] | None:
    """The groups `user` is restricted to, or `None` when they are not
    restricted at all.

    `None` and `set()` mean opposite things and the distinction is the
    whole feature: `None` is "no scoping applies, see everything" (the
    common case, and what every account has until an admin says otherwise);
    an empty `set()` can only be returned as a *filter result*, never from
    here — a user with no rows is unrestricted by definition."""
    result = await db.execute(
        select(UserMachineGroupAccess.group_id).where(
            UserMachineGroupAccess.user_id == user.id
        )
    )
    group_ids = set(result.scalars().all())
    return group_ids or None


async def is_restricted(db: AsyncSession, user: User) -> bool:
    """Whether any group scoping applies to `user` at all. Cheaper to read
    than `allowed_group_ids(...) is not None` at a call site that only needs
    the yes/no (e.g. "may this account target *All machines*?")."""
    return await allowed_group_ids(db, user) is not None


async def machines_visible_to(db: AsyncSession, user: User) -> Select[Machine]:
    """A `Select` for `Machine`, already scope-filtered — compose with
    `.where()` / `.order_by()` / `.options()` exactly as the call site
    already does. Machines with no group are excluded for a restricted user
    (see the model's docstring)."""
    query = select(Machine)
    group_ids = await allowed_group_ids(db, user)
    if group_ids is not None:
        query = query.where(Machine.group_id.in_(group_ids))
    return query


async def groups_visible_to(db: AsyncSession, user: User) -> Select[MachineGroup]:
    """The `MachineGroup` equivalent of `machines_visible_to`."""
    query = select(MachineGroup)
    group_ids = await allowed_group_ids(db, user)
    if group_ids is not None:
        query = query.where(MachineGroup.id.in_(group_ids))
    return query


async def count_visible_machines(db: AsyncSession, user: User) -> int:
    """How many machines `user` can see.

    A dedicated helper rather than `machines_visible_to(...).with_only_columns
    (func.count())` at each call site: that idiom silently drops the FROM
    clause when there is no WHERE to anchor it (the unrestricted case),
    turning the count into a bare `SELECT count(*)` that answers 1. Counting
    belongs here, once, where that is written down."""
    query = await machines_visible_to(db, user)
    return (
        await db.execute(query.with_only_columns(func.count(), maintain_column_froms=True))
    ).scalar_one()


async def count_visible_groups(db: AsyncSession, user: User) -> int:
    """The `MachineGroup` equivalent of `count_visible_machines`."""
    query = await groups_visible_to(db, user)
    return (
        await db.execute(query.with_only_columns(func.count(), maintain_column_froms=True))
    ).scalar_one()


async def can_see_machine(db: AsyncSession, user: User, machine: Machine) -> bool:
    group_ids = await allowed_group_ids(db, user)
    if group_ids is None:
        return True
    return machine.group_id is not None and machine.group_id in group_ids


async def can_see_group_id(db: AsyncSession, user: User, group_id: uuid.UUID | None) -> bool:
    """Whether `user` may see the group `group_id` — for validating a submitted
    `group_id` (a scheduled task's target, a machine's group) without first
    loading the row. A restricted user may never pick "no group": an
    ungrouped machine would be invisible to its own creator."""
    group_ids = await allowed_group_ids(db, user)
    if group_ids is None:
        return True
    return group_id is not None and group_id in group_ids


async def visible_machines_by_ids(
    db: AsyncSession, user: User, machine_ids: Sequence[uuid.UUID]
) -> list[Machine]:
    """Load exactly the machines among `machine_ids` that `user` may see."""
    if not machine_ids:
        return []
    query = await machines_visible_to(db, user)
    result = await db.execute(query.where(Machine.id.in_(machine_ids)))
    return list(result.scalars().all())


async def set_group_access(
    db: AsyncSession, user_id: uuid.UUID, group_ids: Iterable[uuid.UUID]
) -> None:
    """Replace a user's entire grant set (delete-then-insert).

    Wholesale replacement, not a diff: the form this comes from submits the
    complete intended set every time, so reconstructing which individual
    rows changed would be work in service of nothing. Does not commit — the
    caller's own transaction does, so the grant lands together with whatever
    else that request is changing about the account."""
    await db.execute(
        delete(UserMachineGroupAccess).where(UserMachineGroupAccess.user_id == user_id)
    )
    for group_id in dict.fromkeys(group_ids):
        db.add(UserMachineGroupAccess(user_id=user_id, group_id=group_id))


async def group_names_for(db: AsyncSession, group_ids: Iterable[uuid.UUID]) -> list[str]:
    """The names behind a set of group ids, sorted — for the audit summary
    of a scope change, which should read as names a human recognizes rather
    than as UUIDs."""
    ids = list(group_ids)
    if not ids:
        return []
    result = await db.execute(
        select(MachineGroup.name).where(MachineGroup.id.in_(ids)).order_by(MachineGroup.name)
    )
    return list(result.scalars().all())
