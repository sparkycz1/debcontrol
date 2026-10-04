"""What the `/machines` route modules share: the permission dependencies,
look-ups that 404 outside the account's scope, the tab list, and the small
queries more than one of them needs. No routes here — see
`app.web.routes.machines` for how the modules are put together."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.dependencies import require_permission
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.machine_service import MachineService
from app.db.models.machine_tag import Tag
from app.db.models.role import Permission
from app.db.models.user import User
from app.services.access_scope import (
    groups_visible_to,
    machines_visible_to,
)
from app.web.templating import t


def machines_router() -> APIRouter:
    """One area's router — every `/machines` route needs `machine.view`.
    Each area module makes its own and `app.web.routes.machines` includes
    them in order."""
    return APIRouter(
        prefix="/machines", dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))]
    )


_manage = Depends(require_permission(Permission.MACHINE_MANAGE))
_updates = Depends(require_permission(Permission.ACTION_UPDATES))
_power = Depends(require_permission(Permission.ACTION_POWER))


def _machine_tabs(request: Request, machine: Machine, user: User) -> list[tuple[str, str, str]]:
    """The (key, label, url) tabs shown on every one of this machine's own
    pages — same set and order everywhere, so `partials/_tabnav.html` always
    highlights the right one. Terminal is left out entirely for a user
    without `action.terminal`, same as it was hidden inline before this page
    had tabs at all."""
    base = f"/machines/{machine.id}"
    tabs = [
        ("overview", t(request, "machine.tab.overview"), base),
    ]
    # Proxmox VE guests/storage/backups and ZFS pools — only where there
    # are any (`app.ssh.proxmox`); a plain ZFS host gets it as "ZFS".
    if machine.has_proxmox_tab:
        label = "Proxmox" if machine.proxmox_product or machine.pve_guests is not None else "ZFS"
        tabs.append(("proxmox", label, f"{base}/proxmox"))
    tabs += [
        ("monitoring", t(request, "machine.tab.monitoring"), f"{base}/monitoring"),
        ("updates", t(request, "machine.tab.updates"), f"{base}/updates"),
    ]
    if user.has_permission(Permission.ACTION_TERMINAL):
        tabs.append(("terminal", t(request, "machine.tab.terminal"), f"{base}/terminal"))
        # Logs shares Terminal's permission gate rather than plain
        # `machine.view` — see the "Logs" route's own docstring for why.
        tabs.append(("logs", t(request, "machine.tab.logs"), f"{base}/logs"))
    # No separate "Power" tab any more — reboot/shut down live directly on
    # Overview now (see `machine_detail`'s own template), the same one-page
    # placement a machine's few other one-off actions (test connection,
    # discover host key) already have, rather than a whole tab for two
    # buttons. `GET /{id}/power` itself still redirects there for anyone
    # with the old URL bookmarked/linked — see `power_tab`.
    tabs.append(("history", t(request, "machine.tab.history"), f"{base}/history"))
    tabs.append(("settings", t(request, "machine.tab.settings"), f"{base}/edit"))
    return tabs


async def _get_machine_or_404(machine_id: uuid.UUID, db: AsyncSession, user: User) -> Machine:
    """The machine, or a 404 — including when it exists but is outside
    `user`'s machine-group scope (`app.services.access_scope`). 404, never
    403, for the same reason `app/web/routes/ai.py`'s `_get_conversation`
    uses one: a 403 would confirm that a machine with that id exists."""
    # Eager-load `group` — templates read `machine.group` and the async ORM
    # can't lazy-load relationships outside of an `await` (it would raise
    # MissingGreenlet during template rendering).
    query = await machines_visible_to(db, user)
    result = await db.execute(
        query.options(selectinload(Machine.group))
        .where(Machine.id == machine_id)
        # A route that waited for a background job reloads the machine to
        # show what the job wrote — without this the session would hand back
        # the object it already holds, with the values from before the job.
        .execution_options(populate_existing=True)
    )
    machine = result.scalar_one_or_none()
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found.")
    return machine


async def _get_groups(db: AsyncSession, user: User) -> list[MachineGroup]:
    """The groups offered in the machine form's group `<select>` — scoped,
    so a restricted user can't move a machine into a group they can't see
    (which would make it vanish from their own view)."""
    query = await groups_visible_to(db, user)
    result = await db.execute(query.order_by(MachineGroup.name))
    return list(result.scalars().all())


async def _get_all_tags(db: AsyncSession) -> list[Tag]:
    """Every tag currently in use, alphabetical — the machine list's filter
    dropdown and the create/edit forms' autocomplete `<datalist>`. Not
    scoped by machine-group access: a tag *name* existing isn't fleet
    data, and a restricted account typing a tag another machine happens to
    use just filters to nothing, the same as typing a free-text search
    term that doesn't match anything in scope."""
    result = await db.execute(select(Tag).order_by(Tag.name))
    return list(result.scalars().all())


async def _get_service_counts(machine_id: uuid.UUID, db: AsyncSession) -> dict[str, int]:
    result = await db.execute(
        select(func.count())
        .select_from(MachineService)
        .where(MachineService.machine_id == machine_id)
    )
    total = result.scalar_one()
    failed_result = await db.execute(
        select(func.count())
        .select_from(MachineService)
        .where(
            MachineService.machine_id == machine_id, MachineService.active_state == "failed"
        )
    )
    return {"total": total, "failed": failed_result.scalar_one()}


async def _get_services(
    machine_id: uuid.UUID, db: AsyncSession, *, svc_q: str, svc_state: str
) -> list[MachineService]:
    query = select(MachineService).where(MachineService.machine_id == machine_id)
    if svc_q.strip():
        query = query.where(MachineService.unit.ilike(f"%{svc_q.strip()}%"))
    if svc_state:
        query = query.where(MachineService.active_state == svc_state)
    result = await db.execute(query.order_by(MachineService.unit))
    return list(result.scalars().all())
