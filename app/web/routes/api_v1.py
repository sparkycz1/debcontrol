"""Read-only REST API for machines and groups, for external scripts/
monitoring — authenticated with a per-user API token
(`app.auth.dependencies.require_api_permission`), not a browser session.

Lives under `/api/`, already on `app.auth.middleware`'s public-prefix
allowlist — same reasoning as `POST /api/inform`: a machine-to-machine
surface with its own bearer-token authentication, not a cookie-based one.
Read-only by design (no POST/PUT/DELETE here) — this is meant for pulling
status into somewhere else, not for driving the app; use the web UI (or a
future write API, if one is ever needed) for that.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.dependencies import require_api_permission
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.db.session import get_db

router = APIRouter(prefix="/api/v1")

_view_machines = Depends(require_api_permission(Permission.MACHINE_VIEW))
_view_groups = Depends(require_api_permission(Permission.GROUP_VIEW))


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _machine_to_dict(machine: Machine) -> dict[str, object]:
    return {
        "id": str(machine.id),
        "name": machine.name,
        "ip_address": machine.ip_address,
        "port": machine.port,
        "group": machine.group.name if machine.group else None,
        "is_active": machine.is_active,
        "is_reachable": machine.is_reachable,
        "last_ping_at": _isoformat(machine.last_ping_at),
        "os_version": machine.os_version,
        "kernel_version": machine.kernel_version,
        "reboot_required": machine.reboot_required,
        "upgradable_count": machine.upgradable_count,
        "security_upgradable_count": machine.security_upgradable_count,
        "updates_checked_at": _isoformat(machine.updates_checked_at),
    }


@router.get("/machines", dependencies=[_view_machines])
async def list_machines_api(db: AsyncSession = Depends(get_db)) -> list[dict[str, object]]:
    result = await db.execute(select(Machine).options(selectinload(Machine.group)))
    return [_machine_to_dict(m) for m in result.scalars().all()]


@router.get("/machines/{machine_id}", dependencies=[_view_machines])
async def get_machine_api(
    machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    result = await db.execute(
        select(Machine).options(selectinload(Machine.group)).where(Machine.id == machine_id)
    )
    machine = result.scalar_one_or_none()
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found.")
    return _machine_to_dict(machine)


@router.get("/machine-groups", dependencies=[_view_groups])
async def list_machine_groups_api(db: AsyncSession = Depends(get_db)) -> list[dict[str, object]]:
    result = await db.execute(select(MachineGroup))
    return [{"id": str(g.id), "name": g.name} for g in result.scalars().all()]
