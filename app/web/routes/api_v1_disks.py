"""REST API for disks followed by their serial number
(`app.services.disk_history`) — the same reads as the Disks page and a
disk's own page, under the same permission (`machine.view`), scoped to the
disks of machines the token's account can see (a disk whose machine was
deleted only for an account that sees every machine).

- `GET /api/v1/disks?risk=` — every disk: where it is, model, serial,
  kind, temperature, wear, data written, error counters, ZFS membership,
  the failure prediction and its event count. `risk` is `low`,
  `elevated`, `high`, `failing` or `attention` (the last three).
- `GET /api/v1/disks/{id}` — one disk, the same shape plus its S.M.A.R.T.
  attributes.
- `GET /api/v1/disks/{id}/samples?days=` — its readings (at most one an
  hour) over the last `days` (1-3650, default 30): temperature, power-on
  hours, wear, data written and the counters.
- `GET /api/v1/disks/{id}/events` — every event it had, newest first, with
  `text` in the token owner's language.

The temperature and wear thresholds are settings (`GET`/`PATCH
/api/v1/settings`, `health_disk_temp_*` and `health_disk_wear_*`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.disk import Disk
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import disk_history

router = APIRouter(prefix="/api/v1")

_view = Depends(require_api_permission(Permission.MACHINE_VIEW))
_ATTENTION = ("elevated", "high", "failing")


async def _disk_or_404(db: AsyncSession, user: User, disk_id: uuid.UUID) -> Disk:
    disk = await disk_history.visible_disk(db, user, disk_id)
    if disk is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return disk


def _risk(disk: Disk) -> str:
    return str((disk.prediction or {}).get("risk") or "low")


@router.get("/disks", dependencies=[_view])
async def list_disks_api(
    risk: str = Query("", pattern="^(|low|elevated|high|failing|attention)$"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    query = await disk_history.visible_disks_query(db, user)
    disks = (await db.execute(query.order_by(Disk.machine_name, Disk.device))).scalars().all()
    if risk == "attention":
        disks = [d for d in disks if _risk(d) in _ATTENTION]
    elif risk:
        disks = [d for d in disks if _risk(d) == risk]
    return [disk_history.disk_summary(d) for d in disks]


@router.get("/disks/{disk_id}", dependencies=[_view])
async def get_disk_api(
    disk_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    disk = await _disk_or_404(db, user, disk_id)
    return {
        **disk_history.disk_summary(disk),
        "attributes": (disk.latest or {}).get("attributes") or [],
    }


@router.get("/disks/{disk_id}/samples", dependencies=[_view])
async def disk_samples_api(
    disk_id: uuid.UUID,
    days: int = Query(30, ge=1, le=3650),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    disk = await _disk_or_404(db, user, disk_id)
    since = datetime.now(UTC) - timedelta(days=days)
    return [
        {
            "sampled_at": s.sampled_at.isoformat(),
            "temperature_c": s.temperature_c,
            "power_on_hours": s.power_on_hours,
            "wear_percent": s.wear_percent,
            "written_bytes": s.written_bytes,
            "counters": s.counters or {},
        }
        for s in await disk_history.samples_since(db, disk.id, since)
    ]


@router.get("/disks/{disk_id}/events", dependencies=[_view])
async def disk_events_api(
    disk_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    disk = await _disk_or_404(db, user, disk_id)
    return [
        disk_history.event_dict(e, user.locale)
        for e in await disk_history.events_of(db, disk.id)
    ]
