"""Disks (nav: **Disks**, `machine.view`): every physical disk followed by
its serial number (`app.services.disk_history`), wherever it sits now.

- `/disks` — all of them: machine and device, model, kind, temperature,
  wear, the failure risk and how many events each has; `?risk=` narrows
  to "elevated", "high" or "failing" (all three with `?risk=attention`).
- `/disks/{id}` — one disk: the risk and why, wear, data written, the
  temperature over `?days=` (7, 30, 90 or 365), its error counters, every
  event it ever had (also from other machines) and its S.M.A.R.T.
  attributes.
- `/disks/{id}/report` — the same as one printable page (for a warranty
  claim: print it or save it as PDF from the browser).

Scoped to the disks of machines the account can see; one that isn't (or
doesn't exist) is a 404."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.db.models.disk import Disk
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import disk_history
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))])

DAY_CHOICES = (7, 30, 90, 365)
ATTENTION = ("elevated", "high", "failing")


def _risk_of(disk: Disk) -> str:
    return str((disk.prediction or {}).get("risk") or "low")


async def _disk_or_404(db: AsyncSession, user: User, disk_id: uuid.UUID) -> Disk:
    disk = await disk_history.visible_disk(db, user, disk_id)
    if disk is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return disk


@router.get("/disks")
async def disks_page(
    request: Request,
    risk: str = Query("", pattern="^(|low|elevated|high|failing|attention)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    query = await disk_history.visible_disks_query(db, current_user)
    disks = list((await db.execute(query)).scalars().all())
    counts = dict.fromkeys(disk_history.RISKS, 0)
    for disk in disks:
        counts[_risk_of(disk)] = counts.get(_risk_of(disk), 0) + 1
    if risk == "attention":
        disks = [d for d in disks if _risk_of(d) in ATTENTION]
    elif risk:
        disks = [d for d in disks if _risk_of(d) == risk]
    disks.sort(
        key=lambda d: (
            -disk_history.RISKS.index(_risk_of(d)),
            (d.machine_name or "").lower(),
            d.device or "",
        )
    )
    settings = await get_or_create_app_settings(db)
    return templates.TemplateResponse(
        request,
        "disks/list.html",
        {
            "disks": [
                (d, disk_history.latest_view(d), disk_history.prediction_view(d)) for d in disks
            ],
            "risk": risk,
            "counts": counts,
            "thresholds": disk_history.DiskThresholds.from_settings(settings),
        },
    )


async def _detail_context(
    db: AsyncSession, disk: Disk, days: int
) -> dict[str, object]:
    now = datetime.now(UTC)
    samples = await disk_history.samples_since(db, disk.id, now - timedelta(days=days))
    settings = await get_or_create_app_settings(db)
    thresholds = disk_history.DiskThresholds.from_settings(settings)
    latest = disk_history.latest_view(disk)
    temp_class = disk_history.temperature_class(latest)
    return {
        "disk": disk,
        "latest": latest,
        "prediction": disk_history.prediction_view(disk),
        "events": await disk_history.events_of(db, disk.id),
        "samples": samples,
        "sample_times": [s.sampled_at for s in samples],
        "temperatures": [s.temperature_c for s in samples],
        "days": days,
        "day_choices": DAY_CHOICES,
        "temp_class": temp_class,
        "temp_thresholds": thresholds.temp[temp_class],
        "thresholds": thresholds,
        "wear_level": disk_history.wear_level(latest, thresholds),
        "temperature_level": disk_history.temperature_level(latest, thresholds),
        "now": now,
    }


@router.get("/disks/{disk_id}")
async def disk_page(
    request: Request,
    disk_id: uuid.UUID,
    days: int = Query(30),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    disk = await _disk_or_404(db, current_user, disk_id)
    if days not in DAY_CHOICES:
        days = 30
    return templates.TemplateResponse(
        request, "disks/detail.html", await _detail_context(db, disk, days)
    )


@router.get("/disks/{disk_id}/report")
async def disk_report(
    request: Request,
    disk_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    disk = await _disk_or_404(db, current_user, disk_id)
    return templates.TemplateResponse(
        request, "disks/report.html", await _detail_context(db, disk, 365)
    )
