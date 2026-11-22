"""REST API for machine health (`app.services.machine_health`) — the same
reads and the same snooze/clear actions as the Health page and a
machine's health panel, under the same permissions (`machine.view` to
read, `machine.manage` to snooze) and audit action codes, scoped to the
machines the token's account can see.

- `GET /api/v1/health` — the fleet: score, count per status, every
  machine with a warning or a critical problem, every snoozed problem.
- `GET /api/v1/machines/{id}/health` — one machine: status, the ten
  categories, its problems and its snoozed problems.
- `POST /api/v1/machines/{id}/health/snoozes` — snooze one problem (by its
  `key`) for `hours`, or until it is gone (`hours` null).
- `DELETE /api/v1/machines/{id}/health/snoozes/{key}` — clear a snooze.

Each problem carries its message key (`health.finding.<message>`) with
its parameters, plus `text`: the sentence in the token owner's language.
The thresholds are settings (`GET`/`PATCH /api/v1/settings`,
`health_*`)."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.machine_health import HealthSnoozeRequest
from app.services import machine_health
from app.services.access_scope import allowed_group_ids
from app.web.routes.api_v1 import _get_machine_or_404

router = APIRouter(prefix="/api/v1")

_view = Depends(require_api_permission(Permission.MACHINE_VIEW))
_manage = Depends(require_api_permission(Permission.MACHINE_MANAGE))


def _with_text(item: dict[str, Any], locale: str | None) -> dict[str, Any]:
    finding = machine_health.Finding.from_dict(item)
    return {**item, "text": machine_health.finding_text(finding, locale) if finding else None}


def _view_dict(view: machine_health.HealthView, locale: str | None) -> dict[str, Any]:
    data = view.as_dict()
    data["problems"] = [_with_text(p, locale) for p in data["problems"]]
    data["snoozed"] = [_with_text(p, locale) for p in data["snoozed"]]
    return data


@router.get("/health", dependencies=[_view])
async def fleet_health_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> dict[str, object]:
    scope = await allowed_group_ids(db, user)
    fleet = await machine_health.fleet_health(db, scope)
    machines = await machine_health.worst_machines(db, scope, limit=0)
    snoozes = await machine_health.all_snoozes(db, scope)
    return {
        **fleet.as_dict(),
        "machines": [
            {"id": str(m.id), "name": m.name, **_view_dict(v, user.locale)} for m, v in machines
        ],
        "snoozes": [
            {
                **machine_health.snooze_to_dict(s),
                "machine_name": m.name,
                "problem": _with_text(f.as_dict(), user.locale) if f else None,
            }
            for m, s, f in snoozes
        ],
    }


@router.get("/machines/{machine_id}/health", dependencies=[_view])
async def machine_health_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db, user)
    return _view_dict(await machine_health.view_for(db, machine), user.locale)


@router.post(
    "/machines/{machine_id}/health/snoozes",
    dependencies=[_manage],
    status_code=status.HTTP_201_CREATED,
)
async def snooze_machine_health_api(
    payload: HealthSnoozeRequest,
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Snooze one current problem: it stops counting towards the machine's
    health until `hours` pass, it goes away, it gets worse or the snooze is
    deleted. 404 when the machine has no such problem right now."""
    machine = await _get_machine_or_404(machine_id, db, user)
    try:
        row = await machine_health.snooze(
            db, machine, payload.key, hours=payload.hours, by=user.username, note=payload.note
        )
    except machine_health.UnknownFindingError:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail="No such problem on this machine."
        ) from None
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from None
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machine.health.snooze",
        summary=f'Snoozed "{payload.key}" on "{machine.name}" (REST API)',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"key": payload.key, "hours": payload.hours, "note": row.note},
    )
    return {"snooze": machine_health.snooze_to_dict(row)}


@router.delete(
    "/machines/{machine_id}/health/snoozes/{key:path}",
    dependencies=[_manage],
    status_code=status.HTTP_204_NO_CONTENT,
)
async def unsnooze_machine_health_api(
    request: Request,
    machine_id: uuid.UUID,
    key: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, user)
    found = await machine_health.unsnooze(db, machine, key)
    await db.commit()
    if not found:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="This problem is not snoozed.")
    await log_event(
        db,
        request=request,
        action="machine.health.snooze.clear",
        summary=f'Cleared the snooze of "{key}" on "{machine.name}" (REST API)',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"key": key},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
