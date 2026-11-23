"""REST API for tune-ups ("Komplet", Health → Tune-up,
`app.services.tune_up`) — the same start, read and stop as the page, under
the same permissions and audit action codes, scoped to the machines the
token's account can see.

- `GET /api/v1/tune-ups` — the recent tune-ups, newest first, each with
  its machines and their steps.
- `POST /api/v1/tune-ups` — start one: `{"target": "machine" | "group" |
  "all", "machine_id", "group_id", "options": {...}}` (`action.updates`;
  `options.reboot` also needs `action.power`). Every option left out takes
  its default (`system_update`, `docker_update`, `docker_prune`,
  `image_scan` and `security_audit` on; `snapshot` and `reboot` off).
  Returns the new tune-up, or 409 when no machine could start (each
  already has one under way, or none has a confirmed host key).
- `GET /api/v1/tune-ups/{batch_id}` — one tune-up, step by step.
- `POST /api/v1/tune-ups/{batch_id}/cancel` — stop it (`action.updates`).
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import tune_up
from app.web.routes.health_tune_up import cancel_for, chosen_machines, start_for, visible_ids

router = APIRouter(prefix="/api/v1")

_view = Depends(require_api_permission(Permission.MACHINE_VIEW))
_updates = Depends(require_api_permission(Permission.ACTION_UPDATES))


class TuneUpOptions(BaseModel):
    system_update: bool = True
    snapshot: bool = False
    docker_update: bool = True
    docker_prune: bool = True
    image_scan: bool = True
    security_audit: bool = True
    reboot: bool = False


class TuneUpRequest(BaseModel):
    target: Literal["machine", "group", "all"]
    machine_id: uuid.UUID | None = None
    group_id: uuid.UUID | None = None
    options: TuneUpOptions = Field(default_factory=TuneUpOptions)


@router.get("/tune-ups", dependencies=[_view])
async def list_tune_ups_api(
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    views = await tune_up.recent_batches(db, await visible_ids(db, user), max(1, min(limit, 100)))
    return [tune_up.batch_dict(view) for view in views]


@router.post("/tune-ups", dependencies=[_updates], status_code=status.HTTP_201_CREATED)
async def start_tune_up_api(
    request: Request,
    body: TuneUpRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machines = await chosen_machines(
        db,
        user,
        body.target,
        str(body.machine_id) if body.machine_id else None,
        str(body.group_id) if body.group_id else None,
    )
    if not machines:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such machines.")
    options = tune_up.Options.from_dict(body.options.model_dump())
    batch_id, skipped = await start_for(request, db, user, machines, options)
    if batch_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No machine could start: each has a tune-up under way or no confirmed host key.",
        )
    view = await tune_up.batch(db, batch_id, await visible_ids(db, user))
    result: dict[str, Any] = tune_up.batch_dict(view) if view else {"batch_id": str(batch_id)}
    result["skipped"] = skipped
    return result


@router.get("/tune-ups/{batch_id}", dependencies=[_view])
async def get_tune_up_api(
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    view = await tune_up.batch(db, batch_id, await visible_ids(db, user))
    if view is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such tune-up.")
    return tune_up.batch_dict(view)


@router.post("/tune-ups/{batch_id}/cancel", dependencies=[_updates])
async def cancel_tune_up_api(
    request: Request,
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    if await tune_up.batch(db, batch_id, await visible_ids(db, user)) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such tune-up.")
    return {"stopped": await cancel_for(request, db, user, batch_id)}
