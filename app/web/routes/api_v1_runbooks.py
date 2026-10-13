"""REST API for runbooks — the same rules as the pages
(`app/web/routes/runbooks.py`): reading needs `runbook.run` or
`action.terminal`, writing a runbook needs `action.terminal`, running one
needs `runbook.run`. There is no preview step here: a script that posts a
run has the commands from `GET /api/v1/runbooks/{id}` already.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.db.models.runbook import Runbook
from app.db.models.user import User
from app.db.session import get_db
from app.services import runbooks as runbooks_service
from app.services.access_scope import groups_visible_to, visible_machines_by_ids
from app.tasks.jobs import run_runbook


async def _need_access(user: User = Depends(get_api_token_user)) -> None:
    if not (
        user.has_permission(Permission.RUNBOOK_RUN)
        or user.has_permission(Permission.ACTION_TERMINAL)
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")


router = APIRouter(prefix="/api/v1/runbooks", dependencies=[Depends(_need_access)])
_edit = Depends(require_api_permission(Permission.ACTION_TERMINAL))
_run = Depends(require_api_permission(Permission.RUNBOOK_RUN))


class _Step(BaseModel):
    name: str = Field(default="", max_length=120)
    command: str = Field(max_length=runbooks_service.MAX_COMMAND_LENGTH)


class _Param(BaseModel):
    key: str = Field(max_length=32)
    label: str = Field(default="", max_length=120)
    default: str = Field(default="", max_length=200)


class _RunbookSave(BaseModel):
    name: str = Field(max_length=120)
    description: str | None = Field(default=None, max_length=1024)
    steps: list[_Step] = Field(max_length=runbooks_service.MAX_STEPS)
    params: list[_Param] = Field(default_factory=list, max_length=runbooks_service.MAX_PARAMS)


class _RunRequest(BaseModel):
    # Exactly one of the two.
    machine_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    group_id: uuid.UUID | None = None
    values: dict[str, str] = Field(default_factory=dict)


async def _get(db: AsyncSession, runbook_id: uuid.UUID) -> Runbook:
    runbook = await db.get(Runbook, runbook_id)
    if runbook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Runbook not found.")
    return runbook


@router.get("")
async def list_runbooks_api(db: AsyncSession = Depends(get_db)) -> list[dict[str, object]]:
    result = await db.execute(select(Runbook).order_by(Runbook.name))
    return [runbooks_service.as_dict(runbook) for runbook in result.scalars().all()]


@router.get("/runs/{batch_id}")
async def runbook_batch_api(
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """One started run: a result per machine, with the commands that ran
    and their output. Only the machines this account may see."""
    runs = await runbooks_service.visible_batch(db, user, batch_id)
    if not runs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found.")
    return {
        "batch_id": str(batch_id),
        "runs": [runbooks_service.run_as_dict(run) for run in runs],
    }


@router.get("/{runbook_id}")
async def get_runbook_api(
    runbook_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    return runbooks_service.as_dict(await _get(db, runbook_id))


async def _save(
    request: Request, db: AsyncSession, user: User, runbook: Runbook | None, payload: _RunbookSave
) -> dict[str, object]:
    try:
        data = runbooks_service.validate(
            payload.name,
            payload.description,
            [step.model_dump() for step in payload.steps],
            [param.model_dump() for param in payload.params],
        )
        if await runbooks_service.name_taken(db, data.name, runbook.id if runbook else None):
            raise runbooks_service.RunbookError("A runbook with this name already exists.")
    except runbooks_service.RunbookError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    created = runbook is None
    if runbook is None:
        runbook = Runbook(created_by=user.username)
        db.add(runbook)
    runbook.name = data.name
    runbook.description = data.description
    runbook.steps = list(data.steps)
    runbook.params = list(data.params)
    await db.commit()
    await db.refresh(runbook)
    await log_event(
        db,
        request=request,
        action="runbook.create" if created else "runbook.update",
        summary=f'{"Created" if created else "Changed"} runbook "{runbook.name}"',
        target_type="runbook",
        target_id=runbook.id,
        target_label=runbook.name,
        details={"steps": len(data.steps), "params": [p["key"] for p in data.params]},
    )
    return runbooks_service.as_dict(runbook)


@router.post("", dependencies=[_edit], status_code=status.HTTP_201_CREATED)
async def create_runbook_api(
    request: Request,
    payload: _RunbookSave,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Steps are one-line shell commands; `{{key}}` in a command is filled
    from the parameter of that key when the runbook is run."""
    return await _save(request, db, user, None, payload)


@router.put("/{runbook_id}", dependencies=[_edit])
async def update_runbook_api(
    request: Request,
    runbook_id: uuid.UUID,
    payload: _RunbookSave,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    return await _save(request, db, user, await _get(db, runbook_id), payload)


@router.delete("/{runbook_id}", dependencies=[_edit])
async def delete_runbook_api(
    request: Request, runbook_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    runbook = await _get(db, runbook_id)
    name = runbook.name
    await db.delete(runbook)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="runbook.delete",
        summary=f'Deleted runbook "{name}"',
        target_type="runbook",
        target_id=runbook_id,
        target_label=name,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{runbook_id}/run", dependencies=[_run])
async def run_runbook_api(
    request: Request,
    runbook_id: uuid.UUID,
    payload: _RunRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """Run the runbook on `machine_ids` or on every machine of `group_id`
    (machines outside the account's scope are dropped, ones without a
    confirmed host key skipped). `values` fills the parameters; a missing
    one takes its default. A value may only hold letters, digits and
    `_ . : / @ = + , -`. Returns the batch to poll at
    `GET /api/v1/runbooks/runs/{batch_id}`."""
    runbook = await _get(db, runbook_id)
    if bool(payload.machine_ids) == (payload.group_id is not None):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Give either machine_ids or group_id.",
        )
    if payload.group_id is not None:
        groups = await groups_visible_to(db, user)
        group = (
            await db.execute(
                groups.where(MachineGroup.id == payload.group_id).options(
                    selectinload(MachineGroup.machines)
                )
            )
        ).scalar_one_or_none()
        if group is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")
        machines, label = list(group.machines), group.name
    else:
        machines = await visible_machines_by_ids(db, user, payload.machine_ids)
        label = f"{len(machines)} selected machines"
    try:
        batch_id, runs, skipped = await runbooks_service.start(
            db, runbook, machines, payload.values, user.username
        )
    except runbooks_service.RunbookError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    for run in runs:
        run_runbook.delay(str(run.id))
    await log_event(
        db,
        request=request,
        action="runbook.run",
        summary=f'Ran runbook "{runbook.name}" on {label} ({len(runs)} machines)',
        target_type="runbook",
        target_id=runbook.id,
        target_label=runbook.name,
        details={
            "batch_id": str(batch_id),
            "target": label,
            "machine_count": len(runs),
            "skipped": skipped,
            "values": payload.values,
        },
    )
    return {"batch_id": str(batch_id), "started": len(runs), "skipped": skipped}
