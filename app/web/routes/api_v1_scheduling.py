"""REST API for scheduled tasks — mirrors `app/web/routes/scheduling.py`.

See `app.web.routes.api_v1`'s module docstring for the general design
(same permissions as the equivalent web route, same underlying service
calls, mounted under the same `/api/v1` prefix).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.core.timezones import is_valid_timezone
from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.scheduled_task_run import ScheduledTaskRun
from app.db.models.user import User
from app.db.session import get_db
from app.scheduling.cron import compute_next_run, next_runs
from app.scheduling.jobs import run_scheduled_task
from app.scheduling.targets import target_within_scope, task_within_scope
from app.schemas.scheduled_task import ScheduledTaskCreate
from app.schemas.scheduling_config import SchedulingConfigExport
from app.services.scheduling_config import export_scheduling_config, import_scheduling_config

router = APIRouter(prefix="/api/v1/scheduling")

_view = Depends(require_api_permission(Permission.SCHEDULING_VIEW))
_manage = Depends(require_api_permission(Permission.SCHEDULING_MANAGE))


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _task_to_dict(task: ScheduledTask) -> dict[str, object]:
    return {
        "id": str(task.id),
        "name": task.name,
        "action": task.action,
        "action_params": task.action_params,
        "target_type": task.target_type.value,
        "target_machine_id": str(task.target_machine_id) if task.target_machine_id else None,
        "target_group_id": str(task.target_group_id) if task.target_group_id else None,
        "cron_expression": task.cron_expression,
        "timezone": task.timezone or "UTC",
        "require_maintenance_window": task.require_maintenance_window,
        "is_enabled": task.is_enabled,
        "next_run_at": _isoformat(task.next_run_at),
        "last_run_at": _isoformat(task.last_run_at),
        "last_run_summary": task.last_run_summary,
    }


async def _get_task_or_404(task_id: uuid.UUID, db: AsyncSession, user: User) -> ScheduledTask:
    """Scoped like the web UI's equivalent: a task targeting "All machines",
    or a group/machine outside this account's machine-group scope, is a 404
    here too. See `app/web/routes/scheduling.py`."""
    result = await db.execute(
        select(ScheduledTask)
        .options(
            selectinload(ScheduledTask.target_machine), selectinload(ScheduledTask.target_group)
        )
        .where(ScheduledTask.id == task_id)
    )
    task = result.scalar_one_or_none()
    if task is None or not await task_within_scope(db, user, task):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled task not found."
        )
    return task


async def _require_target_in_scope(
    db: AsyncSession, user: User, payload: ScheduledTaskCreate
) -> None:
    """Reject a target this account may not schedule against — including
    "All machines", which is never available to a restricted account (see
    `app.scheduling.targets.target_within_scope` for why it is refused
    rather than narrowed). Enforced at create/edit time only: a stored
    schedule fires with no current user to scope to."""
    if not await target_within_scope(
        db, user, payload.target_type, payload.target_machine_id, payload.target_group_id
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This account is restricted to specific machine groups, so this target "
                'isn\'t available ("all_machines" never is).'
            ),
        )


@router.get("/config/export", dependencies=[_view])
async def export_scheduling_config_api(
    db: AsyncSession = Depends(get_db),
) -> SchedulingConfigExport:
    """The API equivalent of `GET /scheduling/config/export` — see
    `app.services.scheduling_config`. Not scoped to `user`, same as the
    web route: reaching this at all already requires `scheduling.view`
    fleet-wide."""
    return await export_scheduling_config(db)


@router.post("/config/import", dependencies=[_manage])
async def import_scheduling_config_api(
    request: Request,
    payload: SchedulingConfigExport,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The API equivalent of `POST /scheduling/config/import` — each task
    checked against `user`'s machine-group scope and per-action permission,
    same as `create_scheduled_task_api`. See
    `app.services.scheduling_config` for the full skip policy."""
    result = await import_scheduling_config(db, payload, user)
    await log_event(
        db,
        request=request,
        action="scheduled_task.config_import",
        summary=result.summary(),
        details=result.to_dict(),
    )
    return result.to_dict()


@router.get("/cron-preview", dependencies=[_view])
async def cron_preview_api(
    expression: str, count: int = 5, timezone: str = "UTC"
) -> dict[str, object]:
    """The next `count` (1-50) run times of a cron expression read in
    `timezone` (an IANA name, default UTC), as UTC timestamps — what the
    schedule form previews as you type. 422 for an invalid expression or
    an unknown zone."""
    count = max(1, min(count, 50))
    if not is_valid_timezone(timezone.strip()):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Unknown time zone.")
    try:
        runs = next_runs(expression.strip(), count=count, timezone=timezone.strip())
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return {
        "expression": expression.strip(),
        "timezone": timezone.strip(),
        "next_runs": [run.isoformat() for run in runs],
    }


@router.get("", dependencies=[_view])
async def list_scheduled_tasks_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    result = await db.execute(select(ScheduledTask).order_by(ScheduledTask.name))
    return [
        _task_to_dict(t)
        for t in result.scalars().all()
        if await task_within_scope(db, user, t)
    ]


@router.get("/{task_id}", dependencies=[_view])
async def get_scheduled_task_api(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    return _task_to_dict(await _get_task_or_404(task_id, db, user))


@router.post("", dependencies=[_manage], status_code=status.HTTP_201_CREATED)
async def create_scheduled_task_api(
    request: Request,
    payload: ScheduledTaskCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    await _require_target_in_scope(db, user, payload)
    task = ScheduledTask(
        name=payload.name,
        action=payload.action,
        action_params=payload.action_params,
        target_type=payload.target_type,
        target_machine_id=payload.target_machine_id,
        target_group_id=payload.target_group_id,
        cron_expression=payload.cron_expression,
        is_enabled=payload.is_enabled,
        timezone=payload.timezone,
        require_maintenance_window=payload.require_maintenance_window,
        next_run_at=(
            compute_next_run(payload.cron_expression, timezone=payload.timezone)
            if payload.is_enabled
            else None
        ),
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)
    await log_event(
        db,
        request=request,
        action="scheduled_task.create",
        summary=f'Created scheduled task "{task.name}" ({task.action}, {task.cron_expression})',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return _task_to_dict(task)


@router.put("/{task_id}", dependencies=[_manage])
async def update_scheduled_task_api(
    request: Request,
    task_id: uuid.UUID,
    payload: ScheduledTaskCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    task = await _get_task_or_404(task_id, db, user)
    await _require_target_in_scope(db, user, payload)
    task.name = payload.name
    task.action = payload.action
    task.action_params = payload.action_params
    task.target_type = payload.target_type
    task.target_machine_id = payload.target_machine_id
    task.target_group_id = payload.target_group_id
    task.cron_expression = payload.cron_expression
    task.is_enabled = payload.is_enabled
    task.timezone = payload.timezone
    task.require_maintenance_window = payload.require_maintenance_window
    task.next_run_at = (
        compute_next_run(payload.cron_expression, timezone=payload.timezone)
        if payload.is_enabled
        else None
    )
    await db.commit()
    await log_event(
        db,
        request=request,
        action="scheduled_task.update",
        summary=f'Updated scheduled task "{task.name}"',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return _task_to_dict(task)


@router.post("/{task_id}/enable", dependencies=[_manage])
async def enable_scheduled_task_api(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    task = await _get_task_or_404(task_id, db, user)
    task.is_enabled = True
    task.next_run_at = compute_next_run(task.cron_expression, timezone=task.timezone)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="scheduled_task.enable",
        summary=f'Enabled scheduled task "{task.name}"',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return _task_to_dict(task)


@router.post("/{task_id}/disable", dependencies=[_manage])
async def disable_scheduled_task_api(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    task = await _get_task_or_404(task_id, db, user)
    task.is_enabled = False
    task.next_run_at = None
    await db.commit()
    await log_event(
        db,
        request=request,
        action="scheduled_task.disable",
        summary=f'Disabled scheduled task "{task.name}"',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return _task_to_dict(task)


@router.get("/{task_id}/runs", dependencies=[_view])
async def list_scheduled_task_runs_api(
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    """The API equivalent of `GET /scheduling/{id}/history` — every past
    firing of this task, newest first. Not paginated: this app's own web
    UI paginates for display, but a script fetching its own task's history
    can reasonably want it all in one call; this table only grows one row
    per firing of one schedule, not per machine."""
    task = await _get_task_or_404(task_id, db, user)
    result = await db.execute(
        select(ScheduledTaskRun)
        .where(ScheduledTaskRun.scheduled_task_id == task.id)
        .order_by(ScheduledTaskRun.started_at.desc())
    )
    return [
        {
            "id": str(run.id),
            "action": run.action,
            "status": run.status.value,
            "summary": run.summary,
            "attempted": run.attempted,
            "skipped": run.skipped,
            "started_at": _isoformat(run.started_at),
            "finished_at": _isoformat(run.finished_at),
        }
        for run in result.scalars().all()
    ]


@router.post("/{task_id}/run-now", dependencies=[_manage])
async def run_scheduled_task_now_api(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    task = await _get_task_or_404(task_id, db, user)
    run_scheduled_task.delay(str(task.id))
    await log_event(
        db,
        request=request,
        action="scheduled_task.run_now",
        summary=f'Manually ran scheduled task "{task.name}" now',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return {"ok": True}


@router.delete("/{task_id}", dependencies=[_manage])
async def delete_scheduled_task_api(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    task = await _get_task_or_404(task_id, db, user)
    task_name = task.name
    await db.delete(task)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="scheduled_task.delete",
        summary=f'Deleted scheduled task "{task_name}"',
        target_type="scheduled_task",
        target_id=task_id,
        target_label=task_name,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
