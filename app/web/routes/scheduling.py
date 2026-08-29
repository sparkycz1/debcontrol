"""Scheduling — run an existing action (system update, update check, reboot,
shut down, ...) against a machine, a group, or "All machines" on a cron
expression. See `app.scheduling` for the action registry and the background
jobs that evaluate and fire these.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduledTask
from app.db.session import get_db
from app.scheduling.actions import all_actions, get_action
from app.scheduling.cron import compute_next_run
from app.scheduling.targets import decode_target, encode_target
from app.schemas.scheduled_task import ScheduledTaskCreate
from app.web.templating import templates

router = APIRouter(
    prefix="/scheduling", dependencies=[Depends(require_permission(Permission.SCHEDULING_VIEW))]
)
_manage = Depends(require_permission(Permission.SCHEDULING_MANAGE))


async def _get_task_or_404(task_id: uuid.UUID, db: AsyncSession) -> ScheduledTask:
    result = await db.execute(
        select(ScheduledTask)
        .options(
            selectinload(ScheduledTask.target_machine),
            selectinload(ScheduledTask.target_group),
        )
        .where(ScheduledTask.id == task_id)
    )
    task = result.scalar_one_or_none()
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled task not found."
        )
    return task


async def _get_machines(db: AsyncSession) -> list[Machine]:
    result = await db.execute(select(Machine).order_by(Machine.name))
    return list(result.scalars().all())


async def _get_groups(db: AsyncSession) -> list[MachineGroup]:
    result = await db.execute(select(MachineGroup).order_by(MachineGroup.name))
    return list(result.scalars().all())


async def _form_context(
    db: AsyncSession, form: dict[str, str], errors: list[str]
) -> dict[str, object]:
    return {
        "actions": all_actions(),
        "machines": await _get_machines(db),
        "groups": await _get_groups(db),
        "form": form,
        "errors": errors,
    }


def _action_params_from_form(action_key: str, raw_form: dict[str, str]) -> dict[str, str]:
    """Only pull the params the selected action actually declares — anything
    else submitted is ignored rather than stored verbatim."""
    action = get_action(action_key)
    if action is None:
        return {}
    return {
        param.key: raw_form.get(f"param_{param.key}", param.default) for param in action.params
    }


@router.get("")
async def list_scheduled_tasks(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    result = await db.execute(
        select(ScheduledTask)
        .options(
            selectinload(ScheduledTask.target_machine),
            selectinload(ScheduledTask.target_group),
        )
        .order_by(ScheduledTask.name)
    )
    tasks = result.scalars().all()
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "scheduling/list.html",
        {
            "tasks": tasks,
            "csrf_token": csrf_token,
            # One-time notice after "Run now" — not persisted, just echoed
            # back from the query string.
            "ran": request.query_params.get("ran"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/new")
async def new_scheduled_task_form(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    # New schedules default to enabled — everywhere else, "is_enabled" only
    # ends up in `form` when a checkbox was actually submitted (unchecked =
    # the key is simply absent from the POST body), so this default is only
    # applied here, not silently reapplied on a failed-validation re-render.
    context = await _form_context(db, {"is_enabled": "on"}, [])
    context["csrf_token"] = csrf_token
    response = templates.TemplateResponse(request, "scheduling/new.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("", dependencies=[_manage, Depends(verify_csrf)])
async def create_scheduled_task(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    raw_form = {key: str(value) for key, value in (await request.form()).items()}

    errors: list[str] = []
    payload: ScheduledTaskCreate | None = None
    try:
        target_type, target_machine_id, target_group_id = decode_target(raw_form.get("target", ""))
        payload = ScheduledTaskCreate(
            name=raw_form.get("name", ""),
            action=raw_form.get("action", ""),
            action_params=_action_params_from_form(raw_form.get("action", ""), raw_form),
            target_type=target_type,
            target_machine_id=target_machine_id,
            target_group_id=target_group_id,
            cron_expression=raw_form.get("cron_expression", ""),
            is_enabled=bool(raw_form.get("is_enabled")),
        )
    except ValueError as exc:
        errors.append(str(exc))

    if errors or payload is None:
        task_name = raw_form.get("name", "")
        await log_event(
            db,
            request=request,
            action="scheduled_task.create",
            summary=f'Rejected new scheduled task "{task_name}": {"; ".join(errors)}',
            outcome=AuditOutcome.FAILURE,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        context = await _form_context(db, raw_form, errors)
        context["csrf_token"] = csrf_token
        response = templates.TemplateResponse(
            request,
            "scheduling/new.html",
            context,
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    task = ScheduledTask(
        name=payload.name,
        action=payload.action,
        action_params=payload.action_params,
        target_type=payload.target_type,
        target_machine_id=payload.target_machine_id,
        target_group_id=payload.target_group_id,
        cron_expression=payload.cron_expression,
        is_enabled=payload.is_enabled,
        next_run_at=compute_next_run(payload.cron_expression) if payload.is_enabled else None,
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

    return RedirectResponse(url="/scheduling", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{task_id}/edit")
async def edit_scheduled_task_form(
    request: Request, task_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    task = await _get_task_or_404(task_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    form = {
        "name": task.name,
        "action": task.action,
        "target": encode_target(task.target_type, task.target_machine_id, task.target_group_id),
        "cron_expression": task.cron_expression,
        "is_enabled": "on" if task.is_enabled else "",
        **{f"param_{k}": v for k, v in (task.action_params or {}).items()},
    }
    context = await _form_context(db, form, [])
    context["csrf_token"] = csrf_token
    context["task"] = task
    response = templates.TemplateResponse(request, "scheduling/edit.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{task_id}/edit", dependencies=[_manage, Depends(verify_csrf)])
async def update_scheduled_task(
    request: Request, task_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    task = await _get_task_or_404(task_id, db)
    raw_form = {key: str(value) for key, value in (await request.form()).items()}

    errors: list[str] = []
    payload: ScheduledTaskCreate | None = None
    try:
        target_type, target_machine_id, target_group_id = decode_target(raw_form.get("target", ""))
        payload = ScheduledTaskCreate(
            name=raw_form.get("name", ""),
            action=raw_form.get("action", ""),
            action_params=_action_params_from_form(raw_form.get("action", ""), raw_form),
            target_type=target_type,
            target_machine_id=target_machine_id,
            target_group_id=target_group_id,
            cron_expression=raw_form.get("cron_expression", ""),
            is_enabled=bool(raw_form.get("is_enabled")),
        )
    except ValueError as exc:
        errors.append(str(exc))

    if errors or payload is None:
        await log_event(
            db,
            request=request,
            action="scheduled_task.update",
            summary=f'Rejected update to scheduled task "{task.name}": {"; ".join(errors)}',
            outcome=AuditOutcome.FAILURE,
            target_type="scheduled_task",
            target_id=task.id,
            target_label=task.name,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        context = await _form_context(db, raw_form, errors)
        context["csrf_token"] = csrf_token
        context["task"] = task
        response = templates.TemplateResponse(
            request,
            "scheduling/edit.html",
            context,
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    task.name = payload.name
    task.action = payload.action
    task.action_params = payload.action_params
    task.target_type = payload.target_type
    task.target_machine_id = payload.target_machine_id
    task.target_group_id = payload.target_group_id
    task.cron_expression = payload.cron_expression
    task.is_enabled = payload.is_enabled
    task.next_run_at = compute_next_run(payload.cron_expression) if payload.is_enabled else None

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
    return RedirectResponse(url="/scheduling", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{task_id}/toggle", dependencies=[_manage, Depends(verify_csrf)])
async def toggle_scheduled_task(
    request: Request, task_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    task = await _get_task_or_404(task_id, db)
    task.is_enabled = not task.is_enabled
    task.next_run_at = compute_next_run(task.cron_expression) if task.is_enabled else None
    await db.commit()
    await log_event(
        db,
        request=request,
        action="scheduled_task.enable" if task.is_enabled else "scheduled_task.disable",
        summary=f'{"Enabled" if task.is_enabled else "Disabled"} scheduled task "{task.name}"',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return RedirectResponse(url="/scheduling", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{task_id}/run-now", dependencies=[_manage, Depends(verify_csrf)])
async def run_scheduled_task_now(
    request: Request, task_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    """Enqueue an immediate, one-off run — same job the per-minute
    scheduler tick would enqueue, useful for verifying a new schedule
    without waiting for its cron expression to come due. Doesn't affect
    `next_run_at`."""
    task = await _get_task_or_404(task_id, db)
    await request.app.state.arq_redis.enqueue_job("run_scheduled_task", str(task.id))
    await log_event(
        db,
        request=request,
        action="scheduled_task.run_now",
        summary=f'Manually ran scheduled task "{task.name}" now',
        target_type="scheduled_task",
        target_id=task.id,
        target_label=task.name,
    )
    return RedirectResponse(
        url=f"/scheduling?ran={task.id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{task_id}/delete", dependencies=[_manage, Depends(verify_csrf)])
async def delete_scheduled_task(
    request: Request, task_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    task = await _get_task_or_404(task_id, db)
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
    return RedirectResponse(url="/scheduling", status_code=status.HTTP_303_SEE_OTHER)
