"""Scheduling — run an existing action (system update, update check, reboot,
shut down, ...) against a machine, a group, or "All machines" on a cron
expression. See `app.scheduling` for the action registry and the background
jobs that evaluate and fire these.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.scheduled_task_run import ScheduledTaskRun
from app.db.models.user import User
from app.db.session import get_db
from app.scheduling.actions import all_actions, get_action
from app.scheduling.cron import compute_next_run, next_runs
from app.scheduling.jobs import run_scheduled_task
from app.scheduling.targets import (
    decode_target,
    encode_target,
    target_within_scope,
    task_within_scope,
)
from app.schemas.scheduled_task import ScheduledTaskCreate
from app.schemas.scheduling_config import SchedulingConfigExport
from app.services.access_scope import groups_visible_to, is_restricted, machines_visible_to
from app.services.scheduling_config import export_scheduling_config, import_scheduling_config
from app.web.templating import t, templates

router = APIRouter(
    prefix="/scheduling", dependencies=[Depends(require_permission(Permission.SCHEDULING_VIEW))]
)
_manage = Depends(require_permission(Permission.SCHEDULING_MANAGE))

_HISTORY_PAGE_SIZE = 50


async def _get_task_or_404(task_id: uuid.UUID, db: AsyncSession, user: User) -> ScheduledTask:
    """The task, or a 404 — including when it exists but targets something
    outside `user`'s machine-group scope (an "All machines" schedule, or one
    aimed at a group/machine they can't see). 404 rather than 403, matching
    the machine and group lookups."""
    result = await db.execute(
        select(ScheduledTask)
        .options(
            selectinload(ScheduledTask.target_machine),
            selectinload(ScheduledTask.target_group),
        )
        .where(ScheduledTask.id == task_id)
    )
    task = result.scalar_one_or_none()
    if task is None or not await task_within_scope(db, user, task):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scheduled task not found."
        )
    return task


async def _get_machines(db: AsyncSession, user: User) -> list[Machine]:
    query = await machines_visible_to(db, user)
    result = await db.execute(query.order_by(Machine.name))
    return list(result.scalars().all())


async def _get_groups(db: AsyncSession, user: User) -> list[MachineGroup]:
    query = await groups_visible_to(db, user)
    result = await db.execute(query.order_by(MachineGroup.name))
    return list(result.scalars().all())


async def _form_context(
    db: AsyncSession,
    user: User,
    form: dict[str, str],
    errors: list[str],
    *,
    keep_action: str | None = None,
) -> dict[str, object]:
    # An action requiring a permission this user doesn't have (e.g.
    # `run_command` without `action.terminal`) isn't offered at all —
    # `_action_permission_error` is still the actual enforcement (this is
    # presentation only, same split `allow_all_machines` below already
    # follows for the target dropdown). Exception: a task already using
    # that action (`keep_action`, only set when editing) stays listed even
    # if this viewer can't grant it themselves — otherwise saving the edit
    # form unchanged would silently swap it to whatever action happens to
    # be first in the list.
    visible_actions = [
        action
        for action in all_actions()
        if action.extra_permission is None
        or user.has_permission(action.extra_permission)
        or action.key == keep_action
    ]
    return {
        "actions": visible_actions,
        "machines": await _get_machines(db, user),
        "groups": await _get_groups(db, user),
        # The form hides "All machines" for a restricted account; the POST
        # handlers reject it independently (`target_within_scope`), so this
        # is presentation, never the enforcement.
        "allow_all_machines": not await is_restricted(db, user),
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


_OUT_OF_SCOPE_TARGET_ERROR = (
    "Your account is restricted to specific machine groups, so this target "
    "isn't available. Pick one of your own groups or a machine in them "
    '("All machines" is never available to a restricted account).'
)


def _action_permission_error(action_key: str, user: User) -> str | None:
    """`None` if `user` may create/edit a task for `action_key` (either it
    has no extra requirement beyond `scheduling.manage`, already enforced
    by this router's own dependency, or the user also has it) — an error
    message otherwise. See `ScheduledActionSpec.extra_permission`'s own
    docstring for why `run_command` needs this on top of the plain
    `scheduling.manage` every other action is satisfied by."""
    action = get_action(action_key)
    if action is None or action.extra_permission is None:
        return None
    if user.has_permission(action.extra_permission):
        return None
    return (
        f'The "{action.label}" action also needs the '
        f'"{action.extra_permission.value}" permission, which your account '
        "doesn't have."
    )


@router.get("")
async def list_scheduled_tasks(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    result = await db.execute(
        select(ScheduledTask)
        .options(
            selectinload(ScheduledTask.target_machine),
            selectinload(ScheduledTask.target_group),
        )
        .order_by(ScheduledTask.name)
    )
    # Filtered in Python rather than in SQL: "in scope" spans three target
    # shapes (all-machines / group / machine, the last needing the machine's
    # own group), and schedules are few — a readable filter beats a
    # three-branch UNION over a handful of rows.
    tasks = [
        task
        for task in result.scalars().all()
        if await task_within_scope(db, current_user, task)
    ]
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "scheduling/list.html",
        {
            "tasks": tasks,
            "action_labels": {action.key: action.label for action in all_actions()},
            "csrf_token": csrf_token,
            # One-time notice after "Run now" — not persisted, just echoed
            # back from the query string.
            "ran": request.query_params.get("ran"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/config/export")
async def export_scheduling_config_endpoint(
    request: Request, db: AsyncSession = Depends(get_db)
) -> Response:
    """Config-as-code export of every scheduled task, targets resolved to
    machine/group **names** so the file is portable across deployments —
    see `app.services.scheduling_config`. Same convenience `GET
    /machines/config/export` and `GET /roles/config/export` already give."""
    export = await export_scheduling_config(db)

    await log_event(
        db,
        request=request,
        action="scheduled_task.config_export",
        summary=f"Exported configuration for {len(export.scheduled_tasks)} scheduled task(s)",
        details={"task_count": len(export.scheduled_tasks)},
    )

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=export.model_dump_json(indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="scheduling-config-{timestamp}.json"'
        },
    )


@router.get("/config/import")
async def import_scheduling_config_form(request: Request) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "scheduling/config_import.html",
        {"csrf_token": csrf_token, "errors": [], "result": None},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/config/import", dependencies=[_manage, Depends(verify_csrf)])
async def import_scheduling_config_submit(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    json_text: str = Form(""),
) -> Response:
    """Create real `ScheduledTask` rows from a pasted JSON export (see `GET
    /scheduling/config/export`) — each one checked against `current_user`'s
    machine-group scope and per-action permission exactly like the manual
    "New scheduled task" form, and skipped (not silently created) if either
    fails. See `app.services.scheduling_config` for the full skip policy,
    including unresolved targets and an unknown action."""
    text = json_text.strip()
    if not text:
        return templates.TemplateResponse(
            request,
            "scheduling/config_import.html",
            {
                "csrf_token": request.state.csrf_token,
                "errors": [t(request, "common.error.paste_json")],
                "result": None,
            },
        )

    try:
        payload = SchedulingConfigExport.model_validate_json(text)
    except ValidationError as exc:
        return templates.TemplateResponse(
            request,
            "scheduling/config_import.html",
            {
                "csrf_token": request.state.csrf_token,
                "errors": [f"Invalid configuration JSON: {exc}"],
                "result": None,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    result = await import_scheduling_config(db, payload, current_user)

    await log_event(
        db,
        request=request,
        action="scheduled_task.config_import",
        summary=result.summary(),
        details=result.to_dict(),
    )

    return templates.TemplateResponse(
        request,
        "scheduling/config_import.html",
        {"csrf_token": request.state.csrf_token, "errors": [], "result": result},
    )


@router.get("/{task_id}/history")
async def scheduled_task_history(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    page: int = 1,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Every past firing of this task, newest first — the full history
    behind the one-line `last_run_at`/`last_run_summary` the task list
    itself shows. Same offset/limit-plus-one-extra-row pagination as
    `/audit` and the update-run history."""
    task = await _get_task_or_404(task_id, db, current_user)
    page = max(page, 1)

    offset = (page - 1) * _HISTORY_PAGE_SIZE
    result = await db.execute(
        select(ScheduledTaskRun)
        .where(ScheduledTaskRun.scheduled_task_id == task.id)
        .order_by(ScheduledTaskRun.started_at.desc())
        .offset(offset)
        .limit(_HISTORY_PAGE_SIZE + 1)
    )
    runs = list(result.scalars().all())
    has_older = len(runs) > _HISTORY_PAGE_SIZE
    runs = runs[:_HISTORY_PAGE_SIZE]

    return templates.TemplateResponse(
        request,
        "scheduling/history.html",
        {
            "task": task,
            "runs": runs,
            "page": page,
            "has_older": has_older,
        },
    )


@router.get("/cron-preview")
async def cron_preview(request: Request, cron_expression: str = "") -> Response:
    """The schedule form's live "next runs" preview (htmx, as the cron field
    is typed in) — read-only, so plain `scheduling.view` like the form."""
    expression = cron_expression.strip()
    runs: list[datetime] = []
    error: str | None = None
    if expression:
        try:
            runs = next_runs(expression)
        except ValueError:
            error = t(request, "scheduling.cron_preview.invalid")
    return templates.TemplateResponse(
        request,
        "partials/cron_preview.html",
        {"runs": runs, "error": error, "expression": expression},
    )


@router.get("/new")
async def new_scheduled_task_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    # New schedules default to enabled — everywhere else, "is_enabled" only
    # ends up in `form` when a checkbox was actually submitted (unchecked =
    # the key is simply absent from the POST body), so this default is only
    # applied here, not silently reapplied on a failed-validation re-render.
    context = await _form_context(db, current_user, {"is_enabled": "on"}, [])
    context["csrf_token"] = csrf_token
    response = templates.TemplateResponse(request, "scheduling/new.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("", dependencies=[_manage, Depends(verify_csrf)])
async def create_scheduled_task(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
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

    if payload is not None and not await target_within_scope(
        db,
        current_user,
        payload.target_type,
        payload.target_machine_id,
        payload.target_group_id,
    ):
        errors.append(_OUT_OF_SCOPE_TARGET_ERROR)

    if payload is not None:
        permission_error = _action_permission_error(payload.action, current_user)
        if permission_error:
            errors.append(permission_error)

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
        context = await _form_context(db, current_user, raw_form, errors)
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
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    task = await _get_task_or_404(task_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    form = {
        "name": task.name,
        "action": task.action,
        "target": encode_target(task.target_type, task.target_machine_id, task.target_group_id),
        "cron_expression": task.cron_expression,
        "is_enabled": "on" if task.is_enabled else "",
        **{f"param_{k}": v for k, v in (task.action_params or {}).items()},
    }
    context = await _form_context(db, current_user, form, [], keep_action=task.action)
    context["csrf_token"] = csrf_token
    context["task"] = task
    response = templates.TemplateResponse(request, "scheduling/edit.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{task_id}/edit", dependencies=[_manage, Depends(verify_csrf)])
async def update_scheduled_task(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    task = await _get_task_or_404(task_id, db, current_user)
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

    if payload is not None and not await target_within_scope(
        db,
        current_user,
        payload.target_type,
        payload.target_machine_id,
        payload.target_group_id,
    ):
        errors.append(_OUT_OF_SCOPE_TARGET_ERROR)

    if payload is not None:
        permission_error = _action_permission_error(payload.action, current_user)
        if permission_error:
            errors.append(permission_error)

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
        context = await _form_context(
            db, current_user, raw_form, errors, keep_action=task.action
        )
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
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    task = await _get_task_or_404(task_id, db, current_user)
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
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Enqueue an immediate, one-off run — same job the per-minute
    scheduler tick would enqueue, useful for verifying a new schedule
    without waiting for its cron expression to come due. Doesn't affect
    `next_run_at`."""
    task = await _get_task_or_404(task_id, db, current_user)
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
    return RedirectResponse(
        url=f"/scheduling?ran={task.id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{task_id}/delete", dependencies=[_manage, Depends(verify_csrf)])
async def delete_scheduled_task(
    request: Request,
    task_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    task = await _get_task_or_404(task_id, db, current_user)
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
