"""Runbooks pages: the list, the editor, and running one with a preview
of exactly what will run where (`app.services.runbooks`).

Writing a runbook is writing shell commands, so it takes `action.terminal`
— the same permission that lets a person type them. Running one takes
`runbook.run` only. Every page here needs at least one of the two.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.db.models.runbook import Runbook, RunbookRunStatus
from app.db.models.user import User
from app.db.session import get_db
from app.services import runbooks as runbooks_service
from app.services.access_scope import groups_visible_to, machines_visible_to
from app.tasks import jobs as tasks
from app.web.templating import templates


async def _need_access(current_user: User = Depends(get_current_user)) -> None:
    if not (
        current_user.has_permission(Permission.RUNBOOK_RUN)
        or current_user.has_permission(Permission.ACTION_TERMINAL)
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed.")


router = APIRouter(prefix="/runbooks", dependencies=[Depends(_need_access)])
_edit = Depends(require_permission(Permission.ACTION_TERMINAL))
_run = Depends(require_permission(Permission.RUNBOOK_RUN))

_MACHINE_CHOICES = 500


async def _get_runbook(db: AsyncSession, runbook_id: uuid.UUID) -> Runbook:
    runbook = await db.get(Runbook, runbook_id)
    if runbook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Runbook not found.")
    return runbook


def _respond(request: Request, template: str, context: dict[str, object]) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(request, template, {**context, "csrf_token": csrf_token})
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("")
async def list_runbooks(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    machine_id: uuid.UUID | None = None,
) -> Response:
    result = await db.execute(select(Runbook).order_by(Runbook.name))
    machine = None
    if machine_id is not None:
        query = await machines_visible_to(db, current_user)
        machine = (await db.execute(query.where(Machine.id == machine_id))).scalar_one_or_none()
    return _respond(
        request,
        "runbooks/list.html",
        {
            "runbooks": list(result.scalars().all()),
            "batches": await runbooks_service.recent_batches(db, current_user),
            "machine": machine,
            "can_edit": current_user.has_permission(Permission.ACTION_TERMINAL),
            "can_run": current_user.has_permission(Permission.RUNBOOK_RUN),
        },
    )


def _form_context(
    runbook: Runbook | None,
    *,
    name: str,
    description: str,
    steps: str,
    params: str,
    error: str = "",
) -> dict[str, object]:
    return {
        "runbook": runbook,
        "form_name": name,
        "form_description": description,
        "form_steps": steps,
        "form_params": params,
        "error": error,
        "max_steps": runbooks_service.MAX_STEPS,
    }


@router.get("/new", dependencies=[_edit])
async def new_runbook(request: Request) -> Response:
    return _respond(
        request,
        "runbooks/form.html",
        _form_context(None, name="", description="", steps="", params=""),
    )


async def _save(
    request: Request,
    db: AsyncSession,
    current_user: User,
    runbook: Runbook | None,
    name: str,
    description: str,
    steps: str,
    params: str,
) -> Response:
    try:
        data = runbooks_service.validate(
            name,
            description,
            runbooks_service.parse_steps(steps),
            runbooks_service.parse_params(params),
        )
        if await runbooks_service.name_taken(db, data.name, runbook.id if runbook else None):
            raise runbooks_service.RunbookError("A runbook with this name already exists.")
    except runbooks_service.RunbookError as exc:
        response = _respond(
            request,
            "runbooks/form.html",
            _form_context(
                runbook,
                name=name,
                description=description,
                steps=steps,
                params=params,
                error=str(exc),
            ),
        )
        response.status_code = status.HTTP_400_BAD_REQUEST
        return response
    created = runbook is None
    if runbook is None:
        runbook = Runbook(created_by=current_user.username)
        db.add(runbook)
    runbook.name = data.name
    runbook.description = data.description
    runbook.steps = list(data.steps)
    runbook.params = list(data.params)
    await db.commit()
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
    return RedirectResponse(url="/runbooks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("", dependencies=[_edit, Depends(verify_csrf)])
async def create_runbook(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name: str = Form(""),
    description: str = Form(""),
    steps: str = Form(""),
    params: str = Form(""),
) -> Response:
    return await _save(request, db, current_user, None, name, description, steps, params)


@router.get("/{runbook_id}/edit", dependencies=[_edit])
async def edit_runbook(
    request: Request, runbook_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    runbook = await _get_runbook(db, runbook_id)
    return _respond(
        request,
        "runbooks/form.html",
        _form_context(
            runbook,
            name=runbook.name,
            description=runbook.description or "",
            steps=runbooks_service.steps_as_text(runbook.steps or []),
            params=runbooks_service.params_as_text(runbook.params or []),
        ),
    )


@router.post("/{runbook_id}/edit", dependencies=[_edit, Depends(verify_csrf)])
async def update_runbook(
    request: Request,
    runbook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name: str = Form(""),
    description: str = Form(""),
    steps: str = Form(""),
    params: str = Form(""),
) -> Response:
    runbook = await _get_runbook(db, runbook_id)
    return await _save(request, db, current_user, runbook, name, description, steps, params)


@router.post("/{runbook_id}/delete", dependencies=[_edit, Depends(verify_csrf)])
async def delete_runbook(
    request: Request, runbook_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    runbook = await _get_runbook(db, runbook_id)
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
    return RedirectResponse(url="/runbooks", status_code=status.HTTP_303_SEE_OTHER)


async def _targets(
    db: AsyncSession, user: User, target_type: str, machine_id: str, group_id: str
) -> tuple[list[Machine], str]:
    """The machines a run is aimed at, and a label for them. Only what the
    account may see; `RunbookError` when nothing was chosen."""
    try:
        if target_type == "group":
            groups = await groups_visible_to(db, user)
            group = (
                await db.execute(
                    groups.where(MachineGroup.id == uuid.UUID(group_id)).options(
                        selectinload(MachineGroup.machines)
                    )
                )
            ).scalar_one_or_none()
            if group is not None:
                return list(group.machines), group.name
        elif target_type == "machine":
            machines = await machines_visible_to(db, user)
            machine = (
                await db.execute(machines.where(Machine.id == uuid.UUID(machine_id)))
            ).scalar_one_or_none()
            if machine is not None:
                return [machine], machine.name
    except ValueError as exc:
        # Not an id at all (nothing chosen in the form): the same answer as
        # an id that matches nothing.
        raise runbooks_service.RunbookError("Choose a machine or a group to run it on.") from exc
    raise runbooks_service.RunbookError("Choose a machine or a group to run it on.")


async def _run_form(
    request: Request,
    db: AsyncSession,
    user: User,
    runbook: Runbook,
    *,
    values: dict[str, str],
    target_type: str,
    machine_id: str,
    group_id: str,
    error: str = "",
) -> Response:
    machines = await machines_visible_to(db, user)
    machine_rows = await db.execute(
        machines.with_only_columns(Machine.id, Machine.name)
        .order_by(Machine.name)
        .limit(_MACHINE_CHOICES)
    )
    groups = await groups_visible_to(db, user)
    group_rows = await db.execute(
        groups.with_only_columns(MachineGroup.id, MachineGroup.name).order_by(MachineGroup.name)
    )
    response = _respond(
        request,
        "runbooks/run.html",
        {
            "runbook": runbook,
            "values": values,
            "target_type": target_type,
            "machine_id": machine_id,
            "group_id": group_id,
            "machine_choices": [(str(row[0]), row[1]) for row in machine_rows.all()],
            "group_choices": [(str(row[0]), row[1]) for row in group_rows.all()],
            "error": error,
        },
    )
    if error:
        response.status_code = status.HTTP_400_BAD_REQUEST
    return response


@router.get("/{runbook_id}/run", dependencies=[_run])
async def run_runbook_form(
    request: Request,
    runbook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    machine_id: str = "",
) -> Response:
    runbook = await _get_runbook(db, runbook_id)
    return await _run_form(
        request,
        db,
        current_user,
        runbook,
        values={},
        target_type="machine" if machine_id else "group",
        machine_id=machine_id,
        group_id="",
    )


def _values_from(runbook: Runbook, form: dict[str, str]) -> dict[str, str]:
    return {
        str(param.get("key")): form.get(f"param_{param.get('key')}", "").strip()
        for param in runbook.params or []
    }


@router.post("/{runbook_id}/preview", dependencies=[_run, Depends(verify_csrf)])
async def preview_runbook(
    request: Request,
    runbook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    target_type: str = Form("machine"),
    machine_id: str = Form(""),
    group_id: str = Form(""),
) -> Response:
    """What will run, where — nothing is started here."""
    runbook = await _get_runbook(db, runbook_id)
    form = {key: str(value) for key, value in (await request.form()).items()}
    values = _values_from(runbook, form)
    try:
        commands = runbooks_service.render(runbook, values)
        machines, label = await _targets(db, current_user, target_type, machine_id, group_id)
    except runbooks_service.RunbookError as exc:
        return await _run_form(
            request,
            db,
            current_user,
            runbook,
            values=values,
            target_type=target_type,
            machine_id=machine_id,
            group_id=group_id,
            error=str(exc),
        )
    ready = sorted((m.name for m in machines if m.host_key_fingerprint), key=str.lower)
    return _respond(
        request,
        "runbooks/confirm.html",
        {
            "runbook": runbook,
            "commands": commands,
            "values": values,
            "target_type": target_type,
            "machine_id": machine_id,
            "group_id": group_id,
            "target_label": label,
            "machine_names": ready,
            "skipped": len(machines) - len(ready),
        },
    )


@router.post("/{runbook_id}/run", dependencies=[_run, Depends(verify_csrf)])
async def run_runbook(
    request: Request,
    runbook_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    target_type: str = Form("machine"),
    machine_id: str = Form(""),
    group_id: str = Form(""),
) -> Response:
    runbook = await _get_runbook(db, runbook_id)
    form = {key: str(value) for key, value in (await request.form()).items()}
    values = _values_from(runbook, form)
    try:
        machines, label = await _targets(db, current_user, target_type, machine_id, group_id)
        batch_id, runs, skipped = await runbooks_service.start(
            db, runbook, machines, values, current_user.username
        )
    except runbooks_service.RunbookError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    for run in runs:
        tasks.run_runbook.delay(str(run.id))
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
            "values": values,
        },
    )
    return RedirectResponse(url=f"/runbooks/runs/{batch_id}", status_code=status.HTTP_303_SEE_OTHER)


def _batch_context(batch_id: uuid.UUID, runs: list[object]) -> dict[str, object]:
    unfinished = sum(
        1
        for run in runs
        if getattr(run, "status", None) in (RunbookRunStatus.PENDING, RunbookRunStatus.RUNNING)
    )
    return {"runs": runs, "batch_id": batch_id, "has_pending": unfinished > 0}


@router.get("/runs/{batch_id}")
async def runbook_batch(
    request: Request,
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    runs = await runbooks_service.visible_batch(db, current_user, batch_id)
    if not runs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found.")
    return templates.TemplateResponse(
        request, "runbooks/batch.html", _batch_context(batch_id, list(runs))
    )


@router.get("/runs/{batch_id}/status")
async def runbook_batch_status(
    request: Request,
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    runs = await runbooks_service.visible_batch(db, current_user, batch_id)
    return templates.TemplateResponse(
        request, "partials/runbook_batch_status.html", _batch_context(batch_id, list(runs))
    )
