"""Machine groups — organize managed machines (e.g. by environment or role)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.role import Permission
from app.db.session import get_db
from app.schemas.machine_group import MachineGroupCreate
from app.services.machine_actions import (
    send_power_to_machines,
    trigger_check_updates,
    trigger_updates,
)
from app.ssh.power import PowerAction
from app.web.machine_search import machine_search_clause
from app.web.templating import templates

router = APIRouter(
    prefix="/machine-groups", dependencies=[Depends(require_permission(Permission.GROUP_VIEW))]
)
_manage = Depends(require_permission(Permission.GROUP_MANAGE))
_updates = Depends(require_permission(Permission.ACTION_UPDATES))
_power = Depends(require_permission(Permission.ACTION_POWER))

# Typed phrase to confirm a power action against literally every machine —
# "All machines" doesn't have a single name of its own to ask someone to type.
ALL_MACHINES_CONFIRM_PHRASE = "ALL MACHINES"


async def _get_group_or_404(group_id: uuid.UUID, db: AsyncSession) -> MachineGroup:
    result = await db.execute(
        select(MachineGroup)
        .options(selectinload(MachineGroup.machines))
        .where(MachineGroup.id == group_id)
    )
    group = result.scalar_one_or_none()
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")
    return group


@router.get("")
async def list_groups(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    result = await db.execute(
        select(MachineGroup)
        .options(selectinload(MachineGroup.machines))
        .order_by(MachineGroup.name)
    )
    groups = result.scalars().all()
    all_machines_count = await db.scalar(select(func.count()).select_from(Machine))
    return templates.TemplateResponse(
        request,
        "machine_groups/list.html",
        {"groups": groups, "all_machines_count": all_machines_count or 0},
    )


@router.get("/new")
async def new_group_form(request: Request) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request, "machine_groups/new.html", {"errors": [], "form": {}, "csrf_token": csrf_token}
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("", dependencies=[_manage, Depends(verify_csrf)])
async def create_group(
    request: Request,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    description: str = Form(""),
) -> Response:
    try:
        payload = MachineGroupCreate(name=name, description=description or None)
    except ValueError as exc:
        await log_event(
            db,
            request=request,
            action="group.create",
            summary=f'Rejected new group "{name}": {exc}',
            outcome=AuditOutcome.FAILURE,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machine_groups/new.html",
            {
                "errors": [str(exc)],
                "form": {"name": name, "description": description},
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    group = MachineGroup(name=payload.name, description=payload.description)
    db.add(group)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        await log_event(
            db,
            request=request,
            action="group.create",
            summary=f'Rejected new group "{payload.name}": name already exists',
            outcome=AuditOutcome.FAILURE,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machine_groups/new.html",
            {
                "errors": [f'A group named "{payload.name}" already exists.'],
                "form": {"name": name, "description": description},
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_409_CONFLICT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    await db.refresh(group)
    await log_event(
        db,
        request=request,
        action="group.create",
        summary=f'Created group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
    )
    return RedirectResponse(
        url=f"/machine-groups/{group.id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/all")
async def all_machines_group(
    request: Request, db: AsyncSession = Depends(get_db), q: str = ""
) -> Response:
    """The "All machines" virtual group — every machine, always, automatically.

    Unlike real groups, this isn't backed by any membership data (a machine
    can only have one real `group_id`, so it couldn't also "belong" to a
    stored All-machines group without a bigger many-to-many rework). Instead
    this just queries every machine unconditionally, which trivially and
    always satisfies "always all machines" without anything to keep in sync.
    Registered before `/{group_id}` — `uuid.UUID` there won't match the
    literal "all" anyway, but route order is what actually decides it.
    """
    query = select(Machine).options(selectinload(Machine.group))
    if q.strip():
        query = query.where(machine_search_clause(q))
    result = await db.execute(query.order_by(Machine.name))
    machines = result.scalars().all()

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machine_groups/all.html",
        {
            "machines": machines,
            "q": q,
            "csrf_token": csrf_token,
            "power_skipped": request.query_params.get("power_skipped"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/all/updates", dependencies=[_updates, Depends(verify_csrf)])
async def trigger_all_machines_update(
    request: Request,
    db: AsyncSession = Depends(get_db),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    result = await db.execute(select(Machine))
    machines = list(result.scalars().all())

    batch_id, skipped = await trigger_updates(db, request.app.state.arq_redis, machines, strategy)

    await log_event(
        db,
        request=request,
        action="all_machines.updates.run",
        summary=f"Triggered {strategy.value.replace('_', '-')} on all machines",
        target_type="all_machines",
        details={"strategy": strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )

    redirect_url = f"/machine-groups/batches/{batch_id}"
    if skipped:
        redirect_url += f"?skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/all/check-updates", dependencies=[_updates, Depends(verify_csrf)])
async def trigger_all_check_updates(
    request: Request, db: AsyncSession = Depends(get_db)
) -> Response:
    result = await db.execute(select(Machine))
    skipped = await trigger_check_updates(request.app.state.arq_redis, list(result.scalars().all()))
    await log_event(
        db,
        request=request,
        action="all_machines.updates.check",
        summary="Checked for updates on all machines",
        target_type="all_machines",
        details={"skipped": skipped},
    )
    return RedirectResponse(url="/machine-groups/all", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/all/power/{action}")
async def all_power_confirm(request: Request, action: PowerAction) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machine_groups/power_confirm.html",
        {
            "action": action,
            "target_label": "every machine",
            "confirm_phrase": ALL_MACHINES_CONFIRM_PHRASE,
            "action_url": "/machine-groups/all/power",
            "cancel_url": "/machine-groups/all",
            "error": None,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/all/power", dependencies=[_power, Depends(verify_csrf)])
async def all_power_action(
    request: Request,
    db: AsyncSession = Depends(get_db),
    action: PowerAction = Form(...),
    confirm_name: str = Form(...),
) -> Response:
    if confirm_name.strip() != ALL_MACHINES_CONFIRM_PHRASE:
        await log_event(
            db,
            request=request,
            action=f"all_machines.power.{action.value}",
            summary=f"Blocked {action.value} on all machines: confirmation mismatch",
            outcome=AuditOutcome.DENIED,
            target_type="all_machines",
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machine_groups/power_confirm.html",
            {
                "action": action,
                "target_label": "every machine",
                "confirm_phrase": ALL_MACHINES_CONFIRM_PHRASE,
                "action_url": "/machine-groups/all/power",
                "cancel_url": "/machine-groups/all",
                "error": (
                    f'That doesn\'t match — type "{ALL_MACHINES_CONFIRM_PHRASE}" '
                    "exactly to confirm."
                ),
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    result = await db.execute(select(Machine))
    machines = list(result.scalars().all())
    skipped = await send_power_to_machines(request.app.state.arq_redis, machines, action)
    await log_event(
        db,
        request=request,
        action=f"all_machines.power.{action.value}",
        summary=f"Sent {action.value} to all machines",
        target_type="all_machines",
        details={"skipped": skipped},
    )
    redirect_url = "/machine-groups/all"
    if skipped:
        redirect_url += f"?power_skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{group_id}")
async def group_detail(
    request: Request, group_id: uuid.UUID, db: AsyncSession = Depends(get_db), q: str = ""
) -> Response:
    group = await _get_group_or_404(group_id, db)

    members_query = (
        select(Machine).options(selectinload(Machine.group)).where(Machine.group_id == group_id)
    )
    if q.strip():
        members_query = members_query.where(machine_search_clause(q))
    result = await db.execute(members_query.order_by(Machine.name))
    machines = result.scalars().all()

    result = await db.execute(
        select(Machine)
        .options(selectinload(Machine.group))
        .where(or_(Machine.group_id.is_(None), Machine.group_id != group_id))
        .order_by(Machine.name)
    )
    available_machines = result.scalars().all()

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machine_groups/detail.html",
        {
            "group": group,
            "machines": machines,
            "available_machines": available_machines,
            "q": q,
            "csrf_token": csrf_token,
            "power_skipped": request.query_params.get("power_skipped"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{group_id}/machines", dependencies=[_manage, Depends(verify_csrf)])
async def add_machine_to_group(
    request: Request,
    group_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    machine_id: uuid.UUID = Form(...),
) -> Response:
    group = await _get_group_or_404(group_id, db)
    machine = await db.get(Machine, machine_id)
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found.")

    machine.group_id = group.id
    await db.commit()
    await log_event(
        db,
        request=request,
        action="group.machine.add",
        summary=f'Added "{machine.name}" to group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
        details={"machine_id": str(machine.id), "machine_name": machine.name},
    )
    return RedirectResponse(
        url=f"/machine-groups/{group_id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post(
    "/{group_id}/machines/{machine_id}/remove", dependencies=[_manage, Depends(verify_csrf)]
)
async def remove_machine_from_group(
    request: Request, group_id: uuid.UUID, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await db.get(Machine, machine_id)
    if machine is not None and machine.group_id == group_id:
        machine.group_id = None
        await db.commit()
        await log_event(
            db,
            request=request,
            action="group.machine.remove",
            summary=f'Removed "{machine.name}" from group',
            target_type="machine_group",
            target_id=group_id,
            details={"machine_id": str(machine.id), "machine_name": machine.name},
        )
    return RedirectResponse(
        url=f"/machine-groups/{group_id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{group_id}/updates", dependencies=[_updates, Depends(verify_csrf)])
async def trigger_group_update(
    request: Request,
    group_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    group = await _get_group_or_404(group_id, db)
    redis = request.app.state.arq_redis
    batch_id, skipped = await trigger_updates(db, redis, group.machines, strategy)

    await log_event(
        db,
        request=request,
        action="group.updates.run",
        summary=f'Triggered {strategy.value.replace("_", "-")} on group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
        details={"strategy": strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )

    redirect_url = f"/machine-groups/batches/{batch_id}"
    if skipped:
        redirect_url += f"?skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{group_id}/check-updates", dependencies=[_updates, Depends(verify_csrf)])
async def trigger_group_check_updates(
    request: Request, group_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    group = await _get_group_or_404(group_id, db)
    skipped = await trigger_check_updates(request.app.state.arq_redis, group.machines)
    await log_event(
        db,
        request=request,
        action="group.updates.check",
        summary=f'Checked for updates on group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
        details={"skipped": skipped},
    )
    return RedirectResponse(
        url=f"/machine-groups/{group_id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/{group_id}/power/{action}")
async def group_power_confirm(
    request: Request, group_id: uuid.UUID, action: PowerAction, db: AsyncSession = Depends(get_db)
) -> Response:
    group = await _get_group_or_404(group_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machine_groups/power_confirm.html",
        {
            "action": action,
            "target_label": f'every machine in "{group.name}"',
            "confirm_phrase": group.name,
            "action_url": f"/machine-groups/{group_id}/power",
            "cancel_url": f"/machine-groups/{group_id}",
            "error": None,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{group_id}/power", dependencies=[_power, Depends(verify_csrf)])
async def group_power_action(
    request: Request,
    group_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    action: PowerAction = Form(...),
    confirm_name: str = Form(...),
) -> Response:
    group = await _get_group_or_404(group_id, db)

    if confirm_name.strip() != group.name:
        await log_event(
            db,
            request=request,
            action=f"group.power.{action.value}",
            summary=f'Blocked {action.value} on group "{group.name}": confirmation mismatch',
            outcome=AuditOutcome.DENIED,
            target_type="machine_group",
            target_id=group.id,
            target_label=group.name,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machine_groups/power_confirm.html",
            {
                "action": action,
                "target_label": f'every machine in "{group.name}"',
                "confirm_phrase": group.name,
                "action_url": f"/machine-groups/{group_id}/power",
                "cancel_url": f"/machine-groups/{group_id}",
                "error": f'That doesn\'t match — type "{group.name}" exactly to confirm.',
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    skipped = await send_power_to_machines(request.app.state.arq_redis, group.machines, action)
    await log_event(
        db,
        request=request,
        action=f"group.power.{action.value}",
        summary=f'Sent {action.value} to group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
        details={"skipped": skipped},
    )
    redirect_url = f"/machine-groups/{group_id}"
    if skipped:
        redirect_url += f"?power_skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/batches/{batch_id}")
async def update_batch_detail(
    request: Request, batch_id: uuid.UUID, db: AsyncSession = Depends(get_db), skipped: int = 0
) -> Response:
    result = await db.execute(
        select(MachineUpdateRun)
        .options(selectinload(MachineUpdateRun.machine))
        .where(MachineUpdateRun.batch_id == batch_id)
        .order_by(MachineUpdateRun.created_at)
    )
    runs = list(result.scalars().all())
    if not runs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Batch not found.")

    has_pending = any(r.status in (UpdateRunStatus.PENDING, UpdateRunStatus.RUNNING) for r in runs)
    return templates.TemplateResponse(
        request,
        "machine_groups/batch.html",
        {"runs": runs, "batch_id": batch_id, "skipped": skipped, "has_pending": has_pending},
    )


@router.get("/batches/{batch_id}/status")
async def update_batch_status(
    request: Request, batch_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    result = await db.execute(
        select(MachineUpdateRun)
        .options(selectinload(MachineUpdateRun.machine))
        .where(MachineUpdateRun.batch_id == batch_id)
        .order_by(MachineUpdateRun.created_at)
    )
    runs = list(result.scalars().all())
    has_pending = any(r.status in (UpdateRunStatus.PENDING, UpdateRunStatus.RUNNING) for r in runs)
    return templates.TemplateResponse(
        request,
        "partials/update_batch_status.html",
        {"runs": runs, "batch_id": batch_id, "has_pending": has_pending},
    )


@router.post("/{group_id}/delete", dependencies=[_manage, Depends(verify_csrf)])
async def delete_group(
    request: Request, group_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    group = await _get_group_or_404(group_id, db)
    group_name = group.name
    for machine in group.machines:
        machine.group_id = None
    await db.delete(group)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="group.delete",
        summary=f'Deleted group "{group_name}"',
        target_type="machine_group",
        target_id=group_id,
        target_label=group_name,
    )
    return RedirectResponse(url="/machine-groups", status_code=status.HTTP_303_SEE_OTHER)
