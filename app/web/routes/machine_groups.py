"""Machine groups — organize managed machines (e.g. by environment or role)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.session import get_db
from app.schemas.machine_group import MachineGroupCreate
from app.ssh.power import PowerAction
from app.web.machine_search import machine_search_clause
from app.web.templating import templates

router = APIRouter(prefix="/machine-groups")

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


async def _trigger_updates(
    request: Request, db: AsyncSession, machines: list[Machine], strategy: UpgradeStrategy
) -> tuple[uuid.UUID, int]:
    """Create one `MachineUpdateRun` per eligible machine (must have a pinned
    host key) under a shared batch id, commit, then enqueue a job for each.
    Returns (batch_id, skipped_count)."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    batch_id = uuid.uuid4()
    runs = [
        MachineUpdateRun(machine_id=m.id, strategy=strategy, batch_id=batch_id) for m in eligible
    ]
    db.add_all(runs)
    await db.commit()

    # Enqueue only after commit — the worker (a separate process) must be
    # able to find the row the moment it picks the job up.
    for run in runs:
        await request.app.state.arq_redis.enqueue_job("run_machine_update", str(run.id))

    return batch_id, len(machines) - len(eligible)


async def _trigger_check_updates(request: Request, machines: list[Machine]) -> int:
    """Enqueue a `check_machine_updates` job for every eligible (pinned)
    machine. No batch tracking — unlike an actual update run, there's
    nothing meaningful to show on a results page; counts land on each
    machine's own record as each check finishes. Returns skipped count."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    for machine in eligible:
        await request.app.state.arq_redis.enqueue_job("check_machine_updates", str(machine.id))
    return len(machines) - len(eligible)


async def _send_power_to_machines(
    request: Request, machines: list[Machine], action: PowerAction
) -> int:
    """Enqueue a `send_machine_power_command` job for every eligible
    (pinned) machine. Returns skipped count."""
    eligible = [m for m in machines if m.host_key_fingerprint]
    for machine in eligible:
        await request.app.state.arq_redis.enqueue_job(
            "send_machine_power_command", str(machine.id), action.value
        )
    return len(machines) - len(eligible)


@router.get("")
async def list_groups(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    result = await db.execute(
        select(MachineGroup).options(selectinload(MachineGroup.machines)).order_by(MachineGroup.name)
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


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_group(
    request: Request,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    description: str = Form(""),
) -> Response:
    try:
        payload = MachineGroupCreate(name=name, description=description or None)
    except ValueError as exc:
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


@router.post("/all/updates", dependencies=[Depends(verify_csrf)])
async def trigger_all_machines_update(
    request: Request,
    db: AsyncSession = Depends(get_db),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    result = await db.execute(select(Machine))
    machines = list(result.scalars().all())

    batch_id, skipped = await _trigger_updates(request, db, machines, strategy)

    redirect_url = f"/machine-groups/batches/{batch_id}"
    if skipped:
        redirect_url += f"?skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/all/check-updates", dependencies=[Depends(verify_csrf)])
async def trigger_all_check_updates(
    request: Request, db: AsyncSession = Depends(get_db)
) -> Response:
    result = await db.execute(select(Machine))
    await _trigger_check_updates(request, list(result.scalars().all()))
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


@router.post("/all/power", dependencies=[Depends(verify_csrf)])
async def all_power_action(
    request: Request,
    db: AsyncSession = Depends(get_db),
    action: PowerAction = Form(...),
    confirm_name: str = Form(...),
) -> Response:
    if confirm_name.strip() != ALL_MACHINES_CONFIRM_PHRASE:
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
    skipped = await _send_power_to_machines(request, list(result.scalars().all()), action)
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


@router.post("/{group_id}/machines", dependencies=[Depends(verify_csrf)])
async def add_machine_to_group(
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
    return RedirectResponse(
        url=f"/machine-groups/{group_id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{group_id}/machines/{machine_id}/remove", dependencies=[Depends(verify_csrf)])
async def remove_machine_from_group(
    group_id: uuid.UUID, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await db.get(Machine, machine_id)
    if machine is not None and machine.group_id == group_id:
        machine.group_id = None
        await db.commit()
    return RedirectResponse(
        url=f"/machine-groups/{group_id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{group_id}/updates", dependencies=[Depends(verify_csrf)])
async def trigger_group_update(
    request: Request,
    group_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    group = await _get_group_or_404(group_id, db)
    batch_id, skipped = await _trigger_updates(request, db, group.machines, strategy)

    redirect_url = f"/machine-groups/batches/{batch_id}"
    if skipped:
        redirect_url += f"?skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{group_id}/check-updates", dependencies=[Depends(verify_csrf)])
async def trigger_group_check_updates(
    request: Request, group_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    group = await _get_group_or_404(group_id, db)
    await _trigger_check_updates(request, group.machines)
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


@router.post("/{group_id}/power", dependencies=[Depends(verify_csrf)])
async def group_power_action(
    request: Request,
    group_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    action: PowerAction = Form(...),
    confirm_name: str = Form(...),
) -> Response:
    group = await _get_group_or_404(group_id, db)

    if confirm_name.strip() != group.name:
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

    skipped = await _send_power_to_machines(request, group.machines, action)
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


@router.post("/{group_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_group(group_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> Response:
    group = await _get_group_or_404(group_id, db)
    for machine in group.machines:
        machine.group_id = None
    await db.delete(group)
    await db.commit()
    return RedirectResponse(url="/machine-groups", status_code=status.HTTP_303_SEE_OTHER)
