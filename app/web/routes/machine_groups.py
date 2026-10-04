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
from app.auth.dependencies import get_current_user, require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.machine_tag import Tag
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.machine_group import MachineGroupCreate
from app.services.access_scope import (
    can_see_machine,
    count_visible_machines,
    groups_visible_to,
    is_restricted,
    machines_visible_to,
)
from app.services.machine_actions import (
    send_power_to_machines,
    trigger_check_updates,
    trigger_updates,
)
from app.ssh.power import PowerAction
from app.web.machine_search import machine_search_clause
from app.web.routes.machines_list import _MACHINE_LIST_PAGE_SIZE
from app.web.templating import t, templates

router = APIRouter(
    prefix="/machine-groups", dependencies=[Depends(require_permission(Permission.GROUP_VIEW))]
)
_manage = Depends(require_permission(Permission.GROUP_MANAGE))
_updates = Depends(require_permission(Permission.ACTION_UPDATES))
_power = Depends(require_permission(Permission.ACTION_POWER))

# Typed phrase to confirm a power action against literally every machine —
# "All machines" doesn't have a single name of its own to ask someone to type.
ALL_MACHINES_CONFIRM_PHRASE = "ALL MACHINES"


def _group_tabs(request: Request, group: MachineGroup) -> list[tuple[str, str, str]]:
    """The (key, label, url) tabs shown on every one of this group's own
    pages — mirrors `app.web.routes.machines._machine_tabs`. No "Settings"
    tab: unlike a machine, a group has nothing else to configure yet beyond
    its name/description (set once at creation) and deletion, which stays a
    single button on the Overview tab."""
    base = f"/machine-groups/{group.id}"
    return [
        ("overview", t(request, "machine.tab.overview"), base),
        ("updates", t(request, "machine.tab.updates"), f"{base}/updates"),
        ("power", t(request, "group.tab.power"), f"{base}/power"),
    ]


async def _get_group_or_404(group_id: uuid.UUID, db: AsyncSession, user: User) -> MachineGroup:
    """The group, or a 404 — including when it exists but is outside `user`'s
    machine-group scope. 404 rather than 403, same convention as
    `app/web/routes/machines.py`'s `_get_machine_or_404`."""
    query = await groups_visible_to(db, user)
    result = await db.execute(
        query.options(selectinload(MachineGroup.machines)).where(MachineGroup.id == group_id)
    )
    group = result.scalar_one_or_none()
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found.")
    return group


async def _all_visible_machines(db: AsyncSession, user: User) -> list[Machine]:
    """Every machine `user` can see — what the "All machines" virtual group
    means for this account.

    For an unrestricted account that is literally the whole fleet, exactly as
    before. For a restricted one it is their groups' machines and nothing
    else: acting on "all machines" must never reach past the boundary, and
    the page would be lying if it counted machines the account can't open.
    (Scheduling is the one place where "All machines" is refused outright
    instead of narrowed — a *stored* schedule outlives the scope that
    created it. See `app/web/routes/scheduling.py`.)"""
    query = await machines_visible_to(db, user)
    result = await db.execute(query)
    return list(result.scalars().all())


async def _get_all_tags(db: AsyncSession) -> list[Tag]:
    """Every tag currently in use, alphabetical — same helper as
    `app.web.routes.machines`'s own (not shared as a cross-module import:
    each route module owns its own small query helpers, same convention
    as `_get_groups` existing separately in both already)."""
    result = await db.execute(select(Tag).order_by(Tag.name))
    return list(result.scalars().all())


async def _get_group_member_counts(db: AsyncSession) -> dict[uuid.UUID, int]:
    """One cheap aggregate query, not `selectinload(MachineGroup.machines)` —
    the list page only ever needs *how many* machines are in each group, not
    the machines themselves. At fleet sizes in the hundreds/thousands,
    eagerly loading every machine row (with its facts/package-count JSON
    columns) just to call `len()` on it turns one page view into loading the
    entire `machines` table."""
    result = await db.execute(
        select(Machine.group_id, func.count())
        .where(Machine.group_id.is_not(None))
        .group_by(Machine.group_id)
    )
    return {group_id: count for group_id, count in result.all() if group_id is not None}


@router.get("")
async def list_groups(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
) -> Response:
    query = await groups_visible_to(db, current_user)
    if q.strip():
        needle = f"%{q.strip()}%"
        query = query.where(
            or_(MachineGroup.name.ilike(needle), MachineGroup.description.ilike(needle))
        )
    result = await db.execute(query.order_by(MachineGroup.name))
    groups = result.scalars().all()
    member_counts = await _get_group_member_counts(db)
    all_machines_count = await count_visible_machines(db, current_user)
    return templates.TemplateResponse(
        request,
        "machine_groups/list.html",
        {
            "groups": groups,
            "member_counts": member_counts,
            "all_machines_count": all_machines_count or 0,
            "q": q,
        },
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
    current_user: User = Depends(get_current_user),
    name: str = Form(...),
    description: str = Form(""),
) -> Response:
    # A restricted account creating a group would create something it can't
    # then see (a new group is in nobody's grant set) — refuse rather than
    # hand back a group that vanishes on the next request.
    if await is_restricted(db, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Your account is restricted to specific machine groups and can't "
                "create new ones."
            ),
        )
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
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    tag: str = "",
    page: int = 1,
) -> Response:
    """The "All machines" virtual group — every machine, always, automatically.

    Unlike real groups, this isn't backed by any membership data (a machine
    can only have one real `group_id`, so it couldn't also "belong" to a
    stored All-machines group without a bigger many-to-many rework). Instead
    this just queries every machine unconditionally, which trivially and
    always satisfies "always all machines" without anything to keep in sync.
    Registered before `/{group_id}` — `uuid.UUID` there won't match the
    literal "all" anyway, but route order is what actually decides it.

    Paginated the same way `GET /machines` is — this is, after all, the same
    "every machine" listing under a different URL, so it has the same
    unbounded-page-size problem at fleet sizes in the hundreds/thousands.
    """
    page = max(page, 1)
    query = (await machines_visible_to(db, current_user)).options(selectinload(Machine.group))
    if q.strip():
        query = query.where(machine_search_clause(q))
    if tag.strip():
        query = query.where(Machine.tags.any(Tag.name == tag.strip().lower()))

    offset = (page - 1) * _MACHINE_LIST_PAGE_SIZE
    result = await db.execute(
        query.order_by(Machine.name).offset(offset).limit(_MACHINE_LIST_PAGE_SIZE + 1)
    )
    machines = list(result.scalars().all())
    has_more = len(machines) > _MACHINE_LIST_PAGE_SIZE
    machines = machines[:_MACHINE_LIST_PAGE_SIZE]

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machine_groups/all.html",
        {
            "machines": machines,
            "all_tags": await _get_all_tags(db),
            "q": q,
            "tag": tag,
            "page": page,
            "has_more": has_more,
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
    current_user: User = Depends(get_current_user),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    machines = await _all_visible_machines(db, current_user)

    batch_id, skipped = await trigger_updates(db, machines, strategy)

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
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    skipped = await trigger_check_updates(await _all_visible_machines(db, current_user))
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
    current_user: User = Depends(get_current_user),
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

    machines = await _all_visible_machines(db, current_user)
    skipped = await send_power_to_machines(machines, action)
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
    request: Request,
    group_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    tag: str = "",
) -> Response:
    group = await _get_group_or_404(group_id, db, current_user)

    members_query = (
        select(Machine).options(selectinload(Machine.group)).where(Machine.group_id == group_id)
    )
    if q.strip():
        members_query = members_query.where(machine_search_clause(q))
    if tag.strip():
        members_query = members_query.where(Machine.tags.any(Tag.name == tag.strip().lower()))
    result = await db.execute(members_query.order_by(Machine.name))
    machines = result.scalars().all()

    # "Machines you could add to this group" — scoped, so a restricted
    # account can only move machines it can already see. Ungrouped machines
    # are invisible to a restricted account, so for one this list is just
    # the members of its *other* granted groups.
    available_query = await machines_visible_to(db, current_user)
    result = await db.execute(
        available_query.options(selectinload(Machine.group))
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
            "tabs": _group_tabs(request, group),
            "active_tab": "overview",
            "machines": machines,
            "available_machines": available_machines,
            "all_tags": await _get_all_tags(db),
            "q": q,
            "tag": tag,
            "csrf_token": csrf_token,
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
    current_user: User = Depends(get_current_user),
    machine_id: uuid.UUID = Form(...),
) -> Response:
    group = await _get_group_or_404(group_id, db, current_user)
    machine = await db.get(Machine, machine_id)
    # Not just "does it exist" — a machine outside this account's scope is
    # reported as missing, so membership editing can't be used to discover
    # (or quietly reassign) one.
    if machine is None or not await can_see_machine(db, current_user, machine):
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
    request: Request,
    group_id: uuid.UUID,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    await _get_group_or_404(group_id, db, current_user)
    machine = await db.get(Machine, machine_id)
    if (
        machine is not None
        and machine.group_id == group_id
        and await can_see_machine(db, current_user, machine)
    ):
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


@router.get("/{group_id}/updates")
async def group_updates_tab(
    request: Request,
    group_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    group = await _get_group_or_404(group_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machine_groups/updates.html",
        {
            "group": group,
            "tabs": _group_tabs(request, group),
            "active_tab": "updates",
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{group_id}/power")
async def group_power_tab(
    request: Request,
    group_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    group = await _get_group_or_404(group_id, db, current_user)
    return templates.TemplateResponse(
        request,
        "machine_groups/power.html",
        {
            "group": group,
            "tabs": _group_tabs(request, group),
            "active_tab": "power",
            "power_skipped": request.query_params.get("power_skipped"),
        },
    )


@router.post("/{group_id}/updates", dependencies=[_updates, Depends(verify_csrf)])
async def trigger_group_update(
    request: Request,
    group_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    group = await _get_group_or_404(group_id, db, current_user)
    batch_id, skipped = await trigger_updates(db, group.machines, strategy)

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
    request: Request,
    group_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    group = await _get_group_or_404(group_id, db, current_user)
    skipped = await trigger_check_updates(group.machines)
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
        url=f"/machine-groups/{group_id}/updates", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/{group_id}/power/{action}")
async def group_power_confirm(
    request: Request,
    group_id: uuid.UUID,
    action: PowerAction,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    group = await _get_group_or_404(group_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machine_groups/power_confirm.html",
        {
            "action": action,
            "target_label": f'every machine in "{group.name}"',
            "confirm_phrase": group.name,
            "action_url": f"/machine-groups/{group_id}/power",
            "cancel_url": f"/machine-groups/{group_id}/power",
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
    current_user: User = Depends(get_current_user),
    action: PowerAction = Form(...),
    confirm_name: str = Form(...),
) -> Response:
    group = await _get_group_or_404(group_id, db, current_user)

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
                "cancel_url": f"/machine-groups/{group_id}/power",
                "error": f'That doesn\'t match — type "{group.name}" exactly to confirm.',
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    skipped = await send_power_to_machines(group.machines, action)
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
    redirect_url = f"/machine-groups/{group_id}/power"
    if skipped:
        redirect_url += f"?power_skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


async def _visible_batch_runs(
    batch_id: uuid.UUID, db: AsyncSession, user: User
) -> list[MachineUpdateRun]:
    """One batch's update runs, restricted to machines `user` can see.

    A batch is an ad-hoc set of machines, so it can straddle the boundary
    (an unrestricted admin triggering "All machines" produces one batch
    covering everything). Showing a restricted account only its own rows
    keeps the page useful without leaking the rest."""
    visible_ids = (await machines_visible_to(db, user)).with_only_columns(Machine.id)
    result = await db.execute(
        select(MachineUpdateRun)
        .options(selectinload(MachineUpdateRun.machine))
        .where(
            MachineUpdateRun.batch_id == batch_id,
            MachineUpdateRun.machine_id.in_(visible_ids),
        )
        .order_by(MachineUpdateRun.created_at)
    )
    return list(result.scalars().all())


@router.get("/batches/{batch_id}")
async def update_batch_detail(
    request: Request,
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skipped: int = 0,
) -> Response:
    runs = await _visible_batch_runs(batch_id, db, current_user)
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
    request: Request,
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    runs = await _visible_batch_runs(batch_id, db, current_user)
    has_pending = any(r.status in (UpdateRunStatus.PENDING, UpdateRunStatus.RUNNING) for r in runs)
    return templates.TemplateResponse(
        request,
        "partials/update_batch_status.html",
        {"runs": runs, "batch_id": batch_id, "has_pending": has_pending},
    )


@router.post("/{group_id}/delete", dependencies=[_manage, Depends(verify_csrf)])
async def delete_group(
    request: Request,
    group_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    group = await _get_group_or_404(group_id, db, current_user)
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
