"""Machine groups — organize managed machines (e.g. by environment or role)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.session import get_db
from app.schemas.machine_group import MachineGroupCreate
from app.web.templating import templates

router = APIRouter(prefix="/machine-groups")


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
        select(MachineGroup).options(selectinload(MachineGroup.machines)).order_by(MachineGroup.name)
    )
    groups = result.scalars().all()
    return templates.TemplateResponse(request, "machine_groups/list.html", {"groups": groups})


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


@router.get("/{group_id}")
async def group_detail(
    request: Request, group_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    group = await _get_group_or_404(group_id, db)

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
        {"group": group, "available_machines": available_machines, "csrf_token": csrf_token},
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


@router.post("/{group_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_group(group_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> Response:
    group = await _get_group_or_404(group_id, db)
    for machine in group.machines:
        machine.group_id = None
    await db.delete(group)
    await db.commit()
    return RedirectResponse(url="/machine-groups", status_code=status.HTTP_303_SEE_OTHER)
