"""REST API for machines, machine groups, and bulk/fleet-wide actions — for
external scripts/monitoring, authenticated with a per-user API token
(`app.auth.dependencies.require_api_permission`), not a browser session.

Lives under `/api/`, already on `app.auth.middleware`'s public-prefix
allowlist — same reasoning as `POST /api/inform`: a machine-to-machine
surface with its own bearer-token authentication, not a cookie-based one.

Every mutating/action endpoint here calls into the exact same service
functions the equivalent web route uses (`app.services.machine_actions`,
`app.ssh.updates`, ...) and requires the exact same `Permission` the web
route does — this is a second door into the same house, not a looser one.
Destructive actions that the web UI gates behind a typed confirmation
phrase require an explicit `confirm` field here instead (see each route's
docstring).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_api_permission
from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.machine_package import MachinePackage
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.role import Permission
from app.db.session import get_db
from app.schemas.machine import MachineCreate, MachineUpdate
from app.schemas.machine_config import MachineConfigExport
from app.schemas.machine_group import MachineGroupCreate
from app.services.machine_actions import (
    send_power_to_machines,
    trigger_check_updates,
    trigger_updates,
)
from app.services.machine_config import export_machine_config, import_machine_config
from app.ssh.packages import PackageSource
from app.ssh.power import PowerAction

router = APIRouter(prefix="/api/v1")

_view_machines = Depends(require_api_permission(Permission.MACHINE_VIEW))
_manage_machines = Depends(require_api_permission(Permission.MACHINE_MANAGE))
_view_groups = Depends(require_api_permission(Permission.GROUP_VIEW))
_manage_groups = Depends(require_api_permission(Permission.GROUP_MANAGE))
_action_updates = Depends(require_api_permission(Permission.ACTION_UPDATES))
_action_power = Depends(require_api_permission(Permission.ACTION_POWER))

_PACKAGE_SEARCH_LIMIT = 500
_UPDATE_RUNS_PAGE_SIZE = 50

# Fixed confirmation values an API client must echo back for a destructive
# action — the API equivalent of the web UI's typed-name confirmation page.
# "SELECTED MACHINES"/"ALL MACHINES" mirror the phrases the web UI itself
# uses for the same ad-hoc-selection / "All machines" cases.
_BULK_POWER_CONFIRM_PHRASE = "SELECTED MACHINES"
_ALL_MACHINES_CONFIRM_PHRASE = "ALL MACHINES"


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _machine_to_dict(machine: Machine) -> dict[str, object]:
    return {
        "id": str(machine.id),
        "name": machine.name,
        "ip_address": machine.ip_address,
        "port": machine.port,
        "username": machine.username,
        "auth_method": machine.auth_method.value,
        "group": machine.group.name if machine.group else None,
        "group_id": str(machine.group_id) if machine.group_id else None,
        "description": machine.description,
        "is_active": machine.is_active,
        "is_reachable": machine.is_reachable,
        "last_ping_at": _isoformat(machine.last_ping_at),
        "host_key_fingerprint": machine.host_key_fingerprint,
        "os_version": machine.os_version,
        "kernel_version": machine.kernel_version,
        "cpu_architecture": machine.cpu_architecture,
        "uptime_seconds": machine.uptime_seconds,
        "process_count": machine.process_count,
        "reboot_required": machine.reboot_required,
        "upgradable_count": machine.upgradable_count,
        "security_upgradable_count": machine.security_upgradable_count,
        "flatpak_upgradable_count": machine.flatpak_upgradable_count,
        "snap_upgradable_count": machine.snap_upgradable_count,
        "apt_upgradable_packages": machine.apt_upgradable_packages,
        "flatpak_upgradable_packages": machine.flatpak_upgradable_packages,
        "snap_upgradable_packages": machine.snap_upgradable_packages,
        "updates_checked_at": _isoformat(machine.updates_checked_at),
        "packages_updated_at": _isoformat(machine.packages_updated_at),
    }


def _group_to_dict(group: MachineGroup) -> dict[str, object]:
    return {
        "id": str(group.id),
        "name": group.name,
        "description": group.description,
        "machine_count": len(group.machines),
    }


def _package_to_dict(pkg: MachinePackage, *, include_machine: bool = False) -> dict[str, object]:
    data: dict[str, object] = {
        "id": str(pkg.id),
        "machine_id": str(pkg.machine_id),
        "source": pkg.source.value,
        "name": pkg.name,
        "version": pkg.version,
        "held": pkg.held,
    }
    if include_machine:
        data["machine_name"] = pkg.machine.name if pkg.machine else None
    return data


def _update_run_to_dict(run: MachineUpdateRun) -> dict[str, object]:
    return {
        "id": str(run.id),
        "machine_id": str(run.machine_id),
        "batch_id": str(run.batch_id) if run.batch_id else None,
        "strategy": run.strategy.value,
        "status": run.status.value,
        "output": run.output,
        "error": run.error,
        "started_at": _isoformat(run.started_at),
        "finished_at": _isoformat(run.finished_at),
        "created_at": _isoformat(run.created_at),
    }


async def _get_machine_or_404(machine_id: uuid.UUID, db: AsyncSession) -> Machine:
    result = await db.execute(
        select(Machine).options(selectinload(Machine.group)).where(Machine.id == machine_id)
    )
    machine = result.scalar_one_or_none()
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found.")
    return machine


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


# --- Machines: reads --------------------------------------------------------


@router.get("/machines", dependencies=[_view_machines])
async def list_machines_api(db: AsyncSession = Depends(get_db)) -> list[dict[str, object]]:
    result = await db.execute(select(Machine).options(selectinload(Machine.group)))
    return [_machine_to_dict(m) for m in result.scalars().all()]


@router.get("/machines/package-search", dependencies=[_view_machines])
async def package_search_api(
    db: AsyncSession = Depends(get_db), q: str = "", pkg_source: str = ""
) -> dict[str, object]:
    """Fleet-wide package search — the API equivalent of `GET
    /machines/package-search`. See that route for the reasoning behind the
    500-row cap."""
    if not q.strip():
        return {"results": [], "truncated": False}
    query = (
        select(MachinePackage)
        .options(selectinload(MachinePackage.machine))
        .where(MachinePackage.name.ilike(f"%{q.strip()}%"))
    )
    if pkg_source in {source.value for source in PackageSource}:
        query = query.where(MachinePackage.source == PackageSource(pkg_source))
    query = query.order_by(MachinePackage.name).limit(_PACKAGE_SEARCH_LIMIT + 1)
    result = await db.execute(query)
    results = list(result.scalars().all())
    truncated = len(results) > _PACKAGE_SEARCH_LIMIT
    results = results[:_PACKAGE_SEARCH_LIMIT]
    return {
        "results": [_package_to_dict(p, include_machine=True) for p in results],
        "truncated": truncated,
    }


@router.get("/machines/config/export", dependencies=[_view_machines])
async def export_machine_config_api(db: AsyncSession = Depends(get_db)) -> MachineConfigExport:
    """The API equivalent of `GET /machines/config/export?format=json` — see
    `app.services.machine_config`'s module docstring for exactly what's
    included/excluded and why. No CSV variant here (the web UI's is a plain
    download link for a browser; a script consuming this API wants JSON)."""
    return await export_machine_config(db)


@router.post("/machines/config/import", dependencies=[_manage_machines])
async def import_machine_config_api(
    request: Request, payload: MachineConfigExport, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    """The API equivalent of `POST /machines/config/import` — same
    conflict-handling/security policy, see `app.services.machine_config`."""
    result = await import_machine_config(db, payload)
    await log_event(
        db,
        request=request,
        action="machine.config_import",
        summary=result.summary(),
        details=result.to_dict(),
    )
    return result.to_dict()


@router.get("/machines/{machine_id}", dependencies=[_view_machines])
async def get_machine_api(
    machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    return _machine_to_dict(await _get_machine_or_404(machine_id, db))


@router.get("/machines/{machine_id}/packages", dependencies=[_view_machines])
async def list_machine_packages_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    q: str = "",
    pkg_source: str = "",
    held_only: bool = False,
) -> list[dict[str, object]]:
    await _get_machine_or_404(machine_id, db)
    query = select(MachinePackage).where(MachinePackage.machine_id == machine_id)
    if q.strip():
        query = query.where(MachinePackage.name.ilike(f"%{q.strip()}%"))
    if pkg_source in {source.value for source in PackageSource}:
        query = query.where(MachinePackage.source == PackageSource(pkg_source))
    if held_only:
        query = query.where(MachinePackage.held.is_(True))
    result = await db.execute(query.order_by(MachinePackage.source, MachinePackage.name))
    return [_package_to_dict(p) for p in result.scalars().all()]


@router.get("/machines/{machine_id}/packages/held", dependencies=[_view_machines])
async def list_machine_held_packages_api(
    machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> list[dict[str, object]]:
    await _get_machine_or_404(machine_id, db)
    result = await db.execute(
        select(MachinePackage)
        .where(MachinePackage.machine_id == machine_id, MachinePackage.held.is_(True))
        .order_by(MachinePackage.name)
    )
    return [_package_to_dict(p) for p in result.scalars().all()]


@router.get("/machines/{machine_id}/update-runs", dependencies=[_view_machines])
async def list_machine_update_runs_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    status_filter: str = "",
    page: int = 1,
) -> dict[str, object]:
    """The API equivalent of `GET /machines/{id}/updates` — every update run
    for this machine, newest first, paginated/filterable the same way."""
    await _get_machine_or_404(machine_id, db)
    page = max(page, 1)

    query = select(MachineUpdateRun).where(MachineUpdateRun.machine_id == machine_id)
    if status_filter in {s.value for s in UpdateRunStatus}:
        query = query.where(MachineUpdateRun.status == UpdateRunStatus(status_filter))

    offset = (page - 1) * _UPDATE_RUNS_PAGE_SIZE
    result = await db.execute(
        query.order_by(MachineUpdateRun.created_at.desc())
        .offset(offset)
        .limit(_UPDATE_RUNS_PAGE_SIZE + 1)
    )
    runs = list(result.scalars().all())
    has_older = len(runs) > _UPDATE_RUNS_PAGE_SIZE
    runs = runs[:_UPDATE_RUNS_PAGE_SIZE]
    return {
        "runs": [_update_run_to_dict(r) for r in runs],
        "page": page,
        "has_older": has_older,
    }


# --- Machines: writes --------------------------------------------------------


@router.post("/machines", dependencies=[_manage_machines], status_code=status.HTTP_201_CREATED)
async def create_machine_api(
    request: Request, payload: MachineCreate, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    machine = Machine(
        name=payload.name,
        ip_address=payload.ip_address,
        port=payload.port,
        username=payload.username,
        auth_method=payload.auth_method,
        secret_encrypted=encrypt_secret(payload.secret) if payload.secret else None,
        group_id=payload.group_id,
        description=payload.description,
    )
    db.add(machine)
    await db.commit()
    await db.refresh(machine)
    machine = await _get_machine_or_404(machine.id, db)

    await log_event(
        db,
        request=request,
        action="machine.create",
        summary=f'Created machine "{machine.name}" ({machine.ip_address})',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
    )
    return _machine_to_dict(machine)


@router.put("/machines/{machine_id}", dependencies=[_manage_machines])
async def update_machine_api(
    request: Request,
    machine_id: uuid.UUID,
    payload: MachineUpdate,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db)

    connection_target_changed = (
        payload.ip_address != machine.ip_address or payload.port != machine.port
    )

    machine.name = payload.name
    machine.ip_address = payload.ip_address
    machine.port = payload.port
    machine.username = payload.username
    machine.auth_method = payload.auth_method
    machine.group_id = payload.group_id
    machine.description = payload.description
    machine.is_active = payload.is_active

    if payload.auth_method == AuthMethod.PASSWORD:
        if payload.secret:
            machine.secret_encrypted = encrypt_secret(payload.secret)
    else:
        machine.secret_encrypted = None

    if connection_target_changed:
        machine.host_key_fingerprint = None
        machine.discovered_hostname = None
        machine.os_version = None
        machine.kernel_version = None
        machine.cpu_cores = None
        machine.ram_bytes = None
        machine.disks = None
        machine.facts_updated_at = None

    await db.commit()
    machine = await _get_machine_or_404(machine.id, db)

    await log_event(
        db,
        request=request,
        action="machine.update",
        summary=f'Updated machine "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"connection_target_changed": connection_target_changed},
    )
    return _machine_to_dict(machine)


class _ConfirmDelete(BaseModel):
    """Echoing the target's own name back is the API equivalent of the web
    UI's typed-confirmation page for an irreversible action."""

    confirm_name: str = Field(min_length=1)


@router.delete("/machines/{machine_id}", dependencies=[_manage_machines])
async def delete_machine_api(
    request: Request,
    machine_id: uuid.UUID,
    payload: _ConfirmDelete,
    db: AsyncSession = Depends(get_db),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    if payload.confirm_name.strip() != machine.name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm_name" must exactly match the machine\'s name ("{machine.name}").',
        )
    machine_name = machine.name
    await db.delete(machine)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machine.delete",
        summary=f'Deleted machine "{machine_name}"',
        target_type="machine",
        target_id=machine_id,
        target_label=machine_name,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Bulk actions (ad-hoc selection from the machine list) ------------------


class _BulkMachineIds(BaseModel):
    machine_ids: list[uuid.UUID] = Field(min_length=1)


class _BulkUpdatesTrigger(_BulkMachineIds):
    strategy: UpgradeStrategy


class _BulkPowerAction(_BulkMachineIds):
    action: PowerAction
    confirm: str = Field(
        min_length=1,
        description=f'Must be exactly "{_BULK_POWER_CONFIRM_PHRASE}" to confirm.',
    )


async def _get_machines_by_ids(machine_ids: list[uuid.UUID], db: AsyncSession) -> list[Machine]:
    result = await db.execute(select(Machine).where(Machine.id.in_(machine_ids)))
    return list(result.scalars().all())


@router.post("/machines/bulk/check-updates", dependencies=[_action_updates])
async def bulk_check_updates_api(
    request: Request, payload: _BulkMachineIds, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    machines = await _get_machines_by_ids(payload.machine_ids, db)
    skipped = await trigger_check_updates(request.app.state.arq_redis, machines)
    await log_event(
        db,
        request=request,
        action="machines.bulk.updates.check",
        summary=f"Checked for updates on {len(machines)} selected machine(s)",
        details={"machine_count": len(machines), "skipped": skipped},
    )
    return {"machine_count": len(machines), "skipped": skipped}


@router.post("/machines/bulk/updates", dependencies=[_action_updates])
async def bulk_trigger_updates_api(
    request: Request, payload: _BulkUpdatesTrigger, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    machines = await _get_machines_by_ids(payload.machine_ids, db)
    batch_id, skipped = await trigger_updates(
        db, request.app.state.arq_redis, machines, payload.strategy
    )
    await log_event(
        db,
        request=request,
        action="machines.bulk.updates.run",
        summary=(
            f'Triggered {payload.strategy.value.replace("_", "-")} on '
            f"{len(machines)} selected machine(s)"
        ),
        details={"strategy": payload.strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )
    return {"batch_id": str(batch_id), "skipped": skipped}


@router.post("/machines/bulk/power", dependencies=[_action_power])
async def bulk_power_action_api(
    request: Request, payload: _BulkPowerAction, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    if payload.confirm.strip() != _BULK_POWER_CONFIRM_PHRASE:
        await log_event(
            db,
            request=request,
            action=f"machines.bulk.power.{payload.action.value}",
            summary=(
                f"Blocked {payload.action.value} on {len(payload.machine_ids)} selected "
                "machine(s): confirmation mismatch"
            ),
            outcome=AuditOutcome.DENIED,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm" must be exactly "{_BULK_POWER_CONFIRM_PHRASE}".',
        )
    machines = await _get_machines_by_ids(payload.machine_ids, db)
    skipped = await send_power_to_machines(request.app.state.arq_redis, machines, payload.action)
    await log_event(
        db,
        request=request,
        action=f"machines.bulk.power.{payload.action.value}",
        summary=f"Sent {payload.action.value} to {len(machines)} selected machine(s)",
        details={"skipped": skipped},
    )
    return {"machine_count": len(machines), "skipped": skipped}

class _UpdatesTrigger(BaseModel):
    strategy: UpgradeStrategy


@router.post("/machines/{machine_id}/updates", dependencies=[_action_updates])
async def trigger_machine_update_api(
    request: Request,
    machine_id: uuid.UUID,
    payload: _UpdatesTrigger,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db)
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before running updates.",
        )
    run = MachineUpdateRun(machine_id=machine.id, strategy=payload.strategy)
    db.add(run)
    await db.commit()
    await db.refresh(run)
    await request.app.state.arq_redis.enqueue_job("run_machine_update", str(run.id))

    await log_event(
        db,
        request=request,
        action="machine.updates.run",
        summary=f'Triggered {payload.strategy.value.replace("_", "-")} on "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"strategy": payload.strategy.value, "run_id": str(run.id)},
    )
    return _update_run_to_dict(run)


@router.post("/machines/{machine_id}/check-updates", dependencies=[_action_updates])
async def check_machine_updates_api(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db)
    skipped = await trigger_check_updates(request.app.state.arq_redis, [machine])
    await log_event(
        db,
        request=request,
        action="machine.updates.check",
        summary=f'Checked for updates on "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"skipped": skipped},
    )
    return {"skipped": skipped}


class _PowerAction(BaseModel):
    action: PowerAction
    confirm_name: str = Field(min_length=1)


@router.post("/machines/{machine_id}/power", dependencies=[_action_power])
async def machine_power_api(
    request: Request,
    machine_id: uuid.UUID,
    payload: _PowerAction,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    machine = await _get_machine_or_404(machine_id, db)
    if payload.confirm_name.strip() != machine.name:
        await log_event(
            db,
            request=request,
            action=f"machine.power.{payload.action.value}",
            summary=f'Blocked {payload.action.value} on "{machine.name}": confirmation mismatch',
            outcome=AuditOutcome.DENIED,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm_name" must exactly match the machine\'s name ("{machine.name}").',
        )
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before sending power commands.",
        )
    await request.app.state.arq_redis.enqueue_job(
        "send_machine_power_command", str(machine.id), payload.action.value
    )
    await log_event(
        db,
        request=request,
        action=f"machine.power.{payload.action.value}",
        summary=f'Sent {payload.action.value} to "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
    )
    return {"ok": True}




# --- Machine groups ----------------------------------------------------------


@router.get("/machine-groups", dependencies=[_view_groups])
async def list_machine_groups_api(db: AsyncSession = Depends(get_db)) -> list[dict[str, object]]:
    result = await db.execute(select(MachineGroup).options(selectinload(MachineGroup.machines)))
    return [_group_to_dict(g) for g in result.scalars().all()]


@router.post(
    "/machine-groups", dependencies=[_manage_groups], status_code=status.HTTP_201_CREATED
)
async def create_machine_group_api(
    request: Request, payload: MachineGroupCreate, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    group = MachineGroup(name=payload.name, description=payload.description)
    db.add(group)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'A group named "{payload.name}" already exists.',
        ) from None
    group = await _get_group_or_404(group.id, db)
    await log_event(
        db,
        request=request,
        action="group.create",
        summary=f'Created group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
    )
    return _group_to_dict(group)


@router.get("/machine-groups/{group_id}", dependencies=[_view_groups])
async def get_machine_group_api(
    group_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    return _group_to_dict(await _get_group_or_404(group_id, db))


@router.get("/machine-groups/{group_id}/members", dependencies=[_view_groups])
async def list_group_members_api(
    group_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> list[dict[str, object]]:
    group = await _get_group_or_404(group_id, db)
    return [_machine_to_dict(m) for m in group.machines]


@router.put("/machine-groups/{group_id}", dependencies=[_manage_groups])
async def update_machine_group_api(
    request: Request,
    group_id: uuid.UUID,
    payload: MachineGroupCreate,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    group = await _get_group_or_404(group_id, db)
    group.name = payload.name
    group.description = payload.description
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'A group named "{payload.name}" already exists.',
        ) from None
    group = await _get_group_or_404(group.id, db)
    await log_event(
        db,
        request=request,
        action="group.update",
        summary=f'Updated group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
    )
    return _group_to_dict(group)


@router.delete("/machine-groups/{group_id}", dependencies=[_manage_groups])
async def delete_machine_group_api(
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
    return Response(status_code=status.HTTP_204_NO_CONTENT)


class _GroupMachineId(BaseModel):
    machine_id: uuid.UUID


@router.post("/machine-groups/{group_id}/machines", dependencies=[_manage_groups])
async def add_machine_to_group_api(
    request: Request,
    group_id: uuid.UUID,
    payload: _GroupMachineId,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    group = await _get_group_or_404(group_id, db)
    machine = await db.get(Machine, payload.machine_id)
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
    return {"ok": True}


@router.delete("/machine-groups/{group_id}/machines/{machine_id}", dependencies=[_manage_groups])
async def remove_machine_from_group_api(
    request: Request,
    group_id: uuid.UUID,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
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
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- "All machines" (the built-in virtual group) -----------------------------


@router.post("/machine-groups/all/updates", dependencies=[_action_updates])
async def trigger_all_machines_update_api(
    request: Request, payload: _UpdatesTrigger, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    result = await db.execute(select(Machine))
    machines = list(result.scalars().all())
    batch_id, skipped = await trigger_updates(
        db, request.app.state.arq_redis, machines, payload.strategy
    )
    await log_event(
        db,
        request=request,
        action="all_machines.updates.run",
        summary=f"Triggered {payload.strategy.value.replace('_', '-')} on all machines",
        target_type="all_machines",
        details={"strategy": payload.strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )
    return {"batch_id": str(batch_id), "skipped": skipped}


@router.post("/machine-groups/all/check-updates", dependencies=[_action_updates])
async def trigger_all_check_updates_api(
    request: Request, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
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
    return {"skipped": skipped}


class _AllMachinesPowerAction(BaseModel):
    action: PowerAction
    confirm: str = Field(
        min_length=1, description=f'Must be exactly "{_ALL_MACHINES_CONFIRM_PHRASE}" to confirm.'
    )


@router.post("/machine-groups/all/power", dependencies=[_action_power])
async def all_power_action_api(
    request: Request, payload: _AllMachinesPowerAction, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    if payload.confirm.strip() != _ALL_MACHINES_CONFIRM_PHRASE:
        await log_event(
            db,
            request=request,
            action=f"all_machines.power.{payload.action.value}",
            summary=f"Blocked {payload.action.value} on all machines: confirmation mismatch",
            outcome=AuditOutcome.DENIED,
            target_type="all_machines",
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm" must be exactly "{_ALL_MACHINES_CONFIRM_PHRASE}".',
        )
    result = await db.execute(select(Machine))
    machines = list(result.scalars().all())
    skipped = await send_power_to_machines(request.app.state.arq_redis, machines, payload.action)
    await log_event(
        db,
        request=request,
        action=f"all_machines.power.{payload.action.value}",
        summary=f"Sent {payload.action.value} to all machines",
        target_type="all_machines",
        details={"skipped": skipped},
    )
    return {"ok": True, "skipped": skipped}


@router.post("/machine-groups/{group_id}/updates", dependencies=[_action_updates])
async def trigger_group_update_api(
    request: Request,
    group_id: uuid.UUID,
    payload: _UpdatesTrigger,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    group = await _get_group_or_404(group_id, db)
    batch_id, skipped = await trigger_updates(
        db, request.app.state.arq_redis, group.machines, payload.strategy
    )
    await log_event(
        db,
        request=request,
        action="group.updates.run",
        summary=f'Triggered {payload.strategy.value.replace("_", "-")} on group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
        details={"strategy": payload.strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )
    return {"batch_id": str(batch_id), "skipped": skipped}


@router.post("/machine-groups/{group_id}/check-updates", dependencies=[_action_updates])
async def trigger_group_check_updates_api(
    request: Request, group_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
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
    return {"skipped": skipped}


class _GroupPowerAction(BaseModel):
    action: PowerAction
    confirm_name: str = Field(min_length=1)


@router.post("/machine-groups/{group_id}/power", dependencies=[_action_power])
async def group_power_action_api(
    request: Request,
    group_id: uuid.UUID,
    payload: _GroupPowerAction,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    group = await _get_group_or_404(group_id, db)
    if payload.confirm_name.strip() != group.name:
        await log_event(
            db,
            request=request,
            action=f"group.power.{payload.action.value}",
            summary=(
                f'Blocked {payload.action.value} on group "{group.name}": '
                "confirmation mismatch"
            ),
            outcome=AuditOutcome.DENIED,
            target_type="machine_group",
            target_id=group.id,
            target_label=group.name,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f'"confirm_name" must exactly match the group\'s name ("{group.name}").',
        )
    skipped = await send_power_to_machines(
        request.app.state.arq_redis, group.machines, payload.action
    )
    await log_event(
        db,
        request=request,
        action=f"group.power.{payload.action.value}",
        summary=f'Sent {payload.action.value} to group "{group.name}"',
        target_type="machine_group",
        target_id=group.id,
        target_label=group.name,
        details={"skipped": skipped},
    )
    return {"ok": True, "skipped": skipped}



@router.get("/machine-groups/batches/{batch_id}", dependencies=[_view_machines])
async def update_batch_detail_api(
    batch_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> dict[str, object]:
    result = await db.execute(
        select(MachineUpdateRun)
        .options(selectinload(MachineUpdateRun.machine))
        .where(MachineUpdateRun.batch_id == batch_id)
        .order_by(MachineUpdateRun.created_at)
    )
    runs = list(result.scalars().all())
    if not runs:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Batch not found.")
    return {"batch_id": str(batch_id), "runs": [_update_run_to_dict(r) for r in runs]}
