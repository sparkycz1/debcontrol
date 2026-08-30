"""Managed machines — CRUD, host key pinning, connection testing, facts."""

from __future__ import annotations

import asyncio
import csv
import io
import re
import uuid
from datetime import UTC, datetime

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_permission
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.machine_package import MachinePackage
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.pending_machine import PendingMachine
from app.db.models.role import Permission
from app.db.session import get_db
from app.schemas.machine import MachineCreate, MachineUpdate
from app.schemas.machine_config import MachineConfigExport
from app.services.machine_actions import (
    send_power_to_machines,
    trigger_check_updates,
    trigger_updates,
)
from app.services.machine_config import export_machine_config, import_machine_config
from app.ssh.client import discover_host_key_fingerprint
from app.ssh.exceptions import SSHConnectionError
from app.ssh.packages import PackageSource
from app.ssh.power import PowerAction
from app.ssh.updates import PendingPackage

# Imported as a module, not name-by-name: this file already has a route
# function called `preview_machine_update`, which would shadow the task of
# the same name.
from app.tasks import jobs as tasks
from app.web.machine_search import machine_search_clause
from app.web.routes.audit import _csv_safe
from app.web.templating import templates

# Typed phrase to confirm a power action against an arbitrary ad-hoc
# selection from the machine list — unlike a group or "All machines", a
# selection doesn't have a name of its own to ask someone to type.
_BULK_POWER_CONFIRM_PHRASE = "SELECTED MACHINES"

router = APIRouter(
    prefix="/machines", dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))]
)
_manage = Depends(require_permission(Permission.MACHINE_MANAGE))
_updates = Depends(require_permission(Permission.ACTION_UPDATES))
_power = Depends(require_permission(Permission.ACTION_POWER))
_terminal = Depends(require_permission(Permission.ACTION_TERMINAL))

# Fingerprint shaped like "SHA256:<base64...>", as returned by AsyncSSH/OpenSSH.
_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9]+:[A-Za-z0-9+/=_-]+$")


async def _get_machine_or_404(machine_id: uuid.UUID, db: AsyncSession) -> Machine:
    # Eager-load `group` — templates read `machine.group` and the async ORM
    # can't lazy-load relationships outside of an `await` (it would raise
    # MissingGreenlet during template rendering).
    result = await db.execute(
        select(Machine).options(selectinload(Machine.group)).where(Machine.id == machine_id)
    )
    machine = result.scalar_one_or_none()
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found.")
    return machine


async def _get_groups(db: AsyncSession) -> list[MachineGroup]:
    result = await db.execute(select(MachineGroup).order_by(MachineGroup.name))
    return list(result.scalars().all())


async def _get_pending_machines(db: AsyncSession) -> list[PendingMachine]:
    result = await db.execute(select(PendingMachine).order_by(PendingMachine.created_at.desc()))
    return list(result.scalars().all())


async def _get_recent_update_runs(
    machine_id: uuid.UUID, db: AsyncSession, limit: int = 5
) -> list[MachineUpdateRun]:
    result = await db.execute(
        select(MachineUpdateRun)
        .where(MachineUpdateRun.machine_id == machine_id)
        .order_by(MachineUpdateRun.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


async def _get_package_counts(machine_id: uuid.UUID, db: AsyncSession) -> dict[str, int]:
    result = await db.execute(
        select(MachinePackage.source, func.count())
        .where(MachinePackage.machine_id == machine_id)
        .group_by(MachinePackage.source)
    )
    counts = {source.value: 0 for source in PackageSource}
    total = 0
    for source, count in result.all():
        counts[source.value] = count
        total += count
    counts["total"] = total
    return counts


async def _get_held_count(machine_id: uuid.UUID, db: AsyncSession) -> int:
    return (
        await db.scalar(
            select(func.count())
            .select_from(MachinePackage)
            .where(MachinePackage.machine_id == machine_id, MachinePackage.held.is_(True))
        )
    ) or 0


async def _get_packages(
    machine_id: uuid.UUID,
    db: AsyncSession,
    *,
    pkg_q: str,
    pkg_source: str,
    held_only: bool = False,
) -> list[MachinePackage]:
    query = select(MachinePackage).where(MachinePackage.machine_id == machine_id)
    if pkg_q.strip():
        query = query.where(MachinePackage.name.ilike(f"%{pkg_q.strip()}%"))
    if pkg_source in {source.value for source in PackageSource}:
        query = query.where(MachinePackage.source == PackageSource(pkg_source))
    if held_only:
        query = query.where(MachinePackage.held.is_(True))
    result = await db.execute(query.order_by(MachinePackage.source, MachinePackage.name))
    return list(result.scalars().all())


_UPDATE_HISTORY_PAGE_SIZE = 50


async def _get_update_run_or_404(run_id: uuid.UUID, db: AsyncSession) -> MachineUpdateRun:
    run = await db.get(MachineUpdateRun, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return run


@router.get("")
async def list_machines(
    request: Request, db: AsyncSession = Depends(get_db), q: str = ""
) -> Response:
    query = select(Machine).options(selectinload(Machine.group))
    if q.strip():
        query = query.where(machine_search_clause(q))
    result = await db.execute(query.order_by(Machine.name))
    machines = result.scalars().all()
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/list.html",
        {
            "machines": machines,
            "pending_machines": await _get_pending_machines(db),
            "q": q,
            "csrf_token": csrf_token,
            "bulk_error": request.query_params.get("bulk_error"),
            "power_skipped": request.query_params.get("power_skipped"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/new")
async def new_machine_form(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/new.html",
        {
            "auth_methods": list(AuthMethod),
            "groups": await _get_groups(db),
            "errors": [],
            "form": {
                "name": request.query_params.get("name", ""),
                "ip_address": request.query_params.get("ip_address", ""),
            },
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("", dependencies=[_manage, Depends(verify_csrf)])
async def create_machine(
    request: Request,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    ip_address: str = Form(...),
    port: int = Form(22),
    username: str = Form(...),
    auth_method: AuthMethod = Form(...),
    secret: str = Form(""),
    group_id: str = Form(""),
    description: str = Form(""),
) -> Response:
    try:
        payload = MachineCreate(
            name=name,
            ip_address=ip_address,
            port=port,
            username=username,
            auth_method=auth_method,
            secret=secret or None,
            group_id=uuid.UUID(group_id) if group_id else None,
            description=description or None,
        )
    except ValueError as exc:
        await log_event(
            db,
            request=request,
            action="machine.create",
            summary=f'Rejected new machine "{name}": {exc}',
            outcome=AuditOutcome.FAILURE,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machines/new.html",
            {
                "auth_methods": list(AuthMethod),
                "groups": await _get_groups(db),
                "errors": [str(exc)],
                "form": {
                    "name": name,
                    "ip_address": ip_address,
                    "port": port,
                    "username": username,
                    "auth_method": auth_method,
                    "description": description,
                },
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

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

    await log_event(
        db,
        request=request,
        action="machine.create",
        summary=f'Created machine "{machine.name}" ({machine.ip_address})',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
    )

    return RedirectResponse(url=f"/machines/{machine.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/import")
async def import_machines_form(request: Request) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/import.html",
        {"csrf_token": csrf_token, "errors": [], "result": None},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/import", dependencies=[_manage, Depends(verify_csrf)])
async def import_machines_submit(
    request: Request, db: AsyncSession = Depends(get_db), csv_text: str = Form("")
) -> Response:
    """Bulk-add machines from pasted CSV — each row becomes a `PendingMachine`
    in the same review queue self-registration (`POST /api/inform`) uses,
    rather than a `Machine` directly: nothing here is trusted for connecting
    to a machine (no credentials, no host key), so it still goes through the
    normal add-machine form and mandatory host-key confirmation per machine.

    Expected columns (header row required): `ip_address` (required),
    `hostname` (optional). Anything else is ignored.
    """
    errors: list[str] = []
    text = csv_text.strip()
    if not text:
        errors.append("Paste some CSV text first.")
        return templates.TemplateResponse(
            request,
            "machines/import.html",
            {"csrf_token": request.state.csrf_token, "errors": errors, "result": None},
        )

    reader = csv.DictReader(io.StringIO(text))
    fieldnames = [f.strip().lower() for f in (reader.fieldnames or [])]
    if "ip_address" not in fieldnames:
        errors.append('The CSV needs a header row with at least an "ip_address" column.')
        return templates.TemplateResponse(
            request,
            "machines/import.html",
            {"csrf_token": request.state.csrf_token, "errors": errors, "result": None},
        )

    created = 0
    skipped = 0
    for row in reader:
        normalized = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items() if k}
        ip_address = normalized.get("ip_address", "")
        if not ip_address:
            skipped += 1
            continue
        db.add(
            PendingMachine(
                ip_address=ip_address,
                reported_hostname=normalized.get("hostname") or None,
                source_ip=None,
            )
        )
        created += 1
    await db.commit()

    await log_event(
        db,
        request=request,
        action="machine.bulk_import",
        summary=f"Bulk-imported {created} pending machine(s) from CSV ({skipped} row(s) skipped)",
        details={"created": created, "skipped": skipped},
    )
    return templates.TemplateResponse(
        request,
        "machines/import.html",
        {
            "csrf_token": request.state.csrf_token,
            "errors": [],
            "result": {"created": created, "skipped": skipped},
        },
    )


_CONFIG_EXPORT_CSV_FIELDS = (
    "name",
    "ip_address",
    "port",
    "username",
    "auth_method",
    "group",
    "description",
    "is_active",
)


@router.get("/config/export")
async def export_machine_config_endpoint(
    request: Request, db: AsyncSession = Depends(get_db), format: str = "json"  # noqa: A002
) -> Response:
    """Export every existing (non-pending) machine's and group's *structural*
    configuration — deliberately never `secret_encrypted` or
    `host_key_fingerprint`, see `app.services.machine_config`'s module
    docstring. JSON includes both machines and groups; CSV (machines only —
    groups don't flatten to CSV sensibly) is a plain download link, same
    pattern as the audit log's export (see `app/web/routes/audit.py`)."""
    export = await export_machine_config(db)

    await log_event(
        db,
        request=request,
        action="machine.config_export",
        summary=(
            f"Exported configuration for {len(export.machines)} machine(s) and "
            f"{len(export.groups)} group(s) as {format}"
        ),
        details={
            "machine_count": len(export.machines),
            "group_count": len(export.groups),
            "format": format,
        },
    )

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    if format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=_CONFIG_EXPORT_CSV_FIELDS)
        writer.writeheader()
        for machine in export.machines:
            row = machine.model_dump()
            row["auth_method"] = machine.auth_method.value
            writer.writerow({k: _csv_safe(v) for k, v in row.items()})
        return Response(
            content=buffer.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="machines-{timestamp}.csv"'
            },
        )

    return Response(
        content=export.model_dump_json(indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="machine-config-{timestamp}.json"'
        },
    )


@router.get("/config/import")
async def import_machine_config_form(request: Request) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/config_import.html",
        {"csrf_token": csrf_token, "errors": [], "result": None},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/config/import", dependencies=[_manage, Depends(verify_csrf)])
async def import_machine_config_submit(
    request: Request, db: AsyncSession = Depends(get_db), json_text: str = Form("")
) -> Response:
    """Create real `Machine`/`MachineGroup` rows from a pasted JSON export
    (see `GET /machines/config/export`) — not the pending-review queue the
    CSV bulk-import above uses, since this is for restoring/migrating
    *known* configuration rather than discovering unknown hosts. See
    `app.services.machine_config` for the full conflict-handling and
    security policy this implements."""
    text = json_text.strip()
    if not text:
        return templates.TemplateResponse(
            request,
            "machines/config_import.html",
            {
                "csrf_token": request.state.csrf_token,
                "errors": ["Paste some exported JSON text first."],
                "result": None,
            },
        )

    try:
        payload = MachineConfigExport.model_validate_json(text)
    except ValidationError as exc:
        return templates.TemplateResponse(
            request,
            "machines/config_import.html",
            {
                "csrf_token": request.state.csrf_token,
                "errors": [f"Invalid configuration JSON: {exc}"],
                "result": None,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    result = await import_machine_config(db, payload)

    await log_event(
        db,
        request=request,
        action="machine.config_import",
        summary=result.summary(),
        details=result.to_dict(),
    )

    return templates.TemplateResponse(
        request,
        "machines/config_import.html",
        {"csrf_token": request.state.csrf_token, "errors": [], "result": result},
    )


_PACKAGE_SEARCH_LIMIT = 500


@router.get("/package-search")
async def package_search(
    request: Request,
    db: AsyncSession = Depends(get_db),
    q: str = "",
    pkg_source: str = "",
) -> Response:
    """Fleet-wide "who has package X installed, and what version" — the
    other direction from the per-machine Installed packages panel. Useful
    after a CVE announcement: search the name, see every machine and
    version at once instead of checking machines one by one."""
    results: list[MachinePackage] = []
    truncated = False
    if q.strip():
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

    return templates.TemplateResponse(
        request,
        "machines/package_search.html",
        {"q": q, "pkg_source": pkg_source, "results": results, "truncated": truncated},
    )


async def _get_machines_by_ids(machine_ids: list[uuid.UUID], db: AsyncSession) -> list[Machine]:
    if not machine_ids:
        return []
    result = await db.execute(select(Machine).where(Machine.id.in_(machine_ids)))
    return list(result.scalars().all())


@router.post("/bulk/check-updates", dependencies=[_updates, Depends(verify_csrf)])
async def bulk_check_updates(
    request: Request,
    db: AsyncSession = Depends(get_db),
    machine_ids: list[uuid.UUID] = Form(default=[]),
) -> Response:
    """Check-updates for an ad-hoc selection from the machine list — same
    underlying job as the group/"All machines" versions, just against
    whichever rows were ticked rather than a stored group."""
    machines = await _get_machines_by_ids(machine_ids, db)
    if not machines:
        return RedirectResponse(
            url="/machines?bulk_error=Select+at+least+one+machine.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    skipped = await trigger_check_updates(machines)
    await log_event(
        db,
        request=request,
        action="machines.bulk.updates.check",
        summary=f"Checked for updates on {len(machines)} selected machine(s)",
        details={"machine_count": len(machines), "skipped": skipped},
    )
    return RedirectResponse(url="/machines", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/updates", dependencies=[_updates, Depends(verify_csrf)])
async def bulk_trigger_updates(
    request: Request,
    db: AsyncSession = Depends(get_db),
    machine_ids: list[uuid.UUID] = Form(default=[]),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    machines = await _get_machines_by_ids(machine_ids, db)
    if not machines:
        return RedirectResponse(
            url="/machines?bulk_error=Select+at+least+one+machine.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    batch_id, skipped = await trigger_updates(db, machines, strategy)
    await log_event(
        db,
        request=request,
        action="machines.bulk.updates.run",
        summary=(
            f'Triggered {strategy.value.replace("_", "-")} on '
            f"{len(machines)} selected machine(s)"
        ),
        details={"strategy": strategy.value, "batch_id": str(batch_id), "skipped": skipped},
    )
    redirect_url = f"/machine-groups/batches/{batch_id}"
    if skipped:
        redirect_url += f"?skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/power-confirm/{action}", dependencies=[_power, Depends(verify_csrf)])
async def bulk_power_confirm(
    request: Request,
    action: PowerAction,
    machine_ids: list[uuid.UUID] = Form(default=[]),
) -> Response:
    """Render the typed-confirmation page for a bulk power action, carrying
    the selection forward as hidden fields (there's no group/name to look
    the selection back up by, unlike the group-scoped version of this)."""
    if not machine_ids:
        return RedirectResponse(
            url="/machines?bulk_error=Select+at+least+one+machine.",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/bulk_power_confirm.html",
        {
            "action": action,
            "machine_ids": machine_ids,
            "target_label": f"{len(machine_ids)} selected machine(s)",
            "confirm_phrase": _BULK_POWER_CONFIRM_PHRASE,
            "action_url": f"/machines/bulk/power/{action.value}",
            "cancel_url": "/machines",
            "error": None,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/bulk/power/{action}", dependencies=[_power, Depends(verify_csrf)])
async def bulk_power_action(
    request: Request,
    action: PowerAction,
    db: AsyncSession = Depends(get_db),
    machine_ids: list[uuid.UUID] = Form(default=[]),
    confirm_name: str = Form(...),
) -> Response:
    if confirm_name.strip() != _BULK_POWER_CONFIRM_PHRASE:
        await log_event(
            db,
            request=request,
            action=f"machines.bulk.power.{action.value}",
            summary=(
                f"Blocked {action.value} on {len(machine_ids)} selected "
                "machine(s): confirmation mismatch"
            ),
            outcome=AuditOutcome.DENIED,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machines/bulk_power_confirm.html",
            {
                "action": action,
                "machine_ids": machine_ids,
                "target_label": f"{len(machine_ids)} selected machine(s)",
                "confirm_phrase": _BULK_POWER_CONFIRM_PHRASE,
                "action_url": f"/machines/bulk/power/{action.value}",
                "cancel_url": "/machines",
                "error": (
                    f'That doesn\'t match — type "{_BULK_POWER_CONFIRM_PHRASE}" '
                    "exactly to confirm."
                ),
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    machines = await _get_machines_by_ids(machine_ids, db)
    skipped = await send_power_to_machines(machines, action)
    await log_event(
        db,
        request=request,
        action=f"machines.bulk.power.{action.value}",
        summary=f"Sent {action.value} to {len(machines)} selected machine(s)",
        details={"skipped": skipped},
    )
    redirect_url = "/machines"
    if skipped:
        redirect_url += f"?power_skipped={skipped}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{machine_id}")
async def machine_detail(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/detail.html",
        {
            "machine": machine,
            "csrf_token": csrf_token,
            "update_runs": await _get_recent_update_runs(machine_id, db),
            # The package *rows* themselves are deliberately not fetched
            # here — a machine can easily have several hundred installed
            # packages, and rendering them inline made this page slow and
            # cluttered. Only the cheap aggregate counts are needed for the
            # summary line; the full listing loads lazily into a modal (see
            # the "Show installed packages" button and
            # GET /machines/{id}/packages below).
            "package_counts": await _get_package_counts(machine_id, db),
            "held_count": await _get_held_count(machine_id, db),
            # One-time notice after a power action redirect — not persisted
            # anywhere, just echoed back from the query string.
            "power_sent": request.query_params.get("power_sent"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{machine_id}/packages")
async def machine_packages_panel(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    pkg_q: str = "",
    pkg_source: str = "",
    held_only: bool = False,
) -> Response:
    """The modal body for "Show installed packages" on the machine detail
    page — loaded on demand via htmx rather than embedded in that page's
    initial render. Also serves the filter form's own requests, which target
    just `#packages-panel` (not the whole modal) to stay open while filtering.
    """
    machine = await _get_machine_or_404(machine_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "partials/machine_packages.html",
        {
            "machine": machine,
            "csrf_token": csrf_token,
            "packages": await _get_packages(
                machine_id, db, pkg_q=pkg_q, pkg_source=pkg_source, held_only=held_only
            ),
            "package_counts": await _get_package_counts(machine_id, db),
            "held_count": await _get_held_count(machine_id, db),
            "pkg_q": pkg_q,
            "pkg_source": pkg_source,
            "held_only": held_only,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{machine_id}/edit")
async def edit_machine_form(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/edit.html",
        {
            "machine": machine,
            "auth_methods": list(AuthMethod),
            "groups": await _get_groups(db),
            "errors": [],
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/edit", dependencies=[_manage, Depends(verify_csrf)])
async def update_machine(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    ip_address: str = Form(...),
    port: int = Form(22),
    username: str = Form(...),
    auth_method: AuthMethod = Form(...),
    secret: str = Form(""),
    group_id: str = Form(""),
    description: str = Form(""),
    is_active: str = Form(""),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)

    try:
        payload = MachineUpdate(
            name=name,
            ip_address=ip_address,
            port=port,
            username=username,
            auth_method=auth_method,
            secret=secret or None,
            group_id=uuid.UUID(group_id) if group_id else None,
            description=description or None,
            # HTML only sends a checkbox field when it's checked.
            is_active=bool(is_active),
        )
    except ValueError as exc:
        await log_event(
            db,
            request=request,
            action="machine.update",
            summary=f'Rejected update to "{machine.name}": {exc}',
            outcome=AuditOutcome.FAILURE,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machines/edit.html",
            {
                "machine": machine,
                "auth_methods": list(AuthMethod),
                "groups": await _get_groups(db),
                "errors": [str(exc)],
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    # Changing where/how we connect invalidates the trust and facts we
    # previously established for whatever was at the old address — force
    # host-key re-discovery/re-confirmation rather than silently keeping
    # trust that no longer applies to the same physical/logical machine.
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
        # else: keep whatever password is already stored, unchanged.
    else:
        # SSH_KEY doesn't need a per-machine secret — don't leave a stale
        # password sitting around encrypted but unused.
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

    return RedirectResponse(url=f"/machines/{machine.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{machine_id}/discover-host-key", dependencies=[_manage, Depends(verify_csrf)])
async def discover_host_key(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    settings = get_settings()
    csrf_token, new_cookie = get_or_create_csrf_token(request)

    context: dict[str, object] = {"machine": machine, "csrf_token": csrf_token}
    try:
        context["fingerprint"] = await discover_host_key_fingerprint(
            machine.ip_address, machine.port, settings.ssh_connect_timeout
        )
    except SSHConnectionError as exc:
        context["error"] = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.host_key.discover",
        summary=f'Discovered host key fingerprint for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if "error" not in context else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": context["error"]} if "error" in context else None,
    )

    response = templates.TemplateResponse(request, "partials/host_key_discovery.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/trust-host-key", dependencies=[_manage, Depends(verify_csrf)])
async def trust_host_key(
    request: Request,
    machine_id: uuid.UUID,
    fingerprint: str = Form(...),
    db: AsyncSession = Depends(get_db),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    fingerprint = fingerprint.strip()
    if not _FINGERPRINT_RE.match(fingerprint):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid fingerprint format."
        )
    machine.host_key_fingerprint = fingerprint
    await db.commit()

    await log_event(
        db,
        request=request,
        action="machine.host_key.trust",
        summary=f'Trusted host key fingerprint for "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"fingerprint": fingerprint},
    )

    # Now that the machine can be safely connected to, kick off an initial
    # facts gathering pass in the background — don't block the redirect on it.
    tasks.refresh_machine_facts.delay(str(machine.id))

    redirect_url = f"/machines/{machine.id}"
    # The fingerprint-confirmation form only ever renders inside an htmx fragment —
    # a plain 3xx redirect would be silently followed by htmx and the returned HTML
    # would end up swapped into just that panel. HX-Redirect tells htmx to navigate
    # the whole page instead.
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{machine_id}/test-connection", dependencies=[_manage, Depends(verify_csrf)])
async def test_connection_endpoint(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    settings = get_settings()

    async_result = tasks.test_machine_connection.delay(str(machine.id))
    result: dict[str, object] | None = None
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 5
        )
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        # Celery's `AsyncResult.get()` re-raises whatever exception happened
        # inside the task (propagate=True is the default) — we want to show
        # that to the user as a test failure, not crash the request.
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.test_connection",
        summary=f'Tested connection to "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    return templates.TemplateResponse(
        request,
        "partials/test_connection_result.html",
        {"machine": machine, "result": result, "error": error},
    )


@router.post("/{machine_id}/refresh-facts", dependencies=[_manage, Depends(verify_csrf)])
async def refresh_facts_endpoint(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    settings = get_settings()

    async_result = tasks.refresh_machine_facts.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 5
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    if error is None:
        # Facts were updated in the DB by the job — reload to pick them up.
        machine = await _get_machine_or_404(machine_id, db)

    await log_event(
        db,
        request=request,
        action="machine.facts.refresh",
        summary=f'Refreshed facts for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    # The partial has its own "Refresh facts" button, which needs a CSRF
    # token too — reuse the one already set on this client rather than
    # minting (and trying to re-set) a fresh cookie from inside an htmx swap.
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/machine_facts.html",
        {"machine": machine, "error": error, "csrf_token": csrf_token},
    )


@router.post("/{machine_id}/refresh-packages", dependencies=[_manage, Depends(verify_csrf)])
async def refresh_packages_endpoint(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    pkg_q: str = Form(""),
    pkg_source: str = Form(""),
    held_only: bool = Form(False),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    settings = get_settings()

    async_result = tasks.refresh_machine_packages.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    if error is None:
        # Packages were updated in the DB by the job — reload to pick them up.
        machine = await _get_machine_or_404(machine_id, db)

    await log_event(
        db,
        request=request,
        action="machine.packages.refresh",
        summary=f'Refreshed installed packages for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/machine_packages.html",
        {
            "machine": machine,
            "error": error,
            "csrf_token": csrf_token,
            "packages": await _get_packages(
                machine_id, db, pkg_q=pkg_q, pkg_source=pkg_source, held_only=held_only
            ),
            "package_counts": await _get_package_counts(machine_id, db),
            "held_count": await _get_held_count(machine_id, db),
            "pkg_q": pkg_q,
            "pkg_source": pkg_source,
            "held_only": held_only,
        },
    )


@router.post("/{machine_id}/check-updates", dependencies=[_updates, Depends(verify_csrf)])
async def check_updates_endpoint(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    settings = get_settings()

    async_result = tasks.check_machine_updates.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.update_timeout_seconds + 5
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    # Counts were updated in the DB by the job (even on failure, they're
    # reset to "unknown" rather than left stale) — reload either way.
    machine = await _get_machine_or_404(machine_id, db)

    await log_event(
        db,
        request=request,
        action="machine.updates.check",
        summary=f'Checked for updates on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/update_availability.html",
        {"machine": machine, "error": error, "csrf_token": csrf_token},
    )


@router.get("/{machine_id}/updates/preview", dependencies=[_updates])
async def preview_machine_update(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    strategy: UpgradeStrategy = UpgradeStrategy.DIST_UPGRADE,
) -> Response:
    """Simulate (via apt's dry-run mode — nothing is changed on the machine)
    exactly what `POST /machines/{id}/updates` would do, so a human can see
    what would be removed (the risky part of `autoremove`) before actually
    confirming it. A GET, not a POST: it's read-only against debcontrol's
    own DB (nothing is persisted here, unlike "Check for updates now",
    which writes the counts/lists it finds) even though it does perform a
    real SSH round trip — same reasoning `/machines/package-search` and
    `/machines/{id}/updates` (history) already use for a GET that only
    reads, no CSRF token needed.

    This is the page the detail page's "Run update" button now sends you to
    first — the actual trigger (`trigger_machine_update` below) only ever
    fires from this page's own confirm button, or directly via the API for
    a scripted caller (see `app/web/routes/api_v1.py`'s module docstring for
    why the API doesn't get the same forced two-step)."""
    machine = await _get_machine_or_404(machine_id, db)
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before previewing updates.",
        )

    settings = get_settings()
    async_result = tasks.preview_machine_update.delay(str(machine.id), strategy.value)
    error: str | None = None
    to_install_or_upgrade: list[PendingPackage] = []
    to_remove: list[PendingPackage] = []
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=settings.update_timeout_seconds + 5
        )
        if isinstance(result, dict):
            if not result.get("ok"):
                error = str(result.get("error") or "Unknown error.")
            else:
                to_install_or_upgrade = list(result.get("to_install_or_upgrade") or [])
                to_remove = list(result.get("to_remove") or [])
    except TimeoutError:
        error = "The background job did not respond in time."
    except Exception as exc:
        error = str(exc)

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/update_preview.html",
        {
            "machine": machine,
            "strategy": strategy,
            "error": error,
            "to_install_or_upgrade": to_install_or_upgrade,
            "to_remove": to_remove,
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/updates", dependencies=[_updates, Depends(verify_csrf)])
async def trigger_machine_update(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    if not machine.host_key_fingerprint:
        await log_event(
            db,
            request=request,
            action="machine.updates.run",
            summary=f'Blocked update on "{machine.name}": no pinned host key',
            outcome=AuditOutcome.DENIED,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before running updates.",
        )

    # apt update/upgrade can run for a long time — this only creates the
    # record and enqueues the job, it never waits for the result.
    run = MachineUpdateRun(machine_id=machine.id, strategy=strategy)
    db.add(run)
    await db.commit()
    await db.refresh(run)

    tasks.run_machine_update.delay(str(run.id))

    await log_event(
        db,
        request=request,
        action="machine.updates.run",
        summary=f'Triggered {strategy.value.replace("_", "-")} on "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"strategy": strategy.value, "run_id": str(run.id)},
    )

    return RedirectResponse(
        url=f"/machines/{machine.id}/updates/{run.id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/{machine_id}/updates")
async def machine_update_history(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    status_filter: str = "",
    page: int = 1,
) -> Response:
    """Every update run for this machine, newest first, paginated the same
    way `/audit` is (offset/limit, one extra row fetched to know whether an
    "Older" page exists) — the machine detail page's "Recent runs" table
    only ever shows the last 5; this is the full history behind it."""
    machine = await _get_machine_or_404(machine_id, db)
    page = max(page, 1)

    query = select(MachineUpdateRun).where(MachineUpdateRun.machine_id == machine_id)
    if status_filter in {s.value for s in UpdateRunStatus}:
        query = query.where(MachineUpdateRun.status == UpdateRunStatus(status_filter))

    offset = (page - 1) * _UPDATE_HISTORY_PAGE_SIZE
    result = await db.execute(
        query.order_by(MachineUpdateRun.created_at.desc())
        .offset(offset)
        .limit(_UPDATE_HISTORY_PAGE_SIZE + 1)
    )
    runs = list(result.scalars().all())
    has_older = len(runs) > _UPDATE_HISTORY_PAGE_SIZE
    runs = runs[:_UPDATE_HISTORY_PAGE_SIZE]

    return templates.TemplateResponse(
        request,
        "machines/update_history.html",
        {
            "machine": machine,
            "runs": runs,
            "statuses": list(UpdateRunStatus),
            "status_filter": status_filter,
            "page": page,
            "has_older": has_older,
        },
    )


@router.get("/{machine_id}/updates/{run_id}")
async def machine_update_run_detail(
    request: Request,
    machine_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
    run = await _get_update_run_or_404(run_id, db)
    if run.machine_id != machine.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return templates.TemplateResponse(
        request, "machines/update_run.html", {"machine": machine, "run": run}
    )


@router.get("/{machine_id}/updates/{run_id}/status")
async def machine_update_run_status(
    request: Request,
    machine_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Pollable fragment (htmx `hx-trigger="every ...s"`) showing one run's
    status/output. Once the run reaches a terminal state, the fragment stops
    including the polling attributes, so htmx naturally stops re-fetching it.
    """
    run = await _get_update_run_or_404(run_id, db)
    if run.machine_id != machine_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return templates.TemplateResponse(request, "partials/update_run_status.html", {"run": run})


@router.get("/{machine_id}/terminal", dependencies=[_terminal])
async def terminal_page(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    """The interactive web terminal's page shell — the actual byte relay
    happens over the WebSocket in `app/web/routes/terminal_ws.py`, which
    (since `app.auth.middleware` never runs for WebSocket requests) does its
    own independent session/permission check rather than relying on this
    page having already been reached. Gated behind `ACTION_TERMINAL` — see
    that permission's comment in `app/db/models/role.py` for why it's its
    own dedicated permission rather than folded into an existing one."""
    machine = await _get_machine_or_404(machine_id, db)
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before opening a terminal.",
        )
    return templates.TemplateResponse(request, "machines/terminal.html", {"machine": machine})


@router.get("/{machine_id}/power/{action}")
async def power_confirm_form(
    request: Request, machine_id: uuid.UUID, action: PowerAction, db: AsyncSession = Depends(get_db)
) -> Response:
    """First confirmation step: a dedicated page stating exactly what's
    about to happen. The second step — typing the machine's name — is
    enforced server-side in `power_action`, not just disabled-until-typed
    in the browser."""
    machine = await _get_machine_or_404(machine_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/power_confirm.html",
        {"machine": machine, "action": action, "error": None, "csrf_token": csrf_token},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/power", dependencies=[_power, Depends(verify_csrf)])
async def power_action(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    action: PowerAction = Form(...),
    confirm_name: str = Form(...),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)

    if confirm_name.strip() != machine.name:
        await log_event(
            db,
            request=request,
            action=f"machine.power.{action.value}",
            summary=f'Blocked {action.value} on "{machine.name}": confirmation mismatch',
            outcome=AuditOutcome.DENIED,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "machines/power_confirm.html",
            {
                "machine": machine,
                "action": action,
                "error": f'That doesn\'t match — type "{machine.name}" exactly to confirm.',
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    if not machine.host_key_fingerprint:
        await log_event(
            db,
            request=request,
            action=f"machine.power.{action.value}",
            summary=f'Blocked {action.value} on "{machine.name}": no pinned host key',
            outcome=AuditOutcome.DENIED,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before sending power commands.",
        )

    # Fire-and-forget, same reasoning as system updates: the connection can
    # legitimately drop once the machine actually reboots/shuts down, so
    # there's nothing meaningful to wait for here.
    tasks.send_machine_power_command.delay(str(machine.id), action.value)

    await log_event(
        db,
        request=request,
        action=f"machine.power.{action.value}",
        summary=f'Sent {action.value} to "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
    )

    return RedirectResponse(
        url=f"/machines/{machine.id}?power_sent={action.value}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/pending/{pending_id}/dismiss", dependencies=[_manage, Depends(verify_csrf)])
async def dismiss_pending_machine(
    request: Request, pending_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    pending = await db.get(PendingMachine, pending_id)
    if pending is not None:
        await db.delete(pending)
        await db.commit()
        await log_event(
            db,
            request=request,
            action="machine.pending.dismiss",
            summary=f'Dismissed pending machine "{pending.ip_address}"',
            target_type="pending_machine",
            target_id=pending_id,
            target_label=pending.ip_address,
        )
    return RedirectResponse(url="/machines", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{machine_id}/delete", dependencies=[_manage, Depends(verify_csrf)])
async def delete_machine(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    machine = await _get_machine_or_404(machine_id, db)
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
    return RedirectResponse(url="/machines", status_code=status.HTTP_303_SEE_OTHER)
