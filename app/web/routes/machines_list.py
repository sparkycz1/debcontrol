"""The machine list and everything addressed by a fixed path under
`/machines`: saved views and the view mode, adding one machine, CSV import,
the inventory and configuration exports, configuration import, the bulk
actions and dismissing a pending machine."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime
from urllib.parse import urlparse

from fastapi import Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_update_run import UpgradeStrategy
from app.db.models.pending_machine import PendingMachine
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.machine import MachineCreate
from app.schemas.machine_config import MachineConfigExport
from app.services.access_scope import (
    can_see_group_id,
    is_restricted,
    machines_visible_to,
    visible_machines_by_ids,
)
from app.services.fleet_overview import latest_monitoring_samples
from app.services.machine_actions import (
    send_power_to_machines,
    trigger_check_updates,
    trigger_updates,
)
from app.services.machine_config import export_machine_config, import_machine_config
from app.services.machine_grouping import assign_machines_to_group
from app.services.machine_tags import (
    add_tags_to_machines,
    parse_tag_names_from_text,
    remove_tags_from_machines,
    set_machine_tags,
)
from app.services.saved_views import (
    DuplicateViewNameError,
    build_query_string,
    create_saved_view,
    delete_saved_view,
    list_saved_views,
)
from app.ssh.power import PowerAction
from app.web.flash import read_flash, sign_flash
from app.web.machine_search import (
    STATUS_FILTERS,
    apply_group_filter,
    apply_status_filter,
    apply_tag_filter,
    machine_search_clause,
)
from app.web.routes.audit import _csv_safe
from app.web.routes.machines_common import (
    _get_all_tags,
    _get_groups,
    machines_router,
    need_manage,
    need_power,
    need_updates,
)
from app.web.templating import t, templates

router = machines_router()


# Typed phrase to confirm a power action against an arbitrary ad-hoc
# selection from the machine list — unlike a group or "All machines", a
# selection doesn't have a name of its own to ask someone to type.
_BULK_POWER_CONFIRM_PHRASE = "SELECTED MACHINES"


# The machine list's display density — a per-browser cosmetic preference,
# not per-account data worth a DB column (unlike saved views/tags, which
# are meaningful to look up or share across a session). Same plain,
# long-lived, non-httponly-adjacent cookie pattern `app.web.routes.theme`
# already uses for the light/dark toggle.
MACHINES_VIEW_COOKIE_NAME = "machines_view"


_MACHINES_VIEW_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365


_MACHINE_VIEW_MODES = ("table", "list", "cards")


def _bulk_error_url(request: Request, key: str) -> str:
    """Back to the machine list with a signed, translated `bulk_error` —
    see `app.web.flash` for why it's signed."""
    return f"/machines?bulk_error={sign_flash(t(request, key))}"


async def _get_pending_machines(db: AsyncSession) -> list[PendingMachine]:
    result = await db.execute(select(PendingMachine).order_by(PendingMachine.created_at.desc()))
    return list(result.scalars().all())


async def _get_latest_monitoring_by_machine(
    db: AsyncSession, machine_ids: list[uuid.UUID]
) -> dict[uuid.UUID, MachineMonitoringSample]:
    """The Cards view's small CPU/RAM indicator — the latest sample per
    machine on the current page, one batched query (see
    `app.services.fleet_overview.latest_monitoring_samples`)."""
    return await latest_monitoring_samples(db, machine_ids)


# The machines list used to load every row unconditionally — fine at a
# handful of machines, but at fleet sizes in the hundreds/thousands this
# page was one unbounded `SELECT *` and a multi-thousand-row HTML response
# on every visit. Same offset/limit-plus-one-extra-row convention as
# `/audit` and the update-run history: fetch one row past the page size to
# know whether a "Next" page exists, without a separate COUNT(*) query.
_MACHINE_LIST_PAGE_SIZE = 100


@router.get("")
async def list_machines(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    tag: list[str] = Query(default=[]),
    tag_mode: str = "or",
    status_filter: str = Query("", alias="status"),
    group: str = "",
    page: int = 1,
) -> Response:
    page = max(page, 1)
    tag_mode = tag_mode if tag_mode == "and" else "or"
    status_filter, group = _clean_list_filters(status_filter, group)
    query = (await machines_visible_to(db, current_user)).options(selectinload(Machine.group))
    if q.strip():
        query = query.where(machine_search_clause(q))
    query = apply_tag_filter(query, tag, tag_mode)
    query = apply_group_filter(apply_status_filter(query, status_filter), group)

    offset = (page - 1) * _MACHINE_LIST_PAGE_SIZE
    result = await db.execute(
        query.order_by(Machine.name).offset(offset).limit(_MACHINE_LIST_PAGE_SIZE + 1)
    )
    machines = list(result.scalars().all())
    has_more = len(machines) > _MACHINE_LIST_PAGE_SIZE
    machines = machines[:_MACHINE_LIST_PAGE_SIZE]

    view_mode = request.cookies.get(MACHINES_VIEW_COOKIE_NAME, "table")
    if view_mode not in _MACHINE_VIEW_MODES:
        view_mode = "table"

    latest_monitoring = (
        await _get_latest_monitoring_by_machine(db, [m.id for m in machines])
        if view_mode == "cards"
        else {}
    )

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/list.html",
        {
            "machines": machines,
            "pending_machines": await _get_pending_machines(db),
            "all_tags": await _get_all_tags(db),
            "saved_views": await list_saved_views(db, current_user.id),
            "q": q,
            "tag": tag,
            "tag_mode": tag_mode,
            "status_filter": status_filter,
            "status_filters": STATUS_FILTERS,
            "group_filter": group,
            "filter_qs": build_query_string(
                {"q": q, "tag": tag, "tag_mode": tag_mode, "status": status_filter,
                 "group": group}
            ),
            "page": page,
            "has_more": has_more,
            "view_mode": view_mode,
            "latest_monitoring": latest_monitoring,
            "csrf_token": csrf_token,
            "bulk_error": read_flash(request, "bulk_error"),
            "bulk_notice": read_flash(request, "bulk_notice"),
            "power_skipped": request.query_params.get("power_skipped"),
            "groups": await _get_groups(db, current_user),
            "restricted": await is_restricted(db, current_user),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


def _clean_list_filters(status_filter: str, group: str) -> tuple[str, str]:
    """Only a known status and a well-formed group id (or "none") survive —
    what a saved view may store and what the links on the page repeat."""
    status_filter = status_filter if status_filter in STATUS_FILTERS else ""
    if group != "none":
        try:
            group = str(uuid.UUID(group))
        except ValueError:
            group = ""
    return status_filter, group


def _safe_machines_redirect(next_path: str) -> str:
    """Only ever redirect back into `/machines...` — `next` comes from a
    form field an attacker could tamper with, same reasoning
    `app.web.routes.theme._safe_redirect_target` already documents."""
    # The shape static analysis recognises as safe, and stricter than the
    # prefix test alone: no backslashes (browsers read them as slashes), no
    # scheme and no host — so only a path on this site is left.
    target = next_path.replace("\\", "")
    parsed = urlparse(target)
    if not parsed.netloc and not parsed.scheme and target.startswith("/machines"):
        return target
    return "/machines"


@router.post("/view-mode", dependencies=[Depends(verify_csrf)])
async def set_machines_view_mode(
    view: str = Form(...), next: str = Form("/machines")
) -> Response:
    """The "Table" / "List" / "Cards" toggle above the machine list —
    remembered in a cookie, not a query param, so it carries over to the
    next visit (and every saved view/pagination link) without needing to
    be threaded through every href on the page. See
    `MACHINES_VIEW_COOKIE_NAME`."""
    # Looked up, not echoed: the cookie only ever holds one of our constants.
    chosen = {mode: mode for mode in _MACHINE_VIEW_MODES}.get(view, "table")
    response = RedirectResponse(
        url=_safe_machines_redirect(next), status_code=status.HTTP_303_SEE_OTHER
    )
    response.set_cookie(
        MACHINES_VIEW_COOKIE_NAME,
        chosen,
        max_age=_MACHINES_VIEW_COOKIE_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=get_settings().is_production,
    )
    return response


@router.post("/views", dependencies=[Depends(verify_csrf)])
async def save_machine_view(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name: str = Form(...),
    q: str = Form(""),
    tag: list[str] = Form(default=[]),
    tag_mode: str = Form("or"),
    status_filter: str = Form("", alias="status"),
    group: str = Form(""),
) -> Response:
    """"Save this view" on the machine list — captures only the known
    filter fields (never an arbitrary querystring, see
    `app.services.saved_views`), so a saved view always replays as exactly
    the same filtered `GET /machines` request."""
    status_filter, group = _clean_list_filters(status_filter, group)
    query_string = build_query_string(
        {"q": q, "tag": tag, "tag_mode": tag_mode, "status": status_filter, "group": group}
    )
    if not name.strip():
        return RedirectResponse(
            url=f"/machines?{query_string}", status_code=status.HTTP_303_SEE_OTHER
        )
    try:
        await create_saved_view(db, current_user.id, name, query_string)
    except DuplicateViewNameError:
        return RedirectResponse(
            url=f"/machines?{query_string}&view_error=duplicate_name",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(url=f"/machines?{query_string}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/views/{view_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_machine_view(
    view_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    await delete_saved_view(db, current_user.id, view_id)
    return RedirectResponse(url="/machines", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/new")
async def new_machine_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/new.html",
        {
            "auth_methods": list(AuthMethod),
            "groups": await _get_groups(db, current_user),
            "all_tags": await _get_all_tags(db),
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


@router.post("", dependencies=[need_manage, Depends(verify_csrf)])
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
    runbook: str = Form(""),
    tags: str = Form(""),
    current_user: User = Depends(get_current_user),
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
            runbook=runbook or None,
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
                "groups": await _get_groups(db, current_user),
                "all_tags": await _get_all_tags(db),
                "errors": [str(exc)],
                "form": {
                    "name": name,
                    "ip_address": ip_address,
                    "port": port,
                    "username": username,
                    "auth_method": auth_method,
                    "description": description,
                    "runbook": runbook,
                },
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    # A restricted account may only file a new machine into a group it can
    # see — otherwise it would create something it immediately can't find
    # (an ungrouped machine is invisible to a restricted account by design).
    if not await can_see_group_id(db, current_user, payload.group_id):
        await log_event(
            db,
            request=request,
            action="machine.create",
            summary=f'Rejected new machine "{name}": group outside this account\'s access',
            outcome=AuditOutcome.DENIED,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Pick a machine group your account has access to.",
        )

    machine = Machine(
        name=payload.name,
        ip_address=payload.ip_address,
        port=payload.port,
        username=payload.username,
        auth_method=payload.auth_method,
        secret_encrypted=encrypt_secret(payload.secret) if payload.secret else None,
        group_id=payload.group_id,
        description=payload.description,
        runbook=payload.runbook,
    )
    db.add(machine)
    await db.commit()
    await db.refresh(machine)

    await set_machine_tags(db, machine, parse_tag_names_from_text(tags))
    await db.commit()

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


@router.post("/import", dependencies=[need_manage, Depends(verify_csrf)])
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
        errors.append(t(request, "common.error.paste_csv"))
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
    "tags",
    "is_active",
)


_INVENTORY_CSV_FIELDS = (
    "name",
    "ip_address",
    "hostname",
    "group",
    "tags",
    "status",
    "os_version",
    "kernel_version",
    "cpu_architecture",
    "cpu_cores",
    "ram_gb",
    "upgradable",
    "security_upgradable",
    "reboot_required",
    "uptime_days",
    "host_key_pinned",
    "facts_updated_at",
    "updates_checked_at",
)


def _inventory_row(machine: Machine) -> dict[str, object]:
    def iso(value: datetime | None) -> str:
        return value.isoformat() if value else ""

    if machine.is_reachable is None:
        status_label = "unknown"
    else:
        status_label = "online" if machine.is_reachable else "offline"
    return {
        "name": _csv_safe(machine.name),
        "ip_address": machine.ip_address,
        "hostname": _csv_safe(machine.discovered_hostname or ""),
        "group": _csv_safe(machine.group.name if machine.group else ""),
        "tags": _csv_safe(", ".join(tag.name for tag in machine.tags)),
        "status": status_label,
        "os_version": _csv_safe(machine.os_version or ""),
        "kernel_version": _csv_safe(machine.kernel_version or ""),
        "cpu_architecture": machine.cpu_architecture or "",
        "cpu_cores": machine.cpu_cores if machine.cpu_cores is not None else "",
        "ram_gb": round(machine.ram_bytes / 1024**3, 1) if machine.ram_bytes else "",
        "upgradable": machine.upgradable_count if machine.upgradable_count is not None else "",
        "security_upgradable": (
            machine.security_upgradable_count
            if machine.security_upgradable_count is not None
            else ""
        ),
        "reboot_required": "" if machine.reboot_required is None else machine.reboot_required,
        "uptime_days": (
            round(machine.uptime_seconds / 86400, 1) if machine.uptime_seconds else ""
        ),
        "host_key_pinned": bool(machine.host_key_fingerprint),
        "facts_updated_at": iso(machine.facts_updated_at),
        "updates_checked_at": iso(machine.updates_checked_at),
    }


@router.get("/inventory.csv")
async def export_machine_inventory(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    tag: list[str] = Query(default=[]),
    tag_mode: str = "or",
    status_filter: str = Query("", alias="status"),
    group: str = "",
) -> Response:
    """The machine list as a spreadsheet — every machine matching the
    current search/tag/status/group filter (not just the visible page), with the
    status, OS, hardware and update columns an inventory report needs.
    Scoped exactly like the list itself. Unlike `/config/export` (the
    structural import/export round-trip) this is a read-only report; the
    same data is available as JSON from `GET /api/v1/machines`."""
    tag_mode = tag_mode if tag_mode == "and" else "or"
    query = (await machines_visible_to(db, current_user)).options(
        selectinload(Machine.group), selectinload(Machine.tags)
    )
    if q.strip():
        query = query.where(machine_search_clause(q))
    query = apply_tag_filter(query, tag, tag_mode)
    status_filter, group = _clean_list_filters(status_filter, group)
    query = apply_group_filter(apply_status_filter(query, status_filter), group)
    machines = list((await db.execute(query.order_by(Machine.name))).scalars().all())

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_INVENTORY_CSV_FIELDS)
    writer.writeheader()
    for machine in machines:
        writer.writerow(_inventory_row(machine))

    await log_event(
        db,
        request=request,
        action="machine.inventory_export",
        summary=f"Exported the machine inventory ({len(machines)} machine(s)) as CSV",
        details={"machine_count": len(machines), "q": q or None, "tags": tag or None},
    )
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="debcontrol-inventory-{timestamp}.csv"'
        },
    )


@router.get("/config/export")
async def export_machine_config_endpoint(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    format: str = "json",
) -> Response:
    """Export every existing (non-pending) machine's and group's *structural*
    configuration — deliberately never `secret_encrypted` or
    `host_key_fingerprint`, see `app.services.machine_config`'s module
    docstring. JSON includes both machines and groups; CSV (machines only —
    groups don't flatten to CSV sensibly) is a plain download link, same
    pattern as the audit log's export (see `app/web/routes/audit.py`)."""
    export = await export_machine_config(db, current_user)

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
            row["tags"] = ", ".join(machine.tags)
            # Doesn't flatten sensibly into one CSV cell — JSON export is
            # the full-fidelity round-trip for a runbook, same reasoning
            # groups are CSV-machines-only for. See _CONFIG_EXPORT_CSV_FIELDS.
            del row["runbook"]
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


@router.post("/config/import", dependencies=[need_manage, Depends(verify_csrf)])
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
                "errors": [t(request, "common.error.paste_json")],
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


@router.get("/security-updates")
async def security_updates_moved(request: Request) -> Response:
    """Moved to Security → Security updates (`app.web.routes.security`)."""
    return RedirectResponse(url="/security/updates", status_code=308)


@router.get("/package-search")
async def package_search_moved(request: Request) -> Response:
    """Moved to Security → Package search — the query string is kept."""
    query = f"?{request.url.query}" if request.url.query else ""
    return RedirectResponse(url=f"/security/packages{query}", status_code=308)


async def _get_machines_by_ids(
    machine_ids: list[uuid.UUID], db: AsyncSession, user: User
) -> list[Machine]:
    """The submitted selection, minus anything outside `user`'s scope.

    Client-submitted ids are never trusted here: the checkboxes were
    rendered from a scoped list, so an id outside it can only have been
    hand-crafted. Out-of-scope ids are dropped silently rather than
    rejected with an error naming them (see `app.services.access_scope`)."""
    return await visible_machines_by_ids(db, user, machine_ids)


@router.post("/bulk/check-updates", dependencies=[need_updates, Depends(verify_csrf)])
async def bulk_check_updates(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    machine_ids: list[uuid.UUID] = Form(default=[]),
) -> Response:
    """Check-updates for an ad-hoc selection from the machine list — same
    underlying job as the group/"All machines" versions, just against
    whichever rows were ticked rather than a stored group."""
    machines = await _get_machines_by_ids(machine_ids, db, current_user)
    if not machines:
        return RedirectResponse(
            url=_bulk_error_url(request, "machines.error.select_machine"),
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
    started = len(machines) - skipped
    notice = t(request, "machines.bulk.check_started", count=started)
    if skipped:
        notice += " " + t(request, "machines.bulk.check_skipped", count=skipped)
    return RedirectResponse(
        url=f"/machines?bulk_notice={sign_flash(notice)}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/bulk/updates", dependencies=[need_updates, Depends(verify_csrf)])
async def bulk_trigger_updates(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    machine_ids: list[uuid.UUID] = Form(default=[]),
    strategy: UpgradeStrategy = Form(...),
) -> Response:
    machines = await _get_machines_by_ids(machine_ids, db, current_user)
    if not machines:
        return RedirectResponse(
            url=_bulk_error_url(request, "machines.error.select_machine"),
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


@router.post("/bulk/power-confirm/{action}", dependencies=[need_power, Depends(verify_csrf)])
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
            url=_bulk_error_url(request, "machines.error.select_machine"),
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


@router.post("/bulk/power/{action}", dependencies=[need_power, Depends(verify_csrf)])
async def bulk_power_action(
    request: Request,
    action: PowerAction,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
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

    machines = await _get_machines_by_ids(machine_ids, db, current_user)
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


@router.post("/bulk/group", dependencies=[need_manage, Depends(verify_csrf)])
async def bulk_assign_group(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    machine_ids: list[uuid.UUID] = Form(default=[]),
    group_id: str = Form(""),
) -> Response:
    """Move every machine in an ad-hoc selection into one group (or out of
    any group, `group_id="none"`; nothing picked is an error, so the "no
    group" choice is always deliberate) — the bulk equivalent of each machine's own
    Group field on Settings, with the same `machine.manage` permission and
    the same scope rule: a restricted account can only pick a group it can
    see, never "no group" (see `can_see_group_id`)."""
    machines = await _get_machines_by_ids(machine_ids, db, current_user)
    if not machines:
        return RedirectResponse(
            url=_bulk_error_url(request, "machines.error.select_machine"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    choice = group_id.strip()
    if not choice:
        return RedirectResponse(
            url=_bulk_error_url(request, "machines.error.pick_group"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        target_id = None if choice == "none" else uuid.UUID(choice)
    except ValueError:
        target_id = None
        choice = "invalid"
    group = await db.get(MachineGroup, target_id) if target_id else None
    if (choice != "none" and group is None) or not await can_see_group_id(
        db, current_user, target_id
    ):
        return RedirectResponse(
            url=_bulk_error_url(request, "machines.error.group_not_allowed"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    moved = assign_machines_to_group(machines, group)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machines.bulk.group.assign",
        summary=(
            f'Moved {len(moved)} selected machine(s) to group "{group.name}"'
            if group
            else f"Removed {len(moved)} selected machine(s) from their group"
        ),
        target_type="machine_group" if group else None,
        target_id=group.id if group else None,
        target_label=group.name if group else None,
        details={
            "group": group.name if group else None,
            "machines": [m.name for m in moved],
            "unchanged_count": len(machines) - len(moved),
        },
    )
    notice = t(
        request,
        "machines.bulk.group_done" if group else "machines.bulk.group_cleared",
        count=len(moved),
        group=group.name if group else "",
    )
    return RedirectResponse(
        url=f"/machines?bulk_notice={sign_flash(notice)}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/bulk/tags/add", dependencies=[need_manage, Depends(verify_csrf)])
async def bulk_add_tags(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    machine_ids: list[uuid.UUID] = Form(default=[]),
    tags: str = Form(""),
) -> Response:
    """Add one or more tags to every machine in an ad-hoc selection from the
    machine list, leaving each machine's other tags untouched — the bulk
    equivalent of typing into one machine's own tags field on Settings."""
    machines = await _get_machines_by_ids(machine_ids, db, current_user)
    names = parse_tag_names_from_text(tags)
    if not machines or not names:
        return RedirectResponse(
            url=_bulk_error_url(request, "machines.error.select_machine_and_tag"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    await add_tags_to_machines(db, [m.id for m in machines], names)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machines.bulk.tags.add",
        summary=(
            f'Added tag(s) {", ".join(names)} to {len(machines)} selected machine(s)'
        ),
        details={"tags": names, "machine_count": len(machines)},
    )
    return RedirectResponse(url="/machines", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/tags/remove", dependencies=[need_manage, Depends(verify_csrf)])
async def bulk_remove_tags(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    machine_ids: list[uuid.UUID] = Form(default=[]),
    tags: str = Form(""),
) -> Response:
    """Remove one or more tags from every machine in an ad-hoc selection —
    a no-op for any machine that didn't have a given tag in the first
    place, never an error."""
    machines = await _get_machines_by_ids(machine_ids, db, current_user)
    names = parse_tag_names_from_text(tags)
    if not machines or not names:
        return RedirectResponse(
            url=_bulk_error_url(request, "machines.error.select_machine_and_tag"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    await remove_tags_from_machines(db, [m.id for m in machines], names)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machines.bulk.tags.remove",
        summary=(
            f'Removed tag(s) {", ".join(names)} from {len(machines)} selected machine(s)'
        ),
        details={"tags": names, "machine_count": len(machines)},
    )
    return RedirectResponse(url="/machines", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/pending/{pending_id}/dismiss", dependencies=[need_manage, Depends(verify_csrf)])
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
