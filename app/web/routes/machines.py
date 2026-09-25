"""Managed machines — CRUD, host key pinning, connection testing, facts."""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import re
import uuid
from datetime import UTC, datetime
from urllib.parse import urlencode

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_package import MachinePackage
from app.db.models.machine_service import MachineService
from app.db.models.machine_tag import Tag
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.db.models.pending_machine import PendingMachine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.machine import MachineCreate, MachineUpdate
from app.schemas.machine_config import MachineConfigExport
from app.services import monitoring_history
from app.services.access_scope import (
    can_see_group_id,
    groups_visible_to,
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
from app.services.maintenance_windows import active_window_for
from app.services.notifications import condition_thresholds_for_machine
from app.services.saved_views import (
    DuplicateViewNameError,
    build_query_string,
    create_saved_view,
    delete_saved_view,
    list_saved_views,
)
from app.ssh import logs as ssh_logs
from app.ssh.client import discover_host_key_fingerprint
from app.ssh.containers import CONTAINER_ACTIONS
from app.ssh.exceptions import SSHConnectionError
from app.ssh.logs import is_container_name_valid
from app.ssh.packages import PackageSource
from app.ssh.power import PowerAction
from app.ssh.updates import PendingPackage

# Imported as a module, not name-by-name: this file already has a route
# function called `preview_machine_update`, which would shadow the task of
# the same name.
from app.tasks import jobs as tasks
from app.web.flash import read_flash, sign_flash
from app.web.log_lines import parse_log_lines
from app.web.machine_search import apply_tag_filter, machine_search_clause
from app.web.messages import LocalizedText
from app.web.routes.audit import _csv_safe
from app.web.templating import t, templates

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

router = APIRouter(
    prefix="/machines", dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))]
)
_manage = Depends(require_permission(Permission.MACHINE_MANAGE))
_updates = Depends(require_permission(Permission.ACTION_UPDATES))
_power = Depends(require_permission(Permission.ACTION_POWER))
_terminal = Depends(require_permission(Permission.ACTION_TERMINAL))

# Fingerprint shaped like "SHA256:<base64...>", as returned by AsyncSSH/OpenSSH.
_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9]+:[A-Za-z0-9+/=_-]+$")


def _bulk_error_url(request: Request, key: str) -> str:
    """Back to the machine list with a signed, translated `bulk_error` —
    see `app.web.flash` for why it's signed."""
    return f"/machines?bulk_error={sign_flash(t(request, key))}"


def _machine_tabs(request: Request, machine: Machine, user: User) -> list[tuple[str, str, str]]:
    """The (key, label, url) tabs shown on every one of this machine's own
    pages — same set and order everywhere, so `partials/_tabnav.html` always
    highlights the right one. Terminal is left out entirely for a user
    without `action.terminal`, same as it was hidden inline before this page
    had tabs at all."""
    base = f"/machines/{machine.id}"
    tabs = [
        ("overview", t(request, "machine.tab.overview"), base),
        ("monitoring", t(request, "machine.tab.monitoring"), f"{base}/monitoring"),
        ("updates", t(request, "machine.tab.updates"), f"{base}/updates"),
    ]
    if user.has_permission(Permission.ACTION_TERMINAL):
        tabs.append(("terminal", t(request, "machine.tab.terminal"), f"{base}/terminal"))
        # Logs shares Terminal's permission gate rather than plain
        # `machine.view` — see the "Logs" route's own docstring for why.
        tabs.append(("logs", t(request, "machine.tab.logs"), f"{base}/logs"))
    # No separate "Power" tab any more — reboot/shut down live directly on
    # Overview now (see `machine_detail`'s own template), the same one-page
    # placement a machine's few other one-off actions (test connection,
    # discover host key) already have, rather than a whole tab for two
    # buttons. `GET /{id}/power` itself still redirects there for anyone
    # with the old URL bookmarked/linked — see `power_tab`.
    tabs.append(("settings", t(request, "machine.tab.settings"), f"{base}/edit"))
    return tabs


async def _get_machine_or_404(machine_id: uuid.UUID, db: AsyncSession, user: User) -> Machine:
    """The machine, or a 404 — including when it exists but is outside
    `user`'s machine-group scope (`app.services.access_scope`). 404, never
    403, for the same reason `app/web/routes/ai.py`'s `_get_conversation`
    uses one: a 403 would confirm that a machine with that id exists."""
    # Eager-load `group` — templates read `machine.group` and the async ORM
    # can't lazy-load relationships outside of an `await` (it would raise
    # MissingGreenlet during template rendering).
    query = await machines_visible_to(db, user)
    result = await db.execute(
        query.options(selectinload(Machine.group)).where(Machine.id == machine_id)
    )
    machine = result.scalar_one_or_none()
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found.")
    return machine


async def _get_groups(db: AsyncSession, user: User) -> list[MachineGroup]:
    """The groups offered in the machine form's group `<select>` — scoped,
    so a restricted user can't move a machine into a group they can't see
    (which would make it vanish from their own view)."""
    query = await groups_visible_to(db, user)
    result = await db.execute(query.order_by(MachineGroup.name))
    return list(result.scalars().all())


async def _get_all_tags(db: AsyncSession) -> list[Tag]:
    """Every tag currently in use, alphabetical — the machine list's filter
    dropdown and the create/edit forms' autocomplete `<datalist>`. Not
    scoped by machine-group access: a tag *name* existing isn't fleet
    data, and a restricted account typing a tag another machine happens to
    use just filters to nothing, the same as typing a free-text search
    term that doesn't match anything in scope."""
    result = await db.execute(select(Tag).order_by(Tag.name))
    return list(result.scalars().all())


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


async def _get_service_counts(machine_id: uuid.UUID, db: AsyncSession) -> dict[str, int]:
    result = await db.execute(
        select(func.count())
        .select_from(MachineService)
        .where(MachineService.machine_id == machine_id)
    )
    total = result.scalar_one()
    failed_result = await db.execute(
        select(func.count())
        .select_from(MachineService)
        .where(
            MachineService.machine_id == machine_id, MachineService.active_state == "failed"
        )
    )
    return {"total": total, "failed": failed_result.scalar_one()}


async def _get_services(
    machine_id: uuid.UUID, db: AsyncSession, *, svc_q: str, svc_state: str
) -> list[MachineService]:
    query = select(MachineService).where(MachineService.machine_id == machine_id)
    if svc_q.strip():
        query = query.where(MachineService.unit.ilike(f"%{svc_q.strip()}%"))
    if svc_state:
        query = query.where(MachineService.active_state == svc_state)
    result = await db.execute(query.order_by(MachineService.unit))
    return list(result.scalars().all())


_UPDATE_HISTORY_PAGE_SIZE = 50

# The machines list used to load every row unconditionally — fine at a
# handful of machines, but at fleet sizes in the hundreds/thousands this
# page was one unbounded `SELECT *` and a multi-thousand-row HTML response
# on every visit. Same offset/limit-plus-one-extra-row convention as
# `/audit` and the update-run history: fetch one row past the page size to
# know whether a "Next" page exists, without a separate COUNT(*) query.
_MACHINE_LIST_PAGE_SIZE = 100


async def _get_update_run_or_404(run_id: uuid.UUID, db: AsyncSession) -> MachineUpdateRun:
    run = await db.get(MachineUpdateRun, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return run


@router.get("")
async def list_machines(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    q: str = "",
    tag: list[str] = Query(default=[]),
    tag_mode: str = "or",
    page: int = 1,
) -> Response:
    page = max(page, 1)
    tag_mode = tag_mode if tag_mode == "and" else "or"
    query = (await machines_visible_to(db, current_user)).options(selectinload(Machine.group))
    if q.strip():
        query = query.where(machine_search_clause(q))
    query = apply_tag_filter(query, tag, tag_mode)

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


def _safe_machines_redirect(next_path: str) -> str:
    """Only ever redirect back into `/machines...` — `next` comes from a
    form field an attacker could tamper with, same reasoning
    `app.web.routes.theme._safe_redirect_target` already documents."""
    if next_path.startswith("/machines") and not next_path.startswith("//"):
        return next_path
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
    chosen = view if view in _MACHINE_VIEW_MODES else "table"
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
) -> Response:
    """"Save this view" on the machine list — captures only the known
    filter fields (never an arbitrary querystring, see
    `app.services.saved_views`), so a saved view always replays as exactly
    the same filtered `GET /machines` request."""
    query_string = build_query_string({"q": q, "tag": tag, "tag_mode": tag_mode})
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
) -> Response:
    """The machine list as a spreadsheet — every machine matching the
    current search/tag filter (not just the visible page), with the
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


_PACKAGE_SEARCH_LIMIT = 500


@router.get("/package-search")
async def package_search(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
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
        # Scoped by joining the machine each row belongs to — a restricted
        # user searching fleet-wide must not learn which packages sit on a
        # machine they can't otherwise see.
        visible_ids = (await machines_visible_to(db, current_user)).with_only_columns(
            Machine.id
        )
        query = (
            select(MachinePackage)
            .options(selectinload(MachinePackage.machine))
            .where(
                MachinePackage.name.ilike(f"%{q.strip()}%"),
                MachinePackage.machine_id.in_(visible_ids),
            )
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


async def _get_machines_by_ids(
    machine_ids: list[uuid.UUID], db: AsyncSession, user: User
) -> list[Machine]:
    """The submitted selection, minus anything outside `user`'s scope.

    Client-submitted ids are never trusted here: the checkboxes were
    rendered from a scoped list, so an id outside it can only have been
    hand-crafted. Out-of-scope ids are dropped silently rather than
    rejected with an error naming them (see
    `app.services.access_scope.filter_machines`)."""
    return await visible_machines_by_ids(db, user, machine_ids)


@router.post("/bulk/check-updates", dependencies=[_updates, Depends(verify_csrf)])
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
    return RedirectResponse(url="/machines", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/bulk/updates", dependencies=[_updates, Depends(verify_csrf)])
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


@router.post("/bulk/power/{action}", dependencies=[_power, Depends(verify_csrf)])
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


@router.post("/bulk/group", dependencies=[_manage, Depends(verify_csrf)])
async def bulk_assign_group(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    machine_ids: list[uuid.UUID] = Form(default=[]),
    group_id: str = Form(""),
) -> Response:
    """Move every machine in an ad-hoc selection into one group (or out of
    any group, `group_id=""`) — the bulk equivalent of each machine's own
    Group field on Settings, with the same `machine.manage` permission and
    the same scope rule: a restricted account can only pick a group it can
    see, never "no group" (see `can_see_group_id`)."""
    machines = await _get_machines_by_ids(machine_ids, db, current_user)
    if not machines:
        return RedirectResponse(
            url=_bulk_error_url(request, "machines.error.select_machine"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
    try:
        target_id = uuid.UUID(group_id) if group_id.strip() else None
    except ValueError:
        target_id = None
        group_id = "invalid"
    group = await db.get(MachineGroup, target_id) if target_id else None
    if (group_id.strip() and group is None) or not await can_see_group_id(
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


@router.post("/bulk/tags/add", dependencies=[_manage, Depends(verify_csrf)])
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


@router.post("/bulk/tags/remove", dependencies=[_manage, Depends(verify_csrf)])
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


@router.get("/{machine_id}")
async def machine_detail(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/detail.html",
        {
            "machine": machine,
            "maintenance_window": await active_window_for(db, machine),
            "csrf_token": csrf_token,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "overview",
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
            # anywhere, just echoed back from the query string (see
            # `power_action`'s own redirect).
            "power_sent": request.query_params.get("power_sent"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{machine_id}/monitoring")
async def machine_monitoring(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    current_user: User = Depends(get_current_user),
) -> Response:
    """CPU/RAM/disk-usage trend graphs (see `app.services.monitoring_history`
    for the downsampling) plus the services summary/modal trigger.
    `range_key` is one of `monitoring_history.TIME_RANGES`'s keys — an
    unrecognized value quietly falls back to the default rather than
    erroring, same tolerance `status_filter` on the Updates tab already has
    for a bad query param."""
    machine = await _get_machine_or_404(machine_id, db, current_user)

    range_key = monitoring_history.normalize_range_key(range_key)
    history, availability = await monitoring_history.load_machine_history(
        db, machine_id, range_key
    )

    # One unified "Last checked" timestamp for the whole tab, replacing a
    # separate one under each of the CPU/RAM/disk/services sample and the
    # Availability sample — they're usually the same instant ("Refresh
    # now" and the two periodic sweeps that back them both touch the same
    # machine together), but pick whichever is actually more recent rather
    # than assuming that.
    candidates = [
        ts for ts in (machine.monitoring_updated_at, availability.latest_checked_at) if ts
    ]
    last_checked_at = max(candidates) if candidates else None

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/monitoring.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "monitoring",
            "csrf_token": csrf_token,
            "history": history,
            "availability": availability,
            "last_checked_at": last_checked_at,
            "time_ranges": monitoring_history.TIME_RANGES,
            "range_key": range_key,
            "service_counts": await _get_service_counts(machine_id, db),
            "services": await _get_services(machine_id, db, svc_q="", svc_state=""),
            # A configured condition-based notification's own trigger
            # level, drawn as a reference line on the matching chart below
            # — see app.services.notifications.condition_thresholds_for_machine.
            "condition_thresholds": await condition_thresholds_for_machine(db, machine),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/monitoring/refresh", dependencies=[_manage, Depends(verify_csrf)])
async def refresh_machine_monitoring_endpoint(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Refresh now" for the Monitoring tab — forces a fresh monitoring
    sample, a fresh reachability check and a fresh systemd services
    snapshot right now, waits for all three, then
    redirects back to the (now up to date) tab, rather than
    waiting out either sweep's own interval. Same `action.manage`
    permission the sibling facts/packages/services refresh buttons use."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    monitoring_result = tasks.sample_machine_monitoring.delay(str(machine.id))
    reachability_result = tasks.check_machine_reachability_now.delay(str(machine.id))
    # The services table (with per-service CPU/memory) lives on this tab too.
    services_result = tasks.refresh_machine_services.delay(str(machine.id))
    error: str | None = None
    try:
        results = await asyncio.gather(
            asyncio.to_thread(
                monitoring_result.get, timeout=app_settings.ssh_connect_timeout + 30
            ),
            asyncio.to_thread(
                reachability_result.get, timeout=app_settings.ssh_connect_timeout + 15
            ),
            asyncio.to_thread(
                services_result.get, timeout=app_settings.ssh_connect_timeout + 15
            ),
        )
        for result in results:
            if isinstance(result, dict) and not result.get("ok"):
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = LocalizedText(request, "common.error.job_timeout")
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.monitoring.refresh",
        summary=f'Refreshed monitoring for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    return RedirectResponse(
        url=f"/machines/{machine.id}/monitoring?range_key={range_key}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


# --- Self-polling fragments -------------------------------------------------
#
# The Overview/Updates tabs poll these every 20-30s (see the `hx-trigger`
# attributes in detail.html/update_history.html and the templates below) so
# a periodic background sweep (reachability, facts, packages, update checks
# — all Celery Beat jobs the user never explicitly triggers) shows up on an
# already-open page without a manual reload. Each one is a plain DB read, no
# SSH round trip — cheap enough to poll on a timer, unlike the POST
# "refresh now" endpoints above/below, which do make one.


@router.get("/{machine_id}/status-panel")
async def machine_status_panel(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    return templates.TemplateResponse(request, "partials/machine_status.html", {"machine": machine})


@router.get("/{machine_id}/facts-panel")
async def machine_facts_panel(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/machine_facts.html",
        {"machine": machine, "error": None, "csrf_token": csrf_token},
    )


@router.get("/{machine_id}/packages-summary-panel")
async def machine_packages_summary_panel(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    return templates.TemplateResponse(
        request,
        "partials/_packages_summary_inner.html",
        {
            "machine": machine,
            "package_counts": await _get_package_counts(machine_id, db),
            "held_count": await _get_held_count(machine_id, db),
        },
    )


@router.get("/{machine_id}/packages")
async def machine_packages_panel(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    pkg_q: str = "",
    pkg_source: str = "",
    held_only: bool = False,
    current_user: User = Depends(get_current_user),
) -> Response:
    """The modal body for "Show installed packages" on the machine detail
    page — loaded on demand via htmx rather than embedded in that page's
    initial render. Also serves the filter form's own requests, which target
    just `#packages-panel` (not the whole modal) to stay open while filtering.
    """
    machine = await _get_machine_or_404(machine_id, db, current_user)
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


@router.get("/{machine_id}/services-summary-panel")
async def machine_services_summary_panel(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    return templates.TemplateResponse(
        request,
        "partials/_services_summary_inner.html",
        {"machine": machine, "service_counts": await _get_service_counts(machine_id, db)},
    )


@router.get("/{machine_id}/services")
async def machine_services_panel(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    svc_q: str = "",
    svc_state: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The modal body for "Show services" on the Monitoring tab — same
    lazily-loaded-on-open pattern as `machine_packages_panel`."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "partials/machine_services.html",
        {
            "machine": machine,
            "csrf_token": csrf_token,
            "services": await _get_services(machine_id, db, svc_q=svc_q, svc_state=svc_state),
            "service_counts": await _get_service_counts(machine_id, db),
            "svc_q": svc_q,
            "svc_state": svc_state,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{machine_id}/edit")
async def edit_machine_form(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/edit.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "settings",
            "auth_methods": list(AuthMethod),
            "groups": await _get_groups(db, current_user),
            "all_tags": await _get_all_tags(db),
            "errors": [],
            "csrf_token": csrf_token,
            "global_settings": get_settings(),
            "app_settings": await get_or_create_app_settings(db),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/run-onboarding", dependencies=[_manage, Depends(verify_csrf)])
async def run_onboarding_endpoint(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """See `app.ssh.onboarding` and `app.tasks.jobs._run_machine_onboarding`
    for what this actually runs. Blocks on the result (like "Test
    connection"/"Refresh facts" above) rather than polling: this is a
    single bounded SSH exec, not something a fleet-wide sweep repeats, and
    the machine's credential never leaves this process — the task resolves
    it itself from the DB, it is never passed as a task argument."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.run_machine_onboarding.delay(str(machine.id))
    error: str | None = None
    output: str | None = None
    try:
        # Comfortably above the task's own time_limit
        # (app.tasks.jobs._ONBOARDING_EXTRA_SECONDS + 15) so a real failure
        # inside the task — a bad password, a network hiccup — is what
        # this wait reports, not this endpoint giving up first.
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 120
        )
        if isinstance(result, dict):
            if result.get("ok"):
                output = str(result.get("output") or "")
            else:
                error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = LocalizedText(request, "machine.error.setup_timeout")
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.onboarding.run",
        summary=f'Ran initial setup on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    if error is None:
        # Confirm the setup actually took (ncurses-term, the sudoers
        # scope) rather than assuming success — fire-and-forget, the
        # banner on the Overview tab picks up the result on next load.
        tasks.check_machine_readiness.delay(str(machine.id))

    machine = await _get_machine_or_404(machine_id, db, current_user)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/edit.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "settings",
            "auth_methods": list(AuthMethod),
            "groups": await _get_groups(db, current_user),
            "all_tags": await _get_all_tags(db),
            "errors": [],
            "onboarding_error": error,
            "onboarding_output": output,
            "csrf_token": csrf_token,
            "global_settings": get_settings(),
            "app_settings": await get_or_create_app_settings(db),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/recheck-readiness", dependencies=[_manage, Depends(verify_csrf)])
async def recheck_readiness_endpoint(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The readiness banner's "Re-check" button — blocks on one SSH round
    trip, same "Test connection"-style pattern as the other on-demand
    checks on this page."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.check_machine_readiness.delay(str(machine.id))
    with contextlib.suppress(Exception):
        await asyncio.to_thread(async_result.get, timeout=app_settings.ssh_connect_timeout + 15)

    redirect_url = f"/machines/{machine.id}"
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post(
    "/{machine_id}/run-onboarding-with-credential", dependencies=[_manage, Depends(verify_csrf)]
)
async def run_onboarding_with_credential_endpoint(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The readiness banner's "Fix it" flow for a machine that's *already*
    onboarded (SSH_KEY auth, as the app's own "debcontrol" identity) but
    missing something outside that identity's own sudo scope (e.g.
    `dmidecode`, added as a requirement after this machine was first
    onboarded) — `run_machine_onboarding` needs a root-equivalent login to
    (re-)grant that, and the app no longer has one stored for an
    already-onboarded machine.

    Reuses the exact same task a fresh, never-onboarded machine's "Run
    initial setup" button does (`run_machine_onboarding`), by temporarily
    putting this machine into the same shape a password-auth machine is
    already in — `auth_method=PASSWORD` + the submitted one-time
    credential — so the task's own existing logic (connect, run the
    script, and on success switch back to `debcontrol`/SSH_KEY/no stored
    secret) handles the rest unchanged. **On failure, this endpoint itself
    restores the machine's previous username/auth method** rather than
    leaving a real root password sitting in `secret_encrypted` on a
    machine this app otherwise treats as SSH_KEY-only — the task's own
    success-path revert never gets a chance to run when the script fails.
    """
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    previous_username = machine.username
    previous_auth_method = machine.auth_method
    machine.username = username.strip()
    machine.auth_method = AuthMethod.PASSWORD
    machine.secret_encrypted = encrypt_secret(password)
    await db.commit()

    async_result = tasks.run_machine_onboarding.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 120
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = LocalizedText(request, "machine.error.setup_timeout")
    except Exception as exc:
        error = str(exc)

    if error is not None:
        # The task never reached its own success-path revert — restore
        # this machine to what it was before this one-time attempt rather
        # than leaving it on password auth with a real credential stored.
        machine = await _get_machine_or_404(machine_id, db, current_user)
        machine.username = previous_username
        machine.auth_method = previous_auth_method
        machine.secret_encrypted = None
        await db.commit()
    else:
        tasks.check_machine_readiness.delay(str(machine.id))

    await log_event(
        db,
        request=request,
        action="machine.onboarding.run_with_credential",
        summary=f'Ran initial setup (one-time credential) on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    machine = await _get_machine_or_404(machine_id, db, current_user)
    redirect_url = f"/machines/{machine.id}"
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post(
    "/{machine_id}/fix-readiness-directly", dependencies=[_manage, Depends(verify_csrf)]
)
async def fix_readiness_directly_endpoint(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The readiness banner's "Install now" button for a machine connected
    as root — installs `ncurses-term` with the credential already on file,
    no one-time root login needed (there is nothing to grant sudo for: see
    `app.ssh.readiness`'s module docstring). Only ever shown for
    `username == "root"` (`app/web/templates/machines/detail.html`), but
    not re-checked here — a machine reconfigured to a different username
    between page load and this click just gets its own real error back
    from the SSH connection, same as any other stale-page race."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.fix_root_readiness.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 60
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = LocalizedText(request, "machine.error.timeout_reload")
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.readiness.fix_directly",
        summary=f'Installed missing readiness packages directly on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    redirect_url = f"/machines/{machine.id}"
    if request.headers.get("HX-Request") == "true":
        return Response(status_code=status.HTTP_200_OK, headers={"HX-Redirect": redirect_url})
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


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
    runbook: str = Form(""),
    is_active: str = Form(""),
    reachability_check_interval_seconds: str = Form(""),
    facts_refresh_interval_seconds: str = Form(""),
    monitoring_interval_seconds: str = Form(""),
    monitoring_history_retention_days: str = Form(""),
    tags: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)

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
            runbook=runbook or None,
            # HTML only sends a checkbox field when it's checked.
            is_active=bool(is_active),
            reachability_check_interval_seconds=(
                int(reachability_check_interval_seconds)
                if reachability_check_interval_seconds.strip()
                else None
            ),
            facts_refresh_interval_seconds=(
                int(facts_refresh_interval_seconds)
                if facts_refresh_interval_seconds.strip()
                else None
            ),
            monitoring_interval_seconds=(
                int(monitoring_interval_seconds) if monitoring_interval_seconds.strip() else None
            ),
            monitoring_history_retention_days=(
                int(monitoring_history_retention_days)
                if monitoring_history_retention_days.strip()
                else None
            ),
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
                "tabs": _machine_tabs(request, machine, current_user),
                "active_tab": "settings",
                "auth_methods": list(AuthMethod),
                "groups": await _get_groups(db, current_user),
                "all_tags": await _get_all_tags(db),
                "errors": [str(exc)],
                "csrf_token": csrf_token,
                "global_settings": get_settings(),
                "app_settings": await get_or_create_app_settings(db),
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    # Same scope rule as creation: a restricted account can't move a machine
    # into a group (or out of every group) it can't see.
    if not await can_see_group_id(db, current_user, payload.group_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Pick a machine group your account has access to.",
        )

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
    machine.runbook = payload.runbook
    machine.is_active = payload.is_active
    machine.reachability_check_interval_seconds = payload.reachability_check_interval_seconds
    machine.facts_refresh_interval_seconds = payload.facts_refresh_interval_seconds
    machine.monitoring_interval_seconds = payload.monitoring_interval_seconds
    machine.monitoring_history_retention_days = payload.monitoring_history_retention_days

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
        machine.os_id = None
        machine.kernel_version = None
        machine.cpu_cores = None
        machine.cpu_model = None
        machine.ram_bytes = None
        machine.ram_speed_mhz = None
        machine.disks = None
        machine.facts_updated_at = None

    await set_machine_tags(db, machine, parse_tag_names_from_text(tags))
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
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)

    context: dict[str, object] = {"machine": machine, "csrf_token": csrf_token}
    try:
        context["fingerprint"] = await discover_host_key_fingerprint(
            machine.ip_address, machine.port, app_settings.ssh_connect_timeout
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
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
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
    # Same idea for the readiness check — surfaces a banner on the Overview
    # tab if this machine (freshly onboarded through this app, or hand-
    # configured) is actually missing something this app's other features
    # depend on (see app.ssh.readiness).
    tasks.check_machine_readiness.delay(str(machine.id))

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
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.test_machine_connection.delay(str(machine.id))
    result: dict[str, object] | None = None
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 5
        )
    except CeleryTimeoutError:
        error = LocalizedText(request, "common.error.job_timeout")
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
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.refresh_machine_facts.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 5
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = LocalizedText(request, "common.error.job_timeout")
    except Exception as exc:
        error = str(exc)

    if error is None:
        # Facts were updated in the DB by the job — reload to pick them up.
        machine = await _get_machine_or_404(machine_id, db, current_user)

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
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.refresh_machine_packages.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = LocalizedText(request, "common.error.job_timeout")
    except Exception as exc:
        error = str(exc)

    if error is None:
        # Packages were updated in the DB by the job — reload to pick them up.
        machine = await _get_machine_or_404(machine_id, db, current_user)

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


@router.post("/{machine_id}/refresh-services", dependencies=[_manage, Depends(verify_csrf)])
async def refresh_services_endpoint(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    svc_q: str = Form(""),
    svc_state: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.refresh_machine_services.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = LocalizedText(request, "common.error.job_timeout")
    except Exception as exc:
        error = str(exc)

    if error is None:
        machine = await _get_machine_or_404(machine_id, db, current_user)

    await log_event(
        db,
        request=request,
        action="machine.services.refresh",
        summary=f'Refreshed services for "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )

    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/machine_services.html",
        {
            "machine": machine,
            "error": error,
            "csrf_token": csrf_token,
            "services": await _get_services(machine_id, db, svc_q=svc_q, svc_state=svc_state),
            "service_counts": await _get_service_counts(machine_id, db),
            "svc_q": svc_q,
            "svc_state": svc_state,
        },
    )


@router.post("/{machine_id}/check-updates", dependencies=[_updates, Depends(verify_csrf)])
async def check_updates_endpoint(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    async_result = tasks.check_machine_updates.delay(str(machine.id))
    error: str | None = None
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.update_timeout_seconds + 5
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = LocalizedText(request, "common.error.job_timeout")
    except Exception as exc:
        error = str(exc)

    # Counts were updated in the DB by the job (even on failure, they're
    # reset to "unknown" rather than left stale) — reload either way.
    machine = await _get_machine_or_404(machine_id, db, current_user)

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
    current_user: User = Depends(get_current_user),
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
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before previewing updates.",
        )

    app_settings = await get_or_create_app_settings(db)
    async_result = tasks.preview_machine_update.delay(str(machine.id), strategy.value)
    error: str | None = None
    to_install_or_upgrade: list[PendingPackage] = []
    to_remove: list[PendingPackage] = []
    try:
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.update_timeout_seconds + 5
        )
        if isinstance(result, dict):
            if not result.get("ok"):
                error = str(result.get("error") or "Unknown error.")
            else:
                to_install_or_upgrade = list(result.get("to_install_or_upgrade") or [])
                to_remove = list(result.get("to_remove") or [])
    except TimeoutError:
        error = LocalizedText(request, "common.error.job_timeout")
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
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
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


@router.post(
    "/{machine_id}/updates/{run_id}/rollback", dependencies=[_updates, Depends(verify_csrf)]
)
async def rollback_machine_update_endpoint(
    request: Request,
    machine_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Re-install exactly the package versions `run_id` snapshotted right
    before it ran, for whatever's since changed — see
    `app.tasks.jobs._rollback_machine_update`. Same `action.updates`
    permission as running an update itself (not a separate one — undoing
    an update isn't a higher trust level than running one), and creates a
    brand new `MachineUpdateRun` row rather than mutating the source run,
    so both stay in the history exactly as they happened."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    source_run = await _get_update_run_or_404(run_id, db)
    if source_run.machine_id != machine.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    if source_run.status != UpdateRunStatus.SUCCEEDED or not source_run.package_snapshot:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This update run has no captured package snapshot to roll back to.",
        )
    if source_run.rollback_of_run_id is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Can't roll back a rollback."
        )

    rollback_run = MachineUpdateRun(
        machine_id=machine.id, strategy=source_run.strategy, rollback_of_run_id=source_run.id
    )
    db.add(rollback_run)
    await db.commit()
    await db.refresh(rollback_run)

    tasks.rollback_machine_update.delay(str(rollback_run.id))

    await log_event(
        db,
        request=request,
        action="machine.updates.rollback",
        summary=f'Triggered rollback of update run {source_run.id} on "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"source_run_id": str(source_run.id), "rollback_run_id": str(rollback_run.id)},
    )

    return RedirectResponse(
        url=f"/machines/{machine.id}/updates/{rollback_run.id}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/{machine_id}/updates")
async def machine_update_history(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    status_filter: str = "",
    page: int = 1,
    current_user: User = Depends(get_current_user),
) -> Response:
    """Every update run for this machine, newest first, paginated the same
    way `/audit` is (offset/limit, one extra row fetched to know whether an
    "Older" page exists) — the machine detail page's "Recent runs" table
    only ever shows the last 5; this is the full history behind it."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
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

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/update_history.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "updates",
            "csrf_token": csrf_token,
            "runs": runs,
            "statuses": list(UpdateRunStatus),
            "status_filter": status_filter,
            "page": page,
            "has_older": has_older,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/{machine_id}/update-availability-panel")
async def machine_update_availability_panel(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """See the module-level comment above `machine_status_panel` — this is
    the Updates tab's equivalent, polled by `partials/update_availability.html`."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    csrf_token, _ = get_or_create_csrf_token(request)
    return templates.TemplateResponse(
        request,
        "partials/_update_availability_inner.html",
        {"machine": machine, "error": None, "csrf_token": csrf_token},
    )


@router.get("/{machine_id}/updates/{run_id}")
async def machine_update_run_detail(
    request: Request,
    machine_id: uuid.UUID,
    run_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
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
    current_user: User = Depends(get_current_user),
) -> Response:
    """Pollable fragment (htmx `hx-trigger="every ...s"`) showing one run's
    status/output. Once the run reaches a terminal state, the fragment stops
    including the polling attributes, so htmx naturally stops re-fetching it.
    """
    # Resolve the machine through the scoped helper first — this fragment
    # would otherwise expose an out-of-scope machine's update output to
    # anyone who could guess the pair of ids.
    await _get_machine_or_404(machine_id, db, current_user)
    run = await _get_update_run_or_404(run_id, db)
    if run.machine_id != machine_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found.")
    return templates.TemplateResponse(request, "partials/update_run_status.html", {"run": run})


@router.get("/{machine_id}/terminal", dependencies=[_terminal])
async def terminal_page(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The interactive web terminal's page shell — the actual byte relay
    happens over the WebSocket in `app/web/routes/terminal_ws.py`, which
    (since `app.auth.middleware` never runs for WebSocket requests) does its
    own independent session/permission check rather than relying on this
    page having already been reached. Gated behind `ACTION_TERMINAL` — see
    that permission's comment in `app/db/models/role.py` for why it's its
    own dedicated permission rather than folded into an existing one."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before opening a terminal.",
        )
    return templates.TemplateResponse(
        request,
        "machines/terminal.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "terminal",
        },
    )


@router.get("/{machine_id}/logs", dependencies=[_terminal])
async def machine_logs(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    path: str = "",
    lines: int = ssh_logs.DEFAULT_LINE_LIMIT,
    search: str = "",
    since: str = "",
    until: str = "",
    source: str = "",
    container: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The Logs tab — journal by default, one allowed file when `path` is
    given, or one Docker container's `docker logs` when `source=docker`
    (the container picked from the latest monitoring sample's list,
    `Machine.docker_containers`). A live SSH round trip on every load/filter change, same
    "gated behind `action.terminal`, not `machine.view`" reasoning
    `app.ssh.logs`'s module docstring lays out; see that module for the
    command-building and path-restriction logic itself. Audited (which
    machine, journal-vs-file, search term) the same way "Refresh packages
    now"/"Test connection" are — not the returned log content itself,
    which is never stored anywhere in this app."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    if source not in ("journal", "file", "docker"):
        source = "file" if path.strip() else "journal"
    docker_containers = machine.docker_containers or []
    if source == "docker" and not container and docker_containers:
        running = [c for c in docker_containers if c.get("state") == "running"]
        container = str((running or docker_containers)[0].get("name") or "")

    output: str | None = None
    error: str | None = None
    fetch = not (source == "file" and not path.strip()) and not (
        source == "docker" and not container
    )
    if not machine.host_key_fingerprint:
        error = LocalizedText(request, "machine.confirm_key_first_overview")
    elif fetch:
        clamped_lines = max(1, min(lines, ssh_logs.MAX_LINE_LIMIT))
        try:
            if source == "docker":
                async_result = tasks.view_machine_docker_logs.delay(
                    str(machine.id),
                    container=container,
                    lines=clamped_lines,
                    search=search,
                    since=since,
                    until=until,
                )
            elif source == "file":
                async_result = tasks.view_machine_log_file.delay(
                    str(machine.id), path=path.strip(), lines=clamped_lines, search=search
                )
            else:
                async_result = tasks.view_machine_journal.delay(
                    str(machine.id),
                    lines=clamped_lines,
                    search=search,
                    since=since,
                    until=until,
                )
            result = await asyncio.to_thread(
                async_result.get, timeout=app_settings.ssh_connect_timeout + 15
            )
            if isinstance(result, dict):
                if result.get("ok"):
                    output = str(result.get("output") or "")
                else:
                    error = str(result.get("error") or "Unknown error.")
        except CeleryTimeoutError:
            error = LocalizedText(request, "common.error.command_timeout")
        except Exception as exc:
            error = str(exc)

        await log_event(
            db,
            request=request,
            action="machine.logs.view",
            summary=(
                f'Viewed Docker logs of "{container}" on "{machine.name}"'
                if source == "docker"
                else f'Viewed log file "{path.strip()}" on "{machine.name}"'
                if source == "file"
                else f'Viewed journal on "{machine.name}"'
            ),
            outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
            details={"search": search} if search.strip() else None,
        )

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/logs.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "logs",
            "csrf_token": csrf_token,
            "output": output,
            "log_lines": parse_log_lines(output, search),
            "error": error,
            "source": source,
            "container": container,
            "docker_containers": docker_containers,
            "path": path,
            "lines": lines,
            "search": search,
            "since": since,
            "until": until,
            "default_lines": ssh_logs.DEFAULT_LINE_LIMIT,
            "allowed_paths": get_settings().log_file_allowed_path_list,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


def _join_log_path(directory: str, name: str) -> str:
    return name if directory in ("", "/") else f"{directory.rstrip('/')}/{name}"


@router.get("/{machine_id}/logs/browse", dependencies=[_terminal])
async def machine_logs_browse(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    path: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The Logs tab's "browse" picker — lists what's directly inside an
    allowed directory so an operator can navigate to a file rather than
    already knowing its exact path. Starts at the first configured
    `LOG_FILE_ALLOWED_PATHS` prefix when no `path` is given. Same live SSH
    round trip / `action.terminal` gate as the rest of the Logs tab; see
    `app.ssh.logs`'s module docstring."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)
    allowed_paths = get_settings().log_file_allowed_path_list
    current_path = path.strip() or (allowed_paths[0] if allowed_paths else "")

    entries: list[dict[str, object]] = []
    error: str | None = None
    if not machine.host_key_fingerprint:
        error = LocalizedText(request, "machine.confirm_key_first_overview")
    elif not current_path:
        error = LocalizedText(request, "machine.error.no_log_paths")
    else:
        try:
            async_result = tasks.browse_machine_log_directory.delay(
                str(machine.id), path=current_path
            )
            result = await asyncio.to_thread(
                async_result.get, timeout=app_settings.ssh_connect_timeout + 15
            )
            if isinstance(result, dict):
                if result.get("ok"):
                    raw_entries = result.get("entries") or []
                    entries = sorted(
                        (
                            {
                                "name": e["name"],
                                "is_dir": e["is_dir"],
                                "path": _join_log_path(current_path, e["name"]),
                            }
                            for e in raw_entries
                        ),
                        key=lambda e: (not e["is_dir"], str(e["name"]).lower()),
                    )
                else:
                    error = str(result.get("error") or "Unknown error.")
        except CeleryTimeoutError:
            error = LocalizedText(request, "common.error.command_timeout")
        except Exception as exc:
            error = str(exc)

    # Never offer a parent link above whichever allowed root contains
    # `current_path` — that would just error out server-side anyway (see
    # `app.ssh.logs.is_path_allowed`), but there's no reason to dangle a
    # link that can only fail.
    parent_path: str | None = None
    matched_root = next(
        (
            root
            for root in allowed_paths
            if current_path == root or current_path.startswith(f"{root}/")
        ),
        None,
    )
    if matched_root and current_path != matched_root:
        candidate = current_path.rstrip("/").rsplit("/", 1)[0] or "/"
        parent_path = candidate if len(candidate) >= len(matched_root) else matched_root

    if current_path:
        await log_event(
            db,
            request=request,
            action="machine.logs.browse",
            summary=f'Browsed "{current_path}" on "{machine.name}"',
            outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )

    return templates.TemplateResponse(
        request,
        "machines/logs_browse.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "logs",
            "current_path": current_path,
            "parent_path": parent_path,
            "entries": entries,
            "error": error,
            "allowed_paths": allowed_paths,
        },
    )


@router.post("/{machine_id}/docker/check-images", dependencies=[_manage, Depends(verify_csrf)])
async def check_image_updates_endpoint(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Check for image updates now" on the container table — the same
    registry-digest comparison the daily sweep runs, on demand."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)

    error: str | None = None
    try:
        async_result = tasks.check_machine_image_updates.delay(str(machine.id))
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 150
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = LocalizedText(request, "common.error.check_timeout")
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action="machine.docker.check_images",
        summary=f'Checked Docker image updates on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"error": error} if error else None,
    )
    query = {"images_checked": "1"}
    if error is not None:
        query["images_error"] = sign_flash(error)
    return RedirectResponse(
        url=f"/machines/{machine.id}/monitoring?{urlencode(query)}#containers",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post(
    "/{machine_id}/containers/{container}/{action}",
    dependencies=[_power, Depends(verify_csrf)],
)
async def container_action_endpoint(
    request: Request,
    machine_id: uuid.UUID,
    container: str,
    action: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Start/stop/restart one Docker container from the Monitoring tab's
    container table. Same `action.power` permission as reboot/shutdown —
    stopping a service's container is the same kind of disruptive action.
    Waits for docker's own answer, then redirects back with the outcome."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if action not in CONTAINER_ACTIONS or not is_container_name_valid(container):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request.")
    app_settings = await get_or_create_app_settings(db)

    error: str | None = None
    try:
        async_result = tasks.run_container_action_task.delay(
            str(machine.id), action=action, container=container
        )
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 90
        )
        if isinstance(result, dict) and not result.get("ok"):
            error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        error = LocalizedText(request, "common.error.command_timeout")
    except Exception as exc:
        error = str(exc)

    await log_event(
        db,
        request=request,
        action=f"machine.container.{action}",
        summary=f'Container "{container}" {action} on "{machine.name}"',
        outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"container": container, **({"error": error} if error else {})},
    )

    query = {"container": sign_flash(container), "container_action": action}
    if error is not None:
        query["container_error"] = sign_flash(error)
    return RedirectResponse(
        url=f"/machines/{machine.id}/monitoring?{urlencode(query)}#containers",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/{machine_id}/power")
async def power_tab(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The old "Power" tab's URL — reboot/shut down moved to Overview (see
    `machine_detail`), so this just redirects there instead of 404ing on
    whatever still links or is bookmarked here."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    query = f"?{request.url.query}" if request.url.query else ""
    return RedirectResponse(
        url=f"/machines/{machine.id}{query}", status_code=status.HTTP_301_MOVED_PERMANENTLY
    )


@router.get("/{machine_id}/power/{action}")
async def power_confirm_form(
    request: Request,
    machine_id: uuid.UUID,
    action: PowerAction,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """First confirmation step: a dedicated page stating exactly what's
    about to happen. The second step — typing the machine's name — is
    enforced server-side in `power_action`, not just disabled-until-typed
    in the browser."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
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
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)

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
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
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
