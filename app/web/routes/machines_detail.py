"""One machine: the Overview and its self-refreshing panels, editing,
onboarding and readiness, host key pinning, connection test, facts/packages/
services refresh, History and notes, Proxmox, Docker, power actions, delete,
and acknowledging a problem."""

from __future__ import annotations

import asyncio
import contextlib
import re
import uuid
from datetime import UTC, datetime
from urllib.parse import urlencode

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import encrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import AuthMethod
from app.db.models.machine_note import MAX_NOTE_LENGTH
from app.db.models.machine_package import MachinePackage
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.machine import MachineUpdate
from app.services import acknowledgements, machine_timeline
from app.services.access_scope import (
    can_see_group_id,
)
from app.services.machine_notes import EmptyNoteError, add_note, delete_note
from app.services.machine_tags import (
    parse_tag_names_from_text,
    set_machine_tags,
)
from app.services.maintenance_windows import active_window_for
from app.ssh import proxmox
from app.ssh.client import discover_host_key_fingerprint
from app.ssh.containers import CONTAINER_ACTIONS
from app.ssh.exceptions import SSHConnectionError
from app.ssh.logs import is_container_name_valid
from app.ssh.packages import PackageSource
from app.ssh.power import PowerAction
from app.tasks import jobs as tasks
from app.web.flash import sign_flash
from app.web.messages import LocalizedText
from app.web.routes.machines_common import (
    _get_all_tags,
    _get_groups,
    _get_machine_or_404,
    _get_service_counts,
    _get_services,
    _machine_tabs,
    machines_router,
    need_manage,
    need_power,
)
from app.web.templating import t, templates

router = machines_router()


# Fingerprint shaped like "SHA256:<base64...>", as returned by AsyncSSH/OpenSSH.
_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9]+:[A-Za-z0-9+/=_-]+$")


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


@router.post("/{machine_id}/run-onboarding", dependencies=[need_manage, Depends(verify_csrf)])
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


@router.post("/{machine_id}/recheck-readiness", dependencies=[need_manage, Depends(verify_csrf)])
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
    "/{machine_id}/run-onboarding-with-credential", dependencies=[need_manage, Depends(verify_csrf)]
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
    "/{machine_id}/fix-readiness-directly", dependencies=[need_manage, Depends(verify_csrf)]
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


@router.post("/{machine_id}/edit", dependencies=[need_manage, Depends(verify_csrf)])
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


@router.post("/{machine_id}/discover-host-key", dependencies=[need_manage, Depends(verify_csrf)])
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


@router.post("/{machine_id}/trust-host-key", dependencies=[need_manage, Depends(verify_csrf)])
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


@router.post("/{machine_id}/test-connection", dependencies=[need_manage, Depends(verify_csrf)])
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


@router.post("/{machine_id}/refresh-facts", dependencies=[need_manage, Depends(verify_csrf)])
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


@router.post("/{machine_id}/refresh-packages", dependencies=[need_manage, Depends(verify_csrf)])
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


@router.post("/{machine_id}/refresh-services", dependencies=[need_manage, Depends(verify_csrf)])
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


@router.get("/{machine_id}/proxmox")
async def machine_proxmox(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The Proxmox tab — VMs and containers with their state, ZFS pools,
    storages (Proxmox Backup Server included) and backups, from the latest
    monitoring sample and facts refresh (`app.ssh.proxmox`). A machine with
    none of that redirects to its Overview."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not machine.has_proxmox_tab:
        return RedirectResponse(
            url=f"/machines/{machine.id}", status_code=status.HTTP_303_SEE_OTHER
        )
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    running, total = proxmox.guest_counts(machine.pve_guests)
    response = templates.TemplateResponse(
        request,
        "machines/proxmox.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "proxmox",
            "csrf_token": csrf_token,
            "guests_running": running,
            "guests_total": total,
            "unhealthy_pools": proxmox.unhealthy_pools(machine.zfs_pools),
            "last_backup": proxmox.last_backup(machine.pve_backups),
            "can_power": current_user.has_permission(Permission.ACTION_POWER),
            "now_epoch": int(datetime.now(UTC).timestamp()),
            "stale_seconds": proxmox.STALE_BACKUP_SECONDS,
            "queue_warn": proxmox.MAIL_QUEUE_WARN,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post(
    "/{machine_id}/proxmox/guests/{vmid}", dependencies=[need_power, Depends(verify_csrf)]
)
async def proxmox_guest_action(
    request: Request,
    machine_id: uuid.UUID,
    vmid: int,
    db: AsyncSession = Depends(get_db),
    action: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Start / shut down / reboot / stop one VM or container on a Proxmox
    VE host — same permission as the machine's own power actions, audited
    as `machine.guest.<action>`."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)
    guest = proxmox.find_guest(machine.pve_guests, vmid)
    error: str | None = None
    if action not in proxmox.GUEST_ACTIONS or guest is None:
        error = t(request, "proxmox.guest_action_invalid")
    else:
        try:
            result = await asyncio.to_thread(
                tasks.run_proxmox_guest_action.delay(str(machine.id), vmid, action).get,
                timeout=app_settings.ssh_connect_timeout + 90,
            )
            if isinstance(result, dict) and not result.get("ok"):
                error = str(result.get("error") or "Unknown error.")
        except CeleryTimeoutError:
            error = str(LocalizedText(request, "common.error.command_timeout"))
        except Exception as exc:
            error = str(exc)
        label = f"{vmid} ({guest.get('name')})" if guest.get("name") else str(vmid)
        await log_event(
            db,
            request=request,
            action=f"machine.guest.{action}",
            summary=f'Guest {label} {action} on "{machine.name}"',
            outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
            details={"vmid": vmid, **({"error": error} if error else {})},
        )
    if error is not None:
        query = f"guest_error={sign_flash(error)}"
    else:
        query = "guest_notice=" + sign_flash(
            t(
                request,
                "proxmox.guest_action_sent",
                vmid=vmid,
                action=t(request, f"proxmox.action.{action}"),
            )
        )
    return RedirectResponse(
        url=f"/machines/{machine.id}/proxmox?{query}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/{machine_id}/history")
async def machine_history(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    days: int = machine_timeline.DEFAULT_RANGE_DAYS,
    kind: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The History tab — notes, detected changes, update runs,
    reachability transitions and (with `audit.view`) audited actions on
    one time line; see `app.services.machine_timeline`."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    kind = kind if kind in machine_timeline.TIMELINE_KINDS else ""
    timeline = await machine_timeline.load_timeline(
        db,
        machine,
        days=days,
        include_audit=current_user.has_permission(Permission.AUDIT_VIEW),
        kinds={kind} if kind else None,
    )
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/history.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "history",
            "csrf_token": csrf_token,
            "timeline": timeline,
            "ranges": machine_timeline.TIMELINE_RANGES,
            "kinds": machine_timeline.TIMELINE_KINDS,
            "kind": kind,
            "note_error": request.query_params.get("note_error"),
            "max_note_length": MAX_NOTE_LENGTH,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/notes", dependencies=[need_manage, Depends(verify_csrf)])
async def add_machine_note(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    body: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    try:
        await add_note(db, request, machine, current_user, body)
    except EmptyNoteError:
        return RedirectResponse(
            url=f"/machines/{machine.id}/history?note_error=1",
            status_code=status.HTTP_303_SEE_OTHER,
        )
    return RedirectResponse(
        url=f"/machines/{machine.id}/history", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post(
    "/{machine_id}/notes/{note_id}/delete", dependencies=[need_manage, Depends(verify_csrf)]
)
async def delete_machine_note(
    request: Request,
    machine_id: uuid.UUID,
    note_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not await delete_note(db, request, machine, note_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found.")
    return RedirectResponse(
        url=f"/machines/{machine.id}/history", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/{machine_id}/docker/check-images", dependencies=[need_manage, Depends(verify_csrf)])
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
    dependencies=[need_power, Depends(verify_csrf)],
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


@router.post("/{machine_id}/power", dependencies=[need_power, Depends(verify_csrf)])
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


@router.post("/{machine_id}/delete", dependencies=[need_manage, Depends(verify_csrf)])
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


# --- Acknowledging a problem (app.services.acknowledgements) ---------------


@router.post("/{machine_id}/acknowledge", dependencies=[need_manage, Depends(verify_csrf)])
async def acknowledge_machine(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    duration: str = Form("until_recovered"),
    note: str = Form(""),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"I know about this one": withhold notifications about this machine
    until it recovers, the chosen time passes or someone clears it."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    try:
        hours = acknowledgements.hours_for(duration)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from None
    acknowledgements.acknowledge(machine, by=current_user.username, note=note, hours=hours)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machine.acknowledge",
        summary=f'Acknowledged a problem on "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"hours": hours, "note": machine.acknowledged_note},
    )
    return RedirectResponse(url=f"/machines/{machine.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{machine_id}/acknowledge/clear", dependencies=[need_manage, Depends(verify_csrf)])
async def clear_machine_acknowledgement(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    acknowledgements.clear(machine)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="machine.acknowledge.clear",
        summary=f'Cleared the acknowledgement on "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
    )
    return RedirectResponse(url=f"/machines/{machine.id}", status_code=status.HTTP_303_SEE_OTHER)
