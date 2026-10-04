"""A machine's Monitoring tab — the charts over a chosen time window — and
its "Refresh now"."""

from __future__ import annotations

import asyncio
import uuid

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.user import User
from app.db.session import get_db
from app.services import monitoring_history
from app.services.notifications import condition_thresholds_for_machine
from app.tasks import jobs as tasks
from app.web.messages import LocalizedText
from app.web.routes.machines_common import (
    _get_machine_or_404,
    _get_service_counts,
    _get_services,
    _machine_tabs,
    machines_router,
    need_manage,
)
from app.web.templating import templates
from app.web.time_window import window_from_query, window_query

router = machines_router()


@router.get("/{machine_id}/monitoring")
async def machine_monitoring(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    start: str = "",
    end: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """CPU/RAM/disk-usage trend graphs (see `app.services.monitoring_history`
    for the downsampling) plus the services summary/modal trigger.
    `range_key` is one of `monitoring_history.TIME_RANGES`'s keys — an
    unrecognized value quietly falls back to the default rather than
    erroring, same tolerance `status_filter` on the Updates tab already has
    for a bad query param. `start` + `end` (the from-to boxes, or a drag
    across a chart) ask for a custom window instead."""
    machine = await _get_machine_or_404(machine_id, db, current_user)

    window = window_from_query(range_key, start, end)
    range_key = window.range_key
    history, availability = await monitoring_history.load_machine_history(
        db, machine_id, window
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
            "window": window,
            "window_query": window_query(window),
            "service_counts": await _get_service_counts(machine_id, db),
            "services": await _get_services(machine_id, db, svc_q="", svc_state=""),
            # A configured condition-based notification's own trigger
            # level, drawn as a reference line on the matching chart below
            # — see app.services.notifications.condition_thresholds_for_machine.
            "condition_thresholds": await condition_thresholds_for_machine(db, machine),
            # Shown next to the charts when the machine has no interval
            # override of its own, so the hint names an actual number.
            "app_settings": await get_or_create_app_settings(db),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/{machine_id}/monitoring/refresh", dependencies=[need_manage, Depends(verify_csrf)])
async def refresh_machine_monitoring_endpoint(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    range_key: str = monitoring_history.DEFAULT_TIME_RANGE,
    start: str = "",
    end: str = "",
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
        url=(
            f"/machines/{machine.id}/monitoring?"
            f"{window_query(window_from_query(range_key, start, end))}"
        ),
        status_code=status.HTTP_303_SEE_OTHER,
    )
