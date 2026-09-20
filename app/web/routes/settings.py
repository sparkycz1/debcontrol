"""Settings — the app's SSH identity (General), background-check
intervals/timeouts/concurrency and every retention policy (Checks &
retention), the audit log's own hash-chain verification (Security), and
the LDAP/OIDC/syslog/SMTP login and integration configuration
(Integrations) — see `app/db/models/app_settings.py` for why all of this
is Settings-page config rather than environment variables.
"""

from __future__ import annotations

import asyncio
import uuid

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.base import AiProviderError
from app.ai.config import (
    get_or_create_ai_provider_configs,
    get_selectable_models,
    replace_fetched_models,
)
from app.ai.providers import build_client
from app.audit import log_event, verify_chain
from app.auth.dependencies import require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import encrypt_secret
from app.db.models.ai_model import AiModel
from app.db.models.ai_provider import AiProviderConfig, AiProviderKind
from app.db.models.app_settings import (
    DEFAULT_GEOIP_REFRESH_INTERVAL_HOURS,
    DEFAULT_LDAP_USER_SEARCH_FILTER,
    DEFAULT_OIDC_SCOPES,
    DEFAULT_OIDC_USERNAME_CLAIM,
    DEFAULT_SMTP_PORT,
    DEFAULT_SYSLOG_PORT,
    FleetSummaryFrequency,
    SmtpEncryption,
    SyslogProtocol,
)
from app.db.models.audit_log import AuditOutcome
from app.db.models.geoip_database import SINGLETON_ID as GEOIP_SINGLETON_ID
from app.db.models.geoip_database import GeoipDatabase
from app.db.models.machine import AuthMethod, Machine
from app.db.models.role import Permission
from app.db.session import get_db
from app.ssh.identity import (
    activate_pending_identity,
    discard_pending_identity,
    generate_pending_identity,
    get_or_create_identity,
)
from app.tasks.jobs import push_pending_ssh_key
from app.tasks.jobs import refresh_geoip_database as refresh_geoip_database_task
from app.web.templating import t, templates

router = APIRouter(
    prefix="/settings", dependencies=[Depends(require_permission(Permission.SETTINGS_VIEW))]
)
_manage = Depends(require_permission(Permission.SETTINGS_MANAGE))

# Settings grew to nine sections on one long page — split into tabs the same
# way a machine's/group's own pages are (see `partials/_tabnav.html` and
# `_machine_tabs`/`_group_tabs` in app/web/routes/machines.py/
# machine_groups.py), except there's only ever one GET route here rather
# than one per tab: every POST handler below redirects back to `/settings`
# regardless of which tab it belongs to, and giving each tab its own route
# would mean every one of those redirects needs to know which page it's
# redirecting *from* just to send you back to the right place. A `tab` query
# string param is simpler and gets the same result — every handler below
# just needs to know which tab *it itself* belongs to, to redirect back to
# `/settings?tab=<that tab>` instead of losing your place on every save.
_TAB_KEYS = ["general", "checks", "security", "integrations", "ai"]
_VALID_TABS = set(_TAB_KEYS)
_DEFAULT_TAB = "general"


def _tabs(request: Request) -> list[tuple[str, str, str]]:
    """The (key, label, url) tabs rendered by `partials/_tabnav.html` —
    labels resolved per-request so they follow the viewer's own locale, same
    as `_machine_tabs`/`_group_tabs` in app/web/routes/machines.py/
    machine_groups.py."""
    return [
        (key, t(request, f"settings.tab.{key}"), f"/settings?tab={key}") for key in _TAB_KEYS
    ]


def _normalize_tab(tab: str) -> str:
    """An unrecognized/missing `tab` value (a stale bookmark, a typo'd URL)
    falls back to the first tab rather than 404ing or rendering no tab's
    content at all."""
    return tab if tab in _VALID_TABS else _DEFAULT_TAB


async def _render_settings(
    request: Request,
    db: AsyncSession,
    errors: list[str],
    *,
    tab: str = _DEFAULT_TAB,
    **extra: object,
) -> Response:
    identity = await get_or_create_identity(db)
    app_settings = await get_or_create_app_settings(db)
    # Creates the five AI provider rows on first visit — same lazy
    # singleton-row idea as `get_or_create_app_settings` above.
    ai_configs = await get_or_create_ai_provider_configs(db)
    geoip_database = await db.get(GeoipDatabase, GEOIP_SINGLETON_ID)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    context: dict[str, object] = {
        "identity": identity,
        "settings": get_settings(),
        "app_settings": app_settings,
        "geoip_database": geoip_database,
        "csrf_token": csrf_token,
        "errors": errors,
        "syslog_protocols": list(SyslogProtocol),
        "smtp_encryptions": list(SmtpEncryption),
        # Ordered by the enum, so the panel always renders the same five
        # blocks in the same order.
        "ai_configs": [ai_configs[kind] for kind in AiProviderKind if kind in ai_configs],
        "openai_compatible_kind": AiProviderKind.OPENAI_COMPATIBLE.value,
        "selectable_models": await get_selectable_models(db),
        "tabs": _tabs(request),
        "active_tab": tab,
        **extra,
    }
    response = templates.TemplateResponse(request, "settings/index.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("")
async def show_settings(
    request: Request, db: AsyncSession = Depends(get_db), tab: str = _DEFAULT_TAB
) -> Response:
    return await _render_settings(request, db, [], tab=_normalize_tab(tab))


def _parse_retention_days(raw: str) -> tuple[int | None, str | None]:
    """Shared by `update_audit_retention` and
    `update_dashboard_trends_retention` below — both fields mean the same
    thing (empty = keep forever, otherwise a non-negative whole number of
    days). Returns `(days, error_message)`; exactly one is `None`."""
    stripped = raw.strip()
    if stripped == "":
        return None, None
    try:
        value = int(stripped)
        if value < 0:
            raise ValueError("must not be negative")
    except ValueError:
        return None, f'"{stripped}" isn\'t a whole number of days (0 or more).'
    return value, None


def _parse_bounded_int(
    raw: str, *, label: str, minimum: int, maximum: int
) -> tuple[int | None, str | None]:
    """Shared by `update_background_checks` below — every field there is a
    whole number of seconds (or machines) with a sane range, unlike the
    retention fields above (which allow an empty "forever"). Returns
    `(value, error_message)`; exactly one is `None`."""
    stripped = raw.strip()
    try:
        value = int(stripped)
    except ValueError:
        return None, f'"{stripped}" isn\'t a whole number for {label}.'
    if not (minimum <= value <= maximum):
        return None, f"{label} must be between {minimum} and {maximum}."
    return value, None


@router.post("/background-checks", dependencies=[_manage, Depends(verify_csrf)])
async def update_background_checks(
    request: Request,
    db: AsyncSession = Depends(get_db),
    ssh_connect_timeout: str = Form(""),
    update_timeout_seconds: str = Form(""),
    reachability_check_interval_seconds: str = Form(""),
    facts_refresh_interval_seconds: str = Form(""),
    monitoring_interval_seconds: str = Form(""),
    reachability_check_concurrency: str = Form(""),
    notification_condition_check_interval_seconds: str = Form(""),
) -> Response:
    """The SSH connect/update-run timeouts, every background-check
    interval, and the reachability sweep's concurrency cap — moved here
    from environment variables (see `app/db/models/app_settings.py`'s new
    fields and `app.core.config`'s module docstring).

    The two timeouts and the concurrency cap are read fresh from the
    database by every task that uses them (see `app/tasks/jobs.py`), so a
    change here takes effect on the very next check — no restart needed.
    The three intervals are only read by Celery Beat at its own process
    start (`app.tasks.celery_app`), so a change to one of those needs a
    restart of the worker/beat services, same as when they were `.env`
    values — see `settings.checks.background_checks_hint` in the template.

    Bounds below exist for two reasons: a sane range for the setting
    itself, and — for the two timeouts specifically — staying safely under
    Celery's own hard per-task time limit (`app.tasks.jobs.
    _SSH_TASK_TIME_LIMIT_SECONDS`/`_UPDATE_TASK_TIME_LIMIT_SECONDS`), which
    is a fixed constant sized to comfortably exceed these maximums and is
    not itself configurable (a Celery task decorator argument can't read
    the database — see that module's own comment).
    """
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []

    def _field(raw: str, *, label: str, minimum: int, maximum: int) -> int | None:
        value, error = _parse_bounded_int(raw, label=label, minimum=minimum, maximum=maximum)
        if error:
            errors.append(error)
        return value

    ssh_timeout = _field(ssh_connect_timeout, label="SSH connect timeout", minimum=1, maximum=300)
    update_timeout = _field(
        update_timeout_seconds, label="Update run timeout", minimum=60, maximum=14400
    )
    reachability_interval = _field(
        reachability_check_interval_seconds,
        label="Reachability check interval",
        minimum=5,
        maximum=86400,
    )
    facts_interval = _field(
        facts_refresh_interval_seconds, label="Facts refresh interval", minimum=60, maximum=604800
    )
    monitoring_interval = _field(
        monitoring_interval_seconds, label="Monitoring sample interval", minimum=10, maximum=86400
    )
    concurrency = _field(
        reachability_check_concurrency,
        label="Reachability sweep concurrency",
        minimum=1,
        maximum=1000,
    )
    condition_check_interval = _field(
        notification_condition_check_interval_seconds,
        label="Condition-based notification check interval",
        minimum=10,
        maximum=86400,
    )

    if errors:
        return await _render_settings(request, db, errors, tab="checks")

    assert ssh_timeout is not None
    assert update_timeout is not None
    assert reachability_interval is not None
    assert facts_interval is not None
    assert monitoring_interval is not None
    assert concurrency is not None
    assert condition_check_interval is not None

    app_settings.ssh_connect_timeout = ssh_timeout
    app_settings.update_timeout_seconds = update_timeout
    app_settings.reachability_check_interval_seconds = reachability_interval
    app_settings.facts_refresh_interval_seconds = facts_interval
    app_settings.monitoring_interval_seconds = monitoring_interval
    app_settings.reachability_check_concurrency = concurrency
    app_settings.notification_condition_check_interval_seconds = condition_check_interval
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.background_checks.update",
        summary="Updated background-check settings",
        details={
            "ssh_connect_timeout": ssh_timeout,
            "update_timeout_seconds": update_timeout,
            "reachability_check_interval_seconds": reachability_interval,
            "facts_refresh_interval_seconds": facts_interval,
            "monitoring_interval_seconds": monitoring_interval,
            "reachability_check_concurrency": concurrency,
            "notification_condition_check_interval_seconds": condition_check_interval,
        },
    )
    return RedirectResponse(url="/settings?tab=checks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/audit-retention", dependencies=[_manage, Depends(verify_csrf)])
async def update_audit_retention(
    request: Request,
    db: AsyncSession = Depends(get_db),
    retention_days: str = Form(""),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    new_value, error = _parse_retention_days(retention_days)
    if error:
        return await _render_settings(request, db, [error], tab="security")

    app_settings.audit_log_retention_days = new_value
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.audit_retention.update",
        summary=(
            f"Set audit log retention to {new_value} day(s)"
            if new_value is not None
            else "Set audit log retention to keep forever"
        ),
    )

    return RedirectResponse(url="/settings?tab=security", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/geoip", dependencies=[_manage, Depends(verify_csrf)])
async def update_geoip_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    geoip_enabled: str = Form(""),
    geoip_primary_url: str = Form(""),
    # Blank = keep the existing URL unchanged — same convention as
    # oidc_client_secret/ldap_bind_password above, since a MaxMind
    # "permalink" download URL embeds a license key.
    geoip_backup_url: str = Form(""),
    geoip_refresh_interval_hours: str = Form(str(DEFAULT_GEOIP_REFRESH_INTERVAL_HOURS)),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []

    try:
        refresh_interval = int(geoip_refresh_interval_hours)
        if not (1 <= refresh_interval <= 24 * 30):
            raise ValueError
    except ValueError:
        errors.append("Refresh interval must be a whole number of hours between 1 and 720.")
        refresh_interval = app_settings.geoip_refresh_interval_hours

    primary_url = geoip_primary_url.strip()
    if bool(geoip_enabled) and not primary_url and not app_settings.geoip_primary_url_encrypted:
        errors.append("Enabling GeoIP needs at least a primary database URL.")

    if errors:
        return await _render_settings(request, db, errors, tab="integrations")

    app_settings.geoip_enabled = bool(geoip_enabled)
    if primary_url:
        app_settings.geoip_primary_url_encrypted = encrypt_secret(primary_url)
    backup_url = geoip_backup_url.strip()
    if backup_url:
        app_settings.geoip_backup_url_encrypted = encrypt_secret(backup_url)
    app_settings.geoip_refresh_interval_hours = refresh_interval
    await db.commit()

    enabled_label = "enabled" if app_settings.geoip_enabled else "disabled"
    await log_event(
        db,
        request=request,
        action="settings.geoip.update",
        summary=f"Updated GeoIP settings ({enabled_label})",
    )
    return RedirectResponse(url="/settings?tab=integrations", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/geoip/download", dependencies=[_manage, Depends(verify_csrf)])
async def download_geoip_database_now(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    if not app_settings.geoip_primary_url_encrypted:
        return await _render_settings(
            request, db, ["No GeoIP database URL is configured yet."], tab="integrations"
        )

    async_result = refresh_geoip_database_task.delay(force=True)
    try:
        await asyncio.to_thread(async_result.get, timeout=_PUSH_WAIT_SECONDS)
    except CeleryTimeoutError:
        return await _render_settings(
            request,
            db,
            ["The download is still running in the background — check back in a moment."],
            tab="integrations",
        )
    except Exception as exc:
        return await _render_settings(
            request, db, [f"GeoIP download failed: {exc}"], tab="integrations"
        )

    await log_event(
        db,
        request=request,
        action="settings.geoip.download_now",
        summary="Manually triggered a GeoIP database download",
    )
    return RedirectResponse(url="/settings?tab=integrations", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/dashboard-trends-retention", dependencies=[_manage, Depends(verify_csrf)])
async def update_dashboard_trends_retention(
    request: Request,
    db: AsyncSession = Depends(get_db),
    retention_days: str = Form(""),
) -> Response:
    """Same shape as `update_audit_retention` above, for the daily fleet
    snapshots behind the Dashboard's trend chart(s) — see
    `app.db.models.fleet_snapshot.FleetSnapshot` and
    `app.tasks.jobs.purge_old_fleet_snapshots`."""
    app_settings = await get_or_create_app_settings(db)
    new_value, error = _parse_retention_days(retention_days)
    if error:
        return await _render_settings(request, db, [error], tab="checks")

    app_settings.dashboard_trends_retention_days = new_value
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.dashboard_trends_retention.update",
        summary=(
            f"Set dashboard trends retention to {new_value} day(s)"
            if new_value is not None
            else "Set dashboard trends retention to keep forever"
        ),
    )

    return RedirectResponse(url="/settings?tab=checks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/update-run-retention", dependencies=[_manage, Depends(verify_csrf)])
async def update_machine_update_run_retention(
    request: Request,
    db: AsyncSession = Depends(get_db),
    retention_days: str = Form(""),
) -> Response:
    """Same shape as `update_audit_retention`/`update_dashboard_trends_retention`
    above, for the stored `MachineUpdateRun` rows (apt/flatpak/snap output
    per run) — see `app.tasks.jobs.purge_old_machine_update_runs`."""
    app_settings = await get_or_create_app_settings(db)
    new_value, error = _parse_retention_days(retention_days)
    if error:
        return await _render_settings(request, db, [error], tab="checks")

    app_settings.machine_update_run_retention_days = new_value
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.machine_update_run_retention.update",
        summary=(
            f"Set update run history retention to {new_value} day(s)"
            if new_value is not None
            else "Set update run history retention to keep forever"
        ),
    )

    return RedirectResponse(url="/settings?tab=checks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/notification-log-retention", dependencies=[_manage, Depends(verify_csrf)])
async def update_notification_log_retention(
    request: Request,
    db: AsyncSession = Depends(get_db),
    retention_days: str = Form(""),
) -> Response:
    """Same shape as `update_audit_retention`/`update_dashboard_trends_retention`
    above, for `NotificationLog` rows (delivery history — one row per
    actual send attempt) — see `app.tasks.jobs.purge_old_notification_logs`."""
    app_settings = await get_or_create_app_settings(db)
    new_value, error = _parse_retention_days(retention_days)
    if error:
        return await _render_settings(request, db, [error], tab="checks")

    app_settings.notification_log_retention_days = new_value
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.notification_log_retention.update",
        summary=(
            f"Set notification log retention to {new_value} day(s)"
            if new_value is not None
            else "Set notification log retention to keep forever"
        ),
    )

    return RedirectResponse(url="/settings?tab=checks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/monitoring-retention", dependencies=[_manage, Depends(verify_csrf)])
async def update_monitoring_retention(
    request: Request,
    db: AsyncSession = Depends(get_db),
    retention_days: str = Form(""),
) -> Response:
    """Same shape as `update_audit_retention`/`update_dashboard_trends_retention`
    above, for `MachineMonitoringSample` rows — see `app.tasks.jobs.
    purge_old_monitoring_samples`. This is the *instance-wide* default; a
    machine can override it (see `Machine.monitoring_history_retention_days`
    on that machine's own Settings tab)."""
    app_settings = await get_or_create_app_settings(db)
    new_value, error = _parse_retention_days(retention_days)
    if error:
        return await _render_settings(request, db, [error], tab="checks")

    app_settings.monitoring_history_retention_days = new_value
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.monitoring_retention.update",
        summary=(
            f"Set monitoring history retention to {new_value} day(s)"
            if new_value is not None
            else "Set monitoring history retention to keep forever"
        ),
    )

    return RedirectResponse(url="/settings?tab=checks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/monitoring-downsampling", dependencies=[_manage, Depends(verify_csrf)])
async def update_monitoring_downsampling(
    request: Request,
    db: AsyncSession = Depends(get_db),
    after_days: str = Form(""),
    interval_minutes: str = Form(""),
) -> Response:
    """`AppSettings.monitoring_downsample_after_days`/`_interval_minutes` —
    see `app.tasks.jobs.downsample_old_monitoring_samples`'s own docstring
    for what this actually does (thin, not purge). `after_days` follows the
    same "empty = disabled" shape as the retention fields above;
    `interval_minutes` is a bounded interval like the background-check
    fields, not a retention window."""
    app_settings = await get_or_create_app_settings(db)
    new_after_days, error = _parse_retention_days(after_days)
    if error:
        return await _render_settings(request, db, [error], tab="checks")

    new_interval, interval_error = _parse_bounded_int(
        interval_minutes, label="Downsample bucket interval", minimum=1, maximum=1440
    )
    if interval_error:
        return await _render_settings(request, db, [interval_error], tab="checks")
    assert new_interval is not None

    app_settings.monitoring_downsample_after_days = new_after_days
    app_settings.monitoring_downsample_interval_minutes = new_interval
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.monitoring_downsampling.update",
        summary=(
            f"Set monitoring downsampling to start after {new_after_days} day(s), "
            f"{new_interval}-minute buckets"
            if new_after_days is not None
            else "Disabled monitoring downsampling"
        ),
    )

    return RedirectResponse(url="/settings?tab=checks", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/audit-verify", dependencies=[_manage, Depends(verify_csrf)])
async def verify_audit_chain(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    """Recompute the audit log's hash chain on demand — see
    `app.audit.verify_chain`. Result isn't stored anywhere; it's only ever
    the answer to "is the trail intact right now."""
    result = await verify_chain(db)
    await log_event(
        db,
        request=request,
        action="audit_log.verify",
        summary=f"Verified audit log hash chain: {result.message}",
        outcome=AuditOutcome.SUCCESS if result.ok else AuditOutcome.FAILURE,
        details={"checked": result.checked, "broken_at_sequence": result.broken_at_sequence},
    )
    return await _render_settings(request, db, [], tab="security", verify_result=result)


@router.post("/ssh-key/generate", dependencies=[_manage, Depends(verify_csrf)])
async def generate_ssh_key(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    identity = await generate_pending_identity(db)
    await log_event(
        db,
        request=request,
        action="settings.ssh_key.generate",
        summary=f"Generated a replacement SSH key ({identity.pending_fingerprint})",
    )
    return RedirectResponse(url="/settings?tab=general", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ssh-key/activate", dependencies=[_manage, Depends(verify_csrf)])
async def activate_ssh_key(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    try:
        identity = await activate_pending_identity(db)
    except ValueError:
        return await _render_settings(
            request, db, ["No pending SSH key to activate."], tab="general"
        )
    await log_event(
        db,
        request=request,
        action="settings.ssh_key.activate",
        summary=f"Activated new SSH key ({identity.fingerprint})",
    )
    return RedirectResponse(url="/settings?tab=general", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ssh-key/discard", dependencies=[_manage, Depends(verify_csrf)])
async def discard_ssh_key(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    await discard_pending_identity(db)
    await log_event(
        db,
        request=request,
        action="settings.ssh_key.discard",
        summary="Discarded the pending (not-yet-activated) SSH key",
    )
    return RedirectResponse(url="/settings?tab=general", status_code=status.HTTP_303_SEE_OTHER)


# How long the web request waits for one machine's push to finish. All
# machines are dispatched first and awaited concurrently (asyncio.gather),
# same reasoning as app.web.routes.ai's _run_command_and_summarize — a
# large fleet fans out in parallel instead of one slow/unreachable machine
# stacking its timeout onto every machine after it.
_PUSH_WAIT_SECONDS = 60


@router.post("/ssh-key/push", dependencies=[_manage, Depends(verify_csrf)])
async def push_ssh_key(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    """Assisted alternative to copying the pending public key onto every
    machine by hand: run the append-to-authorized_keys command over SSH,
    using each machine's *currently active* credential, on every
    `AuthMethod.SSH_KEY` machine with a pinned host key. A `PASSWORD`-auth
    machine never uses the app's shared identity, so it's not a candidate
    and isn't counted as skipped or failed — it's simply not in scope.

    This never touches the active key or activates anything — it only adds
    the new public key line alongside the current one, exactly like the
    manual instructions above it on this page. "Activate new key" is still
    a separate, deliberate click.
    """
    identity = await get_or_create_identity(db)
    if identity.pending_public_key is None:
        return await _render_settings(request, db, ["No pending SSH key to push."], tab="general")

    result = await db.execute(
        select(Machine).where(
            Machine.auth_method == AuthMethod.SSH_KEY,
            Machine.host_key_fingerprint.is_not(None),
        )
    )
    machines = list(result.scalars().all())
    if not machines:
        return await _render_settings(
            request,
            db,
            ["No machines use the app's shared SSH key with a pinned host key yet."],
            tab="general",
        )

    dispatched = [(machine, push_pending_ssh_key.delay(str(machine.id))) for machine in machines]

    async def _await_one(machine: Machine, async_result: object) -> tuple[str, str | None]:
        try:
            outcome = await asyncio.to_thread(async_result.get, timeout=_PUSH_WAIT_SECONDS)  # type: ignore[attr-defined]
        except CeleryTimeoutError:
            return machine.name, "Timed out."
        except Exception as exc:
            return machine.name, str(exc)
        if isinstance(outcome, dict) and outcome.get("ok"):
            return machine.name, None
        reason = str(outcome.get("error")) if isinstance(outcome, dict) else "Unknown error."
        return machine.name, reason

    outcomes = await asyncio.gather(
        *(_await_one(machine, async_result) for machine, async_result in dispatched)
    )
    failed = [(name, reason) for name, reason in outcomes if reason is not None]
    succeeded_count = len(outcomes) - len(failed)

    await log_event(
        db,
        request=request,
        action="settings.ssh_key.push",
        summary=f"Pushed pending SSH key to {succeeded_count}/{len(outcomes)} machine(s)",
        outcome=AuditOutcome.FAILURE if failed else AuditOutcome.SUCCESS,
        details={
            "fingerprint": identity.pending_fingerprint,
            "succeeded": [name for name, reason in outcomes if reason is None],
            "failed": dict(failed),
        },
    )

    errors = [f"{name}: {reason}" for name, reason in failed]
    return await _render_settings(
        request,
        db,
        errors,
        tab="general",
        push_result={"succeeded": succeeded_count, "total": len(outcomes)},
    )


@router.post("/ldap", dependencies=[_manage, Depends(verify_csrf)])
async def update_ldap_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    ldap_enabled: str = Form(""),
    ldap_server_uri: str = Form(""),
    ldap_use_starttls: str = Form(""),
    ldap_tls_verify: str = Form(""),
    ldap_bind_dn: str = Form(""),
    # Blank = keep the existing bind password unchanged — same convention as
    # Machine.secret_encrypted (app/schemas/machine.py).
    ldap_bind_password: str = Form(""),
    ldap_user_search_base: str = Form(""),
    ldap_user_search_filter: str = Form(""),
    ldap_connect_timeout_seconds: str = Form("5"),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []

    server_uri = ldap_server_uri.strip()
    if server_uri and not (server_uri.startswith(("ldap://", "ldaps://"))):
        errors.append('Server URI must start with "ldap://" or "ldaps://".')

    try:
        timeout = int(ldap_connect_timeout_seconds.strip() or "5")
        if timeout <= 0:
            raise ValueError
    except ValueError:
        errors.append("Connect timeout must be a positive whole number of seconds.")
        timeout = app_settings.ldap_connect_timeout_seconds

    search_filter = ldap_user_search_filter.strip() or DEFAULT_LDAP_USER_SEARCH_FILTER
    if "{username}" not in search_filter:
        errors.append('Search filter must contain "{username}".')

    if bool(ldap_enabled) and not (
        server_uri and ldap_bind_dn.strip() and ldap_user_search_base.strip()
    ):
        errors.append("Enabling LDAP needs at least a server URI, bind DN, and search base.")

    if errors:
        return await _render_settings(request, db, errors, tab="integrations")

    app_settings.ldap_enabled = bool(ldap_enabled)
    app_settings.ldap_server_uri = server_uri or None
    app_settings.ldap_use_starttls = bool(ldap_use_starttls)
    app_settings.ldap_tls_verify = bool(ldap_tls_verify)
    app_settings.ldap_bind_dn = ldap_bind_dn.strip() or None
    if ldap_bind_password:
        app_settings.ldap_bind_password_encrypted = encrypt_secret(ldap_bind_password)
    app_settings.ldap_user_search_base = ldap_user_search_base.strip() or None
    app_settings.ldap_user_search_filter = search_filter
    app_settings.ldap_connect_timeout_seconds = timeout
    await db.commit()

    summary = f"Updated LDAP settings ({'enabled' if app_settings.ldap_enabled else 'disabled'})"
    if not app_settings.ldap_tls_verify:
        summary += " — certificate verification is OFF"
    await log_event(db, request=request, action="settings.ldap.update", summary=summary)
    return RedirectResponse(url="/settings?tab=integrations", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/oidc", dependencies=[_manage, Depends(verify_csrf)])
async def update_oidc_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    oidc_enabled: str = Form(""),
    oidc_provider_name: str = Form(""),
    oidc_issuer_url: str = Form(""),
    oidc_client_id: str = Form(""),
    # Blank = keep the existing client secret unchanged.
    oidc_client_secret: str = Form(""),
    oidc_username_claim: str = Form(""),
    oidc_scopes: str = Form(""),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []

    issuer_url = oidc_issuer_url.strip()
    if issuer_url and not (issuer_url.startswith(("http://", "https://"))):
        errors.append('Issuer URL must start with "http://" or "https://".')

    claim = oidc_username_claim.strip() or DEFAULT_OIDC_USERNAME_CLAIM
    scopes = oidc_scopes.strip() or DEFAULT_OIDC_SCOPES
    if "openid" not in scopes.split():
        errors.append('Scopes must include "openid".')

    if bool(oidc_enabled) and not (issuer_url and oidc_client_id.strip()):
        errors.append("Enabling OIDC needs at least an issuer URL and client ID.")

    if errors:
        return await _render_settings(request, db, errors, tab="integrations")

    app_settings.oidc_enabled = bool(oidc_enabled)
    app_settings.oidc_provider_name = oidc_provider_name.strip() or None
    app_settings.oidc_issuer_url = issuer_url or None
    app_settings.oidc_client_id = oidc_client_id.strip() or None
    if oidc_client_secret:
        app_settings.oidc_client_secret_encrypted = encrypt_secret(oidc_client_secret)
    app_settings.oidc_username_claim = claim
    app_settings.oidc_scopes = scopes
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.oidc.update",
        summary=f"Updated OIDC settings ({'enabled' if app_settings.oidc_enabled else 'disabled'})",
    )
    return RedirectResponse(url="/settings?tab=integrations", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/syslog", dependencies=[_manage, Depends(verify_csrf)])
async def update_syslog_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    syslog_enabled: str = Form(""),
    syslog_host: str = Form(""),
    syslog_port: str = Form(str(DEFAULT_SYSLOG_PORT)),
    syslog_protocol: str = Form(SyslogProtocol.UDP.value),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []

    host = syslog_host.strip()
    try:
        protocol = SyslogProtocol(syslog_protocol)
    except ValueError:
        errors.append("Unknown syslog protocol.")
        protocol = app_settings.syslog_protocol

    try:
        port = int(syslog_port.strip() or str(DEFAULT_SYSLOG_PORT))
        if not (0 < port <= 65535):
            raise ValueError
    except ValueError:
        errors.append("Port must be a whole number between 1 and 65535.")
        port = app_settings.syslog_port

    if bool(syslog_enabled) and not host:
        errors.append("Enabling syslog forwarding needs a server host/IP.")

    if errors:
        return await _render_settings(request, db, errors, tab="integrations")

    app_settings.syslog_enabled = bool(syslog_enabled)
    app_settings.syslog_host = host or None
    app_settings.syslog_port = port
    app_settings.syslog_protocol = protocol
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.syslog.update",
        summary=(
            f"Updated syslog forwarding settings "
            f"({'enabled, ' + protocol.value if app_settings.syslog_enabled else 'disabled'})"
        ),
    )
    return RedirectResponse(url="/settings?tab=integrations", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/smtp", dependencies=[_manage, Depends(verify_csrf)])
async def update_smtp_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    smtp_enabled: str = Form(""),
    smtp_host: str = Form(""),
    smtp_port: str = Form(str(DEFAULT_SMTP_PORT)),
    smtp_encryption: str = Form(SmtpEncryption.STARTTLS.value),
    smtp_username: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from_address: str = Form(""),
    smtp_from_name: str = Form(""),
) -> Response:
    """Configuration only, for now — nothing sends an email through this
    yet (see `AppSettings.smtp_*`'s own comment). Same write-only-secret
    convention as LDAP/OIDC above: a blank password field keeps the stored
    value."""
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []

    host = smtp_host.strip()
    try:
        encryption = SmtpEncryption(smtp_encryption)
    except ValueError:
        errors.append("Unknown SMTP encryption mode.")
        encryption = app_settings.smtp_encryption

    try:
        port = int(smtp_port.strip() or str(DEFAULT_SMTP_PORT))
        if not (0 < port <= 65535):
            raise ValueError
    except ValueError:
        errors.append("Port must be a whole number between 1 and 65535.")
        port = app_settings.smtp_port

    from_address = smtp_from_address.strip()
    if from_address and "@" not in from_address:
        errors.append('"From" address must be a valid email address.')

    if bool(smtp_enabled) and not host:
        errors.append("Enabling the SMTP relay needs a server host/IP.")

    if errors:
        return await _render_settings(request, db, errors, tab="integrations")

    app_settings.smtp_enabled = bool(smtp_enabled)
    app_settings.smtp_host = host or None
    app_settings.smtp_port = port
    app_settings.smtp_encryption = encryption
    app_settings.smtp_username = smtp_username.strip() or None
    if smtp_password:
        app_settings.smtp_password_encrypted = encrypt_secret(smtp_password)
    app_settings.smtp_from_address = from_address or None
    app_settings.smtp_from_name = smtp_from_name.strip() or None
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.smtp.update",
        summary=(
            f"Updated SMTP relay settings "
            f"({'enabled, ' + encryption.value if app_settings.smtp_enabled else 'disabled'})"
        ),
    )
    return RedirectResponse(url="/settings?tab=integrations", status_code=status.HTTP_303_SEE_OTHER)


# --- AI assistant (app/ai/) --------------------------------------------------
#
# Everything below is web-UI-only and `settings.manage`-gated, like LDAP/OIDC.
# The API key is write-only from the browser's point of view: a blank field
# means "keep the stored value", and the stored value is never sent back to
# the page in any form — only the fact that one exists.


async def _get_provider_config(db: AsyncSession, kind_value: str) -> AiProviderConfig | None:
    try:
        kind = AiProviderKind(kind_value)
    except ValueError:
        return None
    configs = await get_or_create_ai_provider_configs(db)
    return configs.get(kind)


@router.post("/ai/provider", dependencies=[_manage, Depends(verify_csrf)])
async def update_ai_provider(
    request: Request,
    db: AsyncSession = Depends(get_db),
    kind: str = Form(""),
    enabled: str = Form(""),
    # Blank = keep the existing API key unchanged, same convention as
    # `oidc_client_secret` / `ldap_bind_password`.
    api_key: str = Form(""),
    base_url: str = Form(""),
) -> Response:
    config = await _get_provider_config(db, kind)
    if config is None:
        return await _render_settings(
            request, db, [f'Unknown AI provider "{kind}".'], tab="ai"
        )

    errors: list[str] = []
    url = base_url.strip()
    if config.kind == AiProviderKind.OPENAI_COMPATIBLE:
        if url and not (url.startswith(("http://", "https://"))):
            errors.append('The base URL must start with "http://" or "https://".')
        if bool(enabled) and not url:
            errors.append("Enabling an OpenAI-compatible provider needs a base URL.")
    if bool(enabled) and not api_key and config.api_key_encrypted is None:
        # OpenRouter can list models without a key, but a chat turn always
        # needs one — so enabling any provider requires one to be stored.
        errors.append("Enabling a provider needs an API key.")

    if errors:
        return await _render_settings(request, db, errors, tab="ai")

    config.enabled = bool(enabled)
    if api_key:
        config.api_key_encrypted = encrypt_secret(api_key)
    if config.kind == AiProviderKind.OPENAI_COMPATIBLE:
        config.base_url = url or None
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.ai_provider.update",
        summary=(
            f"Updated AI provider {config.kind.value} "
            f"({'enabled' if config.enabled else 'disabled'})"
        ),
        # Deliberately no key material, not even a length or a prefix.
        details={"provider": config.kind.value, "enabled": config.enabled},
    )
    return RedirectResponse(url="/settings?tab=ai", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ai/fetch-models", dependencies=[_manage, Depends(verify_csrf)])
async def fetch_ai_models(
    request: Request,
    db: AsyncSession = Depends(get_db),
    kind: str = Form(""),
) -> Response:
    """Call the provider's list-models endpoint synchronously.

    Not a Celery task, unlike the chat turn: this is an admin-only action on
    an admin-only page that makes exactly one HTTP request with a 15-second
    timeout. Blocking the request for that is fine, and pushing it through
    the queue would only add a round trip and a result-polling dance for no
    benefit.
    """
    config = await _get_provider_config(db, kind)
    if config is None:
        return await _render_settings(
            request, db, [f'Unknown AI provider "{kind}".'], tab="ai"
        )

    try:
        client = build_client(config)
        models = await client.list_models()
    except AiProviderError as exc:
        await log_event(
            db,
            request=request,
            action="settings.ai_provider.fetch_models",
            summary=f"Failed to fetch models for AI provider {config.kind.value}",
            outcome=AuditOutcome.FAILURE,
            details={"provider": config.kind.value, "error": str(exc)},
        )
        return await _render_settings(request, db, [str(exc)], tab="ai")

    kept, removed = await replace_fetched_models(db, config, models)
    await log_event(
        db,
        request=request,
        action="settings.ai_provider.fetch_models",
        summary=f"Fetched {kept} model(s) for AI provider {config.kind.value}",
        details={"provider": config.kind.value, "fetched": kept, "removed": removed},
    )
    return RedirectResponse(url="/settings?tab=ai", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ai/models", dependencies=[_manage, Depends(verify_csrf)])
async def update_ai_models(
    request: Request,
    db: AsyncSession = Depends(get_db),
    kind: str = Form(""),
) -> Response:
    """Set exactly which of a provider's fetched models may be chosen for a
    chat conversation. Read straight from the raw form rather than a typed
    parameter because the field is a repeated checkbox name, and an
    all-unticked submission sends it zero times."""
    config = await _get_provider_config(db, kind)
    if config is None:
        return await _render_settings(
            request, db, [f'Unknown AI provider "{kind}".'], tab="ai"
        )

    form = await request.form()
    selected = {str(value) for value in form.getlist("enabled_models")}

    result = await db.execute(select(AiModel).where(AiModel.provider_id == config.id))
    for model in result.scalars().all():
        model.enabled = model.model_id in selected
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.ai_models.update",
        summary=f"Enabled {len(selected)} model(s) for chat on AI provider {config.kind.value}",
        details={"provider": config.kind.value, "enabled_models": sorted(selected)},
    )
    return RedirectResponse(url="/settings?tab=ai", status_code=status.HTTP_303_SEE_OTHER)


def _parse_optional_limit(raw: str, label: str, errors: list[str]) -> int | None:
    value = raw.strip()
    if value == "":
        return None
    try:
        parsed = int(value)
    except ValueError:
        errors.append(f'The {label} limit "{value}" isn\'t a whole number of tokens.')
        return None
    if parsed < 0:
        errors.append(f"The {label} limit must not be negative.")
        return None
    return parsed


@router.post("/ai-limits", dependencies=[_manage, Depends(verify_csrf)])
async def update_ai_limits(
    request: Request,
    db: AsyncSession = Depends(get_db),
    ai_daily_token_limit: str = Form(""),
    ai_weekly_token_limit: str = Form(""),
    ai_monthly_token_limit: str = Form(""),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    errors: list[str] = []
    daily = _parse_optional_limit(ai_daily_token_limit, "daily", errors)
    weekly = _parse_optional_limit(ai_weekly_token_limit, "weekly", errors)
    monthly = _parse_optional_limit(ai_monthly_token_limit, "monthly", errors)
    if errors:
        return await _render_settings(request, db, errors, tab="ai")

    app_settings.ai_daily_token_limit = daily
    app_settings.ai_weekly_token_limit = weekly
    app_settings.ai_monthly_token_limit = monthly
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.ai_limits.update",
        summary="Updated the AI token limits",
        details={"daily": daily, "weekly": weekly, "monthly": monthly},
    )
    return RedirectResponse(url="/settings?tab=ai", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/fleet-summary", dependencies=[_manage, Depends(verify_csrf)])
async def update_fleet_summary_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    frequency: str = Form("disabled"),
    provider_model: str = Form(""),
) -> Response:
    """The scheduled fleet summary's opt-in switch and which model pays for
    it — see `app.tasks.ai_jobs.generate_fleet_summary`. Setting `frequency`
    back to "disabled" deliberately leaves `provider_model` untouched
    (re-enabling later remembers the last choice) rather than clearing it."""
    try:
        parsed_frequency = FleetSummaryFrequency(frequency)
    except ValueError:
        return await _render_settings(
            request, db, [f'"{frequency}" is not a valid frequency.'], tab="ai"
        )

    app_settings = await get_or_create_app_settings(db)

    if parsed_frequency != FleetSummaryFrequency.DISABLED:
        raw = provider_model.strip()
        provider_id_str, _, model_id = raw.partition(":")
        try:
            provider_id = uuid.UUID(provider_id_str)
        except ValueError:
            return await _render_settings(
                request, db, ["Choose a model for the fleet summary first."], tab="ai"
            )
        # Re-check that this provider+model really is enabled — never trust
        # the submitted pair just because the dropdown offered something.
        result = await db.execute(
            select(AiModel, AiProviderConfig)
            .join(AiProviderConfig, AiProviderConfig.id == AiModel.provider_id)
            .where(
                AiModel.provider_id == provider_id,
                AiModel.model_id == model_id,
                AiModel.enabled,
                AiProviderConfig.enabled,
            )
        )
        if result.first() is None:
            return await _render_settings(
                request, db, ["That AI model isn't enabled for use."], tab="ai"
            )
        app_settings.fleet_summary_provider_id = provider_id
        app_settings.fleet_summary_model_id = model_id

    app_settings.fleet_summary_frequency = parsed_frequency
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.fleet_summary.update",
        summary=f"Set the scheduled fleet summary to {parsed_frequency.value}",
        details={
            "frequency": parsed_frequency.value,
            "model": app_settings.fleet_summary_model_id,
        },
    )
    return RedirectResponse(url="/settings?tab=ai", status_code=status.HTTP_303_SEE_OTHER)
