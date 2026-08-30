"""Settings — the app's SSH identity, background-check intervals (both
read-only, sourced from the environment), the audit log retention policy,
and the LDAP/OIDC login configuration (see `app/db/models/app_settings.py`
for why these are Settings-page config rather than environment variables).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.base import AiProviderError
from app.ai.config import get_or_create_ai_provider_configs, replace_fetched_models
from app.ai.providers import build_client
from app.audit import log_event, verify_chain
from app.auth.dependencies import require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.core.security import encrypt_secret
from app.core.version import APP_VERSION, commit_url, get_git_commit
from app.db.models.ai_model import AiModel
from app.db.models.ai_provider import AiProviderConfig, AiProviderKind
from app.db.models.app_settings import (
    DEFAULT_LDAP_USER_SEARCH_FILTER,
    DEFAULT_OIDC_SCOPES,
    DEFAULT_OIDC_USERNAME_CLAIM,
    DEFAULT_SYSLOG_PORT,
    SyslogProtocol,
)
from app.db.models.audit_log import AuditOutcome
from app.db.models.role import Permission
from app.db.session import get_db
from app.ssh.identity import (
    activate_pending_identity,
    discard_pending_identity,
    generate_pending_identity,
    get_or_create_identity,
)
from app.web.templating import templates

router = APIRouter(
    prefix="/settings", dependencies=[Depends(require_permission(Permission.SETTINGS_VIEW))]
)
_manage = Depends(require_permission(Permission.SETTINGS_MANAGE))


async def _render_settings(
    request: Request, db: AsyncSession, errors: list[str], **extra: object
) -> Response:
    identity = await get_or_create_identity(db)
    app_settings = await get_or_create_app_settings(db)
    # Creates the five AI provider rows on first visit — same lazy
    # singleton-row idea as `get_or_create_app_settings` above.
    ai_configs = await get_or_create_ai_provider_configs(db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    git_commit = get_git_commit()
    context: dict[str, object] = {
        "identity": identity,
        "settings": get_settings(),
        "app_settings": app_settings,
        "csrf_token": csrf_token,
        "errors": errors,
        "app_version": APP_VERSION,
        "git_commit": git_commit,
        "commit_url": commit_url(git_commit) if git_commit else None,
        "syslog_protocols": list(SyslogProtocol),
        # Ordered by the enum, so the panel always renders the same five
        # blocks in the same order.
        "ai_configs": [ai_configs[kind] for kind in AiProviderKind if kind in ai_configs],
        "openai_compatible_kind": AiProviderKind.OPENAI_COMPATIBLE.value,
        **extra,
    }
    response = templates.TemplateResponse(request, "settings/index.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("")
async def show_settings(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    return await _render_settings(request, db, [])


@router.post("/audit-retention", dependencies=[_manage, Depends(verify_csrf)])
async def update_audit_retention(
    request: Request,
    db: AsyncSession = Depends(get_db),
    retention_days: str = Form(""),
) -> Response:
    app_settings = await get_or_create_app_settings(db)
    raw = retention_days.strip()

    if raw == "":
        new_value = None
    else:
        try:
            new_value = int(raw)
            if new_value < 0:
                raise ValueError("must not be negative")
        except ValueError:
            return await _render_settings(
                request, db, [f'"{raw}" isn\'t a whole number of days (0 or more).']
            )

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

    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


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
    raw = retention_days.strip()

    if raw == "":
        new_value = None
    else:
        try:
            new_value = int(raw)
            if new_value < 0:
                raise ValueError("must not be negative")
        except ValueError:
            return await _render_settings(
                request, db, [f'"{raw}" isn\'t a whole number of days (0 or more).']
            )

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

    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


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
    return await _render_settings(request, db, [], verify_result=result)


@router.post("/ssh-key/generate", dependencies=[_manage, Depends(verify_csrf)])
async def generate_ssh_key(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    identity = await generate_pending_identity(db)
    await log_event(
        db,
        request=request,
        action="settings.ssh_key.generate",
        summary=f"Generated a replacement SSH key ({identity.pending_fingerprint})",
    )
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ssh-key/activate", dependencies=[_manage, Depends(verify_csrf)])
async def activate_ssh_key(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    try:
        identity = await activate_pending_identity(db)
    except ValueError:
        return await _render_settings(request, db, ["No pending SSH key to activate."])
    await log_event(
        db,
        request=request,
        action="settings.ssh_key.activate",
        summary=f"Activated new SSH key ({identity.fingerprint})",
    )
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ssh-key/discard", dependencies=[_manage, Depends(verify_csrf)])
async def discard_ssh_key(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    await discard_pending_identity(db)
    await log_event(
        db,
        request=request,
        action="settings.ssh_key.discard",
        summary="Discarded the pending (not-yet-activated) SSH key",
    )
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/ldap", dependencies=[_manage, Depends(verify_csrf)])
async def update_ldap_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    ldap_enabled: str = Form(""),
    ldap_server_uri: str = Form(""),
    ldap_use_starttls: str = Form(""),
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
    if server_uri and not (server_uri.startswith("ldap://") or server_uri.startswith("ldaps://")):
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
        return await _render_settings(request, db, errors)

    app_settings.ldap_enabled = bool(ldap_enabled)
    app_settings.ldap_server_uri = server_uri or None
    app_settings.ldap_use_starttls = bool(ldap_use_starttls)
    app_settings.ldap_bind_dn = ldap_bind_dn.strip() or None
    if ldap_bind_password:
        app_settings.ldap_bind_password_encrypted = encrypt_secret(ldap_bind_password)
    app_settings.ldap_user_search_base = ldap_user_search_base.strip() or None
    app_settings.ldap_user_search_filter = search_filter
    app_settings.ldap_connect_timeout_seconds = timeout
    await db.commit()

    await log_event(
        db,
        request=request,
        action="settings.ldap.update",
        summary=f"Updated LDAP settings ({'enabled' if app_settings.ldap_enabled else 'disabled'})",
    )
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/oidc", dependencies=[_manage, Depends(verify_csrf)])
async def update_oidc_settings(
    request: Request,
    db: AsyncSession = Depends(get_db),
    oidc_enabled: str = Form(""),
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
    if issuer_url and not (issuer_url.startswith("http://") or issuer_url.startswith("https://")):
        errors.append('Issuer URL must start with "http://" or "https://".')

    claim = oidc_username_claim.strip() or DEFAULT_OIDC_USERNAME_CLAIM
    scopes = oidc_scopes.strip() or DEFAULT_OIDC_SCOPES
    if "openid" not in scopes.split():
        errors.append('Scopes must include "openid".')

    if bool(oidc_enabled) and not (issuer_url and oidc_client_id.strip()):
        errors.append("Enabling OIDC needs at least an issuer URL and client ID.")

    if errors:
        return await _render_settings(request, db, errors)

    app_settings.oidc_enabled = bool(oidc_enabled)
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
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


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
        return await _render_settings(request, db, errors)

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
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


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
        return await _render_settings(request, db, [f'Unknown AI provider "{kind}".'])

    errors: list[str] = []
    url = base_url.strip()
    if config.kind == AiProviderKind.OPENAI_COMPATIBLE:
        if url and not (url.startswith("http://") or url.startswith("https://")):
            errors.append('The base URL must start with "http://" or "https://".')
        if bool(enabled) and not url:
            errors.append("Enabling an OpenAI-compatible provider needs a base URL.")
    if bool(enabled) and not api_key and config.api_key_encrypted is None:
        # OpenRouter can list models without a key, but a chat turn always
        # needs one — so enabling any provider requires one to be stored.
        errors.append("Enabling a provider needs an API key.")

    if errors:
        return await _render_settings(request, db, errors)

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
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


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
        return await _render_settings(request, db, [f'Unknown AI provider "{kind}".'])

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
        return await _render_settings(request, db, [str(exc)])

    kept, removed = await replace_fetched_models(db, config, models)
    await log_event(
        db,
        request=request,
        action="settings.ai_provider.fetch_models",
        summary=f"Fetched {kept} model(s) for AI provider {config.kind.value}",
        details={"provider": config.kind.value, "fetched": kept, "removed": removed},
    )
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


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
        return await _render_settings(request, db, [f'Unknown AI provider "{kind}".'])

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
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)


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
        return await _render_settings(request, db, errors)

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
    return RedirectResponse(url="/settings", status_code=status.HTTP_303_SEE_OTHER)
