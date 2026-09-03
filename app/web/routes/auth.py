"""Login, logout, the TOTP second factor, OIDC login, and each user's own
"My account" page (password change, TOTP enrollment, recovery codes,
"log out everywhere").

Deliberately has no `APIRouter(prefix=...)` — its paths span the root
(`/login`, `/logout`), `/auth/oidc/...`, and `/account/...`, none of which
share a prefix worth factoring out.

See `app.auth.middleware` for why `/login`, `/login/totp`, `/logout`, and the
two `/auth/oidc/...` paths are reachable without a session at all, and
`app.auth.login` for the local/LDAP password check and TOTP verification
this calls into.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers import options_to_json

from app.audit import client_ip, log_event
from app.auth import totp as totp_module
from app.auth import webauthn as webauthn_module
from app.auth.api_tokens import create_api_token, revoke_api_token
from app.auth.dependencies import get_current_user
from app.auth.login import (
    check_password,
    consume_recovery_code,
    find_user_for_login,
    verify_totp_step,
)
from app.auth.oidc import OidcNotConfiguredError, handle_callback, redirect_to_provider
from app.auth.rate_limit import check_rate_limit
from app.auth.security import hash_password, verify_password
from app.auth.sessions import (
    PENDING_TOTP_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    WEBAUTHN_CHALLENGE_COOKIE_NAME,
    clear_pending_totp_cookie,
    clear_session_cookie,
    clear_webauthn_challenge_cookie,
    create_pending_totp_ticket,
    create_session,
    create_webauthn_challenge_ticket,
    get_valid_session,
    read_pending_totp_ticket,
    read_webauthn_challenge_ticket,
    revoke_all_sessions_for_user,
    revoke_session,
    set_pending_totp_cookie,
    set_session_cookie,
    set_webauthn_challenge_cookie,
)
from app.auth.webauthn import WebAuthnError
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import verify_csrf
from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.api_token import ApiToken
from app.db.models.app_settings import AppSettings
from app.db.models.audit_log import AuditOutcome
from app.db.models.totp_recovery_code import TotpRecoveryCode
from app.db.models.user import AuthProvider, User
from app.db.models.webauthn_credential import WebAuthnCredential
from app.db.session import get_db
from app.i18n import available_locales, get_locale
from app.schemas.user import MIN_PASSWORD_LENGTH
from app.web.templating import templates

router = APIRouter()

# High-limit-by-design per-source-IP caps — see app.auth.rate_limit's module
# docstring for why these exist alongside (not instead of) the per-account
# lockout in app.auth.login.
_LOGIN_RATE_LIMIT = 30
_TOTP_RATE_LIMIT = 30
_RATE_WINDOW_SECONDS = 300  # 5 minutes

_RATE_LIMIT_MESSAGE = "Too many attempts from your network — try again in a few minutes."

_OIDC_ERROR_MESSAGES = {
    "not_configured": "OIDC isn't fully configured — ask an administrator to finish setting it up.",
    "failed": (
        "The OIDC provider didn't complete the login (it may have been cancelled or timed out)."
    ),
    "no_account": (
        "No enabled debcontrol account matches your OIDC identity. "
        "Ask an administrator to check the account is set up for OIDC login."
    ),
}


async def _user_webauthn_credentials(
    db: AsyncSession, user_id: uuid.UUID
) -> list[WebAuthnCredential]:
    result = await db.execute(
        select(WebAuthnCredential)
        .where(WebAuthnCredential.user_id == user_id)
        .order_by(WebAuthnCredential.created_at)
    )
    return list(result.scalars().all())


def _safe_next(value: str | None) -> str:
    """Only ever follow a same-site, absolute path — never an attacker-
    supplied external URL (`?next=https://evil.example`, an open redirect)."""
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return "/"


def _render_login(
    request: Request,
    app_settings: AppSettings,
    *,
    next_url: str,
    error: str | None,
    oidc_error: str | None = None,
    username: str = "",
    status_code: int = status.HTTP_200_OK,
) -> Response:
    return templates.TemplateResponse(
        request,
        "auth/login.html",
        {
            "csrf_token": request.state.csrf_token,
            "next": next_url,
            "error": error,
            "oidc_error": oidc_error,
            "app_settings": app_settings,
            "form": {"username": username},
        },
        status_code=status_code,
    )


async def _finish_login(
    request: Request, db: AsyncSession, user: User, next_url: str, *, provider: str
) -> Response:
    user.last_login_at = datetime.now(UTC)
    await db.commit()
    _session, raw_token = await create_session(
        db, user, ip_address=client_ip(request), user_agent=request.headers.get("user-agent")
    )
    # An admin-set password (new account, or a reset) must be changed before
    # doing anything else — send them straight to where that happens instead
    # of wherever they were originally headed.
    if user.must_change_password:
        next_url = "/account"
    await log_event(
        db,
        request=request,
        action="user.login",
        summary=f'"{user.username}" logged in',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
        details={"provider": provider},
    )
    response = RedirectResponse(url=next_url, status_code=status.HTTP_303_SEE_OTHER)
    set_session_cookie(response, raw_token)
    clear_pending_totp_cookie(response)
    return response


@router.get("/login")
async def login_form(
    request: Request, db: AsyncSession = Depends(get_db), next: str = "", oidc_error: str = ""
) -> Response:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_token and await get_valid_session(db, raw_token) is not None:
        return RedirectResponse(url=_safe_next(next), status_code=status.HTTP_303_SEE_OTHER)
    app_settings = await get_or_create_app_settings(db)
    return _render_login(
        request,
        app_settings,
        next_url=_safe_next(next),
        error=None,
        oidc_error=_OIDC_ERROR_MESSAGES.get(oidc_error),
    )


async def _within_rate_limit(request: Request, *, bucket: str, limit: int) -> bool:
    redis = request.app.state.redis
    key = f"rate_limit:{bucket}:{client_ip(request) or 'unknown'}"
    return await check_rate_limit(redis, key, limit=limit, window_seconds=_RATE_WINDOW_SECONDS)


@router.post("/login", dependencies=[Depends(verify_csrf)])
async def login_submit(
    request: Request,
    db: AsyncSession = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
) -> Response:
    next_url = _safe_next(next)
    app_settings = await get_or_create_app_settings(db)

    if not await _within_rate_limit(request, bucket="login", limit=_LOGIN_RATE_LIMIT):
        await log_event(
            db,
            request=request,
            action="auth.rate_limited",
            summary=f'Blocked login attempt for "{username}": too many attempts from this network',
            outcome=AuditOutcome.DENIED,
        )
        return _render_login(
            request,
            app_settings,
            next_url=next_url,
            error=_RATE_LIMIT_MESSAGE,
            username=username,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    result = await check_password(db, app_settings, username, password)

    if result.reason == "provider_unavailable":
        await log_event(
            db,
            request=request,
            action="user.login",
            summary=f'Login attempt for "{username}" failed: the LDAP directory is unavailable',
            outcome=AuditOutcome.FAILURE,
        )
        return _render_login(
            request,
            app_settings,
            next_url=next_url,
            error="The directory server is currently unavailable — try again shortly.",
            username=username,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    if result.reason == "locked_out":
        assert result.user is not None
        await log_event(
            db,
            request=request,
            action="user.login",
            summary=f'Blocked login for "{result.user.username}": account temporarily locked',
            outcome=AuditOutcome.DENIED,
            target_type="user",
            target_id=result.user.id,
            target_label=result.user.username,
        )
        message = (
            f"Too many failed attempts — try again after {result.locked_until:%H:%M UTC}."
            if result.locked_until is not None
            else "Too many failed attempts — try again shortly."
        )
        return _render_login(
            request,
            app_settings,
            next_url=next_url,
            error=message,
            username=username,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    if not result.ok:
        target = result.user
        await log_event(
            db,
            request=request,
            action="user.login",
            summary=f'Failed login attempt for "{username}"',
            outcome=AuditOutcome.DENIED,
            target_type="user" if target else None,
            target_id=target.id if target else None,
            target_label=target.username if target else None,
        )
        return _render_login(
            request,
            app_settings,
            next_url=next_url,
            error="Invalid username or password.",
            username=username,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user = result.user
    assert user is not None
    has_webauthn = bool(await _user_webauthn_credentials(db, user.id))
    if user.totp_enabled or has_webauthn:
        ticket = create_pending_totp_ticket(user.id)
        response = RedirectResponse(
            url=f"/login/totp?next={quote(next_url, safe='')}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        set_pending_totp_cookie(response, ticket)
        return response

    return await _finish_login(request, db, user, next_url, provider=user.auth_provider.value)


async def _totp_challenge_context(
    request: Request, db: AsyncSession, user_id: uuid.UUID, *, next_url: str, error: str | None
) -> dict[str, object] | None:
    """Shared context for both the second-factor challenge page and its
    error re-renders — `None` if the pending user has vanished/been
    deactivated since the ticket was issued (caller redirects to /login)."""
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        return None
    credentials = await _user_webauthn_credentials(db, user_id)
    return {
        "csrf_token": request.state.csrf_token,
        "next": next_url,
        "error": error,
        # A user with TOTP enabled always gets the code form; one with only
        # passkeys (no TOTP) skips straight to "use a passkey" since there's
        # no code to type. Both true shows the code form plus a fallback link.
        "show_totp_form": user.totp_enabled,
        "has_webauthn": bool(credentials),
    }


@router.get("/login/totp")
async def totp_challenge_form(
    request: Request, db: AsyncSession = Depends(get_db), next: str = "/"
) -> Response:
    ticket = request.cookies.get(PENDING_TOTP_COOKIE_NAME)
    user_id = read_pending_totp_ticket(ticket) if ticket else None
    context = (
        await _totp_challenge_context(request, db, user_id, next_url=_safe_next(next), error=None)
        if user_id is not None
        else None
    )
    if context is None:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "auth/totp_challenge.html", context)


@router.post("/login/totp", dependencies=[Depends(verify_csrf)])
async def totp_challenge_submit(
    request: Request,
    db: AsyncSession = Depends(get_db),
    code: str = Form(...),
    next: str = Form("/"),
) -> Response:
    next_url = _safe_next(next)
    ticket = request.cookies.get(PENDING_TOTP_COOKIE_NAME)
    user_id = read_pending_totp_ticket(ticket) if ticket else None
    if user_id is None:
        response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        clear_pending_totp_cookie(response)
        return response

    user = await db.get(User, user_id)
    if user is None or not user.is_active or not user.totp_enabled:
        response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        clear_pending_totp_cookie(response)
        return response

    if not await _within_rate_limit(request, bucket="totp", limit=_TOTP_RATE_LIMIT):
        await log_event(
            db,
            request=request,
            action="auth.rate_limited",
            summary=f'Blocked TOTP attempt for "{user.username}": too many attempts from this IP',
            outcome=AuditOutcome.DENIED,
            target_type="user",
            target_id=user.id,
            target_label=user.username,
        )
        context = await _totp_challenge_context(
            request, db, user_id, next_url=next_url, error=_RATE_LIMIT_MESSAGE
        )
        assert context is not None
        return templates.TemplateResponse(
            request,
            "auth/totp_challenge.html",
            context,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    if user.is_locked_out:
        context = await _totp_challenge_context(
            request,
            db,
            user_id,
            next_url=next_url,
            error="Too many failed attempts — try again shortly.",
        )
        assert context is not None
        return templates.TemplateResponse(
            request,
            "auth/totp_challenge.html",
            context,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    if not await verify_totp_step(db, user, code):
        await log_event(
            db,
            request=request,
            action="user.login.totp",
            summary=f'Wrong TOTP/recovery code for "{user.username}"',
            outcome=AuditOutcome.DENIED,
            target_type="user",
            target_id=user.id,
            target_label=user.username,
        )
        context = await _totp_challenge_context(
            request, db, user_id, next_url=next_url, error="Invalid code."
        )
        assert context is not None
        return templates.TemplateResponse(
            request,
            "auth/totp_challenge.html",
            context,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    return await _finish_login(
        request, db, user, next_url, provider=f"{user.auth_provider.value}+totp"
    )


@router.get("/login/webauthn/options")
async def login_webauthn_options(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    """Called by `webauthn.js` right before `navigator.credentials.get()` —
    same pending-2FA ticket as the TOTP challenge, so this only ever hands
    out an authentication challenge for the account that already passed
    step one (password/LDAP)."""
    ticket = request.cookies.get(PENDING_TOTP_COOKIE_NAME)
    user_id = read_pending_totp_ticket(ticket) if ticket else None
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Your login session has expired — start over.",
        )
    user = await db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Your login session has expired — start over.",
        )
    credentials = await _user_webauthn_credentials(db, user_id)
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No passkeys are registered for this account.",
        )
    options, challenge = webauthn_module.generate_authentication(request, credentials=credentials)
    response = Response(content=options_to_json(options), media_type="application/json")
    challenge_ticket = create_webauthn_challenge_ticket(
        user_id=user_id, challenge=challenge, purpose="authenticate"
    )
    set_webauthn_challenge_cookie(response, challenge_ticket)
    return response


@router.post("/login/webauthn/verify", dependencies=[Depends(verify_csrf)])
async def login_webauthn_verify(
    request: Request,
    db: AsyncSession = Depends(get_db),
    credential: str = Form(...),
    next: str = Form("/"),
) -> Response:
    next_url = _safe_next(next)
    pending_ticket = request.cookies.get(PENDING_TOTP_COOKIE_NAME)
    challenge_ticket = request.cookies.get(WEBAUTHN_CHALLENGE_COOKIE_NAME)
    pending_user_id = read_pending_totp_ticket(pending_ticket) if pending_ticket else None
    challenge_info = (
        read_webauthn_challenge_ticket(challenge_ticket, purpose="authenticate")
        if challenge_ticket
        else None
    )
    if (
        pending_user_id is None
        or challenge_info is None
        or challenge_info[0] != pending_user_id
    ):
        response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        clear_pending_totp_cookie(response)
        clear_webauthn_challenge_cookie(response)
        return response
    _, challenge = challenge_info

    user = await db.get(User, pending_user_id)
    if user is None or not user.is_active:
        response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        clear_pending_totp_cookie(response)
        clear_webauthn_challenge_cookie(response)
        return response

    if not await _within_rate_limit(request, bucket="totp", limit=_TOTP_RATE_LIMIT):
        await log_event(
            db,
            request=request,
            action="auth.rate_limited",
            summary=(
                f'Blocked passkey sign-in attempt for "{user.username}": '
                "too many attempts from this IP"
            ),
            outcome=AuditOutcome.DENIED,
            target_type="user",
            target_id=user.id,
            target_label=user.username,
        )
        context = await _totp_challenge_context(
            request, db, pending_user_id, next_url=next_url, error=_RATE_LIMIT_MESSAGE
        )
        assert context is not None
        return templates.TemplateResponse(
            request,
            "auth/totp_challenge.html",
            context,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    if user.is_locked_out:
        context = await _totp_challenge_context(
            request,
            db,
            pending_user_id,
            next_url=next_url,
            error="Too many failed attempts — try again shortly.",
        )
        assert context is not None
        return templates.TemplateResponse(
            request,
            "auth/totp_challenge.html",
            context,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    verified = None
    stored: WebAuthnCredential | None = None
    try:
        credential_id = webauthn_module.credential_id_from_authentication_json(credential)
        for candidate in await _user_webauthn_credentials(db, user.id):
            if candidate.credential_id == credential_id:
                stored = candidate
                break
        if stored is not None:
            verified = webauthn_module.verify_authentication(
                credential=credential, expected_challenge=challenge, request=request, stored=stored
            )
    except WebAuthnError:
        verified = None

    if stored is None or verified is None:
        await log_event(
            db,
            request=request,
            action="user.login.totp",
            summary=f'Failed passkey sign-in attempt for "{user.username}"',
            outcome=AuditOutcome.DENIED,
            target_type="user",
            target_id=user.id,
            target_label=user.username,
        )
        context = await _totp_challenge_context(
            request, db, pending_user_id, next_url=next_url, error="Passkey sign-in failed."
        )
        assert context is not None
        return templates.TemplateResponse(
            request,
            "auth/totp_challenge.html",
            context,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    stored.sign_count = verified.new_sign_count
    stored.last_used_at = datetime.now(UTC)
    await db.commit()

    final_response = await _finish_login(
        request, db, user, next_url, provider=f"{user.auth_provider.value}+webauthn"
    )
    clear_webauthn_challenge_cookie(final_response)
    return final_response


@router.post("/logout", dependencies=[Depends(verify_csrf)])
async def logout(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    session = await get_valid_session(db, raw_token) if raw_token else None
    if session is not None:
        await revoke_session(db, session)
        await log_event(
            db,
            request=request,
            action="user.logout",
            summary=f'"{session.user.username}" logged out',
            target_type="user",
            target_id=session.user_id,
            target_label=session.user.username,
        )
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    clear_session_cookie(response)
    return response


@router.get("/auth/oidc/login")
async def oidc_login(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    app_settings = await get_or_create_app_settings(db)
    if not app_settings.oidc_enabled:
        return RedirectResponse(
            url="/login?oidc_error=not_configured", status_code=status.HTTP_303_SEE_OTHER
        )
    redirect_uri = str(request.url_for("oidc_callback"))
    try:
        return await redirect_to_provider(request, app_settings, redirect_uri)  # type: ignore[no-any-return]
    except OidcNotConfiguredError:
        return RedirectResponse(
            url="/login?oidc_error=not_configured", status_code=status.HTTP_303_SEE_OTHER
        )


@router.get("/auth/oidc/callback", name="oidc_callback")
async def oidc_callback(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    app_settings = await get_or_create_app_settings(db)
    if not app_settings.oidc_enabled:
        return RedirectResponse(
            url="/login?oidc_error=not_configured", status_code=status.HTTP_303_SEE_OTHER
        )

    try:
        claims = await handle_callback(request, app_settings)
    except OidcNotConfiguredError:
        return RedirectResponse(
            url="/login?oidc_error=not_configured", status_code=status.HTTP_303_SEE_OTHER
        )
    except Exception:
        # Authlib/the provider/the network can fail in many different ways
        # (cancelled consent, expired state, provider outage, ...) — all of
        # them mean the same thing to the user: the login didn't complete.
        await log_event(
            db,
            request=request,
            action="user.login",
            summary="OIDC login failed to complete",
            outcome=AuditOutcome.DENIED,
        )
        return RedirectResponse(
            url="/login?oidc_error=failed", status_code=status.HTTP_303_SEE_OTHER
        )

    claim_name = app_settings.oidc_username_claim
    claim_value = str(claims.get(claim_name) or "").strip()
    user = await find_user_for_login(db, claim_value) if claim_value else None
    if user is None or not user.is_active or user.auth_provider != AuthProvider.OIDC:
        await log_event(
            db,
            request=request,
            action="user.login",
            summary=(
                f'Blocked OIDC login: no matching enabled account for {claim_name}="{claim_value}"'
            ),
            outcome=AuditOutcome.DENIED,
        )
        return RedirectResponse(
            url="/login?oidc_error=no_account", status_code=status.HTTP_303_SEE_OTHER
        )

    return await _finish_login(request, db, user, "/", provider="oidc")


async def _render_account(
    request: Request,
    db: AsyncSession,
    user: User,
    *,
    errors: list[str] | None = None,
    **extra: object,
) -> Response:
    count_result = await db.execute(
        select(TotpRecoveryCode).where(
            TotpRecoveryCode.user_id == user.id, TotpRecoveryCode.used_at.is_(None)
        )
    )
    unused_recovery_codes = len(count_result.scalars().all())
    tokens_result = await db.execute(
        select(ApiToken)
        .where(ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None))
        .order_by(ApiToken.created_at.desc())
    )
    webauthn_credentials = await _user_webauthn_credentials(db, user.id)
    context: dict[str, object] = {
        "user": user,
        "csrf_token": request.state.csrf_token,
        "errors": errors or [],
        "unused_recovery_codes": unused_recovery_codes,
        "min_password_length": MIN_PASSWORD_LENGTH,
        "api_tokens": list(tokens_result.scalars().all()),
        "available_locales": available_locales(),
        "webauthn_credentials": webauthn_credentials,
        **extra,
    }
    return templates.TemplateResponse(request, "auth/account.html", context)


@router.get("/account")
async def account_page(
    request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)
) -> Response:
    return await _render_account(request, db, user)


@router.post("/account/display-name", dependencies=[Depends(verify_csrf)])
async def update_display_name(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    display_name: str = Form(""),
) -> Response:
    # `current_user` (from the auth middleware's own, already-closed DB
    # session) can't be mutated and saved through `db` — a different
    # session's `commit()` only persists objects that session itself
    # loaded/added. Re-fetch through `db` before writing to it. Every
    # mutating route below does the same for the same reason.
    user = await db.get(User, current_user.id)
    assert user is not None
    user.display_name = display_name.strip() or None
    await db.commit()
    await log_event(
        db,
        request=request,
        action="user.account.update",
        summary=f'"{user.username}" updated their display name',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return RedirectResponse(url="/account", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/account/locale", dependencies=[Depends(verify_csrf)])
async def update_locale(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    locale: str = Form(...),
) -> Response:
    """Self-service UI language — see `app.i18n`'s module docstring for how
    a locale file becomes a picker option. An unknown code (a stale form
    from before a locale file was removed, or a tampered request) is
    silently treated as "use the default" rather than rejected — the same
    "never worse than doing nothing" fallback `get_locale` itself uses,
    so there's no separate error path to test here."""
    user = await db.get(User, current_user.id)
    assert user is not None
    resolved = get_locale(locale)
    user.locale = resolved.code
    await db.commit()
    await log_event(
        db,
        request=request,
        action="user.account.update",
        summary=f'"{user.username}" changed their language to "{resolved.label}"',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return RedirectResponse(url="/account", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/account/password", dependencies=[Depends(verify_csrf)])
async def change_own_password(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
) -> Response:
    user = await db.get(User, current_user.id)
    assert user is not None
    errors: list[str] = []
    if user.auth_provider != AuthProvider.LOCAL:
        errors.append("Only local accounts have a debcontrol password to change.")
    elif user.password_hash is None or not verify_password(user.password_hash, current_password):
        errors.append("Current password is incorrect.")
    elif new_password != confirm_password:
        errors.append("New password and confirmation don't match.")
    elif len(new_password) < MIN_PASSWORD_LENGTH:
        errors.append(f"New password must be at least {MIN_PASSWORD_LENGTH} characters.")

    if errors:
        return await _render_account(request, db, user, errors=errors)

    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    await db.commit()
    await log_event(
        db,
        request=request,
        action="user.password.change",
        summary=f'"{user.username}" changed their own password',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return RedirectResponse(url="/account", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/account/totp/enroll")
async def totp_enroll_form(request: Request, user: User = Depends(get_current_user)) -> Response:
    if user.auth_provider == AuthProvider.OIDC:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC accounts don't enroll TOTP here — the provider handles its own MFA.",
        )
    if user.totp_enabled:
        return RedirectResponse(url="/account", status_code=status.HTTP_303_SEE_OTHER)

    secret = totp_module.generate_secret()
    uri = totp_module.provisioning_uri(secret, user.username)
    return templates.TemplateResponse(
        request,
        "auth/totp_enroll.html",
        {
            "user": user,
            "csrf_token": request.state.csrf_token,
            "secret": secret,
            "qr_svg": totp_module.qr_code_svg(uri),
            "error": None,
            # See app.auth.middleware's `_totp_enrollment_required` — this
            # page is where that block sends someone, and worth explaining
            # why they landed here rather than wherever they meant to go.
            "required_by_role": user.role.require_totp,
        },
    )


@router.post("/account/totp/enroll", dependencies=[Depends(verify_csrf)])
async def totp_enroll_confirm(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    secret: str = Form(...),
    code: str = Form(...),
) -> Response:
    if current_user.auth_provider == AuthProvider.OIDC or current_user.totp_enabled:
        return RedirectResponse(url="/account", status_code=status.HTTP_303_SEE_OTHER)
    user = await db.get(User, current_user.id)
    assert user is not None

    if not totp_module.verify_code(secret, code):
        uri = totp_module.provisioning_uri(secret, user.username)
        return templates.TemplateResponse(
            request,
            "auth/totp_enroll.html",
            {
                "user": user,
                "csrf_token": request.state.csrf_token,
                "secret": secret,
                "qr_svg": totp_module.qr_code_svg(uri),
                "error": (
                    "That code didn't match — check your authenticator app's clock and try again."
                ),
                "required_by_role": user.role.require_totp,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    user.totp_secret_encrypted = encrypt_secret(secret)
    user.totp_enabled = True
    user.totp_confirmed_at = datetime.now(UTC)
    # Clear out anything left from an earlier enrollment (shouldn't normally
    # exist — disabling TOTP deletes them too, see totp_disable below — but
    # never show a mix of old and new codes).
    await db.execute(delete(TotpRecoveryCode).where(TotpRecoveryCode.user_id == user.id))
    plain_codes = totp_module.generate_recovery_codes()
    for plain_code in plain_codes:
        db.add(TotpRecoveryCode(user_id=user.id, code_hash=hash_password(plain_code)))
    await db.commit()

    await log_event(
        db,
        request=request,
        action="user.totp.enable",
        summary=f'"{user.username}" enabled two-factor authentication',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return await _render_account(request, db, user, recovery_codes=plain_codes, just_enrolled=True)


@router.post("/account/totp/disable", dependencies=[Depends(verify_csrf)])
async def totp_disable(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    code: str = Form(...),
) -> Response:
    if not current_user.totp_enabled:
        return RedirectResponse(url="/account", status_code=status.HTTP_303_SEE_OTHER)
    user = await db.get(User, current_user.id)
    assert user is not None

    secret = decrypt_secret(user.totp_secret_encrypted) if user.totp_secret_encrypted else None
    ok = bool(secret and totp_module.verify_code(secret, code))
    if not ok:
        ok = await consume_recovery_code(db, user, code)
    if not ok:
        return await _render_account(
            request, db, user, errors=["Invalid code — two-factor authentication was not disabled."]
        )

    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_confirmed_at = None
    await db.execute(delete(TotpRecoveryCode).where(TotpRecoveryCode.user_id == user.id))
    await db.commit()
    await log_event(
        db,
        request=request,
        action="user.totp.disable",
        summary=f'"{user.username}" disabled two-factor authentication',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return RedirectResponse(url="/account", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/account/totp/recovery-codes/regenerate", dependencies=[Depends(verify_csrf)])
async def regenerate_recovery_codes(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    code: str = Form(...),
) -> Response:
    if not user.totp_enabled:
        return RedirectResponse(url="/account", status_code=status.HTTP_303_SEE_OTHER)

    # Deliberately requires a fresh *TOTP* code, not a recovery code — a
    # recovery code should get you back in, not let itself be used to mint
    # a whole new batch (an attacker who obtained a single leaked recovery
    # code, with a hijacked session, could otherwise invalidate and relearn
    # all of them).
    secret = decrypt_secret(user.totp_secret_encrypted) if user.totp_secret_encrypted else None
    if not (secret and totp_module.verify_code(secret, code)):
        return await _render_account(
            request, db, user, errors=["Invalid code — recovery codes were not regenerated."]
        )

    await db.execute(delete(TotpRecoveryCode).where(TotpRecoveryCode.user_id == user.id))
    plain_codes = totp_module.generate_recovery_codes()
    for plain_code in plain_codes:
        db.add(TotpRecoveryCode(user_id=user.id, code_hash=hash_password(plain_code)))
    await db.commit()

    await log_event(
        db,
        request=request,
        action="user.totp.recovery_codes.regenerate",
        summary=f'"{user.username}" regenerated their TOTP recovery codes',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return await _render_account(request, db, user, recovery_codes=plain_codes)


@router.get("/account/webauthn/register/options")
async def webauthn_register_options(
    request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)
) -> Response:
    if user.auth_provider == AuthProvider.OIDC:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC accounts don't register passkeys here — the provider handles its own MFA.",
        )
    existing = await _user_webauthn_credentials(db, user.id)
    options, challenge = webauthn_module.generate_registration(
        request, user_id=user.id, username=user.username, existing=existing
    )
    response = Response(content=options_to_json(options), media_type="application/json")
    challenge_ticket = create_webauthn_challenge_ticket(
        user_id=user.id, challenge=challenge, purpose="register"
    )
    set_webauthn_challenge_cookie(response, challenge_ticket)
    return response


@router.post("/account/webauthn/register/verify", dependencies=[Depends(verify_csrf)])
async def webauthn_register_verify(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    credential: str = Form(...),
    name: str = Form(""),
) -> Response:
    user = await db.get(User, current_user.id)
    assert user is not None
    challenge_ticket = request.cookies.get(WEBAUTHN_CHALLENGE_COOKIE_NAME)
    challenge_info = (
        read_webauthn_challenge_ticket(challenge_ticket, purpose="register")
        if challenge_ticket
        else None
    )
    if challenge_info is None or challenge_info[0] != user.id:
        return await _render_account(
            request, db, user, errors=["Passkey registration expired — try again."]
        )
    _, challenge = challenge_info

    try:
        verified = webauthn_module.verify_registration(
            credential=credential, expected_challenge=challenge, request=request
        )
    except WebAuthnError as exc:
        return await _render_account(request, db, user, errors=[str(exc)])

    db.add(
        WebAuthnCredential(
            user_id=user.id,
            name=(name.strip() or "Passkey")[:100],
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            device_type=verified.credential_device_type.value,
            backed_up=verified.credential_backed_up,
        )
    )
    await db.commit()
    response = await _render_account(request, db, user, just_registered_webauthn=True)
    clear_webauthn_challenge_cookie(response)
    await log_event(
        db,
        request=request,
        action="user.webauthn.register",
        summary=f'"{user.username}" registered a new passkey',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return response


@router.post("/account/webauthn/{credential_id}/delete", dependencies=[Depends(verify_csrf)])
async def webauthn_delete(
    request: Request,
    credential_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    result = await db.execute(
        select(WebAuthnCredential).where(
            WebAuthnCredential.id == credential_id, WebAuthnCredential.user_id == current_user.id
        )
    )
    credential = result.scalar_one_or_none()
    if credential is not None:
        await db.delete(credential)
        await db.commit()
        await log_event(
            db,
            request=request,
            action="user.webauthn.delete",
            summary=f'"{current_user.username}" removed a passkey ("{credential.name}")',
            target_type="user",
            target_id=current_user.id,
            target_label=current_user.username,
        )
    return RedirectResponse(url="/account", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/account/sessions/revoke-all", dependencies=[Depends(verify_csrf)])
async def revoke_other_sessions(
    request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)
) -> Response:
    current_session = getattr(request.state, "session", None)
    await revoke_all_sessions_for_user(
        db, user.id, except_session_id=current_session.id if current_session else None
    )
    await log_event(
        db,
        request=request,
        action="user.sessions.revoke_all",
        summary=f'"{user.username}" logged out all other sessions',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return RedirectResponse(url="/account", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/account/api-tokens", dependencies=[Depends(verify_csrf)])
async def create_own_api_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name: str = Form(...),
    expires_in_days: str = Form(""),
) -> Response:
    user = await db.get(User, current_user.id)
    assert user is not None
    if not user.api_access_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="An administrator hasn't granted this account API access.",
        )
    name = name.strip()
    if not name:
        return await _render_account(request, db, user, errors=["Token name can't be empty."])

    expires_at: datetime | None = None
    raw_days = expires_in_days.strip()
    if raw_days:
        try:
            days = int(raw_days)
            if days <= 0:
                raise ValueError
        except ValueError:
            return await _render_account(
                request,
                db,
                user,
                errors=["Expiry must be a positive whole number of days, or blank for no expiry."],
            )
        expires_at = datetime.now(UTC) + timedelta(days=days)

    token, raw_token = await create_api_token(db, user, name=name, expires_at=expires_at)
    await log_event(
        db,
        request=request,
        action="user.api_token.create",
        summary=f'"{user.username}" created an API token ("{token.name}")',
        target_type="user",
        target_id=user.id,
        target_label=user.username,
    )
    return await _render_account(request, db, user, new_api_token=raw_token)


@router.post("/account/api-tokens/{token_id}/revoke", dependencies=[Depends(verify_csrf)])
async def revoke_own_api_token(
    request: Request,
    token_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    revoked = await revoke_api_token(db, token_id, owner_id=current_user.id)
    if revoked:
        await log_event(
            db,
            request=request,
            action="user.api_token.revoke",
            summary=f'"{current_user.username}" revoked an API token',
            target_type="user",
            target_id=current_user.id,
            target_label=current_user.username,
        )
    return RedirectResponse(url="/account", status_code=status.HTTP_303_SEE_OTHER)
