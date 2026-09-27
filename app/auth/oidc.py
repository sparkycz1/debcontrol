"""OIDC login — standard authorization-code flow via Authlib, which also
validates the ID token's signature and nonce for us (it knows the provider's
JWKS once it's fetched `server_metadata_url`).

No account is ever created from this — see the module docstring on
`app.db.models.user`. `handle_callback` only returns the provider's claims;
matching that to an existing debcontrol account (by comparing
`AppSettings.oidc_username_claim`) happens in the route
(`app/web/routes/auth.py`), same as it would for any other claim-based
identity check.

A fresh `OAuth()` client is registered from current `AppSettings` on every
call rather than once at startup, since the config is editable at runtime
from the Settings page — the cost is one extra discovery-document fetch per
login, which is an acceptable trade for picking up config changes (or a
newly-enabled/disabled provider) without restarting the app.

Authlib's Starlette integration stores the OAuth `state`/`nonce` in
`request.session` — that's Starlette's own `SessionMiddleware`, registered in
`app.main` with `SECRET_KEY`, and is unrelated to the app's own login
sessions (`app.auth.sessions`), which is what a completed OIDC login itself
sets up once `handle_callback` and the username match succeed.
"""

from __future__ import annotations

from typing import Any

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import Request

from app.core.security import decrypt_secret
from app.db.models.app_settings import AppSettings

_CLIENT_NAME = "oidc"


class OidcNotConfiguredError(Exception):
    """OIDC is enabled but Settings is missing something required to start
    a login (issuer, client ID, ...)."""


def _build_client(app_settings: AppSettings) -> Any:
    if not app_settings.oidc_issuer_url or not app_settings.oidc_client_id:
        raise OidcNotConfiguredError(
            "OIDC is not fully configured — set the issuer URL and client ID in Settings."
        )
    client_secret = (
        decrypt_secret(app_settings.oidc_client_secret_encrypted)
        if app_settings.oidc_client_secret_encrypted
        else None
    )
    oauth = OAuth()
    oauth.register(
        name=_CLIENT_NAME,
        client_id=app_settings.oidc_client_id,
        client_secret=client_secret,
        server_metadata_url=(
            f"{app_settings.oidc_issuer_url.rstrip('/')}/.well-known/openid-configuration"
        ),
        client_kwargs={"scope": app_settings.oidc_scopes},
    )
    return getattr(oauth, _CLIENT_NAME)


async def redirect_to_provider(
    request: Request, app_settings: AppSettings, redirect_uri: str
) -> Any:
    client = _build_client(app_settings)
    return await client.authorize_redirect(request, redirect_uri)


async def handle_callback(request: Request, app_settings: AppSettings) -> dict[str, Any]:
    """Complete the code exchange and return the provider's claims about
    who just logged in (from the validated ID token, or a `userinfo` call
    for a provider that doesn't include claims on the token response)."""
    client = _build_client(app_settings)
    token = await client.authorize_access_token(request)
    userinfo = token.get("userinfo")
    if userinfo is None:
        userinfo = await client.userinfo(token=token)
    return dict(userinfo)


async def check_discovery(app_settings: AppSettings) -> str:
    """Settings → Integrations → OIDC "Test": fetch the provider's discovery
    document and check it is one — the step every login starts with.
    Returns the issuer it reports; raises `OidcNotConfiguredError` (not
    configured) or `ValueError` (unreachable or not a discovery document)
    with the reason. Uses the *saved* settings, so save first."""
    if not app_settings.oidc_issuer_url or not app_settings.oidc_client_id:
        raise OidcNotConfiguredError(
            "OIDC is not fully configured — set the issuer URL and client ID in Settings."
        )
    url = f"{app_settings.oidc_issuer_url.rstrip('/')}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            document = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValueError(f"Could not read {url}: {exc}") from exc
    if not isinstance(document, dict) or not document.get("authorization_endpoint"):
        raise ValueError(f"{url} is not an OpenID Connect discovery document.")
    return str(document.get("issuer") or url)
