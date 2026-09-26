"""REST API for Settings — deliberately a subset of what
`app/web/routes/settings.py` exposes.

What's exposed and why:

- **Version/commit info** and the **SSH public key/fingerprint** — safe to
  read over a bearer-token API; the public key is *meant* to be copied
  elsewhere (into `authorized_keys`), and version/commit is already shown
  unauthenticated-adjacent on the Settings page to any logged-in user with
  `settings.view`.
- **Background-check intervals and timeouts, every retention window,
  monitoring downsampling, the AI token limits and the sign-in policy's
  session lifetime/lockout numbers** — operational facts, not secrets.
  These are also *writable* here (`PATCH /api/v1/settings`,
  `settings.manage`), with exactly the ranges the Settings page enforces
  (`app.services.settings_limits`) and the same audit action codes.

What's deliberately **not** exposed here, even to a `settings.manage`
token:

- **Rotating the SSH key** (`/settings/ssh-key/...`) — this is a multi-step,
  human-in-the-loop process (generate, manually copy the public half onto
  every machine's `authorized_keys`, then activate) specifically designed
  so the app is never locked out of a machine mid-rotation. Automating the
  "activate" step over an API makes it too easy to fire before the manual
  copy step has actually happened everywhere, with no server-side way to
  tell the difference — a mistake here can lock debcontrol out of every
  managed machine at once. Left as a deliberately web-UI-only, human-paced
  action.
- **LDAP/OIDC configuration** (`/settings/ldap`, `/settings/oidc`) — these
  carry encrypted secrets (bind password, client secret) and change how
  *every* login on the instance is authenticated; a bug or a stolen token
  reconfiguring the login provider is a much bigger blast radius than
  anything else this API can do. Read access isn't offered either, since
  the encrypted secret fields aren't meaningful to return and everything
  else about the config is only useful alongside the ability to change it.
- **Syslog forwarding configuration** — lower-risk than LDAP/OIDC, but
  still a live security-monitoring integration point; left for the web UI
  for the same "changing where audit data flows shouldn't be a one-token
  API call" reasoning, pending an explicit ask.
- **GeoIP configuration** (`/settings/geoip`, `/settings/geoip/download`)
  — same reasoning as syslog: the download URLs carry an encrypted secret
  (a MaxMind "permalink" embeds a license key), and "Download now"
  triggers an outbound network fetch on demand. The *result* of GeoIP
  being enabled (each audit entry's `geo_*` columns) is already exposed
  read-only via `/api/v1/audit`, same as `ip_address` itself.
- **The sign-in network allowlist** (`login_allowed_networks`, Settings ->
  Security) — a wrong value locks every browser *and* every API token out
  of the instance at once; the web form refuses a list that excludes the
  address saving it, a safeguard that doesn't carry over to a script
  running from somewhere else. Same "changes who can reach the app at
  all" reasoning as LDAP/OIDC above.
- **SMTP relay and AI provider credentials/models, and the fleet summary
  schedule** — each carries or selects a stored secret (relay password,
  provider API key); same reasoning as syslog.

If a future need justifies any of these over the API, they should get
their own deliberate design pass (e.g. requiring a fresh confirmation
field, or a narrower permission than `settings.manage`) rather than being
folded in here by default.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth import session_policy
from app.auth.dependencies import require_api_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.version import APP_VERSION, commit_url, get_git_commit
from app.db.models.role import Permission
from app.db.session import get_db
from app.services.settings_limits import (
    AUDIT_ACTION_BY_FIELD,
    BOUNDED_FIELDS,
    NEEDS_RESTART_FIELDS,
    RETENTION_FIELDS,
    SIGN_IN_POLICY_FIELDS,
    TOKEN_LIMIT_FIELDS,
)
from app.ssh.identity import get_or_create_identity

router = APIRouter(prefix="/api/v1/settings")

_view = Depends(require_api_permission(Permission.SETTINGS_VIEW))
_manage = Depends(require_api_permission(Permission.SETTINGS_MANAGE))

_WRITABLE_FIELDS = (*BOUNDED_FIELDS, *RETENTION_FIELDS, *TOKEN_LIMIT_FIELDS)


@router.get("", dependencies=[_view])
async def get_settings_api(db: AsyncSession = Depends(get_db)) -> dict[str, object]:
    identity = await get_or_create_identity(db)
    app_settings = await get_or_create_app_settings(db)
    git_commit = get_git_commit()
    return {
        "app_version": APP_VERSION,
        "git_commit": git_commit,
        "git_commit_url": commit_url(git_commit) if git_commit else None,
        "ssh_public_key": identity.public_key,
        "ssh_fingerprint": identity.fingerprint,
        "ssh_pending_fingerprint": identity.pending_fingerprint,
        **{field: getattr(app_settings, field) for field in _WRITABLE_FIELDS},
    }


def _validate(field: str, value: object) -> tuple[int | None, str | None]:
    """`(value, error)` — the same rules the Settings page applies."""
    if isinstance(value, bool) or not (value is None or isinstance(value, int)):
        suffix = "" if field in BOUNDED_FIELDS else " or null"
        return None, f"{field}: must be a whole number{suffix}"
    if field in BOUNDED_FIELDS:
        minimum, maximum = BOUNDED_FIELDS[field]
        if value is None or not (minimum <= value <= maximum):
            return None, f"{field}: must be between {minimum} and {maximum}"
        return value, None
    if value is not None and value < 0:
        return None, f"{field}: must not be negative"
    return value, None


@router.patch("", dependencies=[_manage])
async def update_settings_api(
    request: Request,
    changes: dict[str, Any] = Body(...),
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    """Change any subset of the operational settings (see the module
    docstring); fields left out are untouched, and `null` means "keep
    forever"/"unlimited" for a retention or token-limit field. All or
    nothing: any unknown field or out-of-range value is a 422 and nothing
    is saved. `needs_restart` lists changed intervals that Celery Beat only
    reads at startup (restart the worker/beat services to apply them)."""
    unknown = sorted(set(changes) - set(_WRITABLE_FIELDS))
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Not a writable setting: {', '.join(unknown)}",
        )
    validated: dict[str, int | None] = {}
    errors: list[str] = []
    for field, raw in changes.items():
        value, error = _validate(field, raw)
        if error:
            errors.append(error)
        else:
            validated[field] = value
    if errors:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail="; ".join(errors))

    app_settings = await get_or_create_app_settings(db)
    changed = {f: v for f, v in validated.items() if getattr(app_settings, f) != v}
    for field, value in changed.items():
        setattr(app_settings, field, value)
    await db.commit()
    if SIGN_IN_POLICY_FIELDS & changed.keys():
        session_policy.invalidate()

    # One audit entry per Settings form touched, under that form's own
    # action code.
    by_action: dict[str, dict[str, int | None]] = {}
    for field, value in changed.items():
        by_action.setdefault(AUDIT_ACTION_BY_FIELD[field], {})[field] = value
    for action, details in by_action.items():
        await log_event(
            db,
            request=request,
            action=action,
            summary=f"Updated {', '.join(details)} via the API",
            details=details,
        )
    return {
        "changed": sorted(changed),
        "needs_restart": sorted(NEEDS_RESTART_FIELDS & changed.keys()),
    }
