"""REST API for Settings — deliberately a read-only subset of what
`app/web/routes/settings.py` exposes.

What's exposed and why:

- **Version/commit info** and the **SSH public key/fingerprint** — safe to
  read over a bearer-token API; the public key is *meant* to be copied
  elsewhere (into `authorized_keys`), and version/commit is already shown
  unauthenticated-adjacent on the Settings page to any logged-in user with
  `settings.view`.
- **Background-check intervals** and **audit log retention** — operational
  facts, not secrets.

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

If a future need justifies any of these over the API, they should get
their own deliberate design pass (e.g. requiring a fresh confirmation
field, or a narrower permission than `settings.manage`) rather than being
folded in here by default.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_api_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.version import APP_VERSION, commit_url, get_git_commit
from app.db.models.role import Permission
from app.db.session import get_db
from app.ssh.identity import get_or_create_identity

router = APIRouter(prefix="/api/v1/settings")

_view = Depends(require_api_permission(Permission.SETTINGS_VIEW))


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
        "facts_refresh_interval_seconds": app_settings.facts_refresh_interval_seconds,
        "update_timeout_seconds": app_settings.update_timeout_seconds,
        "ssh_connect_timeout": app_settings.ssh_connect_timeout,
        "audit_log_retention_days": app_settings.audit_log_retention_days,
    }
