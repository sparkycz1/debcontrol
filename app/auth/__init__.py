"""Authentication and authorization.

- `app.auth.security` — password hashing (argon2id).
- `app.auth.totp` — TOTP two-factor enrollment/verification and recovery codes.
- `app.auth.ldap` — LDAP bind authentication.
- `app.auth.oidc` — OIDC authorization-code login.
- `app.auth.sessions` — server-side login sessions (cookie + DB row) and the
  short-lived signed "pending 2FA" ticket.
- `app.auth.login` — ties the above together: local/LDAP password checking,
  TOTP verification, and shared brute-force lockout bookkeeping.
- `app.auth.dependencies` — `get_current_user` / `require_permission` FastAPI
  dependencies for routes.
- `app.auth.middleware` — the ASGI middleware that requires a valid session
  for every request except an explicit public allowlist (see `app.main`).

See `app/db/models/user.py`, `app/db/models/role.py` for the data model, and
the "Authentication & RBAC" section of the Architecture wiki page for the
overall design and its trade-offs.
"""

from __future__ import annotations
