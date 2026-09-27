# 🔐 Authentication & RBAC

*Logins, sessions, roles and permissions, machine-group scoping, 2FA, UI
language and the REST API's auth. See [Architecture](Architecture.md) for
the rest.*

Every page needs a session except `/login*`, `/auth/oidc/*`, `/healthz`,
`/static/`, `/branding/` and `/api/*` (bearer tokens) — enforced by one
middleware, `app.auth.middleware.require_auth`.

## Logging in

### No accounts are ever auto-created

Every `User` is created in debcontrol (**Users**); LDAP and OIDC only
decide *how* an existing account proves who it is (`auth_provider`):

- **`local`** — an argon2id password hash.
- **`ldap`** — search-then-bind: a service account finds the DN, a second
  connection binds with the entered password (empty passwords refused).
  TLS verification is on by default (`ldap_tls_verify`).
- **`oidc`** — authorization-code flow (Authlib); the account is matched
  on a configurable claim (`oidc_username_claim`, default `email`).
  Nothing is created or updated from claims.

**Two steps**: `/login` asks for the username (plus the OIDC button), then
`/login/password` offers a passkey or password. The passkey button always
shows, whether or not the account exists (no enumeration). Every failure
reads "Invalid username or password"; only a locked account gets its own
message.

### Sessions are server-side rows

`UserSession` is a DB row per login; the cookie holds a random token whose
SHA-256 is stored. Sessions can be revoked instantly (disabling a user,
password reset, "log out everywhere"). They slide by the idle timeout
(default 12 h) up to an absolute cap (default 30 days). Short-lived signed
tickets (pending 2FA, WebAuthn challenge, the OIDC flow cookie) never grant
a session on their own.

### Sign-in policy: session lifetime, lockout, allowed networks

**Settings → Security → Sign-in** (`settings.manage`, audited as
`settings.sign_in_policy.update`): idle timeout, maximum session length,
failed attempts before lockout (default 5), lockout duration (default
15 min) and an optional **network allowlist** (IPs/CIDRs; empty =
anywhere). The allowlist is checked before any session lookup, for the UI,
the API and the WebSockets; `/static/`, `/branding/`, `/healthz` and
`POST /api/inform` are exempt. Behind a proxy it needs trusted proxy
headers. The form refuses a list that would lock out the address saving
it. The numbers are also in `PATCH /api/v1/settings`; the allowlist is
not. The same tab lists local/LDAP accounts without any second factor.

Per-IP rate limiting adds **30 attempts per 5 minutes** on `POST /login`
and `POST /login/totp` (Redis).

### TOTP and passkeys

- **TOTP** (local/LDAP): self-service enrollment with a QR code (inline
  SVG), confirmed with a real code, plus eight one-time recovery codes
  (argon2-hashed; regenerating needs a TOTP code, not a recovery code).
- **Passkeys (WebAuthn)**: registered on **My account**; usable as the
  *primary* login (step two, no password) or as the *second factor*
  after a password. The RP id/origin comes from the request, so behind a
  proxy `X-Forwarded-Proto` must be trusted (`TRUSTED_PROXY_IPS`).
  A signature counter that goes backwards is refused (clone detection).
- **Role-enforced 2FA** (`Role.require_totp`): checked on every request;
  an affected account can only reach TOTP/passkey enrollment, its account
  page and logout until it has one. An API token of such an account gets
  a 403. OIDC accounts are exempt.
- `must_change_password` only redirects after the next login.

### OIDC

Authlib keeps `state`/`nonce` in its own short cookie (`oidc_flow`,
`SameSite=Lax`, 10 min); a completed login creates a normal session. The
client is built from current settings on each login, so config edits
apply immediately.

### Bootstrapping and recovery

`scripts/create_admin.py` creates the first administrator (a CLI script,
not a first-run web page). `scripts/reset_account.py` unlocks an account
or resets its password/2FA from the console.

## Roles and permissions

### RBAC: custom roles, a fixed permission set

Admins create **roles** from a fixed set of permissions —
`machine.view`/`.manage`, `group.view`/`.manage`, `action.updates`,
`action.power`, `action.terminal`, `ai.access`, `scheduling.view`/`.manage`,
`notification.view`/`.manage`, `audit.view`, `settings.view`/`.manage`,
`user.manage`, `user.impersonate` — and give each user **one role**.
Every `.manage` implies its `.view`; `action.*` are independent;
`user.manage` covers users and roles. Permissions are resource-wide, not
per object; *which* machines they apply to is the scoping below.

**Guardrails**: you can't deactivate, delete or change the role of your
own account, and no change may leave nobody with `user.manage`.

### Temporary permissions

**Users → edit → Temporary permissions** grants one permission to one
account for up to 30 days, on top of its role; it can be revoked early.
Audited as `user.temporary_permission.grant` / `.revoke`. REST:
`GET/POST /api/v1/users/{id}/temporary-permissions`,
`DELETE …/{grant_id}`.

### Impersonate

**Users → Sign in as** (`user.impersonate`) creates a new session for the
target account and keeps the admin's own session in a signed cookie;
**Log out** returns to it. You can't impersonate yourself, stack
impersonations, impersonate a disabled account or one that itself holds
`user.impersonate`. Start and stop are audited
(`user.impersonate.start` / `.stop`); everything in between is audited
as the impersonated account. The header always shows both names.
Web-only.

### Machine-group scoping

Permissions say *what* an account may do; scoping says *on which
machines*. **Users** (`user.manage`) can limit an account to chosen
groups (`UserMachineGroupAccess`); **no rows = unrestricted**, and a
restricted account never sees ungrouped machines. Admins can't change
their own scope.

`app/services/access_scope.py` enforces it everywhere: machine and group
pages, search, bulk actions, config export, scheduling, the Dashboard,
the REST API, the terminal/logs/live WebSockets and the AI assistant's
tools. Out-of-scope reads as **404**, and bulk requests silently drop
out-of-scope ids. A restricted account can't schedule against "All
machines". The **audit log is not scoped** — `audit.view` sees
everything.

## Per-user API tokens: gated by a separate account-level flag, inheriting the role live

API tokens (`dcpat_…`, only the SHA-256 stored) authenticate the REST API
and optionally `POST /api/inform`. A token acts with its owner's
permissions **as of each request**, so role changes and deactivation
apply immediately. An account can have tokens only while an admin has
set `User.api_access_enabled` — checked at creation and on every use.
Created and revoked on **My account**; the value is shown once.

## Per-user UI language (i18n)

Each account picks its language on **My account → Language**
(`User.locale`; empty = `DEFAULT_LANGUAGE` from `.env`, English unless
set). Strings live in flat JSON files, `app/i18n/locales/<code>.json`;
**adding a language needs no code change**:

```json
{
  "meta": { "code": "xx", "label": "Native name" },
  "strings": { "nav.dashboard": "...", "...": "..." }
}
```

`meta.code` must match the file name. Missing keys fall back to English.
Templates call `t(request, "key", **values)`.

- **Plurals**: with an integer `count`, `<key>.<category>` is tried first
  (English `one`/`other`, Czech `one`/`few`/`other`), then `<key>`.
  Never write "user(s)".
- **Audit entries** are stored in English; other languages show the
  translated `audit.action_label.<code>` with the English text on hover.
  A new action code needs that key in every locale.
- Every page is translated; both shipped locales (`en`, `cs`) have every
  key. A new string needs a key in every locale file.

> [!WARNING]
> If a translated string puts quotes or other HTML-special characters
> around a `{placeholder}`, use `t(request, "…", query=q | e) | safe` —
> pre-escape the value and mark the whole string safe; otherwise
> autoescape mangles the literal quotes.

## The REST API: read and write, mirroring the web UI

`/api/v1/…` covers nearly everything the web UI does — machines, groups,
bulk and fleet actions, updates, monitoring, logs, Proxmox, Docker,
scheduling, users, roles, the audit log, notifications, endpoint checks,
the Dashboard, the operational part of Settings and self-service account
settings. Routers: `api_v1.py` (machines/groups/bulk), `api_v1_scheduling`,
`_users`, `_roles`, `_audit`, `_settings`, `_dashboard`, `_account`,
`_checks`, `_notifications`.

- **Same permission** as the web route (`require_api_permission`), **same
  service functions**, **same guardrails** and **same audit codes**
  (attributed to the token's owner).
- A typed confirmation becomes a JSON field (`confirm_name`, `confirm`,
  `confirm_username`). No CSRF (bearer tokens only).
- Machine lists page with `limit`/`offset`.

**Deliberately web-only**: SSH key rotation (human-paced, to avoid
lock-out); LDAP/OIDC, SMTP, syslog, GeoIP and AI provider credentials and
their *Test* buttons; the fleet-summary schedule; the sign-in network
allowlist; the terminal, live log follow and AI chat (interactive);
impersonation; the "Fix it" one-time credential; CSV bulk import.

### Interactive docs: Swagger UI at `/api`

`GET /api` serves Swagger UI generated from the live routes (only
`/api/` paths). It needs a logged-in account **with**
`api_access_enabled` — the schema (`/openapi.json`) maps every endpoint,
so it isn't public. Click **Authorize** and paste one of your tokens.
Swagger UI is vendored (`swagger-ui-bundle.js` **and**
`swagger-ui-standalone-preset.js`, both required) and booted from
`static/js/swagger-init.js`, because FastAPI's default page uses a CDN
and inline script, which CSP forbids.
