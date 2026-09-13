# 🔐 Authentication & RBAC

*Logins, sessions, roles/permissions, per-user scoping, 2FA, and the REST
API's own auth story. Split out of [Architecture](Architecture.md) so this
one topic is easier to search — start there for the rest (SSH handling,
machine management, audit log, notifications, HTTP hardening).*

Every page requires a valid session except `/login`, `/login/totp`,
`/login/webauthn/options` + `/login/webauthn/verify`, the
`/auth/oidc/...` endpoints, `/healthz`, and `/api/*` (which has its own
bearer-token auth) — enforced by one ASGI middleware,
`app.auth.middleware.require_auth`, registered in `app/main.py` before the
security-headers middleware so CSP etc. still land on a redirect-to-login
response.

### No accounts are ever auto-created

Every `User` row is created inside debcontrol first, through **Users** —
never by LDAP or OIDC. `auth_provider` (`local`/`ldap`/`oidc`) only
decides *how* an existing account proves who it is:

- **`local`**: a password stored here, argon2id-hashed.
- **`ldap`**: `username` doubles as the LDAP username. `authenticate`
  does search-then-bind: a service account searches for the DN by
  username (filter-escaped), a *second*, independent connection binds as
  that DN with the entered password. Empty password rejected before the
  bind step — many directories treat that as a successful
  "unauthenticated bind". `AppSettings.ldap_tls_verify` (on by default)
  controls cert verification for `ldaps://`/StartTLS — `ldap3.Server`
  defaults to *no* verification without an explicit `Tls` object, so
  `app.auth.ldap` always passes one; turning it off is an explicit
  opt-out for a directory with a known self-signed cert.
- **`oidc`**: redirected to the provider (Authlib, auth-code flow); on
  callback, matched by comparing `username` against a configurable claim
  (`oidc_username_claim`, default `email`). No account created/updated
  from provider claims. Login button reads "Log in with OIDC" unless
  `oidc_provider_name` names the real provider.

`/login` is shared by `local`/`ldap`; `check_password` looks the
username up and branches internally. An `oidc` account hitting the
password form gets the same generic wrong-password message.

**Login is two steps**: `GET /login` collects only the username (+ OIDC
button if enabled), then `/login/password?username=...` offers a
passkey *or* password — a passkey there signs straight in, no password
ever submitted, GitHub/Google-style. `username` travels as a plain query
param, not a secret, trusted for nothing beyond "whose passkeys to
offer" — real auth is the password form (still `POST /login`) or
WebAuthn. The passkey button always shows on step two regardless of
whether the account has one or exists at all — enumeration-resistance
(`_resolve_webauthn_login_user`'s docstring). A passkey used this way
needs no further factor — already *is* one — straight to `_finish_login`,
same endpoint a post-password TOTP/passkey confirmation lands at.

### Sessions are server-side rows, not a signed cookie

`UserSession` is a DB row per login; the cookie carries an opaque random
token, only its SHA-256 is stored — a DB leak alone doesn't hand over a
live session. Revocable immediately: disabling a user, a password reset,
or "log out everywhere" all mark rows revoked. Sessions slide
(`SESSION_IDLE_TIMEOUT`, 12h, extended per request) up to an absolute
cap (`SESSION_ABSOLUTE_MAX`, 30 days).

The middleware runs outside FastAPI's DI, opening a DB session via
`request.app.state.db_session_factory` — same pattern `app/tasks/jobs.py`
uses, so tests can point it at their own SQLite engine.

Two *signed but stateless* values exist, both `itsdangerous.
URLSafeTimedSerializer` keyed by `SECRET_KEY`, 5-minute expiry, neither
granting a session alone: the pending-2FA ticket for the gap between
"password/LDAP passed" and "second factor confirmed" (also read by
WebAuthn login — same mid-login state regardless of which factor), and
the WebAuthn challenge ticket for one ceremony's challenge. `SECRET_KEY`
also signs the OIDC-flow session cookie.

### RBAC: custom roles, a fixed permission set

An admin defines named `Role`s and picks exactly which of the fixed
`Permission`s each grants — `machine.view`/`.manage`, `group.view`/
`.manage`, `action.updates`, `action.power`, `action.terminal`,
`ai.access`, `scheduling.view`/`.manage`, `notification.view`/`.manage`,
`audit.view`, `settings.view`/`.manage`, `user.manage`, `user.impersonate`
— then assigns **one role per user**. Resource-grained, not per-object.

A `MANAGE` permission always also grants the matching `VIEW`
(`_MANAGE_IMPLIES_VIEW`) — otherwise `machine.manage` without
`machine.view` would 403 on every machines page (GETs gate at the *view*
level, state-changing routes add their own). `action.updates`/
`action.power` are independent of `machine.manage` and each other.
`user.manage` covers both users and roles.

> [!IMPORTANT]
> Permissions themselves are resource-grained rather than per-object: a role
> grants `machine.view`, not "view machine X". *Which* machines and groups an
> account may use those permissions on is a separate, orthogonal, opt-in
> layer — see "Machine-group scoping" below. Nothing else is per-object:
> nothing is "private" to whoever created it, and scheduled tasks are not
> owned by their author.

### Time-limited per-user permissions: on top of the role, not instead of it

**Users → edit a user → Temporary permissions** grants one `Permission`
directly to *this account*, expiring after a chosen number of hours
(`TemporaryPermissionGrant`, up to `MAX_GRANT_HOURS` — 30 days) — "this
user gets `action.terminal` for 2 hours," no role edit, no disposable role.

`User.has_permission` checks the *union* of the role's own permissions
and currently-active temporary grants (`active_temporary_permissions`, a
plain in-memory filter — no query, no background job). Like
`Role.permission_grants`, `temporary_permission_grants` is
`lazy="selectin"` on `User`, so every session-resolving request already
has what it needs; an expired grant just stops counting the instant
`expires_at` passes, same as a session's own expiry. `role_has_permission`
(the role-only check `app/web/routes/users.py` uses to simulate "would this
account still have `user.manage` if its role changed?") deliberately
never considers temporary grants — those are per-user, not per-role, so
there is nothing for a role-only check to see.

A grant can also be ended early (`revoked_at`) from the same page. Both
the grant and the revoke are audit-logged
(`user.temporary_permission.grant`/`.revoke`); the REST API mirrors both
at `POST`/`GET /api/v1/users/{id}/temporary-permissions` and `DELETE
.../temporary-permissions/{grant_id}`.

### Impersonate: signing in as another account

**Users → "Sign in as"** (`user.impersonate`, `app/web/routes/impersonation.py`)
lets an admin act as any other account without knowing its password — for
reproducing what a restricted role actually sees, or helping someone
without asking for their credentials.

- **How the session swap works**: starting it doesn't touch the admin's
  own session row at all. It creates a brand-new `UserSession` for the
  target account (tagged `impersonator_id`), points the browser's session
  cookie at that new session, and stashes the admin's own raw session
  token in a second, signed, httponly cookie (`impersonation_return`) —
  unreadable/untamperable in the browser in between.
- **Ending it is folded into the ordinary "log out" button**, not a
  separate control: logging out of an impersonated session restores the
  admin's own original session instead of signing out entirely — like
  closing a `su` shell. A full, ordinary logout only happens if the return
  cookie is missing/expired or the original session no longer validates.
- **Guardrails**: an admin can't impersonate themselves, can't start a
  second impersonation on top of one already active (stop first), and can
  never impersonate an account that itself holds `user.impersonate` — no
  admin-on-admin impersonation and no impersonation chains. A disabled
  account can't be impersonated either.
- **Audit trail**: starting and stopping are their own entries
  (`user.impersonate.start`/`.stop`) naming both accounts. Every action
  taken *during* the impersonated session is audit-logged exactly like
  normal, under the impersonated account — `request.state.impersonator`
  is available to any call site that wants to additionally record who was
  really driving (the topbar banner below uses it purely for display).
- **UI**: the header shows the impersonated account's name with the
  admin's own name alongside it in a colored tag, so it's never ambiguous
  which account is "you" right now.
- **Not in the REST API** — see `api_v1.py`'s module docstring: swapping a
  browser's session cookie has no meaningful shape as a stateless
  bearer-token call.

### Machine-group scoping: which machines an account may see

An orthogonal layer on top of the permission matrix — permissions decide
*what* an account may do, this decides *to which machines and groups*.

- **Model**: `UserMachineGroupAccess`, a plain many-to-many join of
  `users` × `machine_groups`. One row = "this account may see this group and its machines".
- **Default, and the whole backward-compatibility story**: **zero rows =
  unrestricted**, sees everything. One or more rows restricts to exactly
  those groups. Machines in no group are never visible to a restricted
  account. No backfill needed.
- **Where it's set**: Users page (`user.manage`), a checkbox list —
  account administration, alongside `api_access_enabled`, not a new
  `Permission`. Audit-logged. An admin can't change **their own** scope, mirroring the self-role-change guard.
- **Enforcement**: one service, `app/services/access_scope.py`, used
  everywhere — machines/groups (lists, detail, search, bulk actions,
  membership, config export), scheduling, Dashboard live counts, the
  REST API, the SSH terminal WebSocket, the AI assistant's tools. Out of
  scope reads as **404, never 403** (a 403 confirms the row exists);
  bulk endpoints drop out-of-scope ids from a client selection rather
  than trusting them.
- **"All machines"**: narrowed on the live page, but **refused outright
  as a scheduling target** for a restricted account (server-side at
  create/edit, not just hidden) — a stored schedule outlives the scope that created it.
- **Not affected**: the **audit log** — `audit.view` stays global, no
  group filtering (a partial security trail would be worse than none).
  Daily fleet-snapshot stays fleet-wide too (no current user); a
  restricted account just doesn't see the trend chart. Scheduled tasks
  are scope-checked when written, never when they fire.

### Guardrails against locking everyone out

- **Self-protection**: can't deactivate, delete, or change the role of your own account.
- **Last-admin protection**: `count_active_users_with_permission` checks,
  before committing, whether a change would leave *nobody* holding
  `user.manage`. The **role**-level check (editing a role to drop
  `user.manage`) is the one that bites in practice.

### Brute-force lockout, shared by password and TOTP

Both the password/LDAP-bind step and the TOTP-code step increment
`failed_login_attempts`/`locked_until`: **5 failures locks the account
for 15 minutes**, reset on any success.

### Generic failure messages, except for lockout

Nonexistent username, wrong password, inactive account, `oidc` account
hitting the password form — all render the identical "Invalid username
or password" (no enumeration). **Locked-out** gets a distinct message.

### TOTP: opt-in, self-service, with recovery codes

`local`/`ldap` only, not `oidc`. Self-service enrollment — only the
owner can scan the QR (confirmed by entering a real code before
anything persists). Rendered as inline SVG, not `<img src="data:...">`, so no `img-src` CSP exception needed.

Eight one-time recovery codes generated at enrollment (shown once,
argon2-hashed), regenerated wholesale on TOTP disable+re-enable or via
"Regenerate recovery codes" — which needs a fresh *TOTP* code, not a
recovery code, so one leaked code can't relearn the batch.

### WebAuthn/passkeys: a second factor alongside (or instead of) TOTP

`app.auth.webauthn` wraps py_webauthn — derives RP id/origin from the
live `Request`, not a config value (same reasoning as OIDC's redirect
URI: getting either wrong fails the ceremony, no sensible static
default), around one `WebAuthnCredential` row per authenticator
(credential id, public key, signature counter, device type,
`backed_up`). `local`/`ldap` only, same restriction as TOTP.

Both the RP origin and OIDC's redirect URI need `request.url.scheme`
correct — `ProxyHeadersMiddleware` (outermost in `app.main`) must
correct it from `X-Forwarded-Proto` first behind a reverse proxy, or
both derive "http" regardless of what the browser used, and WebAuthn
fails with "Unexpected client data origin". See `TRUSTED_PROXY_IPS`.

Both ceremonies (registration, login second-factor) follow the same
shape: a `GET .../options` route generates a challenge, hands back
browser-ready JSON, stashes it in a short-lived signed cookie (5 min,
`purpose` "register"/"authenticate" so one can't replay as the other);
`webauthn.js` decodes it, drives `navigator.credentials.create()`/
`.get()`, submits as a normal form POST to `.../verify` — no fetch round
trip once the ceremony completes. A non-advancing signature counter is
the spec's clone-detection signal and hard-fails; two authenticators
both stuck at count 0 (common for counter-less platform passkeys) is
accepted — py_webauthn only flags a **decrease or non-increase from a
previously nonzero count**.

A passkey works two ways, both ending at `_finish_login`: **primary**,
from step two of login, before any password check; or **second
factor**, when `POST /login` routes an account with TOTP or a
registered passkey to `/login/totp` instead of finishing directly (that
page shows the TOTP form only if enabled, and a passkey button whenever
one exists). `_resolve_webauthn_login_user` distinguishes the two
contexts for the shared options/verify routes — a `pending_totp` ticket
present means second-factor; its absence + a `username` value means
primary (WebAuthn's own cryptographic proof establishes identity either way).

### Role-enforced TOTP: real-time, not just a login-time redirect

`Role.require_totp` mandates a second factor — TOTP, or a registered
passkey, either satisfies it — for everyone holding a given role.
`app.auth.middleware` checks the *current* session's user's *current* role
and *current* `totp_enabled`/passkey state on **every request** (a cheap
in-memory pre-check, `_needs_second_factor_check`, keeps the extra
passkey-count query off the hot path for accounts that don't need it), so
toggling the flag on takes effect on the next request of every affected
user. A blocked user may reach exactly `GET`/`POST /account/totp/enroll`,
`GET /account/webauthn/register/options` + `POST .../verify`, the account
page they're linked from, and `/logout`; everything else redirects to the
TOTP enrollment page (or, for an `HX-Request`, sends `HX-Redirect` so htmx
navigates the whole page) — registering a passkey there satisfies the
block exactly like enrolling TOTP would.

By contrast `User.must_change_password` only steers `_finish_login`'s
post-login redirect (`app/web/routes/auth.py`), so an already-logged-in
user is unaffected until they log out and back in.

API tokens go through `app.auth.dependencies.get_api_token_user`, with the
same live check but a different outcome: a blocked token gets a flat 403
saying the account needs TOTP enrolled via the web UI first.
(`must_change_password` isn't API-gated today.)

OIDC accounts are unconditionally exempt from `require_totp`, since TOTP
isn't offered to them at all.

### OIDC's "session" is unrelated to the app's own

Authlib's Starlette integration stashes `state`/`nonce` across the redirect
to and from the provider in Starlette's own `SessionMiddleware`
(`app/main.py`, cookie `oidc_flow`, `SameSite=Lax` since `Strict` would
drop it on the provider's redirect back, 10-minute expiry). A completed
OIDC login then creates a real session via the same `create_session` path
local/LDAP logins use.

A fresh OIDC client is registered from current `AppSettings` on every login
attempt rather than once at startup, since issuer/client ID/secret are
editable at runtime; the cost is one extra discovery-document fetch per
login.

### Bootstrapping the first account

`scripts/create_admin.py` is the one way into a fresh deployment: creates
(or reuses) an "Administrator" role with every permission and a `local`
account with a prompted password. A CLI script, not an unauthenticated
"first-run setup" page.

`scripts/reset_account.py` is the same idea for an account already
locked out (forgotten password, lost TOTP device) — console-only, able
to bypass a locked account's second factor precisely because it needs shell access.

### Per-IP login rate limiting, alongside per-account lockout

`check_rate_limit` caps **30 attempts / 5 minutes** per source IP on
both `POST /login` and `POST /login/totp` — a Redis `INCR`+`EXPIRE`
fixed-window counter, same Redis *server* Celery uses but shares nothing
else with the queue. High by design: blunts credential stuffing/
enumeration at scale without locking out a shared office/VPN IP.

### Per-user API tokens: gated by a separate account-level flag, inheriting the role live

`ApiToken` gives each user bearer tokens (`dcpat_...`, only the SHA-256
hash stored) for two things, both under `/api/` and outside the session requirement:

- The REST API, for external scripts/automation, not the web UI itself.
- `POST /api/inform`, a per-user alternative to the shared
  `INFORM_TOKEN` — attributable, individually revocable.

A token authorizes whatever the owning user's role permits *at the
moment of each request* (re-checked, never a creation-time snapshot) —
revoking a permission or deactivating the account takes effect
immediately on every token it ever issued. Created/revoked from "My
account"; raw value shown once at creation.

Whether an account may have API tokens **at all** is separate —
`User.api_access_enabled`, unchecked by default, checked twice: **at
creation** (403 without the flag, form hidden) and **on every use**
(a token whose owner currently has the flag off is refused, same as a
deactivated owner) — unchecking cuts off every token that account ever
issued immediately. Only a `user.manage` admin sets it.

### Per-user UI language (i18n)

Each account has its own UI language (**My account → Language**),
self-service, defaulting to the deployment's own configured default if
never chosen (`User.locale` is nullable — `NULL` means "use the default,"
not a stored code) — `DEFAULT_LANGUAGE` in `.env`, English (`en`) unless
set otherwise; `scripts/setup.py` asks for this on a fresh install. See
[Installation](Installation.md)'s env var table.
`app.i18n` deliberately isn't `gettext`/Babel — a flat JSON file per
locale is the lowest-friction format for a translator with no Python
tooling, and there's no other i18n need (dates already render in
`Settings.tz`, not per-locale).

**Adding a language needs no code change** — drop a new
`app/i18n/locales/<code>.json` file:

```json
{
  "meta": { "code": "xx", "label": "Native name" },
  "strings": { "nav.dashboard": "...", "...": "..." }
}
```

`meta.code` must match the filename stem (mismatch skips + logs the
whole file rather than silently registering under the wrong code).
Doesn't need every key: `translate()` falls back key-by-key to English,
then the literal key, so a partial translation degrades to readable
English, never a blank/crash. Picked up on next process restart (parsed
once at first use, per process) — no migration, no Settings toggle.

Wired in three places: `app.auth.middleware` sets `request.state.locale`
on *every* request (anonymous default, or the account's choice once a
session resolves); the Jinja global `t(request, "some.key", **kwargs)`
looks it up (`**kwargs` `str.format`-substituted); `POST /account/locale`
(web) and its REST equivalents let an account change its choice — an
unrecognized code silently falls back to default rather than rejecting.

**Coverage today**: the entire app — every template either calls `t()`
for its strings or has none of its own (a pure macro/wrapper). Both
shipped locales (`en.json`, `cs.json`) translate every key. A new string
needs the same treatment — wrap it, add the key to every locale file,
per CLAUDE.md's i18n-parity rule. One page renders only in English by
design: `auth/totp_challenge.html` (reached before a session resolves to
an account, same reason `login.html` always renders in English) — its
markup is translated the same as anywhere else, it just never sees a
non-default locale in practice. `auth/totp_enroll.html`, reached from
the authenticated Account page, does render in the account's own language.

> [!WARNING]
> A translated string with literal quote marks or other HTML-special
> characters around a `{placeholder}` (e.g. `"No machines match
> \"{query}\"."`) needs `| safe` on the `t(...)` call, and the
> interpolated value pre-escaped with `| e`
> (`t(request, "...", query=q | e) | safe`) — otherwise Jinja's
> autoescape HTML-entity-escapes the *whole* string (the template's own
> literal `"` becomes `&#34;`), since it's now one expression instead of
> quotes as untouched markup around a separately-escaped `{{ q }}`. Bit
> `machines/list.html` this exact way — pre-escaping the interpolated
> value (not skipping `| safe` and losing the literal quotes) is what
> keeps it safe against a free-text search term containing HTML.

### The REST API: read and write, mirroring the web UI

`/api/v1/...` covers essentially everything doable from the web UI:
machines (create/update/delete, trigger updates/checks/power, package
listings, fleet-wide package search, on-demand test-connection/discover-
host-key/trust-host-key/refresh-facts/refresh-packages/refresh-services/
run-onboarding/recheck-readiness/logs, the pending-machines review queue),
machine groups (create/update/delete, membership, group- and "All
machines"-scoped actions), the ad-hoc bulk actions from the machine list,
scheduling (full CRUD plus enable/disable/run-now), users and roles (full
CRUD), the audit log (list/filter/export), a read-only slice of
Settings, and self-service account settings (currently just UI language —
see [Per-user UI language](#per-user-ui-language-i18n)). Split across
router modules under `app/web/routes/` (`api_v1.py` for
machines/groups/bulk, `api_v1_scheduling.py`, `api_v1_users.py`,
`api_v1_roles.py`, `api_v1_audit.py`, `api_v1_settings.py`,
`api_v1_dashboard.py` for the Dashboard's trend-snapshot history and the
scheduled fleet summary's latest output,
`api_v1_account.py` for self-service account settings), all mounted under
`/api/v1` in `app.main`.

- **Same permission, every time** — `require_api_permission(...)` with
  the exact `Permission` its web equivalent requires.
- **Same guardrails, reused** — last-admin/self-protection checks called
  from the same functions the web routes use, not re-derived.
- **Same underlying service calls** — machine/group actions go through
  `app.services.machine_actions`, the same Celery tasks a scheduled task
  or a web click would enqueue.
- **Typed confirmation becomes an explicit field** — an exact name (or
  `ALL MACHINES`) in the web UI becomes `confirm_name`/`confirm`/
  `confirm_username` in the JSON body.
- **No CSRF on `/api/v1/...`** — bearer-token only, consistent with the rest of `/api/`.
- **Audit logging works the same way** — `get_api_token_user` sets
  `request.state.user`, so `log_event` attributes an API action to the token's owner.

Deliberately still web-UI-only: **SSH key rotation** (a multi-step
human-paced process so the app never locks itself out mid-rotation);
**LDAP/OIDC config** and **AI provider credentials** (encrypted
secrets); **syslog forwarding config**. `GET /api/v1/settings` exposes
only version/commit, SSH public key/fingerprint, check intervals, and
audit retention — all read-only. Also excluded: the **SSH terminal** and
**AI chat** (inherently interactive, no REST shape); the "Fix it" flow
submitting a **fresh one-time credential** (vs. `POST /{id}/run-onboarding`,
which reuses the credential on file, and *is* in the API); **CSV bulk
import** (a script already has `POST /machines` or `POST /api/inform`).

#### Interactive docs: Swagger UI at `/api`

The REST API is browsable and callable from
[**Swagger UI**](https://swagger.io/tools/swagger-ui/) at `GET /api`,
generated from the app's own live route definitions (FastAPI's
`openapi()`), so docs and API can't drift apart.

> [!NOTE]
> **This requires being logged in AND `User.api_access_enabled`**, the
> same account-level flag (separate from role permissions) that gates
> actually creating an API token. `/api` and the schema it loads (`GET
> /openapi.json`, a hand-written route too — FastAPI's built-in
> `openapi_url` is disabled in `app.main` specifically so this check can
> gate it) are deliberately *not* on the public, bearer-token-only footing
> of `/api/v1/...` itself — an OpenAPI document is a complete map of every
> endpoint, parameter, and permission this app has, and an account with no
> API access can't do anything with that map anyway (there's no token to
> "Authorize" with). On the page, click **Authorize** and paste one of your
> own API tokens (see
> [Per-user API tokens](#per-user-api-tokens-gated-by-a-separate-account-level-flag-inheriting-the-role-live))
> to send requests — the same bearer-token auth the real API uses.

FastAPI's built-in docs route pulls Swagger UI from a CDN and inlines its
boot `<script>`, both incompatible with this app's CSP. `/api` is
therefore hand-written (`app/web/routes/api_docs.py`): a Jinja template,
`swagger-ui-dist` vendored at a pinned version, boot logic in
`app/web/static/js/swagger-init.js`.

> [!IMPORTANT]
> Swagger UI ships its **topbar/page-chrome layout** ("StandaloneLayout")
> in a *separate* bundle — `swagger-ui-standalone-preset.js` — from the
> main `swagger-ui-bundle.js`. Both must be vendored and loaded, in that
> order, or the page renders as a bare, chrome-less widget (or nothing at
> all, with a console warning).

The generated schema tags every `/api/v1/...` operation with a `bearerAuth`
HTTP security scheme (`app/main.py`'s `_custom_openapi()`), added by
rewriting the OpenAPI document rather than adding a `Security(...)`
dependency to every endpoint, since `get_api_token_user` already reads the
`Authorization` header itself. Web-only routes are left undecorated.

