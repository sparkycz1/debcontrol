# Architecture

## Stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.14.7 | |
| Web framework | FastAPI | async, OpenAPI schema for free |
| Templates / UI | Jinja2 + [htmx](https://htmx.org) (vendored locally) | no SPA build, no CDN |
| Database | PostgreSQL 18.6 | via `asyncpg` + SQLAlchemy 2.0 (async); image pinned to an exact patch |
| Migrations | Alembic | async engine |
| Cache / task queue | Redis 8.10.1 | queue via [`arq`](https://github.com/python-arq/arq); image pinned to an exact patch |
| SSH client | [AsyncSSH](https://asyncssh.readthedocs.io/) | async, strict host key verification |
| Cron scheduling | [`croniter`](https://github.com/kiorky/croniter) | parses standard 5-field cron expressions for Scheduling |
| Auth | `argon2-cffi`, `ldap3`, `Authlib`, `pyotp` + `qrcode` | local password hashing, LDAP bind, OIDC, TOTP — see "Authentication & RBAC" below |
| Reverse proxy (optional) | [Caddy](https://caddyproxy.com/) | automatic HTTPS, TLS 1.3 only, HTTP/3 |
| Packaging / lockfile | [`uv`](https://docs.astral.sh/uv/) | `uv.lock` is committed |
| Containers | Docker (multi-stage build) + Docker Compose | |

### Why server-rendered + htmx, not a SPA

The app is an internal admin tool, not a public product with rich
client-side interactivity requirements. Server-rendered Jinja2 templates
mean: no separate frontend build/deploy pipeline, no client-side API
tokens to protect, and a much smaller attack surface (no JS framework
supply chain, no bundler). htmx is used sparingly for the two truly
async-feeling interactions (discovering a host key fingerprint, testing a
connection) and is vendored locally rather than pulled from a CDN.

### Why arq over Celery

`arq` is a thin, async-native task queue on top of Redis — it fits
naturally into an already-async FastAPI app without pulling in Celery's
much larger dependency and configuration surface. The trade-off: `arq` is
currently in "maintenance only" mode upstream, and it pins `redis-py <6`
(see [Installation](Installation.md) / the root `README.md` for the
version-pinning implications). The **Scheduling** feature (cron-triggered
actions) is built entirely on top of `arq`'s existing `cron()` jobs plus
[`croniter`](https://github.com/kiorky/croniter) for expression parsing —
see "Scheduling: reusing actions, not reimplementing them" below — rather
than needing a heavier queue with built-in scheduling. If heavier queue
features are needed later (retries with complex backoff, multiple
queues/priorities), Celery or `ReArq` are the natural next steps.

### Why AsyncSSH over Paramiko

AsyncSSH is fully asynchronous and integrates directly with FastAPI's
event loop, avoiding a thread pool just to do SSH I/O. It's actively
maintained and supports modern algorithms (Ed25519, etc.).

## Project structure

```
app/
  audit.py      the single audit-log write path (hash chaining, verification)
  auth/         login (local/LDAP/OIDC), sessions, RBAC permissions, TOTP,
                per-IP rate limiting, per-user API tokens — see
                "Authentication & RBAC" below
  core/         config (pydantic-settings), logging, encryption, CSRF,
                editable app settings (app/core/app_settings.py)
  db/           SQLAlchemy models + async session
  schemas/      Pydantic schemas for forms
  scheduling/   cron-scheduled actions: registry, cron parsing, scheduler jobs
  services/     logic shared between manual routes and the scheduler
  ssh/          AsyncSSH client (host key pinning), facts, updates, power
  tasks/        arq worker + background jobs
  web/          FastAPI routers, Jinja2 templates, static files
alembic/        DB migrations
tests/          pytest (async, isolated from real infrastructure)
scripts/        helper scripts (secret generation, first-admin bootstrap,
                console-only account recovery, one-command upgrade)
wiki/           this documentation
```

## Authentication & RBAC

Every page requires a valid session except `/login`, `/login/totp`, the
`/auth/oidc/...` endpoints, `/healthz`, and `/api/*` (self-registration,
which has its own bearer-token auth) — enforced by one ASGI middleware,
`app.auth.middleware.require_auth`, registered in `app/main.py` before the
security-headers middleware (so CSP etc. still land on a redirect-to-login
response, not just on responses that reached a route — see the ordering
comment there for why registration order determines that).

### No accounts are ever auto-created

Every `User` row (`app/db/models/user.py`) is created inside debcontrol
first, through the **Users** page — never by LDAP or OIDC. `auth_provider`
(`local` / `ldap` / `oidc`) only decides *how* an already-existing account
proves who it is:

- **`local`**: a password stored here, argon2id-hashed (`app.auth.security`).
- **`ldap`**: the account's `username` is used as the LDAP username — no
  separate field for it. `app.auth.ldap.authenticate` does search-then-bind:
  a service account (configured in Settings) searches for the user's DN by
  username (with the username filter-escaped —
  `ldap3.utils.conv.escape_filter_chars` — as defense in depth on top of
  `username` already being restricted to a safe character set), then a
  *second*, independent connection binds as that DN with the password just
  entered. The user's own credentials are never used for anything else. An
  empty password is rejected before ever reaching the bind step — many
  directories treat that as a trivially-successful "unauthenticated bind,"
  which would otherwise let anyone in as any known username.
- **`oidc`**: redirected to the provider (Authlib, standard authorization-
  code flow); on callback, the account is matched by comparing `username`
  against a claim from the validated ID token — which claim is configurable
  in Settings (`AppSettings.oidc_username_claim`, default `email`), since it
  varies by provider. No account is created or updated from provider
  claims beyond that comparison.

The **login form itself** (`/login`) is shared by `local` and `ldap`
accounts — it doesn't ask which kind of account it is; `app.auth.login.
check_password` looks the username up first and branches internally. An
`oidc` account attempting the password form is rejected with the same
generic "Invalid username or password" message as a wrong password or an
unknown username (see "Generic failure messages" below) — from the outside,
none of those three cases are distinguishable.

### Sessions are server-side rows, not a signed cookie

`SECRET_KEY` (already present, "reserved for future session/signing use"
since the very first commit) would have made a stateless signed-cookie
session easy — that's deliberately not what `app.auth.sessions` does.
Instead, `UserSession` (`app/db/models/user_session.py`) is a DB row per
login; the cookie only carries an opaque random token, and only its
SHA-256 is stored (`token_hash`) — a DB leak alone doesn't hand over a live
session. The reason this matters: a stateless token is only as revocable as
its own expiry. A row is revocable immediately — disabling a user, an admin
resetting someone's password, or "log out everywhere" (own account or, for
an admin, someone else's) all just mark rows revoked, with no need to wait
out a token's lifetime. Sessions slide (`SESSION_IDLE_TIMEOUT`, 12h,
extended on each authenticated request) up to an absolute cap from creation
(`SESSION_ABSOLUTE_MAX`, 30 days).

The middleware needs a DB session to validate the cookie but runs outside
FastAPI's dependency injection, so it opens one via
`request.app.state.db_session_factory` — the same pattern
`app/tasks/jobs.py` already used for background jobs (`AsyncSessionLocal`
directly, no `Depends(get_db)`). The factory lives on `app.state` (set in
`app.main`'s `lifespan`) specifically so tests can point it at their own
SQLite engine instead of the real Postgres one — see `tests/conftest.py`'s
`_configure_app_for_tests`.

A short-lived, *signed but stateless* value is used for exactly one thing
where a DB row would be overkill: the few minutes between "password/LDAP
check passed" and "TOTP code confirmed" (`app.auth.sessions.
create_pending_totp_ticket`, an `itsdangerous.URLSafeTimedSerializer` keyed
by `SECRET_KEY`, 5-minute expiry). It carries no privilege by itself — it
doesn't grant a session — so statelessness there isn't a revocability
concern the way the login session itself is.

### RBAC: custom roles, a fixed permission set

An admin defines named `Role`s (`app/db/models/role.py`) and picks exactly
which of 12 fixed `Permission`s each one grants — `machine.view`/`.manage`,
`group.view`/`.manage`, `action.updates`, `action.power`, `scheduling.
view`/`.manage`, `audit.view`, `settings.view`/`.manage`, `user.manage` —
then assigns **one role per user** (not multiple; simpler mental model, and
nothing here needed a union-of-roles model). Permissions are
resource-grained, not per-object: there's no "can manage machine X but not
machine Y."

A `MANAGE` permission always also grants the matching `VIEW` permission
(`User.has_permission` / `role_has_permission`, `_MANAGE_IMPLIES_VIEW`) —
otherwise a role granted e.g. `machine.manage` but not `machine.view` (an
easy admin mistake, since granting manage obviously implies "can at least
look") would find every machines page returning 403, since routes are
gated with `require_permission` at the *view* level for GETs and additional
per-route permissions for state-changing ones. `action.updates`/
`action.power` are deliberately their own permissions, independent of
`machine.manage` — running updates and sending power commands aren't the
same trust level as editing a machine's connection details, and power
(destructive, no undo) is kept separate from updates.

`user.manage` bundles user AND role management under one permission —
splitting them further wasn't worth it, since a role editor who can't also
assign roles to users isn't useful on its own.

### Guardrails against locking everyone out

Two checks run before any change that could remove access, not just
document the risk:

- **Self-protection**: a user can't deactivate, delete, or change the role
  of their own account (`app/web/routes/users.py`) — that has to go through
  another admin.
- **Last-admin protection**: `app.auth.login.
  count_active_users_with_permission` (with `excluding_user_id` or
  `excluding_role_id`) checks, before committing, whether the change would
  leave *nobody* holding `user.manage`. The user-level check is defensive —
  in practice the acting admin always still counts, since reaching the
  route required `user.manage` in the first place — but the **role**-level
  check (`app/web/routes/roles.py`, editing a role to drop `user.manage`)
  is the one that actually bites: if the acting admin's own account uses
  that role, stripping the permission from it would remove their own access
  in the same stroke.

### Brute-force lockout, shared by password and TOTP

`User.failed_login_attempts`/`locked_until` are incremented by both the
password/LDAP-bind step and the TOTP-code step (`app.auth.login.
_register_failed_attempt`) — 5 failures locks the account for 15 minutes,
reset on any successful step. A locked-out user sees a distinct
"too many failed attempts" message rather than the generic invalid-
credentials one — see "Generic failure messages" below for why that
asymmetry is intentional.

### Generic failure messages, except for lockout

A nonexistent username, a wrong password, an inactive account, and an
`oidc` account trying the password form all render the identical "Invalid
username or password" — none of those is distinguishable from outside
(username enumeration). A **locked-out** account gets a different, specific
message instead: hiding "you're locked out" from a legitimate locked-out
user is worse than the marginal information it gives an attacker who
already knows they triggered it.

### TOTP: opt-in, self-service, with recovery codes

Available to `local`/`ldap` accounts, not `oidc` (the provider's own MFA,
if any, covers those instead). Enrollment is necessarily self-service — an
admin creates the account, but only the account's own owner can scan the
QR code with their own device (`GET /account/totp/enroll`, confirmed by
entering a real code before anything is persisted). The QR code is rendered
as inline SVG (`app.auth.totp.qr_code_svg`, `qrcode`'s `SvgPathImage`
factory) directly in the page rather than as an `<img src="data:...">` —
no `data:` URI needed, and nothing to carve an exception into the CSP's
`img-src` for.

Eight one-time recovery codes are generated at enrollment (shown once,
hashed with the same argon2 hasher as passwords) and regenerated wholesale
whenever TOTP is disabled and re-enabled, or explicitly via "Regenerate
recovery codes" — which deliberately requires a fresh *TOTP* code, not a
recovery code itself, so a single leaked recovery code (with a hijacked
session) can't be used to invalidate and relearn the whole batch.

### OIDC's "session" is unrelated to the app's own

Authlib's Starlette integration needs somewhere to stash `state`/`nonce`
across the redirect to and from the provider — that's Starlette's own
`SessionMiddleware` (`app/main.py`, cookie `oidc_flow`, `SameSite=Lax` since
`Strict` would drop it on the provider's redirect back, 10-minute expiry).
It's registered purely for that one exchange and has nothing to do with
`app.auth.sessions` — the app's actual login session, which is what a
completed OIDC login goes on to create via the same `create_session` path
local/LDAP logins use.

A fresh OIDC client is registered from current `AppSettings` on every login
attempt rather than once at startup, since the config (issuer, client
ID/secret) is editable at runtime from Settings — the cost is one extra
discovery-document fetch per login, an acceptable trade for picking up a
config change or a newly-enabled provider without restarting the app.

### Bootstrapping the first account

Since accounts are never auto-created and every page requires a login,
`scripts/create_admin.py` is the one way into a fresh deployment — a CLI
script (`docker compose exec web python scripts/create_admin.py --username
admin`) that creates (or reuses) an "Administrator" role with every
permission and a `local` account with a prompted password. Deliberately a
CLI script, not an unauthenticated "first-run setup" page — a page like
that is exactly the kind of thing that's easy to forget to disable/remove.

`scripts/reset_account.py` is the same idea for an account that's already
locked out with no way in through the web UI at all (forgotten password,
lost TOTP device) — also console-only, for the same reason, and able to
bypass a locked account's own second factor precisely because it requires
shell access on the server rather than anything web-reachable.

### Per-IP login rate limiting, alongside per-account lockout

The per-account lockout above stops one account from being guessed, but has
no limit on how many *different* usernames one source tries — that's what
`app.auth.rate_limit.check_rate_limit` closes: a coarse, high-limit-by-design
cap (30 attempts / 5 minutes) per source IP on both `POST /login` and
`POST /login/totp`, using a plain Redis `INCR`+`EXPIRE` fixed-window counter
on `app.state.arq_redis` (the same connection arq's job queue already holds
open — no second Redis client needed). "High-limit-by-design" is
deliberate: this exists to blunt obviously abusive volume (credential
stuffing, enumeration at scale), not to lock out a shared office/VPN egress
IP or someone who mistypes a password a few times.

### Per-user API tokens: read-only, and inheriting the role live

`app.db.models.api_token.ApiToken` gives each user their own bearer tokens
(`dcpat_...`, only the SHA-256 hash stored — same scheme as session
tokens) for two things, both under `/api/` and therefore outside
`app.auth.middleware`'s session requirement (see "Self-registration" below
for why that prefix is public in the first place):

- The read-only REST API (`app.web.routes.api_v1`) — `GET /api/v1/machines`,
  `/machines/{id}`, `/machine-groups` — meant for external scripts/
  monitoring, not the web UI.
- `POST /api/inform`, as a per-user alternative to the shared
  `INFORM_TOKEN` (which still works, for backward compatibility);
  attributable and individually revocable instead of one token every
  machine shares.

A token authorizes whatever its owning user's role permits *at the moment
of each request* (`app.auth.api_tokens.get_user_for_api_token` re-checks,
never a snapshot taken at creation) — revoking a permission or deactivating
the account takes effect on every token it ever issued immediately, the
same as it would on that user's browser session. Self-service, like TOTP:
created and revoked from "My account", and the raw value is shown exactly
once at creation.

## Security model

See "Authentication & RBAC" above for logins, sessions, and permissions —
everything below covers the rest of the app's security posture (SSH
handling, secrets at rest, audit integrity, HTTP hardening), most of which
predates auth and is unrelated to it. See the root `README.md`'s "What's
deliberately empty" section for what's still missing.

### SSH host key pinning

Covered in depth in
[SSH Host Key Verification](SSH-Host-Key-Verification.md). Summary: no
connection is ever made to a machine whose host key fingerprint hasn't
been explicitly confirmed by a human, and any later mismatch hard-fails
the connection instead of silently reconnecting.

### Secrets at rest

Machine passwords and the app's own SSH private key are encrypted in
Postgres using Fernet (AES + HMAC, from the `cryptography` package). The
encryption key lives only in the `ENCRYPTION_KEY` environment variable —
never in the database or the repo. This does **not** replace user
authentication; it protects SSH credentials from a database-only
compromise (a leaked backup, a misconfigured read replica, etc.).

### One shared SSH identity, not one key per machine

Rather than asking an operator to generate and paste a private key per
machine, debcontrol generates a single ed25519 keypair for itself on first
use (`app/ssh/identity.py`, `app/db/models/ssh_identity.py`) and reuses it
everywhere "SSH key" is the chosen auth method. The private half never
touches disk in plaintext — it's decrypted in memory only for the
duration of a connection. The public half is shown on the **Settings**
page; appending it to a machine's `~/.ssh/authorized_keys` is a manual
step today (see
[Managed Machine Requirements](Managed-Machine-Requirements.md)).
Per-machine passwords remain available as a fallback, with the UI calling
that out as not recommended.

Rotating this key (Settings → "Generate replacement key") generates a
*second* keypair into `pending_*` columns on the same singleton row rather
than replacing the active one immediately (`app.ssh.identity.
generate_pending_identity`) — every machine's `authorized_keys` still only
has the old public key at that point, so switching immediately would lock
the app out of all of them at once. The operator appends the pending public
key everywhere (alongside the old line, not replacing it yet), then
"Activate" swaps it in (`activate_pending_identity`). Getting the key onto
each machine is still a manual step either way — only the app's own side of
rotation is automated.

### Self-registration is not the same as trust

`POST /api/inform` lets a machine announce itself (IP, hostname, basic
facts it can read locally) using a shared bearer token
(`INFORM_TOKEN`) — meant for a first-boot/cloud-init script, see
[Managed Machine Requirements](Managed-Machine-Requirements.md). This only
ever creates a `PendingMachine` row for a human to look at; it grants no
access and establishes no trust. Turning a pending entry into a real,
manageable `Machine` still goes through the ordinary add-machine form and
the mandatory host-key discovery/confirmation flow — self-registration
just pre-fills the IP/name so there's less retyping.

### System updates: the first bulk SSH operation

Running `apt-get update` / `dist-upgrade` or `full-upgrade` / `autoremove` /
`autoclean` (**Machines → a machine → System updates**, or the same action
scoped to a group / "All machines") is the first feature that (a) needs
root on the target and (b) can legitimately run for a long time. Both
shaped the design:

- **A dedicated long timeout.** `open_connection`'s timeout only bounds
  the SSH handshake; the apt sequence itself gets its own budget
  (`UPDATE_TIMEOUT_SECONDS`, default 30 minutes) via arq's `func(...,
  timeout=...)`, distinct from the default job timeout every other
  background job uses. See `app/tasks/worker.py`.
- **Cleanup always runs, chained by `;` not `&&`.** If the upgrade step
  fails, `autoremove`/`autoclean` still run — they're independently
  useful and shouldn't be skipped because of an unrelated upgrade
  problem. The upgrade step's own exit status is still what determines
  whether the run is recorded as succeeded or failed. See
  `app/ssh/updates.py`.
- **`sudo -n` throughout**, never a bare `apt-get` assuming the
  connecting user is root. Non-interactive so a machine without
  passwordless sudo configured fails immediately with a clear error
  instead of hanging on a password prompt that can never be answered
  over a non-interactive SSH exec. See
  [Managed Machine Requirements](Managed-Machine-Requirements.md) for the
  sudoers line this expects.
- **Every run is a row, not just a Redis job.** `MachineUpdateRun`
  persists status/output/error/timestamps in Postgres — arq's own result
  storage is Redis-backed with a TTL and isn't a domain record, so it's
  not what the UI's run-detail and batch pages are built on. A `batch_id`
  (just a shared UUID, not a foreign key to anything) is the only thing
  connecting the runs from one group/"All machines" trigger — there's no
  separate "batch" table, since a `WHERE batch_id = ...` query is all a
  batch results page ever needs.
- **The scheduler-vs-worker split from facts refresh applies here too.**
  A group/"all" trigger creates every `MachineUpdateRun` row and enqueues
  every job in one request/commit, then returns — it never awaits the
  actual updates inline, for the same reason `refresh_all_machine_facts`
  doesn't: one slow or unreachable machine can't be allowed to hold up
  the others or the triggering request.

### Checking for updates without installing them

"Check for updates now" (`app/ssh/updates.check_updates`) still needs
root — an accurate count means actually refreshing the apt cache
(`apt-get update`), not trusting whatever's already cached — but the
enumeration step after that (`apt list --upgradable`) doesn't. It shares
`run_system_update`'s long timeout (via the same `func(...,
timeout=UPDATE_TIMEOUT_SECONDS)` pattern) and its own periodic sweep,
`check_all_machine_updates`, is the same fan-out-then-reschedule shape as
`refresh_all_machine_facts` — both run on the same
`FACTS_REFRESH_INTERVAL_SECONDS` cadence rather than introducing a
separate config knob for what's conceptually the same kind of periodic
check. A failed check (most commonly: sudo not configured yet) resets the
counts to "unknown" rather than leaving a stale number on screen or,
worse, implying zero updates.

Reboot-required detection is different: it needs no privileges at all
(comparing `uname -r` against the newest installed `linux-image-*`
package via `dpkg`), so it rides along in the regular, unprivileged facts
command instead of the root-requiring update check — see
`app/ssh/facts.py`.

### Power actions: fire-and-forget, double-confirmed, untracked

Reboot and shutdown (`app/ssh/power.py`) are deliberately the simplest
SSH action in the app:

- **No persistent history**, unlike `MachineUpdateRun`. There's nothing
  reliable to report — `shutdown -r/-h now` typically returns almost
  immediately, but the SSH connection can legitimately be torn down
  mid-response the moment the remote actually goes down, and that's
  treated as an expected outcome, not an error, rather than something
  worth recording as a "failure." The existing per-minute reachability
  check already shows the machine going offline (and, for a reboot,
  coming back online) — reusing that instead of inventing a second status
  system.
- **Confirmed twice, deliberately not with two stacked JS `confirm()`
  dialogs** (those get reflexively clicked through). The first step is a
  dedicated page stating exactly what's about to happen to which
  machine/group; the second is typing that machine's or group's exact
  name — checked server-side (`power_action` / `group_power_action` /
  `all_power_action` in the route layer), not just disabled-until-typed
  in the browser. "All machines" has no single name of its own, so it
  uses a fixed phrase (`ALL_MACHINES_CONFIRM_PHRASE = "ALL MACHINES"`)
  instead.
- **Same eligibility rule as updates**: a group/all action silently skips
  any machine without a pinned host key fingerprint (surfaced as a
  skipped-count message), since `open_connection` would refuse those
  anyway.

### Scheduling: reusing actions, not reimplementing them

**Scheduling** (`app.scheduling`) runs an existing action — system update,
update check, reboot, shut down — against a machine, a group, or "All
machines" on a cron expression, instead of a human clicking a button. A few
decisions shaped it:

- **An action registry, not a hardcoded list.** `app.scheduling.actions`
  defines a `ScheduledActionSpec` (key, label, description, optional
  per-action params, and a `run` function) and a `register_action()` call.
  `app.scheduling.builtin_actions.register_builtin_actions()` registers the
  four that exist today by wrapping the same functions the manual
  buttons use (see below) — nothing about the `ScheduledTask` model, the
  scheduler tick, or the "New scheduled task" form needs to change to add a
  future fifth action; it only needs one more `register_action()` call.
  It's idempotent and called from both `app.main` (so the web UI has
  something to list) and `app.tasks.worker` (so the scheduler tick does
  too) — either process can run without importing the other.
- **One shared implementation for "trigger this against N machines".**
  `_trigger_updates` / `_trigger_check_updates` / `_send_power_to_machines`
  used to live only in the machine-groups routes; they moved to
  `app.services.machine_actions` (taking the arq redis pool directly rather
  than a `Request`) so a scheduled run and a human clicking "Update now" on
  a group go through the exact same code path, including the same
  skip-unpinned-machines behavior.
- **A fixed one-minute tick, not a configurable self-rescheduling interval.**
  Unlike the facts/update-check sweeps (`FACTS_REFRESH_INTERVAL_SECONDS`),
  cron expressions are minute-grained by construction, so
  `run_due_scheduled_tasks` runs on a plain fixed `cron(second=0)` — the
  same shape as `ping_all_machines` — rather than needing a new setting.
  Each `ScheduledTask` keeps a denormalized `next_run_at` (computed via
  [`croniter`](https://github.com/kiorky/croniter) on create/edit/enable and
  advanced immediately when the tick fires it), so the tick itself is one
  indexed `WHERE next_run_at <= now` query, not N cron-expression
  evaluations every minute. Advancing `next_run_at` *before* the actual
  action job runs (not after) means a slow-running action can't cause the
  same task to be re-enqueued on the next tick before it has even started.
- **No per-run history — same reasoning as power actions.** A schedule
  firing only records a short `last_run_summary` ("Triggered for 3
  machine(s), 1 skipped.") plus `last_run_at`, not a persisted log of every
  firing. Whatever the action actually does already has its own record
  where that belongs (`MachineUpdateRun` for updates; the reachability
  check for power actions) — a second log of "the schedule fired" would
  just be a shadow of that.
- **Always UTC, no per-schedule timezone.** One less setting, and it matches
  every other timestamp already in the app.
- **Reboot/shutdown are schedulable, and deliberately not re-confirmed at
  fire time.** The double-confirmation UX (see below) is what stops a
  *human* from misclicking; a schedule someone deliberately created and can
  see, edit, and disable at `/scheduling` doesn't need — and can't
  sensibly have — a second confirmation step at 3am. Both are flagged
  `destructive=True` in the registry, which the "New scheduled task" form
  surfaces with a ⚠ next to their label so this is obvious before saving.
- **Target encoding: one `<select>`, not a type radio plus two
  conditionally-relevant pickers.** `app.scheduling.targets.encode_target`/
  `decode_target` fold target type + id into one string (`"all"`,
  `"machine:<uuid>"`, `"group:<uuid>"`) so the form has a single dropdown
  listing "All machines", every group, and every machine — no client-side
  JS needed to hide whichever selector doesn't apply.

### Audit log: who, what, outcome, when

**Audit** (`app.audit`, `app/db/models/audit_log.py`) records what happened,
its outcome, the source IP, and when — for essentially every mutating
action and every safeguard that blocked one (a typed confirmation that
didn't match, an unpinned host key, a bad self-registration token, a
rejected form, a failed or locked-out login). A few decisions:

- **`actor`** carries a human account's username for anything a logged-in
  user did, or a fixed label (`"scheduler (automatic)"`, `"retention policy
  (automatic)"`) for something a background job did on its own — it's
  `None` only for the handful of pre-login events (a failed login attempt
  itself, self-registration) where there's no account to attribute it to
  yet. `ip_address` is recorded alongside it, not instead of it, for every
  HTTP-triggered event.
- **One write path, called after the fact, never before.** `app.audit.
  log_event()` is the only thing that creates `AuditLogEntry` rows. It
  commits independently of whatever the caller's own transaction is doing,
  and every call site invokes it *after* its own commit (or, for a
  rejected/failed action, once there's nothing else left to commit) — never
  before — so a logging failure can never roll back the action it
  describes, and a validation failure that persisted nothing else still
  gets its own record. A logging failure is caught and swallowed (logged at
  `ERROR`, not raised) for the same reason: an audit-trail gap is far
  better than a broken update button.
- **Not a foreign key.** `target_type`/`target_id` are plain strings, and
  `target_label` is a snapshot of the target's name *at the time of the
  event* — a machine or group can be renamed or deleted later, and the
  trail has to read sensibly regardless (`app/db/models/machine_update_run.
  py`'s `batch_id` uses the same non-FK pattern for the same reason).
- **Scheduled firings are logged too, with a fixed actor.** `app.scheduling.
  jobs.run_scheduled_task` has no HTTP request (and so no IP) behind it —
  entries it writes use `actor="scheduler (automatic)"` instead, which is
  what distinguishes "this reboot happened because of a schedule" from a
  person's IP address in the log.
- **Routine background sweeps are not logged.** `ping_all_machines` (every
  minute, every machine) and the periodic facts/update-check sweeps would
  flood the log with heartbeats, not audit-worthy events — only a
  human-or-schedule-triggered action (and the safeguard that blocked one)
  gets an entry. The per-machine detail of what actually happened already
  lives in its own record (`MachineUpdateRun`, the reachability check) —
  the audit entry for a *trigger* doesn't duplicate that, it just answers
  "who/what IP asked for this, and when."
- **CSRF rejections aren't logged.** `verify_csrf` runs as a route
  dependency before the route body (and its DB session) even exists — hooking
  an audit write into it is a lower-level change than the rest of this
  feature and was left out of this pass.
- **No pagination cursor beyond offset.** Fine for an append-only table
  that a human is paging through; see below for what does exist to make
  this closer to a real tamper-evident log (hash chaining, retention).

### Audit log integrity: hash chaining, and its actual guarantee

Every `AuditLogEntry` is linked into a hash chain (`sequence`, `prev_hash`,
`entry_hash`) so that altering or deleting an entry is detectable, not just
"trust the database." Design:

- **What `entry_hash` covers.** A SHA-256 over a canonical (sorted-keys)
  JSON serialization of the entry's own fields, concatenated with the
  *previous* entry's `entry_hash` (`app.audit._compute_entry_hash`). Change
  anything about an entry — its summary, outcome, target, even its
  timestamp — and its hash no longer matches what a verifier recomputes;
  delete an entry and the next one's `prev_hash` no longer points at
  anything real. `app.audit.verify_chain` walks every chained entry in
  `sequence` order, recomputes each hash, and additionally compares the
  newest entry's hash against `AuditChainState.last_hash` — that last check
  is what catches deleting the *most recent* entries outright (which a
  simple walk over whatever rows remain wouldn't notice on its own).
  Reachable from the **Settings** page ("Verify chain integrity now"),
  which also logs the verification itself as an `audit_log.verify` entry.
- **`created_at` is assigned in Python, not by the database.** Every other
  timestamp in this app uses a Postgres `server_default=now()`; this one
  can't, because `log_event` needs the exact value *before* the insert —
  it's part of what gets hashed, and a server-assigned default isn't known
  until after the row exists.
- **Serialized through one locked row, not a hash of "whatever the last
  row happens to be."** `AuditChainState` is a dedicated one-row table;
  `log_event` reads it with `SELECT ... FOR UPDATE` and holds that lock for
  the rest of its transaction, so two audit writes racing from different
  requests — or from different *processes*, since both the web app and the
  arq worker write audit entries — can never both link a new entry to the
  same previous hash. Postgres enforces the lock for real; on SQLite (used
  in tests) `FOR UPDATE` is accepted but is a no-op, which is fine there
  since aiosqlite has no real concurrent writers to race in the first
  place.
- **What this doesn't protect against.** Direct database access (a
  superuser editing rows and recomputing the hash chain correctly to
  match) is not defended against — there's no external anchor (no
  write-once storage, no periodic hash publication elsewhere) to compare
  against, only internal self-consistency. This catches accidental
  corruption and a casual attempt to quietly edit or remove an entry
  in-place; it is not a substitute for restricting who can reach the
  database at all.
- **Entries from before this feature existed have no chain.**
  `sequence`/`prev_hash`/`entry_hash` are nullable for exactly that reason
  — `verify_chain` skips unchained rows rather than reporting every one of
  them as broken.

### Audit log retention: the first setting editable through the UI

`AppSettings.audit_log_retention_days` (`app/db/models/app_settings.py`),
set from the **Settings** page, controls how many days of audit history
`app.tasks.jobs.purge_old_audit_log_entries` keeps — a fixed daily sweep
(same shape as `ping_all_machines`, since only *how many days* needs to be
configurable, not how often the sweep itself runs). `None` (the default)
means keep forever; deliberately not defaulting to some finite window,
since silently discarding audit history is a much worse surprise than an
unbounded table.

This is the first value in the whole app that's editable at runtime
through the UI, rather than fixed at deploy time via `.env` — see
`app/db/models/app_settings.py` for why that's a separate table/mechanism
from `app.core.config.Settings` rather than, say, a form that rewrites
`.env`. Purging only ever removes the *oldest* rows (`created_at <
cutoff`); it can never touch `AuditChainState` or the newest entries, so
it can never invalidate `verify_chain` for whatever remains — a verifier
just starts from whatever the current oldest surviving entry is. The purge
itself is logged (`audit_log.purge`, actor `"retention policy
(automatic)"`) with how many entries were removed.

### Audit log export and syslog forwarding: the DB row is always the truth

`GET /audit/export?format=csv|json` (`app/web/routes/audit.py`) respects the
same `q`/`outcome` filters as the list view and streams every matching
`AuditLogEntry` back as a download — a plain `<a href>` link, not a POST,
since the only side effect is an `audit_log.export` entry for the export
itself (auditing who pulled a copy of the audit log is exactly the kind of
thing worth recording), not anything CSRF-worthy. Not paginated: it fetches
every matching row in one request, acceptable for an infrequent,
admin-triggered action on a self-hosted tool's own table.

`app.audit_syslog.forward_to_syslog` is a live *mirror*, not an alternative
record: `log_event` calls it once per entry, right after that entry's own
commit succeeds, using whatever `AppSettings.syslog_*` is currently
configured (UDP, plain TCP, or TCP-over-TLS — RFC 5424 message format,
RFC 6587 octet-counting framing for the two TCP modes). It's deliberately
best-effort and fire-and-forget: a SIEM being unreachable, slow, or
misconfigured must never be allowed to block or fail the action being
audited, so any delivery failure is caught, logged, and swallowed inside
its own nested `try`/`except` — the outer one that handles a failure to
*write* the entry never even sees it. All socket I/O is blocking
(`socket`/`ssl`, simplest for a one-shot send with no connection to keep
alive) so it always runs via `asyncio.to_thread`, the same pattern
`app.auth.ldap`'s synchronous `ldap3` calls use to stay off the event loop.

### Version metadata: baked in at build time, not read from `.git`

The Settings page shows `APP_VERSION` (`app/core/version.py`, bumped by
hand per release — currently `0.1.0`, no automated semantic versioning yet)
and the exact git commit the running image was built from, linked to
GitHub. The Docker image never contains a `.git` directory (see
`.dockerignore`/the `Dockerfile`'s `COPY`s), so the commit has to be baked
in at build time instead: a `GIT_COMMIT` build arg becomes an `ENV` in the
image (`Dockerfile`), set from `docker-compose.yml`'s `args:` block, which
in turn reads it from the `GIT_COMMIT` shell variable —
`scripts/upgrade.sh` exports `GIT_COMMIT=$(git rev-parse HEAD)` right
before building, so every upgrade stamps the image with the commit it just
pulled. Running locally without Docker, `GIT_COMMIT` is never set, so
`get_git_commit()` falls back to asking the local `.git` checkout directly.

### CSRF protection: a double-submit cookie, provisioned centrally

A double-submit cookie pattern: a random `csrftoken` cookie (`SameSite=
Strict`, `HttpOnly`) is set on GET requests that render a form, and the
same value must be echoed back as a hidden field on POST — predates login
(from the very first commit) and still doesn't depend on it, deliberately:
it protects the login form itself too (a "login CSRF" — tricking a victim's
browser into authenticating as the *attacker's* account — is a real
enough class of attack to guard against even pre-session).

Since `app.auth.middleware` now runs on every request anyway, it ensures a
token exists and stashes it on `request.state.csrf_token` centrally, so new
pages (the nav's logout button, "My account") can just read that instead of
each doing their own `get_or_create_csrf_token`/`set_csrf_cookie` dance —
`get_or_create_csrf_token` (`app/core/csrf.py`) checks
`request.state.csrf_token` before minting a *second*, different token, so
existing routes that still do their own dance stay consistent with
whichever token the middleware already decided on for that request.

### HTTP security headers

Set unconditionally by the app itself (`app/main.py`), regardless of which
reverse proxy — if any — sits in front of it: a strict
Content-Security-Policy (no inline scripts/styles, no external origins),
`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, and a restrictive `Permissions-Policy`.
`Strict-Transport-Security` is added when `APP_ENV=production`. The
bundled Caddy config (see [Reverse Proxy: Caddy](Reverse-Proxy-Caddy.md))
additionally sets its own HSTS header and strips the `Server` header at
the edge.

### Container hardening

The runtime image runs as a non-root user, is built via a multi-stage
Dockerfile (build tools never ship in the final image), and the app's own
port is bound to `127.0.0.1` only — it never listens on a
publicly-reachable interface directly. Postgres and Redis ports aren't
published to the host at all by default.

### Deliberately deferred

- Per-schedule timezones (everything is UTC) and a scheduled "power on" to
  pair with scheduled shutdown (there's no way for the app to power on a
  machine that's off — see [Managed Machine
  Requirements](Managed-Machine-Requirements.md)).
- CSRF rejections aren't audit-logged (rate-limit rejections are, as
  `auth.rate_limited` — see "Per-IP login rate limiting" above).
- The read-only REST API (`/api/v1/...`) has no write counterpart yet —
  creating/editing machines is web-UI-only.
