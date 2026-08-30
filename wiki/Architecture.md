# 🏗️ Architecture

## 🧱 Stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.14.7 | |
| Web framework | FastAPI | async, OpenAPI schema for free |
| Templates / UI | Jinja2 + [htmx](https://htmx.org) (vendored locally) | no SPA build, no CDN |
| Database | PostgreSQL 18.6 | via `asyncpg` + SQLAlchemy 2.0 (async); image pinned to an exact patch |
| Migrations | Alembic | async engine |
| Task queue / broker | Redis 8.10.1 | **broker _and_ result backend** for [Celery](https://docs.celeryq.dev/); also backs the login rate limiter; image pinned to an exact patch |
| Background tasks | [Celery](https://docs.celeryq.dev/) + Celery Beat | one `worker` process pool, exactly one `beat` scheduler — see [Background tasks](#background-tasks-celery-and-celery-beat) |
| SSH client | [AsyncSSH](https://asyncssh.readthedocs.io/) | async, strict host key verification |
| Cron scheduling | [`croniter`](https://github.com/kiorky/croniter) | parses standard 5-field cron expressions for Scheduling |
| Auth: passwords | [`argon2-cffi`](https://github.com/hynek/argon2-cffi) | argon2id hashing for local accounts |
| Auth: LDAP | [`ldap3`](https://github.com/cannatag/ldap3) | pure Python, no system libldap headers needed |
| Auth: OIDC | [`Authlib`](https://authlib.org/) | discovery, authorization-code flow, ID token validation |
| Auth: TOTP | [`pyotp`](https://github.com/pyauth/pyotp) + [`qrcode`](https://github.com/lincolnloop/python-qrcode) | RFC 6238 two-factor codes; QR rendered as inline SVG |
| Reverse proxy (optional) | [Caddy](https://caddyproxy.com/) | automatic HTTPS, TLS 1.3 only, HTTP/3 |
| Packaging / lockfile | [`uv`](https://docs.astral.sh/uv/) | `uv.lock` is committed |
| Containers | Docker (multi-stage build) + Docker Compose | |

### Dependency version notes

- **`redis-py` (the client library) no longer carries an upper pin.** It
  used to be capped at `<6` for one reason only: the **previous task queue**
  refused redis-py 6.x (see
  [Why Celery](#why-celery-and-why-the-project-moved-off-the-previous-queue)).
  That cap retired with it — the effective ceiling now comes from
  `kombu[redis]` (Celery's transport
  layer), which declares `redis >=4.5.2,!=4.5.5,!=5.0.2,<6.5`. Repeating a
  stricter bound in this repo would only hide the real one, so
  `pyproject.toml` keeps just the lower bound (`redis[hiredis]>=5.3.1`) and
  the resolver currently lands on **redis-py 6.4.0**.
  > [!NOTE]
  > The client library version and the Redis **server** version are
  > independent of each other. redis-py 5.x and 6.x both talk to a Redis
  > 8.x server perfectly well — do not try to "match" them.
- Versions in `pyproject.toml` are lower bounds (`>=`); exact, reproducible
  versions for installation come from the committed `uv.lock`.
- Docker images for stateful services (`postgres:18.6`, `redis:8.10.1`,
  and `caddy:2.11.4` if used) are pinned to an exact patch version rather
  than a floating tag — see [Installation](Installation.md#updating) for
  why and how that's bumped deliberately.

### Why server-rendered + htmx, not a SPA

The app is an internal admin tool, not a public product with rich
client-side interactivity requirements. Server-rendered Jinja2 templates
mean: no separate frontend build/deploy pipeline, no client-side API
tokens to protect, and a much smaller attack surface (no JS framework
supply chain, no bundler). htmx is used sparingly for the two truly
async-feeling interactions (discovering a host key fingerprint, testing a
connection) and is vendored locally rather than pulled from a CDN.

The same reasoning shaped the visual design pass over the whole UI: it's
one shared stylesheet (`app/web/static/css/style.css`) applied to a small,
consistent set of utility classes every template already used (`.button`,
`.panel`, `.data-table`, `.badge`, `.alert`, `.form`, `.page-header`, ...)
rather than a per-template redesign — a design-token change (spacing,
color, radius) or a component fix (e.g. the alert icon layout below)
propagates everywhere at once, and no template needed to change markup to
pick it up. The one interactive addition — a collapsible mobile nav — is
a checkbox-driven CSS toggle (`.nav-toggle`), not JavaScript: it works
under the same strict CSP (no inline scripts) without adding a script,
and stays keyboard-operable (visually hidden via clip/absolute
positioning, not `display: none`, so Tab still reaches it). The active
nav link is computed from `request.url.path` directly in `base.html`, not
from a per-page flag every route would otherwise need to remember to set.

One layout detail worth calling out because it looks like it should be
simpler than it is: `.alert`'s icon is CSS `::before` content positioned
*absolutely* inside reserved left padding, not a flex sibling of the
message. Several alerts in this app render a variable number of `<p>`
tags (one per validation error) inside a single `.alert` div — as flex
siblings of the icon, those would lay out in a row instead of stacking;
absolutely positioning the icon out of flow lets the message content keep
its normal block layout regardless of how many paragraphs it has.

### Background tasks: Celery and Celery Beat

All background work runs on **Celery**, with the existing Redis instance
(`REDIS_URL`) as **both** the broker and the result backend. That covers
three different kinds of work:

| Kind | Examples | Triggered by |
|---|---|---|
| **Periodic sweeps** | reachability ping, facts refresh, package refresh, update-availability check | Celery **Beat**, on `timedelta` schedules read from Settings |
| **Daily housekeeping** | audit-log purge, fleet snapshot, snapshot purge | Celery **Beat**, on `crontab()` schedules |
| **One-off, per machine** | SSH connect test, facts/packages refresh, apt update, update preview, reboot/shutdown | a route or another task calling `some_task.delay(...)` |

Two Compose services back this: **`worker`** (executes tasks; safe to
scale) and **`beat`** (publishes the schedule; **must never be scaled past
one replica** — every replica would publish the same entries, so each daily
purge would fire once per replica).

#### Why Celery, and why the project moved off the previous queue

Until version 0.2.0 the queue was
[`arq`](https://github.com/python-arq/arq) — thin, async-native, and a
natural fit for an async FastAPI app without Celery's configuration
surface. Two things pushed the project off it:

- **It is in maintenance-only mode upstream**, and its hard
  `redis-py <6` pin had started dictating an unrelated dependency's version
  for the whole project (see [Dependency version notes](#dependency-version-notes)).
- **Its `cron()` is minute-grained only.** The three configurable
  fleet sweeps needed arbitrary second-level intervals, so each one was
  written as a *self-rescheduling* job: it did its work and then re-enqueued
  itself with `_defer_by=timedelta(...)`, with a hand-written startup hook
  to kick the first one off. That was a workaround, and a fragile one — if
  a job ever died before its re-enqueue, that sweep simply stopped forever
  with nothing to notice.

Celery Beat supports `timedelta(seconds=N)` schedules natively, so all of
that self-rescheduling boilerplate is gone: every periodic job is now a
plain declarative entry in `celery_app.conf.beat_schedule` and each job body
just does its work and returns. Beat owning the cadence also means a dead
worker no longer silently ends a sweep — the next tick is published
regardless.

What Celery costs in return: a **noticeably larger dependency tree**
(`kombu`, `billiard`, `amqp`, `vine`, `click-*`) and the two design points
below, neither of which the async-native queue needed.

#### Async bodies, sync task wrappers

Celery tasks are synchronous; this app's logic (SQLAlchemy async sessions,
`asyncssh`) is not. Every job is therefore written twice over, deliberately:

```python
async def _refresh_machine_facts(machine_id: str) -> dict[str, Any]:
    ...  # the real work

@celery_app.task(name="app.tasks.jobs.refresh_machine_facts")
def refresh_machine_facts(machine_id: str) -> dict[str, Any]:
    return asyncio.run(_refresh_machine_facts(machine_id))
```

The wrapper is kept to exactly one line so no logic ever lives on the sync
side. Tests call the `_`-prefixed coroutine directly.

Every task is registered with an **explicit `name=`** rather than Celery's
auto-derived dotted path. Beat entries, `.delay()` call sites, and messages
already sitting in Redis all refer to a task by name — deriving it from the
file layout would mean that moving or renaming a module silently orphans
queued messages instead of failing loudly. The names happen to match today's
paths; they are a contract, not a coincidence.

> [!WARNING]
> **`celery.exceptions.TimeoutError` is not the builtin `TimeoutError`** —
> it does not subclass it. A few routes enqueue a task and block on its
> result inline; every one of them must catch
> `from celery.exceptions import TimeoutError as CeleryTimeoutError`.
> Catching the builtin compiles fine and turns the timeout branch into dead
> code. Related: `AsyncResult.get()` is a **blocking, synchronous** call,
> so those routes wrap it in `asyncio.to_thread(...)` — calling it straight
> from an `async def` handler stalls the entire event loop, and every other
> concurrent request with it, for the full duration.

#### Fork safety: the DB engine is rebuilt in every worker child

> [!IMPORTANT]
> This is the subtlest part of the Celery setup, and the kind of bug that
> **never shows up in the test suite** — tests run against in-memory SQLite
> in a single process. It only bites a real Postgres deployment.

Celery's default worker pool is **prefork**. The parent process imports the
entire application — including `app/db/session.py`, which builds its async
engine and session factory as module-level singletons at import time — and
*then* forks its child processes. Left alone, every child would inherit the
same asyncpg connection pool: the same already-open TCP sockets to Postgres,
shared across the parent and all its siblings.

That is not merely untidy. Two processes writing into one socket interleave
their protocol frames; one process closing a connection yanks it out from
under another; per-connection state (prepared-statement cache, transaction
status) becomes a lie in whichever process did not create it. The symptoms
are sporadic `InterfaceError`/`InternalClientError`, results arriving for
the wrong query, or a wedged worker — never a clean, obvious crash.

`app/tasks/celery_app.py` therefore connects a **`worker_process_init`**
signal handler that discards what the child inherited and builds a fresh
engine and session factory inside each forked child, after the fork:

```python
@worker_process_init.connect
def _init_worker_process(**kwargs):
    from app.db import session as db_session
    db_session.engine = create_async_engine(...)
    db_session.AsyncSessionLocal = async_sessionmaker(bind=db_session.engine, ...)
    register_builtin_actions()   # idempotent; each child needs its own registry
```

> [!CAUTION]
> The inherited engine is **never** `dispose()`d — that would close sockets
> the parent and every sibling are still using. It is abandoned, not closed.

For that rebind to be visible, **every job body must reach the factory
through the module** — `db_session.AsyncSessionLocal(...)`, never
`from app.db.session import AsyncSessionLocal`. A name bound at import time
would keep pointing at the parent's pool no matter what the signal handler
does. If you add a new task, follow that convention.

### 🔑 Why AsyncSSH over Paramiko

AsyncSSH is fully asynchronous and integrates directly with FastAPI's
event loop, avoiding a thread pool just to do SSH I/O. It's actively
maintained and supports modern algorithms (Ed25519, etc.).

## 📂 Project structure

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
  tasks/        Celery app (beat schedule, fork-safety hook) + task bodies
  web/          FastAPI routers, Jinja2 templates, static files
alembic/        DB migrations
tests/          pytest (async, isolated from real infrastructure)
scripts/        helper scripts (secret generation, first-admin bootstrap,
                console-only account recovery, one-command upgrade)
ansible/        onboarding playbook — see Ansible-Onboarding.md
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

`SECRET_KEY` (present since the very first commit, and used elsewhere today
for the OIDC-flow session and the pending-TOTP token — see "OIDC's
'session' is unrelated to the app's own" and "TOTP" below) would have made
a stateless signed-cookie session just as easy to build for logins
themselves — that's deliberately not what `app.auth.sessions` does.
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

One consequence worth stating explicitly, since it's easy to assume
otherwise: because permissions are resource-grained rather than
per-object, **any two users whose roles both grant a given permission
already see the exact same things for it** — two users with `machine.view`
see every machine, not just "their" group's; two with `scheduling.view`
see every scheduled task, including ones targeting machines or groups they
had no hand in creating. There's no concept of a schedule, machine, or
group being "private" to whoever made it, and no per-group scoping of any
permission. If your team wants users limited to a subset of machines/
groups (rather than all-or-nothing per feature), that's a real gap today,
not a bug — it would need a new, separate access model layered on top of
this one, not a change to how `Permission` currently works.

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

### Role-enforced TOTP: real-time, not just a login-time redirect

`Role.require_totp` lets an admin mandate TOTP for everyone holding a given
role. The naive version of this — checking it once at login and redirecting
to enrollment — has an obvious hole: an already-logged-in user (or a user
whose role gets this flag turned on mid-session) keeps full access until
their session naturally ends. Contrast with `User.must_change_password`,
which really does work that way: it only steers `_finish_login`'s
post-login redirect (`app/web/routes/auth.py`), so a user who's already
logged in when an admin resets their password keeps going about their
business, unaffected, until they log out and back in. That's an accepted
gap for a forced-password-reset (worst case, they change it next time), but
"this role's users must have 2FA" is a stronger security promise, and this
feature deliberately holds it to a stronger standard: `app.auth.middleware`
checks the *current* session's user's *current* role and *current*
`totp_enabled` state on every single request, not once at login. Toggling
the flag on takes effect for every affected user's very next request,
session or no session change involved. A blocked user is allowed exactly
two things: `GET`/`POST /account/totp/enroll` (to fix the problem) and
`/logout` (already public, no session needed at all) — everything else
redirects there (or, for an `HX-Request`, sends `HX-Redirect` so htmx
navigates the whole page rather than swapping the redirect target's HTML
into a fragment).

API tokens go through a separate check
(`app.auth.dependencies.get_api_token_user`) with the same live-check
philosophy, but a different outcome: an API token has no interactive way to
scan a QR code, so instead of trying to redirect it anywhere, a blocked
token gets a flat 403 explaining the account needs TOTP enrolled via the
web UI first. (`must_change_password` isn't API-gated at all today, an
inconsistency worth revisiting — see "Deliberately out of scope" if it's
ever promoted to the same "must be dealt with immediately" tier as this.)

OIDC accounts are unconditionally exempt from `require_totp`, for the same
reason TOTP isn't offered to them at all (previous section) — enforcing an
unsatisfiable requirement would just be a permanent lockout with no way
out, not a security improvement.

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
on `app.state.redis` — a plain `redis.asyncio` pool opened once in
`app.main`'s lifespan, so a burst of login attempts doesn't open a fresh
connection per request. It hits the same Redis *server* Celery uses but
shares nothing else with the queue. "High-limit-by-design" is
deliberate: this exists to blunt obviously abusive volume (credential
stuffing, enumeration at scale), not to lock out a shared office/VPN egress
IP or someone who mistypes a password a few times.

### Per-user API tokens: gated by a separate account-level flag, inheriting the role live

`app.db.models.api_token.ApiToken` gives each user their own bearer tokens
(`dcpat_...`, only the SHA-256 hash stored — same scheme as session
tokens) for two things, both under `/api/` and therefore outside
`app.auth.middleware`'s session requirement (see "Self-registration" below
for why that prefix is public in the first place):

- The REST API (`app.web.routes.api_v1*` — split across several modules,
  see "The REST API: read and write, mirroring the web UI" below) — meant
  for external scripts/automation, not the web UI itself.
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

Whether an account can have API tokens *at all* is a separate, admin-set
boolean on the account itself — `User.api_access_enabled` — distinct from
the role-based `Permission` matrix above. A role's permissions decide
*what* a token can do once it exists; this flag decides *whether the
account may have one in the first place*, and is unchecked by default for
every new account. It's checked in two places, both mirroring the existing
`is_active` check right next to them:

- **At creation** — `create_own_api_token` (`app/web/routes/auth.py`)
  rejects a new token (403) for an account without the flag, and the
  Account page hides the "create token" form (showing a note to ask an
  admin instead) rather than just letting the POST fail.
- **On every use** — `app.auth.api_tokens.get_user_for_api_token` refuses
  a token whose owning user currently has `api_access_enabled = False`,
  in the same function and right alongside where it already refuses one
  whose owner is `is_active = False`. An admin unchecking the box cuts off
  every token that account has ever issued immediately — no separate
  revocation step, the same way deactivating an account already works.

Only a `user.manage` admin can set the checkbox, from the Users "add"/
"edit" forms — the same gate as every other admin-set field there (e.g.
`is_active`).

### The REST API: read and write, mirroring the web UI

`/api/v1/...` started as read-only (`GET /machines`, `/machines/{id}`,
`/machine-groups`) and now covers essentially everything meaningfully
doable from the web UI: machines (create/update/delete, trigger updates/
checks/power, package listings, fleet-wide package search), machine groups
(create/update/delete, membership, group- and "All machines"-scoped
actions), the ad-hoc bulk actions from the machine list, scheduling
(full CRUD plus enable/disable/run-now), users and roles (full CRUD, with
the exact same self-protection and last-admin guardrails the web routes
already enforce — reused, not reimplemented), the audit log (list/filter/
export), and a read-only slice of Settings. Split across several router
modules under `app/web/routes/` (`api_v1.py` for machines/groups/bulk,
`api_v1_scheduling.py`, `api_v1_users.py`, `api_v1_roles.py`,
`api_v1_audit.py`, `api_v1_settings.py`) once a single file would have
gotten unwieldy, all mounted under the same `/api/v1` prefix in
`app.main`.

A few design rules keep this a second door into the same house, not a
looser one:

- **Same permission, every time.** Every route uses
  `require_api_permission(...)` with the exact `Permission` its web
  equivalent requires — never a new, looser, or stricter one.
- **Same guardrails, reused.** The user/role guardrails
  (`app.auth.login.count_active_users_with_permission`, self-protection
  against deactivating/deleting/reassigning your own account) are called
  from the same functions the web routes use, not re-derived.
- **Same underlying service calls.** Machine/group actions call
  `app.services.machine_actions`, which enqueues the same Celery tasks the
  web routes do — a scheduled task, a web click, and an API call all end
  up running the identical background task.
- **Typed confirmation becomes an explicit field.** Where the web UI
  requires typing a machine's/group's exact name (or a fixed phrase like
  `ALL MACHINES`) before a destructive action (power, delete), the API
  requires the equivalent value in the JSON body (`confirm_name`,
  `confirm`, or — for deleting a user — `confirm_username`) instead of
  silently skipping the safeguard just because there's no browser involved.
- **No CSRF on `/api/v1/...`**, same as before — bearer-token auth only,
  consistent with `/api/inform` and the rest of `/api/`.
- **Audit logging works the same way.** `app.auth.dependencies.
  get_api_token_user` now sets `request.state.user` for API-token
  requests (previously only cookie-session requests via
  `app.auth.middleware` had it set) — so `app.audit.log_event`'s automatic
  actor resolution attributes an API-triggered action to the token's
  owning user, exactly like a browser-driven one, with no route needing to
  pass `actor=` explicitly just because the request came in over the API.

What's deliberately still web-UI-only, and why: SSH key rotation
(`/settings/ssh-key/...`) is a multi-step, human-paced process specifically
designed so the app is never locked out of every machine mid-rotation —
automating the "activate" step over an API makes it too easy to fire before
the public key has actually been copied everywhere, with no way for the
server to tell the difference. LDAP/OIDC configuration carries encrypted
secrets and changes how *every* login on the instance is authenticated — a
bug or a stolen token reconfiguring the login provider is a much bigger
blast radius than anything else this API can do, so it's neither readable
nor writable here. Syslog forwarding configuration is lower-risk but still
a live security-monitoring integration point, left for the web UI for the
same reasoning pending an explicit need. `GET /api/v1/settings` exposes
only what's unambiguously safe to read over a bearer token: version/commit
info, the SSH public key/fingerprint (meant to be copied elsewhere anyway),
background-check intervals, and audit log retention.

#### Interactive docs: Swagger UI at `/api`

The whole REST API above is browsable and directly callable from
[**Swagger UI**](https://swagger.io/tools/swagger-ui/), served at plain
`GET /api`. It's generated straight from the app's own live route
definitions (via FastAPI's `openapi()`), so the docs and the API can never
silently drift apart — there's no separate spec file to forget to update.

> [!NOTE]
> **This requires being logged in**, same as every other page. `/api` and
> the schema it loads (`GET /openapi.json`) are deliberately *not* on the
> same public, bearer-token-only footing as `/api/v1/...` itself — an
> OpenAPI document is a complete map of every endpoint, parameter, and
> permission this app has, and handing that to anyone with network access,
> logged in or not, would be a reconnaissance gift. Once you're on the
> page, click **Authorize** and paste one of your own API tokens (see
> [Account](Home.md), or the "Per-user API tokens" section above) to
> actually send requests from it — that's the same bearer-token auth the
> real API uses, nothing special to the docs page.

**Self-hosted, not the CDN default.** FastAPI's own built-in docs route
normally pulls Swagger UI's JS/CSS from jsdelivr's CDN and inlines its own
`<script>` to boot it — both are flatly incompatible with this app's CSP
(`script-src 'self'`, `style-src 'self'`, no CDN, no inline scripts). So
`/api` is a hand-written route (`app/web/routes/api_docs.py`) instead: a
plain Jinja template, `swagger-ui-dist` vendored locally (same convention
as htmx and xterm.js — pinned to an exact version, no CDN reference at
runtime), and Swagger UI's boot logic in its own external file
(`app/web/static/js/swagger-init.js`) instead of inline.

> [!IMPORTANT]
> Swagger UI ships its **topbar/page-chrome layout** ("StandaloneLayout")
> as a *separate* bundle — `swagger-ui-standalone-preset.js` — from the
> main `swagger-ui-bundle.js`. Plenty of examples floating around only
> reference the one file and quietly render a bare, chrome-less widget (or,
> depending on version, nothing at all with a console warning). Both files
> must be vendored and loaded, in that order, for the page shown in the
> screenshot-worthy version of Swagger UI to actually appear. This was only
> caught by loading the real page in a real browser and reading the console
> — see the note in `wiki/Development.md` about verifying anything
> CSP-adjacent against an actual browser, not just by reading the code.

**What "Authorize" documents.** The generated schema tags every
`/api/v1/...` operation with a `bearerAuth` HTTP security scheme
(`app/main.py`'s `_custom_openapi()`) — this is added by rewriting the
generated OpenAPI document, not by adding a `Security(...)` dependency to
every one of the ~100 API endpoints, since `app.auth.dependencies.
get_api_token_user` already reads the `Authorization` header itself and
doesn't need FastAPI's own security machinery to function. Web-only routes
(session-cookie pages, not `/api/v1/...`) are left undecorated.

## 🔒 Security model

See "Authentication & RBAC" above for logins, sessions, and permissions —
everything below covers the rest of the app's security posture (SSH
handling, secrets at rest, audit integrity, HTTP hardening), most of which
predates auth and is unrelated to it. See "Deliberately out of scope"
below for what's still missing.

> [!IMPORTANT]
> The **AI assistant** (the `/ai` page, `app/ai/` and
> `app/tasks/ai_jobs.py`) is the highest-risk surface in this application
> by a wide margin: it can propose arbitrary shell commands, derived from a
> third-party model's interpretation of natural language, against real
> machines. Its safeguards — `ai.access` gating the page while every tool
> stays gated by the same permission the equivalent manual button needs,
> the permission being re-checked three separate times, and above all the
> rule that no mutating action ever runs without a CSRF-protected human
> confirmation showing the literal command and every resolved target — are
> documented in full, including the residual prompt-injection risk they
> deliberately do **not** eliminate, in
> [AI Assistant](AI-Assistant.md). Read that page before enabling the
> feature.

### 🔑 SSH host key pinning

Covered in depth in
[SSH Host Key Verification](SSH-Host-Key-Verification.md). Summary: no
connection is ever made to a machine whose host key fingerprint hasn't
been explicitly confirmed by a human, and any later mismatch hard-fails
the connection instead of silently reconnecting.

### Machine/group configuration export & import: structural, not a credentials backup

`app.services.machine_config` (used by both `app/web/routes/machines.py`
and `app/web/routes/api_v1.py` — one service function, two doors, same
convention as `app.services.machine_actions`) lets an operator export every
machine's and group's *structural* configuration and re-import it
elsewhere, e.g. to stand up a new instance from an existing fleet's layout.
It deliberately never touches `Machine.secret_encrypted` or
`Machine.host_key_fingerprint` — consistent with the "no blind trust on
first use" model above, an import is not a way to skip the manual host-key
confirmation step, and it's not a way to move password credentials between
databases either. Concretely:

- A `ssh_key`-auth machine imports cleanly — the app's one shared identity
  key needs nothing machine-specific.
- A `password`-auth machine can't be re-created with that method (there's
  no secret to import); it comes back as `ssh_key` instead, and its name is
  surfaced in the result so an operator knows to revisit its credentials by
  hand.
- Every imported machine starts with no pinned host key, exactly like a
  freshly hand-added one — the normal "Discover key fingerprint" +
  outside-the-app confirmation flow applies before anything connects to it.

Conflict handling is asymmetric on purpose: a machine name that already
exists is **skipped**, not overwritten (silently replacing an existing
machine's connection details, and forcing it to lose its pinned host key,
is a worse default than asking a human to resolve the conflict), while a
group name that already exists is simply **reused** for membership (there's
no credential or trust state on a group to lose, so match-or-create is
harmless). This is why import is a real create path directly into
`Machine`/`MachineGroup` — unlike CSV bulk-import (`POST /machines/import`)
and self-registration, which land in the `PendingMachine` review queue
because *those* inputs describe genuinely unknown hosts, not already-known
configuration being restored or migrated.

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

`ansible/debcontrol-onboard.yml` automates everything a machine needs
*before* that POST — the account, its SSH key, the scoped sudoers files —
then makes the same call. It's a single flat playbook rather than a
packaged role, deliberately: this is meant to be copied into or
`import_playbook`'d from someone's existing provisioning pipeline, not
installed as a dependency with its own versioning story. No secret has a
default baked in (the public key, URL, and bearer token are all required
vars) — see [Ansible Onboarding](Ansible-Onboarding.md).

### System updates: the first bulk SSH operation

Running `apt-get update` / `dist-upgrade` or `full-upgrade` / `autoremove` /
`autoclean` (**Machines → a machine → System updates**, or the same action
scoped to a group / "All machines") is the first feature that (a) needs
root on the target and (b) can legitimately run for a long time. Both
shaped the design:

- **A dedicated long timeout.** `open_connection`'s timeout only bounds
  the SSH handshake; the apt sequence itself gets its own budget
  (`UPDATE_TIMEOUT_SECONDS`, default 30 minutes) via a per-task
  `@celery_app.task(..., time_limit=...)`, distinct from the 60-second
  default (`task_time_limit`) every other background task uses. See
  `app/tasks/jobs.py` and `app/tasks/celery_app.py`.
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
- **Every run is a row, not just a queued message.** `MachineUpdateRun`
  persists status/output/error/timestamps in Postgres — Celery's own result
  backend is Redis-backed with a TTL and isn't a domain record, so it's
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
- **Every run ever, not just the last few.** The machine detail page's
  "Recent runs" table only ever shows the last 5 (it's a summary, not the
  full record) — `GET /machines/{id}/updates` is the full paginated,
  status-filterable history, using the same offset/limit-plus-one-extra-row
  pagination convention as `/audit` (`app/web/routes/audit.py`) rather than
  inventing a second one. No new model or migration needed: `MachineUpdateRun`
  already records every run permanently, this is purely a read-side view
  over data that already existed.

### Previewing a manual update before it runs

Clicking "Run update" on a machine's detail page no longer enqueues the
real job directly — it links to `GET /machines/{id}/updates/preview`
first, which simulates the *exact* same command sequence
`build_update_command` would run for real, using apt's own dry-run mode
(`apt-get -s`, aka `--simulate`) for both the upgrade step and
`autoremove`, and shows what would be installed/upgraded and, most
importantly, what would be *removed* — `autoremove` is the one step in
this sequence capable of surprising an operator. Only the preview page's
own "Confirm" button actually calls `POST /machines/{id}/updates`, which
is otherwise unchanged (same permission, same pinned-fingerprint check,
same audit action code `machine.updates.run`). A few decisions:

- **Deliberately scoped to this one entry point.** Scheduled/cron-triggered
  updates (`app.scheduling.builtin_actions`) still run immediately, with no
  human present to preview or confirm anything — that's the entire point
  of scheduling them. Manually-triggered group/bulk updates
  (`app/web/routes/machine_groups.py`, `/machines/bulk/updates`) are also
  unchanged: a preview naturally answers "what would happen on machine X",
  and doesn't generalize cleanly to "what would happen across N machines
  at once" without a lot more UI than this pass warrants — a future
  iteration could add a per-machine-in-a-batch preview, but that's out of
  scope here.
- **A plain confirm button, not a typed-name confirmation.** Power actions
  require typing the machine's exact name because they're irreversible and
  immediate the moment the button is clicked with no preview involved at
  all. This flow already *is* the extra step — the preview page itself is
  the friction that a typed name would otherwise add, and requires an
  actual SSH round trip (not just a client-side dialog) to reach, which a
  reflexively-clicked JS `confirm()` never does. Requiring a typed name on
  top of that would be redundant friction for a non-destructive-by-default
  action (most update runs change nothing worth naming to confirm) whereas
  the one destructive part is *specifically the removals list*, already
  called out prominently and styled as a warning on the same page.
- **A GET, not a POST.** The preview persists nothing to `Machine` (unlike
  "Check for updates now", which writes its counts/lists to the DB) even
  though it performs a real SSH round trip — same reasoning
  `/machines/package-search` and the update-run history page already use
  for a read-only GET that happens to do real work. No CSRF token needed.
- **An empty plan still lets you confirm.** If nothing would be
  installed, upgraded, or removed, the preview page says so but still
  shows the same "Confirm — run this update" button — clicking it still
  runs `apt-get update`/`autoremove`/`autoclean`/flatpak/snap exactly like
  today, matching existing behavior for "nothing pending" rather than
  silently skipping the run.
- **The API keeps a direct trigger.** `POST /api/v1/machines/{id}/updates`
  is intentionally *not* forced through a preview step first — see that
  route's docstring in `app/web/routes/api_v1.py`; a scripted caller
  presumably already knows what it's asking for, the same reasoning that
  already applies to every other unconfirmed single-machine trigger in
  that file (unlike the destructive, typed-confirmation actions, which
  *do* require an explicit `confirm`/`confirm_name` field there).
  `GET /api/v1/machines/{id}/updates/preview` is offered alongside it as an
  optional tool for a caller that wants to check first or build its own
  preview UI, not a mandatory gate.
- **Reuses `check_updates`'s parsing conventions.** The simulate command
  uses the same `echo ===MARKER===`-delimited-sections trick as
  `_CHECK_UPDATES_COMMAND`, and `parse_apt_simulated_changes`
  (`app/ssh/updates.py`) is a sibling of `parse_apt_upgradable_packages` —
  same "pure function, no I/O, unit-testable against canned output" shape,
  parsing `Inst `/`Remv `-prefixed lines from `apt-get -s`'s output instead
  of `apt list --upgradable`'s.

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

### Which packages, not just how many

`check_updates` originally only counted upgradable packages
(`upgradable_count`/`security_upgradable_count`); it now also returns the
actual list — name, current version, new version — as
`PendingPackage` (a `TypedDict`, `app/ssh/updates.py`), stored as a JSON
column per source on `Machine`
(`apt_upgradable_packages`/`flatpak_upgradable_packages`/
`snap_upgradable_packages`), same pattern as `disks`. There's deliberately
no separate history table: this is "what a check most recently found,"
overwritten on every run, exactly like the counts it sits next to — a
manual "Check for updates now" click, the periodic sweep, and a **user-
created scheduled task** using the `check_updates` action all write to the
same columns, so whichever ran last is what's shown. apt's entry gets a
real version diff (`apt list --upgradable`'s `[upgradable from: X]`
suffix, parsed with a regex); flatpak/snap only surface the available
version — getting their *current* version would mean cross-referencing a
second command's output per app, which wasn't worth the extra round trip
for a "which packages" list whose main value is the names.

### New facts: CPU architecture, uptime, process count

Added to the same single `FACTS_COMMAND` round trip as everything else in
`app/ssh/facts.py`, using the same `echo ===MARKER===`-per-section
convention — no new SSH connection, no new privilege requirement. Chosen
specifically for portability over a minimal image:

- **CPU architecture**: `uname -m` — already a dependency (used for the
  kernel version too).
- **Uptime**: `/proc/uptime`'s first field via `awk`, floored to whole
  seconds — proc is guaranteed on Linux, no `uptime`/`procps` binary
  needed.
- **Process count**: `ls -d /proc/[0-9]*/ | wc -l` rather than `ps -e |
  wc -l` — `procps` (which provides `ps`) isn't part of Debian's minimal
  base system the way `coreutils` is, so counting numeric `/proc` entries
  gets the same answer without assuming it's installed.

Two more, same round trip, same conventions:

- **Filesystem usage**: `df -B1 --output=target,size,used,avail,pcent`,
  excluding `tmpfs`/`devtmpfs`/`squashfs`/`overlay` — `-B1` forces byte
  units so the parser never has to guess whether `df` rounded to
  human-readable units. Parsed by taking the *last four* whitespace-
  separated fields as size/used/avail/pcent and joining everything before
  that as the mount point — a mount point containing a space would break
  this, which is an accepted, documented edge case rather than something
  worth a more fragile parsing scheme for.
- **Network interfaces**: `ip -4 -o addr show scope global`, filtered to
  global-scope (i.e. not loopback/link-local) IPv4 addresses — `iproute2`
  is the one dependency here that isn't `coreutils`/`util-linux`, but it's
  standard on any non-minimal Debian/Ubuntu install and is what modern
  Debian ships instead of `net-tools`' `ifconfig`. Missing entirely (some
  minimal containers) just yields an empty list, same graceful-degradation
  pattern as every other fact here.

### flatpak and snap: optional, guarded, never blocking apt

System updates and the update-availability check both cover three package
sources — apt, flatpak, snap — not apt alone, but neither flatpak nor
snap is assumed to be installed (most Debian/Ubuntu server images have
neither). Every flatpak/snap step in `app/ssh/updates.py` is wrapped in
`command -v flatpak`/`command -v snap`, so a machine without one simply
skips that part; it's never treated as a failure.

The check-side commands were chosen specifically because they're genuine,
side-effect-free dry runs, not because they were the obvious first guess:

- **flatpak** has no `--dry-run` flag for `update`. `flatpak remote-ls
  --updates <remote>` is the real read-only equivalent — it lists what a
  remote currently has that differs from what's deployed, without pulling
  or installing anything — run once per configured remote (usually just
  `flathub`) and de-duplicated by application id in
  `parse_flatpak_upgradable_output`, since the same app tracked from two
  remotes would otherwise be double-counted.
- **snap** has an official one: `snap refresh --list`, snapd's own
  documented dry-run listing of pending refreshes — and unlike actually
  refreshing, it doesn't need root.

Applying updates is a different story: `flatpak update -y --noninteractive`
and `snap refresh` are both run via `sudo -n`, same as apt, on the
assumption that a non-interactive system-wide flatpak/snap operation
commonly needs it too (interactively, both would otherwise go through
polkit, which has no non-interactive story). This is opt-in — the
sudoers example in
[Managed Machine Requirements](Managed-Machine-Requirements.md) shows the
two extra `NOPASSWD` lines as optional — and if they're not configured,
only the flatpak/snap steps fail (visible in the run's stored output);
the apt part of the same run is unaffected, since the three steps are
`;`-chained, not `&&`-chained, matching the existing autoremove/autoclean
pattern.

Update counts from all three sources are surfaced everywhere apt's count
already was — the machine list, the detail page, the dashboard's "needs
updates" tally, and the REST API — as separate fields
(`flatpak_upgradable_count`, `snap_upgradable_count`) rather than merged
into `upgradable_count`, since apt's count also carries a
`security_upgradable_count` breakdown that doesn't have a flatpak/snap
equivalent — merging would have made "how many are security updates"
ambiguous.

### Installed packages: a snapshot table, not a JSON blob

**Machines → a machine → Installed packages** needed somewhere to put a
per-machine list that can run into the thousands of rows (a typical
Debian install has several hundred to a thousand-plus apt packages
alone). A `MachinePackage` row per package (rather than a JSON column on
`Machine`, the pattern `disks` already uses for a handful of small
entries) makes that list filterable and countable with an ordinary SQL
query instead of deserializing and scanning a blob in Python on every
page load.

Gathering is a single SSH round trip (`app/ssh/packages.py`, the same
`echo ===MARKER===`-delimited-sections trick as `app/ssh/facts.py`) for
`dpkg-query`, then flatpak and snap if either is present — none of it
needs root, unlike the update check/run above. A refresh replaces a
machine's entire package set in one transaction (delete-then-bulk-insert)
rather than diffing row by row: this is a snapshot of "what's installed
right now," not a package-change history, so there's nothing to diff
against.

Refresh timing follows the same periodic cadence as facts
(`FACTS_REFRESH_INTERVAL_SECONDS`, via `refresh_all_machine_packages` —
the same fan-out-then-reschedule shape as `refresh_all_machine_facts`),
plus one extra trigger: `run_machine_update` enqueues both a package
refresh and a fresh update-availability check for its machine right after
finishing, success or failure, so running an update doesn't leave the
page showing stale counts and an outdated package list until the next
sweep.

`held` (`apt-mark showhold`) is a per-row boolean on `MachinePackage`
rather than a separate list, since it's a property *of* an already-listed
apt package, not a fourth package source — a held row is still gathered
and stored exactly like any other apt entry, just flagged. flatpak/snap
rows are always `held=False`; neither package manager has the concept.

### Fleet-wide package search: the other direction

Every other package view in the app answers "what does *this* machine
have installed"; **Machines → Package search** answers the opposite
question — "which machines have *this* installed, and what version" —
the one that actually matters right after a CVE announcement. It's a
single query across `MachinePackage` with an optional source filter, no
new storage: the per-machine snapshot table already built for the
per-machine view is exactly the index this needs, just queried the other
way round. Capped at 500 rows (`_PACKAGE_SEARCH_LIMIT`) with a "narrow
your search" notice past that, the same kind of documented, deliberate
limit as the audit log export's unpaginated query — a fleet-wide search
is an infrequent, human-triggered lookup, not a hot path worth building
real pagination for yet.

`MachinePackage.machine` is the one relationship deliberately added back
onto that model (`viewonly=True`, no `back_populates` — `Machine` still
has no `packages` collection of its own, for the same eager-loading-cost
reason as before) purely so the search results page can show which
machine each hit belongs to without a second round-trip per row.

### Bulk actions from the machine list: the same service functions, a different source of `Machine` rows

**Machines** list checkboxes (system update, check-updates, reboot/
shutdown) call the exact same `app/services/machine_actions.py` functions
(`trigger_updates`, `trigger_check_updates`, `send_power_to_machines`)
that the group and "All machines" buttons already used — the only
difference is where the `list[Machine]` comes from: `WHERE id IN
(...)` over an ad-hoc checkbox selection instead of a group's membership
or every machine. This is why bulk update reuses the *group* batch-results
page (`/machine-groups/batches/{batch_id}`) rather than a new one — a
`MachineUpdateRun.batch_id` was never tied to groups specifically, just
"triggered together," so there was nothing group-specific to duplicate.

Power still requires typing a confirmation phrase, same as every other
power action — but an ad-hoc selection has no name to ask for the way a
group does, so it uses a fixed phrase (`SELECTED MACHINES`, mirroring
"All machines"'s `ALL MACHINES`) and carries the selected IDs forward as
hidden form fields on the confirmation page, since there's no group row
to look the selection back up from by id.

### Officially supporting deb-based distributions generically

debcontrol's official support statement is "Debian and its derivatives
(e.g. Ubuntu), for as long as each is supported by its own upstream" —
deliberately a policy, not a hardcoded version list, so it never needs
updating as new releases ship or old ones reach end-of-life. This tracks
what was already true of the implementation before it was said out loud:
every command debcontrol runs — `dpkg`, `apt`, `systemd`'s `shutdown`,
`/etc/os-release`, and now `flatpak`/`snap` — is either present on a
stock Debian install or standard optional tooling any Debian-based
distribution ships or can install; nothing here inspects
`/etc/os-release` to branch on which distro it's talking to.

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

### 🖥️ Interactive SSH terminal: the most powerful capability in the app

**Machines → a machine → Terminal** opens a real, interactive shell to that
machine in the browser — not a fixed command like updates/power, but
arbitrary command execution as whatever user (and sudo rights, if any) the
machine's configured account has. It's treated accordingly:

- **Its own dedicated permission**, `Permission.ACTION_TERMINAL` — not
  folded into `ACTION_UPDATES` or `MACHINE_MANAGE`, since neither implies
  "can run anything." A role has to be granted this explicitly, same as
  every other permission (see "Adding a new permission" in
  [Development](Development.md)).
- **Same pinned-fingerprint requirement as every other SSH-connecting
  action** — a machine with no confirmed host key fingerprint can't open a
  terminal, same `UnknownHostKeyError` refusal `open_connection` already
  gives every other action.
- **Session start/end are audited, not keystrokes.** `machine.terminal.open`
  is logged the moment the shell actually starts (after the SSH connection
  succeeds); `machine.terminal.close` is logged with the session's duration
  when it ends, however it ends (clean disconnect, error, or the hard time
  cap below). What was typed or displayed is deliberately *not* recorded —
  a keystroke-level transcript of a potentially root-capable shell would
  itself become a sensitive artifact (any secret typed or shown during the
  session would end up sitting in the audit log), and this app's existing
  audit philosophy is already "who did what, not a full transcript of what
  happened" (see "Audit log: who, what, outcome, when" above).
- **A WebSocket, authenticated by hand.** `app.auth.middleware.require_auth`
  is registered via `@app.middleware("http")` in `app.main` — Starlette
  never invokes `http`-scoped middleware for a WebSocket connection, so a
  WebSocket route gets *no* auth for free. `app/web/routes/terminal_ws.py`
  re-implements the same session-cookie lookup
  (`app.auth.sessions.get_valid_session`) and permission check by hand,
  and closes the socket (code `1008`, policy violation) before accepting
  the connection or touching SSH at all if either fails — never
  accept-then-fail. The page shell itself
  (`GET /machines/{id}/terminal` in `app/web/routes/machines.py`) *is*
  gated by the ordinary `require_permission`/pinned-fingerprint checks
  every other page uses, but that only proves someone could load the page;
  the socket doesn't trust that on its own.
- **A hard 2-hour session cap** (`TERMINAL_SESSION_MAX_SECONDS` in
  `terminal_ws.py`), closed server-side regardless of activity — long
  enough for real, uninterrupted admin work (installing something, chasing
  a problem down, editing several files), short enough that a forgotten
  browser tab against the single most powerful capability in this app
  doesn't hold a live, potentially root-capable SSH connection open
  indefinitely. The SSH connection and remote process are always torn down
  in a `finally` block on every exit path (clean disconnect, error, or the
  cap firing) — there's no path that leaks a connection.
- **AsyncSSH's own PTY support, not a new dependency.** `app.ssh.client.
  open_shell_session` is a sibling of `open_connection` (calls it, then
  `conn.create_process(term_type=..., term_size=..., encoding=None)`) —
  AsyncSSH already supports everything an interactive shell needs
  (`create_process`, `change_terminal_size` for resize), so this needed no
  new Python dependency. `encoding=None` keeps the byte stream raw rather
  than decoded, since a terminal relays arbitrary bytes (partial UTF-8
  sequences, ANSI escapes) rather than parsed text.
- **A simple binary/text WebSocket protocol.** Binary frames carry raw
  terminal bytes in both directions (client keystrokes in, remote PTY
  output out); text frames carry small JSON control messages — a
  client-sent `resize` (cols/rows), and a server-sent `error` for a failure
  before there's a PTY to relay bytes from yet.
- **xterm.js, vendored locally — real terminal emulation, not a hand-built
  approximation.** This app's whole convention is vendored-locally JS (see
  how htmx is vendored under `app/web/static/js/`, never pulled from a
  CDN) under a strict CSP with no inline scripts. xterm.js (MIT-licensed)
  plus its `addon-fit` (auto-sizing to the container) are vendored the same
  way — `app/web/static/js/xterm.min.js` /
  `xterm-addon-fit.min.js`, `app/web/static/css/xterm.css` — rather than a
  hand-built renderer, since real terminal emulation (full ANSI/VT
  handling, alternate screen buffer, `vim`/`htop`/`less` rendering
  correctly) is exactly what a purpose-built library already does well;
  reimplementing a meaningful subset of it would be strictly worse for no
  benefit once the real library was available to fetch. `app/web/static/js/
  terminal.js` is this app's own small, CSP-safe wiring script (external
  file, no inline `<script>`) connecting xterm.js to the WebSocket above.
- **CSP: `connect-src 'self'` added, nothing broader.** The existing policy
  had no explicit `connect-src` at all (falling back to `default-src
  'self'`); it's now spelled out explicitly for clarity, still scoped to
  `'self'` — a WebSocket connection to this page's own origin is already
  covered by the same-origin `ws`/`wss` upgrade CSP's `'self'` keyword
  matches, so nothing wider was needed.
- **Not exposed over the REST API.** The terminal is inherently an
  interactive, browser-only feature — there's no meaningful "REST"
  operation to expose (see `app/web/routes/api_v1.py`'s module docstring
  for the same reasoning already applied to SSH key rotation and LDAP/OIDC
  configuration: some things are deliberately web-UI-only).

### 🕒 Scheduling: reusing actions, not reimplementing them

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
  It's idempotent and called from `app.main` (so the web UI has something
  to list), from `app.scheduling.jobs` at import time, and again in each
  forked Celery worker child — every process can run without importing the
  others.
- **One shared implementation for "trigger this against N machines".**
  `_trigger_updates` / `_trigger_check_updates` / `_send_power_to_machines`
  used to live only in the machine-groups routes; they moved to
  `app.services.machine_actions`, which takes no `Request` and no queue
  handle at all — Celery tasks are importable objects, so it just calls
  `some_task.delay(...)` — so a scheduled run and a human clicking "Update now" on
  a group go through the exact same code path, including the same
  skip-unpinned-machines behavior.
- **A fixed one-minute tick, not a configurable interval.**
  Unlike the facts/update-check sweeps (`FACTS_REFRESH_INTERVAL_SECONDS`),
  cron expressions are minute-grained by construction, so
  `run_due_scheduled_tasks` is a plain `crontab()` Beat entry (every
  minute) rather than needing a new setting. (`ping_all_machines`'s
  reachability sweep was once this shape too, but has its own configurable
  `timedelta` schedule — see `REACHABILITY_CHECK_INTERVAL_SECONDS` — since
  sub-minute and multi-minute cadences are both reasonable there.)
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

### 📝 Audit log: who, what, outcome, when

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
  requests — or from different *processes*, since the web app and every
  forked Celery worker child all write audit entries — can never both link a new entry to the
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

### 📊 Dashboard trends: a daily snapshot, retained the same way as the audit log

`FleetSnapshot` (`app/db/models/fleet_snapshot.py`) is one row per calendar
day of the exact fleet-wide counts the Dashboard already shows live — total/
online/offline machines, machines needing (security) updates, machines
needing a reboot. Both the live Dashboard and the daily snapshot job
(`app.tasks.jobs.record_fleet_snapshot`, a fixed 02:00 UTC cron tick) go
through the same `app.services.fleet_stats.compute_fleet_stats`, so the
trend line and "what the Dashboard says right now" can never define these
counts differently. The job is idempotent per calendar day (checked before
inserting, and enforced again by a unique constraint on `snapshot_date`) so
a worker restart re-firing the same day's cron tick is a no-op, not a
duplicate row.

`AppSettings.dashboard_trends_retention_days` and the paired
`purge_old_fleet_snapshots` job (03:05 UTC) are a deliberate copy of the
audit log retention pattern above — same Settings-page UI shape, same
"only remove rows older than the cutoff" purge. The one difference is the
default: audit retention defaults to "keep forever" because silently
discarding audit history is a much worse surprise than an unbounded table,
but a fleet-count trend is a lightweight, purely-derived convenience for a
chart, not a compliance record — so it defaults to a bounded 90 days
instead, with `None` still available for "keep forever" if an operator
wants that.

The Dashboard only renders the trend chart(s) once at least two snapshots
exist (a single point isn't a trend, and a fresh install has none). The
chart itself (`app/web/templates/macros/charts.html`) is generated
entirely server-side as inline SVG using only presentation attributes
(`fill=`, `stroke=`) — never a `style=` attribute or a `<style>` block —
so it needs no exception carved into the CSP's `style-src 'self'`, and no
external charting library either (this app vendors htmx locally and allows
no other external script/asset host at all). `GET /api/v1/dashboard/trends`
exposes the same raw series read-only, gated by `machine.view` (the same
permission that already governs seeing these numbers anywhere else) rather
than inventing a dedicated "dashboard" permission for one read-only report.

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

A rejection (missing or mismatched token) is itself recorded in the audit
log — `verify_csrf` calls `log_event` with `action="auth.csrf_rejected"`,
`outcome=AuditOutcome.DENIED`, before raising the 403 — the same as any
other safeguard that blocks a request (see "Audit log: who, what, outcome,
when" above).

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

### Configuration is validated at startup

`Settings` (`app/core/config.py`, pydantic-settings) refuses to construct —
so the app refuses to start — if `SECRET_KEY`, `ENCRYPTION_KEY`, or
`INFORM_TOKEN` still look like a placeholder copied straight from
`.env.example` (starts with `change-me`, or is under 16 characters). This
is checked once, at process startup, not discovered later at first use —
a misconfigured deployment fails loudly and immediately instead of running
with a guessable secret. `/docs` and `/openapi.json` are similarly
disabled outright when `APP_ENV=production` (`app/main.py`), rather than
just left unlinked.

### Container hardening

The runtime image runs as a non-root user, is built via a multi-stage
Dockerfile (build tools never ship in the final image), and Postgres/
Redis ports aren't published to the host at all by default. The app's own
port (`8080`) *is* published on every interface, not just loopback —
still plain HTTP, still meant to sit behind a TLS-terminating reverse
proxy, but debcontrol no longer restricts direct access to this host for
you. If that matters for your deployment, either firewall port `8080`
from anything but your reverse proxy, or bind
`docker-compose.yml`'s `web.ports` entry to `127.0.0.1:8080:8080`.

### Deliberately out of scope

- **Per-schedule timezones.** Scheduling's cron expressions are always
  interpreted as UTC — this is permanent, not a stopgap: one expression
  means the same instant regardless of who's looking at it or which
  machine/group it targets, with no per-schedule override to reconcile.
  The `TZ` environment variable (see [Installation](Installation.md))
  changes container log timestamps and local-time display, and nothing
  else — it never touches how a schedule fires.
- There's also no scheduled "power on" to pair with scheduled shutdown —
  there's no way for the app to power on a machine that's off (see
  [Managed Machine Requirements](Managed-Machine-Requirements.md)).
- Rotating the app's SSH identity, and configuring LDAP/OIDC/syslog, stay
  web-UI-only over the REST API (see "The REST API: read and write,
  mirroring the web UI" above for why) — everything else the web UI can do
  now has an API equivalent.
- The **AI assistant** is web-UI-only for the same reason, only more so,
  and its conversations are private to the account that created them (no
  shared or admin view). See
  [AI Assistant → Deliberately out of scope](AI-Assistant.md#-deliberately-out-of-scope).
