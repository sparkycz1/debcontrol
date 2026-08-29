# debcontrol

A web application for managing Debian machines over SSH. Officially
supported: Debian and its derivatives (e.g. Ubuntu), for as long as each
is supported by its own upstream — see the wiki:
[Managed Machine Requirements](wiki/Managed-Machine-Requirements.md#os).
Every page requires a login; access is controlled by custom roles (RBAC)
an admin defines, and accounts can authenticate locally, against LDAP, or
via OIDC SSO, with optional TOTP two-factor for local/LDAP accounts. See
[wiki/Architecture.md](wiki/Architecture.md#authentication--rbac) for the
design and [wiki/Installation.md](wiki/Installation.md) for bootstrapping
the first admin account.

Full documentation (installation, reverse proxy guides, architecture,
security model) lives in the [wiki](wiki/Home.md) — it's written to be
published as the GitHub wiki once this repo is pushed there (see
[wiki/README.md](wiki/README.md)).

## Technology

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.14.7 | |
| Web framework | FastAPI | async, OpenAPI schema for free |
| Templates / UI | Jinja2 + [htmx](https://htmx.org) (vendored locally) | no SPA build, no CDN |
| Database | PostgreSQL 18.6 | via `asyncpg` + SQLAlchemy 2.0 (async); image pinned to an exact patch version |
| Migrations | Alembic | async engine |
| Cache / task queue | Redis 8.10.1 | queue via [`arq`](https://github.com/python-arq/arq) |
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

- **`redis-py` (the client library) is intentionally pinned to the `<6` line**,
  even though the Redis *server* in `docker-compose.yml` runs `redis:8.10`.
  The client library version and the server version are independent —
  `arq` (the task queue) only supports `redis-py <6` as of August 2026 (see
  its `pyproject.toml`), but redis-py 5.x talks to a Redis 8.x server just
  fine. If/when `arq` raises that ceiling, `redis[hiredis]` in
  `pyproject.toml` can be unpinned.
- `arq` is currently in "maintenance only" mode (bugfixes, no new
  features). That's fine for v1 — it's the lightest queue option on top of
  Redis, no Celery required. If that becomes a problem later, alternatives
  are `Celery` or `ReArq` (a fork that continues `arq`).
- Versions in `pyproject.toml` are lower bounds (`>=`); exact,
  reproducible versions for installation come from `uv.lock`.
- **Docker images for stateful services are pinned to an exact patch
  version** — `postgres:18.6`, `redis:8.10.1` — rather than the floating
  `postgres:18` / `redis:8.10`. A floating tag gets silently rebuilt onto
  newer minor/patch releases, and an unplanned Postgres/Redis upgrade on
  `docker compose up` is exactly the kind of surprise this project avoids
  elsewhere too. Bump the pin deliberately (and test against it) instead.

## Security decisions

- **Every page requires a session** (`app/auth/middleware.py`) except
  `/login`, the OIDC endpoints, `/healthz`, and `/api/inform` (which has its
  own bearer-token auth). Sessions are server-side rows
  ([app/db/models/user_session.py](app/db/models/user_session.py)), not a
  stateless signed cookie — an admin disabling an account, a password
  change, or "log out everywhere" all just revoke rows, no waiting for a
  token to expire on its own.
- **Custom RBAC** — an admin defines named roles with an exact permission
  matrix (12 permissions across machines/groups/actions/scheduling/audit/
  settings/users; a MANAGE permission always implies the matching VIEW one)
  and assigns one role per user. See
  [app/db/models/role.py](app/db/models/role.py).
- **Local passwords are argon2id-hashed**; a brute-force lockout (5 failed
  attempts, 15 minutes) applies to both the password step and the TOTP
  step. **LDAP** login is search-then-bind against a directory configured
  in Settings, with the user's own credentials only ever used for the
  final bind. **OIDC** login never auto-creates an account — a user is
  always created in debcontrol first, then matched to the provider by
  comparing a configurable ID-token claim against their username. See
  [app/auth/login.py](app/auth/login.py), [app/auth/ldap.py](app/auth/ldap.py),
  [app/auth/oidc.py](app/auth/oidc.py).
- **Optional TOTP two-factor** for local/LDAP accounts (not OIDC — the
  provider handles its own MFA), with one-time recovery codes. See
  [app/auth/totp.py](app/auth/totp.py).
- **Guardrails against locking everyone out**: you can't deactivate,
  delete, or demote your own account, and the last active account holding
  `user.manage` can't be deactivated, deleted, or demoted away from it
  either — checked before every such change, not just documented. See
  [app/web/routes/users.py](app/web/routes/users.py),
  [app/web/routes/roles.py](app/web/routes/roles.py).
- **No blind "trust on first use" for SSH host keys.** A machine's key
  fingerprint must be explicitly discovered ("Discover key fingerprint")
  and manually confirmed (outside the app, e.g. via the hosting provider's
  console) before anything connects to it. A fingerprint mismatch on a
  later connection = hard refusal (possible MITM), never silently ignored.
  See [app/ssh/client.py](app/ssh/client.py).
- **Passwords/private keys are stored encrypted** in the DB (Fernet/AES
  from the `cryptography` package, key only in `ENCRYPTION_KEY` in the
  environment). See [app/core/security.py](app/core/security.py).
- **One shared, app-managed SSH identity**, generated on first use and
  never written to disk in plaintext (see
  [app/db/models/ssh_identity.py](app/db/models/ssh_identity.py)). Its
  public half is shown on the Settings page for an operator to distribute
  manually — plain passwords are still supported per machine, but the UI
  calls that out as not recommended.
- **Self-registration (`POST /api/inform`) requires a bearer token**
  (`INFORM_TOKEN`) and only ever creates a *pending* entry for a human to
  review — nothing it submits is trusted for actually connecting to the
  machine. See [app/web/routes/inform.py](app/web/routes/inform.py).
- **CSRF protection** (double-submit cookie) on every form, including the
  login form itself. See [app/core/csrf.py](app/core/csrf.py).
- **Strict Content-Security-Policy** and other security headers
  (`X-Frame-Options`, `X-Content-Type-Options`, ...) — no inline
  scripts/styles, no external CDN. See [app/main.py](app/main.py).
- **Non-root user in Docker**, minimal multi-stage image, no DB/Redis
  ports published to the host by default. The app's own HTTP port
  (`8080`) is published on all interfaces — it's meant to sit behind a
  TLS-terminating reverse proxy, but nothing stops direct access; block
  `8080` at the firewall if you don't want that (or bind it to
  `127.0.0.1:8080:8080` in `docker-compose.yml` instead).
- **Optional bundled Caddy reverse proxy** with TLS 1.3 only, HTTP/3, and
  hardened headers — or bring your own (nginx/Traefik/Caddy guides in the
  wiki).
- **Configuration is validated at startup** — the app refuses to start
  with placeholder/short secrets copied from `.env.example` (see
  `Settings` in [app/core/config.py](app/core/config.py)).
- `/docs` and `/openapi.json` are disabled in production (`APP_ENV=production`).

There is an **Audit log** ([app/audit.py](app/audit.py)) recording who
(the account, and the source IP), what, its outcome, and when — including
logins, logouts, and every user/role/settings change — hash-chained so an
altered or removed entry is detectable. **Not** yet included: IP-based
login rate limiting (only per-account lockout).

## Quick start (Docker)

```bash
cp .env.example .env
python scripts/generate_secrets.py
```

Paste the printed values (`SECRET_KEY`, `ENCRYPTION_KEY`,
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`) into `.env`, and make sure
`DATABASE_URL`/`REDIS_URL` use the same passwords as
`POSTGRES_PASSWORD`/`REDIS_PASSWORD`.

**Without a reverse proxy in front (or if you already run your own):**

```bash
docker compose up -d --build
```

The app listens on port `8080` (plain HTTP, all interfaces — see the
firewall note above). Point your own nginx/Traefik/Caddy at
`127.0.0.1:8080` — see the reverse-proxy guides in the wiki:
[nginx](wiki/Reverse-Proxy-Nginx.md) ·
[Traefik](wiki/Reverse-Proxy-Traefik.md) ·
[Caddy (standalone)](wiki/Reverse-Proxy-Caddy.md).

**With the bundled Caddy** (automatic HTTPS via Let's Encrypt, TLS 1.3
only, HTTP/3): set `DOMAIN` and `ACME_EMAIL` in `.env`, point that domain's
DNS at this host, make sure ports 80/tcp, 443/tcp and 443/udp are open,
then:

```bash
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

See [wiki/Reverse-Proxy-Caddy.md](wiki/Reverse-Proxy-Caddy.md) for details
and troubleshooting.

This brings up: the image build, Postgres 18.6, Redis 8.10.1, a one-off
`migrate` service (Alembic `upgrade head`), and — once that finishes
successfully — `web`, `worker` (arq), and optionally `caddy`.

**Then create the first administrator account** — every debcontrol account
is created inside the app itself, so there's no other way in on a fresh
deployment:

```bash
docker compose exec web python scripts/create_admin.py --username admin
```

It prompts for a password (at least 12 characters) and creates an
"Administrator" role with every permission if one doesn't exist yet. You'll
be asked to change that password on first login. See
[wiki/Installation.md](wiki/Installation.md) for LDAP/OIDC setup. If an
account (including that first admin) ever gets locked out with no other way
in — forgotten password, lost TOTP device — `scripts/reset_account.py` does
the same thing from the server console: `docker compose exec web python
scripts/reset_account.py --username admin [--disable-totp]`.

**Upgrading later** is one command: `./scripts/upgrade.sh` — pulls, rebuilds,
and restarts (Caddy included automatically if it's running), refusing to
run over uncommitted local changes. See
[wiki/Installation.md](wiki/Installation.md#updating) for what it does step
by step, or to do it by hand instead.

## Local development without Docker (DB/Redis still via Docker)

```bash
uv sync
docker compose up -d db redis
uv run alembic upgrade head
uv run python scripts/create_admin.py --username admin
uv run uvicorn app.main:app --reload
# in a second terminal:
uv run arq app.tasks.worker.WorkerSettings
```

## Tests and quality checks

```bash
uv run pytest
uv run ruff check .
uv run mypy app alembic tests
```

Tests don't run against real infrastructure — `get_db` is swapped for an
isolated in-memory SQLite session in tests (see
[tests/conftest.py](tests/conftest.py)), so they're fast and have no side
dependencies. SSH against real machines is only unit-tested at the logic
level (refusing to connect without a pinned fingerprint) — end-to-end
verification against an actual Debian machine has to be done manually via
the UI ("Test connection").

## Project structure

```
app/
  audit.py      the single audit-log write path (hash chaining, verification)
  auth/         login (local/LDAP/OIDC), sessions, RBAC permissions, TOTP
  core/         config, logging, encryption, CSRF, editable app settings
  db/           SQLAlchemy models + async session
  schemas/      Pydantic schemas for forms
  scheduling/   cron-scheduled actions: registry, cron parsing, scheduler jobs
  services/     logic shared between manual routes and the scheduler
                (e.g. "trigger an update for these machines")
  ssh/          AsyncSSH client (host key pinning), facts, updates, power
  tasks/        arq worker + background jobs (facts/reachability/update
                sweeps, the daily audit-log purge)
  web/          FastAPI routers, Jinja2 templates, static files
alembic/        DB migrations
tests/          pytest (async, isolated from real infrastructure)
scripts/        helper scripts (secret generation, first-admin bootstrap,
                console-only account recovery, one-command upgrade)
ansible/        onboarding playbook — sets up a machine and self-registers
                it, see wiki/Ansible-Onboarding.md
wiki/           documentation, meant to become the GitHub wiki
```

## Navigation / features

- **Dashboard** — the post-login landing page: machine counts (online/
  offline, pending updates, security updates, reboot-required), upcoming
  scheduled tasks, and recent audit activity — each section only shown if
  the current role can see that area, same permission checks as the nav
  itself. See [app/web/routes/dashboard.py](app/web/routes/dashboard.py).
- **Machines** — add, view, edit, and remove managed Debian machines; pin
  SSH host key fingerprints; test connectivity. Editing the IP address or
  port resets the pinned fingerprint and gathered facts, since those
  belonged to whatever was previously reachable there. Once a fingerprint is
  confirmed, the app automatically discovers and periodically refreshes
  OS version, kernel version, hostname, CPU architecture/cores, RAM,
  disks, filesystem usage (used/free/%, `df`), network interfaces (IPv4,
  `ip addr`), uptime, and process count (see
  [app/ssh/facts.py](app/ssh/facts.py); interval configurable via
  `FACTS_REFRESH_INTERVAL_SECONDS`), and shows an online/offline status
  badge from a lightweight per-minute reachability check
  ([app/ssh/reachability.py](app/ssh/reachability.py)). An **Installed
  packages** panel lists every apt package (and flatpak app / snap, if
  either is present), each with its version and held/pinned status
  (`apt-mark showhold`), searchable/filterable by source — refreshed on
  the same schedule as facts, and again right after any update run on
  that machine (see [app/ssh/packages.py](app/ssh/packages.py)). A
  separate **Package search** page searches that same data across every
  machine at once ("who still has package X installed, and what
  version") — handy right after a CVE announcement. Machines can also
  self-register via `POST /api/inform` (bearer-token authenticated — either
  the shared `INFORM_TOKEN` or a per-user API token, see "My account" below)
  and show up as "pending" for review before being added; a CSV **Bulk
  import** does the same for a whole list of IPs/hostnames at once (still no
  credentials or host key — every one still goes through the normal
  add-machine flow individually). Free-text search
  (name, IP, hostname, OS/kernel version, username, notes) across the
  machine list. Each machine has a **System updates** panel: always
  `apt-get update`, then `dist-upgrade` or `full-upgrade` (your choice),
  then `autoremove`/`autoclean` unconditionally, then `flatpak update` and
  `snap refresh` too if either is installed — one combined run, one
  combined output — runs in the background (can take a while) with a
  live-updating status page; a "Check for updates now" dry run shows how
  many apt packages (and how many security ones), flatpak apps, and snaps
  are available to update — and *which* ones, by name and version, under a
  "Which ...?" disclosure — without installing anything. That package list
  reflects whichever check ran most recently: the button, the periodic
  sweep, or a scheduled "check_updates" task (see **Scheduling** below).
  A reboot-required
  badge appears automatically when a newer kernel is installed but not
  yet running. apt requires root or passwordless sudo for `apt-get`;
  flatpak/snap checking is read-only, and updating them is recommended to
  also go through passwordless sudo (see the wiki: Managed Machine
  Requirements). See [app/ssh/updates.py](app/ssh/updates.py). A **Power** panel sends
  `shutdown -r/-h now` (reboot/shut down), gated behind a dedicated
  confirmation page that requires typing the machine's exact name — see
  [app/ssh/power.py](app/ssh/power.py). All three of these (update, check,
  power) are also available as **bulk actions** straight from the
  machine list — tick a checkbox per machine (or "select all") and use
  the action bar below the table — without first needing to put those
  machines in a group; power still requires typing a fixed confirmation
  phrase.
- **Machine groups** — organize machines into named groups (e.g. by
  environment or role); assign/remove machines from a group. The groups
  list itself is searchable by name/description, and each group's member
  list is separately searchable by the same machine fields as the main
  Machines list. System updates, update checks, and power actions all
  work here too, scoped to the group (or to **All machines**, a built-in
  group that's always literally every machine — see the "All machines"
  details on the Machine groups page) — machines without a pinned host
  key are silently skipped and the count surfaced.
- **Scheduling** — run any existing action (system update, update check,
  reboot, shut down) against a machine, a group, or **All machines** on a
  cron expression (standard 5-field, always UTC). Adding a schedule reuses
  the exact same trigger logic as the manual buttons — same
  skip-unpinned-machines behavior, same double-confirmation-worthy actions
  flagged with a ⚠ in the form. Each schedule can be enabled/disabled, run
  immediately ("Run now", without waiting for its cron expression), and
  shows when it last fired and a one-line summary — not a full history,
  since the action's own record (an update run, the reachability check)
  already has that. New features that add a schedulable action only need
  to register one `ScheduledActionSpec` — see
  [app/scheduling/builtin_actions.py](app/scheduling/builtin_actions.py).
- **Audit** — a read-only, searchable/filterable log of essentially every
  mutating action (and every safeguard that blocked one — a confirmation
  mismatch, an unpinned host key, a bad self-registration token, a failed
  or locked-out login): who (account + source IP), what happened, its
  outcome, and when. Every entry is hash-chained (each links to the
  previous one's SHA-256, verifiable on the Settings page) so an altered or
  removed entry is detectable — see [app/audit.py](app/audit.py). Exportable
  as CSV/JSON (respecting the current search/outcome filter), and can be
  live-forwarded to an external syslog server (Settings) as a SIEM mirror.
- **Users** — create/edit/deactivate/delete accounts, assign a role, reset
  a local password (forces a change + signs them out everywhere), and force
  a sign-out. Login method (local/LDAP/OIDC) is per-account; local accounts
  set a password here, LDAP/OIDC accounts are matched by username instead
  — see [app/web/routes/users.py](app/web/routes/users.py).
- **Roles** — define named roles with an exact permission checkbox matrix;
  a role in use can't be deleted, and a role can't be edited to strip
  `user.manage` if that would leave nobody able to manage users — see
  [app/web/routes/roles.py](app/web/routes/roles.py).
- **My account** — change your own password (with re-entering the current
  one), enroll/disable TOTP two-factor and view/regenerate recovery codes,
  "log out everywhere else", and create/revoke your own **API tokens** for
  the read-only REST API (`GET /api/v1/machines`, `/machines/{id}`,
  `/machine-groups`) or as a per-user alternative to the shared
  `INFORM_TOKEN` — a token authorizes whatever your role currently permits,
  checked fresh on every request, and stops working immediately if your
  role changes or your account is deactivated — see
  [app/web/routes/auth.py](app/web/routes/auth.py) and
  [app/web/routes/api_v1.py](app/web/routes/api_v1.py).
- **Settings** — shows the running **version and git commit** (linked to
  GitHub — see [app/core/version.py](app/core/version.py)), the app's SSH
  public key/fingerprint (for manual distribution to machines) with a
  **rotate** flow (generate a replacement key, deploy its public half to
  `authorized_keys` alongside the old one, then activate it — the old key
  is never touched until you do), the current background-check intervals,
  the audit log retention policy (how many days of entries to keep before a
  daily purge, see
  [app/db/models/app_settings.py](app/db/models/app_settings.py)) plus an
  on-demand hash-chain integrity check, **CSV/JSON export** of the audit
  log, **syslog forwarding** of every audit entry to an external server —
  e.g. a SIEM — over plain UDP/TCP or TLS (see
  [app/audit_syslog.py](app/audit_syslog.py); best-effort, the DB row is
  always the real record), and the LDAP/OIDC login configuration (server,
  bind account, search filter / issuer, client credentials — secrets stored
  encrypted, same as SSH passwords).

See the wiki's
[Managed Machine Requirements](wiki/Managed-Machine-Requirements.md) for
what a Debian machine needs (and, spoiler: mostly already has) to be
managed this way — or run the [Ansible playbook](ansible/) in
[wiki/Ansible-Onboarding.md](wiki/Ansible-Onboarding.md) to have it done
automatically and self-register the machine as pending.

## What's deliberately empty / for later

- Running arbitrary commands across machines — system updates are the
  first bulk/group-scoped SSH operation (see `app/ssh/updates.py`,
  `app/db/models/machine_update_run.py`); the same `batch_id` grouping
  pattern is meant to extend to other commands later.
- CSRF rejections aren't audit-logged (login/TOTP rate-limit rejections are,
  as `auth.rate_limited`).
- Per-schedule timezones (Scheduling is always UTC) and a scheduled
  "power on" to pair with scheduled shutdown.
- Actually copying the app's public SSH key onto each machine's
  `authorized_keys` is still a manual step (Settings supports generating
  and activating a replacement key, but not pushing it out); turning a
  pending self-registered/bulk-imported machine directly into a managed one
  without re-entering its IP/name is also still manual.
- Self-service password reset (forgotten password) — an admin resets it
  from the Users page, or `scripts/reset_account.py` from the server
  console if nobody can log in at all (see wiki/Installation.md).
- The read-only REST API (`/api/v1/...`) is exactly that — read-only; there's
  no API for creating/editing machines yet, only the web UI.
