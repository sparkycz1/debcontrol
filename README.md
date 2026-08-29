# debcontrol

A web application for managing Debian machines over SSH. There's no login
yet — run it on a trusted network / behind a reverse proxy you control
until authentication is added.

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
| Cache / task queue | Redis 8.8 | queue via [`arq`](https://github.com/python-arq/arq) |
| SSH client | [AsyncSSH](https://asyncssh.readthedocs.io/) | async, strict host key verification |
| Cron scheduling | [`croniter`](https://github.com/kiorky/croniter) | parses standard 5-field cron expressions for Scheduling |
| Reverse proxy (optional) | [Caddy](https://caddyproxy.com/) | automatic HTTPS, TLS 1.3 only, HTTP/3 |
| Packaging / lockfile | [`uv`](https://docs.astral.sh/uv/) | `uv.lock` is committed |
| Containers | Docker (multi-stage build) + Docker Compose | |

### Dependency version notes

- **`redis-py` (the client library) is intentionally pinned to the `<6` line**,
  even though the Redis *server* in `docker-compose.yml` runs `redis:8.8`.
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
  version** — `postgres:18.6`, `redis:8.8.2` — rather than the floating
  `postgres:18` / `redis:8.8`. A floating tag gets silently rebuilt onto
  newer minor/patch releases, and an unplanned Postgres/Redis upgrade on
  `docker compose up` is exactly the kind of surprise this project avoids
  elsewhere too. Bump the pin deliberately (and test against it) instead.

## Security decisions (v1)

The app has no login yet, but a few things are handled from the start
because they're painful to retrofit later:

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
- **CSRF protection** (double-submit cookie) on every form, even without
  sessions/login. See [app/core/csrf.py](app/core/csrf.py).
- **Strict Content-Security-Policy** and other security headers
  (`X-Frame-Options`, `X-Content-Type-Options`, ...) — no inline
  scripts/styles, no external CDN. See [app/main.py](app/main.py).
- **Non-root user in Docker**, minimal multi-stage image, no DB/Redis
  ports published to the host by default, and the app's own HTTP port is
  bound to loopback only (`127.0.0.1:8000`) — it's meant to sit behind a
  TLS-terminating reverse proxy.
- **Optional bundled Caddy reverse proxy** with TLS 1.3 only, HTTP/3, and
  hardened headers — or bring your own (nginx/Traefik/Caddy guides in the
  wiki).
- **Configuration is validated at startup** — the app refuses to start
  with placeholder/short secrets copied from `.env.example` (see
  `Settings` in [app/core/config.py](app/core/config.py)).
- `/docs` and `/openapi.json` are disabled in production (`APP_ENV=production`).

What's **deliberately missing** and left for a later phase (login):
authentication/authorization of app users, rate limiting. There is an
**Audit log** ([app/audit.py](app/audit.py)) recording what happened, its
outcome, the source IP, and when — but not *who*, since there's no login
yet to attribute it to. Don't expose the app to an untrusted network/the
internet until then.

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

The app listens on `127.0.0.1:8000` (plain HTTP, loopback only). Point
your own nginx/Traefik/Caddy at that address — see the reverse-proxy
guides in the wiki:
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

This brings up: the image build, Postgres 18.6, Redis 8.8, a one-off
`migrate` service (Alembic `upgrade head`), and — once that finishes
successfully — `web`, `worker` (arq), and optionally `caddy`.

## Local development without Docker (DB/Redis still via Docker)

```bash
uv sync
docker compose up -d db redis
uv run alembic upgrade head
uv run uvicorn app.main:app --reload
# in a second terminal:
uv run arq app.tasks.worker.WorkerSettings
```

## Tests and quality checks

```bash
uv run pytest
uv run ruff check .
uv run mypy app
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
  core/       config, logging, encryption, CSRF
  db/         SQLAlchemy models + async session
  schemas/    Pydantic schemas for forms
  ssh/        AsyncSSH client (host key pinning)
  tasks/      arq worker + background jobs
  web/        FastAPI routers, Jinja2 templates, static files
alembic/      DB migrations
tests/        pytest (async, isolated from real infrastructure)
scripts/      helper scripts (secret generation)
wiki/         documentation, meant to become the GitHub wiki
```

## Navigation / features

- **Machines** — add, view, edit, and remove managed Debian machines; pin
  SSH host key fingerprints; test connectivity. Editing the IP address or
  port resets the pinned fingerprint and gathered facts, since those
  belonged to whatever was previously reachable there. Once a fingerprint is
  confirmed, the app automatically discovers and periodically refreshes
  OS version, kernel version, hostname, CPU cores, RAM, and disks (see
  [app/ssh/facts.py](app/ssh/facts.py); interval configurable via
  `FACTS_REFRESH_INTERVAL_SECONDS`), and shows an online/offline status
  badge from a lightweight per-minute reachability check
  ([app/ssh/reachability.py](app/ssh/reachability.py)). Machines can also
  self-register via `POST /api/inform` (bearer-token authenticated) and
  show up as "pending" for review before being added. Free-text search
  (name, IP, hostname, OS/kernel version, username, notes) across the
  machine list. Each machine has a **System updates** panel: always
  `apt-get update`, then `dist-upgrade` or `full-upgrade` (your choice),
  then `autoremove`/`autoclean` unconditionally — runs in the background
  (can take a while) with a live-updating status page; a "Check for
  updates now" dry run shows how many packages (and how many security
  ones) are available without installing anything; a reboot-required
  badge appears automatically when a newer kernel is installed but not
  yet running. Both the update and the check require root or passwordless
  sudo for `apt-get` (see the wiki: Managed Machine Requirements). See
  [app/ssh/updates.py](app/ssh/updates.py). A **Power** panel sends
  `shutdown -r/-h now` (reboot/shut down), gated behind a dedicated
  confirmation page that requires typing the machine's exact name — see
  [app/ssh/power.py](app/ssh/power.py).
- **Machine groups** — organize machines into named groups (e.g. by
  environment or role); assign/remove machines from a group. Search,
  system updates, update checks, and power actions all work here too,
  scoped to the group (or to **All machines**, a built-in group that's
  always literally every machine — see the "All machines" details on the
  Machine groups page) — machines without a pinned host key are silently
  skipped and the count surfaced.
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
  mismatch, an unpinned host key, a bad self-registration token): what
  happened, its outcome, the source IP, and when. There's no login yet, so
  entries record the source IP rather than an identity — see
  [app/audit.py](app/audit.py).
- **Users** — placeholder; no authentication yet.
- **Settings** — shows the app's SSH public key/fingerprint (for manual
  distribution to machines) and the current background-check intervals.
  No user-configurable preferences yet (no auth).

See the wiki's
[Managed Machine Requirements](wiki/Managed-Machine-Requirements.md) for
what a Debian machine needs (and, spoiler: mostly already has) to be
managed this way.

## What's deliberately empty / for later

- Login and authorization for app users.
- Running arbitrary commands across machines — system updates are the
  first bulk/group-scoped SSH operation (see `app/ssh/updates.py`,
  `app/db/models/machine_update_run.py`); the same `batch_id` grouping
  pattern is meant to extend to other commands later.
- *Who* performed an audited action — the **Audit** log (see above) records
  the source IP and what happened, not an identity, until there's a login
  to attribute it to; CSRF rejections also aren't logged (see
  wiki/Architecture.md).
- Per-schedule timezones (Scheduling is always UTC) and a scheduled
  "power on" to pair with scheduled shutdown.
- Automated SSH key distribution (currently a manual step — see Settings)
  and turning a pending self-registered machine directly into a managed
  one without re-entering its IP/name.
