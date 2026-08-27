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
| Database | PostgreSQL 18 | via `asyncpg` + SQLAlchemy 2.0 (async) |
| Migrations | Alembic | async engine |
| Cache / task queue | Redis 8.8 | queue via [`arq`](https://github.com/python-arq/arq) |
| SSH client | [AsyncSSH](https://asyncssh.readthedocs.io/) | async, strict host key verification |
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
authentication/authorization of app users, an audit log, rate limiting.
Don't expose the app to an untrusted network/the internet until then.

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

This brings up: the image build, Postgres 18, Redis 8.8, a one-off
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

- **Machines** — add, view, and remove managed Debian machines; pin SSH
  host key fingerprints; test connectivity.
- **Machine groups** — organize machines into named groups (e.g. by
  environment or role); assign/remove machines from a group.
- **Users** — placeholder; no authentication yet.
- **Settings** — placeholder; nothing user-configurable yet.

## What's deliberately empty / for later

- Login and authorization for app users.
- Running arbitrary commands / bulk operations across many machines (the
  groundwork already exists in `app/tasks/jobs.py` and `app/ssh/client.py`).
- Audit log.
- Bulk machine import / importing an existing `known_hosts` file.
