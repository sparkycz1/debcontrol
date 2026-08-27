# Architecture

## Stack

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
version-pinning implications). If heavier queue features are needed later
(scheduling UI, retries with complex backoff, multiple queues/priorities),
Celery or `ReArq` are the natural next steps.

### Why AsyncSSH over Paramiko

AsyncSSH is fully asynchronous and integrates directly with FastAPI's
event loop, avoiding a thread pool just to do SSH I/O. It's actively
maintained and supports modern algorithms (Ed25519, etc.).

## Project structure

```
app/
  core/       config (pydantic-settings), logging, encryption, CSRF
  db/         SQLAlchemy models + async session
  schemas/    Pydantic schemas for forms
  ssh/        AsyncSSH client (host key pinning)
  tasks/      arq worker + background jobs
  web/        FastAPI routers, Jinja2 templates, static files
alembic/      DB migrations
tests/        pytest (async, isolated from real infrastructure)
scripts/      helper scripts (secret generation)
wiki/         this documentation
```

## Security model

The app has no user authentication yet. Everything below is scoped to
what's true *before* that lands — see the root `README.md`'s "What's
deliberately empty" section for what's coming later.

### SSH host key pinning

Covered in depth in
[SSH Host Key Verification](SSH-Host-Key-Verification.md). Summary: no
connection is ever made to a machine whose host key fingerprint hasn't
been explicitly confirmed by a human, and any later mismatch hard-fails
the connection instead of silently reconnecting.

### Secrets at rest

Machine passwords and private keys are encrypted in Postgres using Fernet
(AES + HMAC, from the `cryptography` package). The key lives only in the
`ENCRYPTION_KEY` environment variable — never in the database or the repo.
This does **not** replace user authentication; it protects the SSH
credentials of *managed machines* from a database-only compromise (a
leaked backup, a misconfigured read replica, etc.).

### CSRF protection without sessions

Since there's no login yet, there's no session to hang CSRF protection
off of. Instead, a double-submit cookie pattern is used: a random
`csrftoken` cookie (`SameSite=Strict`, `HttpOnly`) is set on GET requests
that render a form, and the same value must be echoed back as a hidden
field on POST. See `app/core/csrf.py`.

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

- Authentication/authorization for app users (the **Users** tab is a
  placeholder for this).
- An audit log of actions taken against managed machines.
- Rate limiting at the application layer (a reverse proxy or upstream
  service is expected to handle this today).
