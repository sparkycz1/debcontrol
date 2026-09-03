# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

debcontrol: a FastAPI + htmx web app for managing a fleet of Debian/Ubuntu
(and Proxmox VE, and other common distros) machines over SSH — facts,
package updates, monitoring, a browser SSH terminal, scheduled actions,
RBAC, an AI assistant, and a full read/write REST API mirroring the web
UI. Server-rendered Jinja2 + htmx, not a SPA. Python 3.14, SQLAlchemy 2.0
async + PostgreSQL, Celery + Redis for background work, deployed via
Docker Compose only (no supported bare-metal/venv run path for the app
itself).

**The wiki is the primary source of truth, not this file** — it is
detailed, current, and actively maintained alongside the code:

- **[wiki/Development.md](wiki/Development.md)** — commands, testing
  conventions, and step-by-step recipes for the most common changes
  (adding a route, a permission, a machine/group action, a background
  task, an audit log call). Read the relevant recipe before adding one of
  these rather than improvising a new pattern.
- **[wiki/Architecture.md](wiki/Architecture.md)** — the full technical
  and security model: why things are built the way they are, project
  structure, auth/RBAC, the REST API, SSH/update/monitoring internals,
  the audit log, CSRF/CSP/headers.
- **[wiki/Home.md](wiki/Home.md)** — the feature table (what every page
  does), the canonical wiki table of contents.

When a task touches something these already document, follow the existing
pattern and update the relevant wiki page in the same change — don't let
docs drift from code (a completeness audit is what closed several such
gaps in this repo's history; see recent commits).

## Commands

```bash
uv sync                          # install deps into .venv (needed for tests/lint/mypy)
uv run pytest                    # full suite — no real Postgres/Redis/Celery broker touched
uv run pytest tests/test_x.py    # one file
uv run pytest tests/test_x.py::test_name   # one test
uv run ruff check .              # lint
uv run mypy app alembic tests    # type check (strict for app/ and alembic/)
uv run alembic revision --autogenerate -m "..."   # after changing a model — READ the generated file
uv run alembic upgrade head
uv run alembic heads             # must show exactly one head before committing a migration
```

There is no supported way to run the app itself outside Docker:
`docker compose up -d --build` (or `python scripts/setup.py` for a guided
first-time setup). See [wiki/Installation.md](wiki/Installation.md).

**Before committing**, run the same gate this repo's history consistently
uses: `ruff check .`, `mypy app alembic tests`, `pytest`, `alembic heads`
(single head) — all clean.

**Every round of changes** bumps `APP_VERSION` in `app/core/version.py`
**and** `version` in `pyproject.toml` together (patch for a small fix,
minor for a feature/infrastructure change, major only if explicitly
asked) — then run `uv lock` and commit the updated `uv.lock` in the same
commit. Forgetting the `uv lock` step breaks `uv sync --locked` in the
Docker build for anyone on a fresh install (this has happened; see git
history around v0.19.0/v0.19.1).

## Architecture, beyond what one file shows

- **The async/sync seam.** App logic is async all the way down
  (SQLAlchemy async sessions, asyncssh), but Celery tasks are synchronous.
  Every background job in `app/tasks/jobs.py` is `async def _do_thing(...)`
  (the real work) plus a one-line `def do_thing(...): return
  asyncio.run(_do_thing(...))` wrapped in `@celery_app.task(name="...")`.
  Tests call the underscore-prefixed coroutine directly, never the sync
  wrapper (which can't run inside pytest-asyncio's already-running loop).
- **Fork safety.** Celery workers fork; a `from app.db.session import
  AsyncSessionLocal` name captured at import time in the parent process
  keeps pointing at the parent's (now-invalid) connection pool in a forked
  child. Task code always opens sessions as `db_session.AsyncSessionLocal()`
  through the module (`from app.db import session as db_session`), never
  via a direct binding.
- **One action, three callers, one code path.** A machine/group action
  (system update, power, a custom command) lives once in
  `app/services/machine_actions.py` and is called identically by a human's
  button click (`app/web/routes/machines.py`), the REST API
  (`app/web/routes/api_v1.py`), and a cron-scheduled task
  (`app/scheduling/`) — never reimplemented per caller.
- **The REST API mirrors the web UI, deliberately incompletely.** Every
  `api_v1_*.py` router under `app/web/routes/` uses the exact same
  `Permission` and calls the exact same service/task functions its web
  equivalent does — see `api_v1.py`'s module docstring for what's
  deliberately excluded (SSH key rotation, LDAP/OIDC/syslog config, the
  interactive terminal, the AI chat) and why. Closing a *genuine* gap
  between the two needs a matching wiki/Architecture.md update.
- **WebSockets do their own auth.** `app.auth.middleware` never runs for
  `scope["type"] == "websocket"` requests (Starlette only invokes
  `http`-scoped middleware for those) — `terminal_ws.py` and `live_ws.py`
  each re-implement the session-cookie + permission check by hand at the
  top of the handler, before `accept()`ing the connection.
- **Live updates are a doorbell, not a data feed.** `app/services/
  live_updates.py` publishes `{"kind": "..."}` over Redis pub/sub after a
  background job's commit; `app/web/routes/live_ws.py` relays it to the
  browser; `static/js/live-updates.js` turns it into a `live-<kind>` DOM
  event an htmx panel's `hx-trigger` listens for, re-triggering that
  panel's own already-permission-checked fetch. The push never carries
  machine data itself.
- **CSP is strict — no inline scripts or styles, no CDN.** `script-src
  'self'`, `style-src 'self'`. Every third-party JS/CSS bundle (htmx,
  xterm.js, Swagger UI) is vendored under `app/web/static/`, not loaded
  from a CDN. A CSP violation is silent at the Python layer (route returns
  200, tests pass) and only shows up as a blank widget + console error in
  a real browser — verify anything CSP-adjacent there, not just by reading
  the code. New CSS reads colors through `--color-*` custom properties in
  `style.css` (never a hardcoded color), since the light theme
  (`:root[data-theme="light"]`) only overrides those variables.
- **Audit logging is a deliberate, curated trail, not a debug log.**
  `app.audit.log_event(...)` is called once, after the triggering
  `db.commit()`, for every human- or schedule-initiated mutation and for
  each safeguard that blocked one (bad confirmation, missing host key) —
  never for the unattended periodic sweeps themselves (reachability
  checks, the facts/update-check Beat sweeps). Action codes are
  `lowercase.dot.separated`.
- **Model discovery for Alembic** happens via explicit imports in
  `app/db/models/__init__.py` and `alembic/env.py` — a new model module
  not imported there is invisible to `--autogenerate`.
