# 🛠️ Development

*Ruff, mypy, pytest, one Alembic head — the gate CI runs too — plus
recipes for the most common changes.*

## 📦 Setup

```bash
uv sync
```

Installs dependencies into `.venv` for tests, linting and type checking.
The app itself only runs in Docker ([Installation](Installation.md));
iterate with `docker compose up -d --build`.

## ✅ The gate

```bash
uv run ruff check .
uv run mypy app alembic tests     # strict for app/ and alembic/
uv run pytest
uv run alembic heads              # exactly one head
```

CI (`.github/workflows/ci.yml`) runs the same on every push and PR, plus
`pip-audit` over `uv.lock`; Dependabot watches Python, Docker and Actions
dependencies.

### Tests

Tests never touch Postgres, Redis or a Celery broker: `tests/conftest.py`
sets dummy config, gives each test an in-memory SQLite session and stubs
`Task.apply_async`.

- **`client`** — logged in with every permission; **`anonymous_client`** —
  no session; **`login_as(client, permissions={...})`** — exactly those
  permissions (RBAC tests); `create_local_user(...)` for real password
  logins.
- **`celery_calls`** (autouse) records every enqueued
  `(task_name, args, kwargs)`; `celery_calls.result_for["<task>"] = {...}`
  sets what a route waiting on `AsyncResult.get()` receives.
- `app.state.redis` is a `FakeRedis` for the login rate limiter.
- Test a task through its `async def _name(...)` coroutine, not the Celery
  wrapper (`asyncio.run` can't run inside pytest-asyncio's loop); point
  `app.db.session.AsyncSessionLocal` at the test factory with
  `monkeypatch`.

## 🗄️ Database migrations

After changing a model in `app/db/models/`:

```bash
uv run alembic revision --autogenerate -m "describe the change"
```

**Read the generated file** — autogenerate misses or mangles some changes.
A new model module must be imported in `app/db/models/__init__.py` (and
therefore `alembic/env.py`) or autogenerate won't see it. New columns must
be nullable or have a server default, since real instances upgrade in
place. `uv run alembic upgrade head` / `downgrade -1` to apply or undo.

## 🧩 Adding a page / router

1. A module under `app/web/routes/`, gated with
   `APIRouter(dependencies=[Depends(require_permission(Permission.X))])`
   and stricter per-route permissions for changes (see the
   `_manage`/`_updates`/`_power` pattern in `machines.py`).
2. Register it in `app/main.py`.
3. Templates extend `base.html`; strings go through `t()` (below). A nav
   link is gated with `current_user.has_permission(...)`.
4. Every mutating route has `Depends(verify_csrf)`; forms use
   `request.state.csrf_token`.
5. Log the change (or the safeguard that refused it) with
   `app.audit.log_event` after the commit.
6. Add the REST equivalent under `api_v1_*.py` with the same permission and
   service calls — or document why it stays web-only.
7. Update the wiki page that describes the feature.

## 🔐 Adding a permission

1. Add it to `Permission` in `app/db/models/role.py`
   (`lowercase.dot.separated`).
2. A `.manage` with a matching `.view` goes into `_MANAGE_IMPLIES_VIEW`
   (`app/db/models/user.py`).
3. Migration: `ALTER TYPE permission ADD VALUE ...` in its own
   `op.execute(...)`. Existing roles don't get it automatically.
4. Add `permission.<code>` and `permission.<code>.hint` to every locale.

## 🖧 Adding a machine/group action

Put the "do this to a list of machines" logic in
`app/services/machine_actions.py` (no `Request`, just `task.delay(...)`),
so a button, the REST API and a schedule all use the same code. Wire it
into the machine, group and "All machines" routes and the API. To make it
schedulable, register a `ScheduledActionSpec` in
`app/scheduling/builtin_actions.py` (`destructive=True` for anything
without an undo).

## ⏱️ Adding a background task

1. `async def _my_task(...)` in `app/tasks/jobs.py`, opening sessions as
   `db_session.AsyncSessionLocal()` **through the module** — see
   [fork safety](Architecture.md#fork-safety-the-db-engine-is-rebuilt-in-every-worker-child).
2. A one-line wrapper with an explicit name:

   ```python
   @celery_app.task(name="app.tasks.jobs.my_task")
   def my_task(arg: str) -> dict[str, Any]:
       return asyncio.run(_my_task(arg))
   ```

   Add `time_limit=` if it may exceed 60 s. A periodic read-only SSH
   collector returns `run_in_worker_loop(_my_task(arg))` instead, opens SSH
   with `app.ssh.pool.machine_connection(...)` and wraps commands that may
   use `sudo` in `app.ssh.shell.with_root_shim(...)`.
3. Enqueue with `my_task.delay(...)` — one task per machine for a fan-out.
   A route that must wait uses `await asyncio.to_thread(result.get,
   timeout=...)` and catches `celery.exceptions.TimeoutError`.
4. Periodic? Add a `beat_schedule` entry in `app/tasks/celery_app.py`;
   tasks never re-enqueue themselves.
5. A new task module must be added to `celery_app`'s `include=[...]`.

## 📝 Recording an action in the audit log

`app.audit.log_event(db, request=request, action="...", summary="...", ...)`
is the only way audit rows are written.

- Call it **after** `db.commit()`.
- Log refusals too (`AuditOutcome.DENIED` / `FAILURE`) — see
  `power_action` in `machines.py`.
- Codes are `lowercase.dot.separated` (`machine.power.reboot`).
- `summary` is English; add `audit.action_label.<code>` to **every** locale.
- Scheduled runs pass `actor=` (see `_SCHEDULER_ACTOR`); unattended
  periodic sweeps are **not** logged.

## 🌐 UI strings and languages

See [Per-user UI language](Authentication-RBAC.md#per-user-ui-language-i18n).

- **In a template**: `{{ t(request, "area.key", name=value) }}` with
  `"Hello, {name}!"` in the locale.
- **Every new key goes into every locale file** (`en.json` and `cs.json`
  today), with Czech plural variants (`.one`/`.few`/`.other`) where a
  count is involved. Keep the `area.` prefixes consistent.
- **In JavaScript**: emit the keys with
  `{% from "partials/_js_i18n.html" import js_i18n with context %}{{ js_i18n([...]) }}`
  and read them from the `#js-i18n` JSON block.
- **From a route**: `t(request, ...)` for page-only messages;
  `LocalizedText(request, ...)` (`app.web.messages`) when the same message
  also goes to the audit log; `sign_flash(...)` / `flash(request, ...)`
  for messages carried through a redirect — never render a raw query
  parameter.
- **A new language**: copy `en.json` to `<code>.json`, set `meta.code` and
  the native `meta.label`, translate, restart.

## 📐 Conventions

- Code, comments, commits and docs are in English.
- Follow existing patterns (`machine_groups.py` for CRUD routes,
  `machine_group.py` for models).
- New CSS uses the `--color-*` variables — the light theme overrides only
  those.
- User-supplied redirect targets go through
  `app.web.redirects.safe_local_path`.
- **Every round of changes** bumps `APP_VERSION` (`app/core/version.py`)
  and `version` (`pyproject.toml`) together — patch for fixes, minor for
  features — then `uv lock`. When that reaches `main`,
  `.github/workflows/release.yml` tags `vX.Y.Z` and publishes a release
  whose notes are each commit's subject and full body since the last tag
  (commits touching only CI, tests, docs or version numbers are left out),
  so the version commit's body must list **every** user-facing change,
  moved URL, migration and upgrade note. A missed version can be released
  from Actions → Release → Run workflow.
- Merged PR branches are deleted automatically.

> [!TIP]
> **Verify anything CSP-related in a real browser.** A CSP violation is
> silent in Python (200, tests pass) and only shows as a broken widget and
> a console error — e.g. an inline `style=` collapsing the terminal, or
> Swagger UI missing its second bundle.
