# 🛠️ Development

## 📦 Setup

```bash
uv sync
cp .env.example .env
python scripts/generate_secrets.py   # paste values into .env
docker compose up -d db redis
uv run alembic upgrade head
```

## ▶️ Running the app

The web app, the task worker, and the periodic scheduler are **three
separate processes**:

```bash
# Terminal 1 — the web app
uv run uvicorn app.main:app --reload

# Terminal 2 — the Celery worker (needed if you're touching anything in
# app/tasks, app/scheduling, or app/ssh, or clicking any button that
# enqueues background work)
uv run celery -A app.tasks.celery_app worker --loglevel=info

# Terminal 3 — Celery Beat, ONLY if you need the periodic sweeps or the
# per-minute scheduled-task tick. Most feature work does not.
uv run celery -A app.tasks.celery_app beat --loglevel=info
```

> [!TIP]
> On Windows the prefork pool isn't available; add `--pool=solo` to the
> worker command. That runs one task at a time in-process and skips the
> fork entirely — which also means the `worker_process_init` fork-safety
> hook described in
> [Architecture](Architecture.md#fork-safety-the-db-engine-is-rebuilt-in-every-worker-child)
> never fires, so **never** use `--pool=solo` to reason about production
> behaviour.

> [!IMPORTANT]
> Run **exactly one** `beat` process. Two of them publish the same schedule
> twice, so every sweep and every daily purge fires twice.

Set `POSTGRES_HOST=localhost`/`REDIS_HOST=localhost` in `.env` when running
the app itself outside Docker like this — `db`/`redis` (the defaults) are
only resolvable from inside the Compose network.

## ✅ Tests

```bash
uv run pytest
```

Tests never touch real Postgres, Redis, **or a Celery broker**:
`tests/conftest.py` sets dummy config values before `app.main` is imported,
overrides the `get_db` dependency with an isolated in-memory SQLite session
per test, and monkeypatches `celery.app.task.Task.apply_async` (what
`.delay()` calls underneath) so no message is ever published. This makes the
suite fast and independent of `docker compose` being up at all.

Two fixtures exist specifically for background work:

- **`celery_calls`** (autouse) — records every `(task_name, args, kwargs)`
  a request enqueued, also reachable as `app.state.celery_calls`. Assert on
  `celery_calls.names` to check *that* a task was enqueued, e.g.
  `assert "app.tasks.jobs.run_machine_update" in app.state.celery_calls.names`.
  Set `celery_calls.result_for["<task name>"] = {...}` to control what a
  route blocking on `AsyncResult.get()` gets back (the default is
  `{"ok": True, "output": "fake"}`).
- **`FakeRedis`** on `app.state.redis` — an `INCR`/`EXPIRE` stub for the
  login rate limiter only. Unrelated to the queue.

> [!NOTE]
> Task bodies are tested by calling the underscore-prefixed **coroutine**
> (`_record_fleet_snapshot()`), not the Celery task wrapper — the wrapper
> is `asyncio.run(...)`, which cannot run inside pytest-asyncio's already
> running event loop. Point `app.db.session.AsyncSessionLocal` at the test
> session factory with `monkeypatch.setattr` when doing so.

Since every route now requires a session, `tests/conftest.py` offers three
fixtures instead of just one `client`:

- **`client`** — already logged in as a user with *every* permission. What
  most tests want, since they're exercising a feature, not RBAC itself.
- **`anonymous_client`** — no session cookie at all; for login/logout/
  TOTP/access-denied tests (see `tests/test_auth.py`).
- **`login_as(some_client, permissions={Permission.X, ...})`** — creates a
  role+user with exactly those permissions and points `some_client`'s
  session cookie at them; for RBAC boundary tests (see
  `tests/test_rbac.py`) — e.g. confirming a role with only `machine.view`
  gets a 403 on a POST that needs `machine.manage`.

`tests/conftest.py` also exposes `create_local_user(db_session_factory,
username=..., password=...)` for tests that need to exercise the actual
`/login` form with a real, known password, rather than skip straight to an
injected session.

## 🧹 Linting and type checking

```bash
uv run ruff check .
uv run ruff format --check .   # if/when formatting is enforced
uv run mypy app alembic tests
```

`mypy` runs in `strict` mode for `app/` and `alembic/`; `tests/` has a
relaxed override (see `pyproject.toml`) since annotating every fixture
adds little value.

## 🗄️ Database migrations

Models live in `app/db/models/`. After changing one:

```bash
uv run alembic revision --autogenerate -m "describe the change"
```

Then **read the generated migration** — autogenerate is a good first
draft, not a guarantee of correctness (it can miss things like
check-constraint changes, or get column-type changes on Postgres wrong).
Apply it locally:

```bash
uv run alembic upgrade head
```

To roll back one revision:

```bash
uv run alembic downgrade -1
```

Every new model module needs to be imported somewhere that always runs
before Alembic looks at metadata — see the imports in `alembic/env.py`
and `app/db/models/__init__.py`.

## 🧩 Adding a new page / router

1. Add a route module under `app/web/routes/`.
2. Decide which `Permission` it needs (see "Adding a new permission"
   below) and gate it — usually at the router level:
   `APIRouter(prefix=..., dependencies=[Depends(require_permission(Permission.X))])`,
   with a stricter one added per-route for state-changing endpoints where
   that differs from the view-level gate (see `app/web/routes/machines.py`
   for the `_manage`/`_updates`/`_power` pattern). Every route not on
   `app.auth.middleware`'s public allowlist already requires *some* valid
   session — this is about which *permission*, on top of that.
3. Register its router in `app/main.py` (`app.include_router(...)`).
4. Add templates under `app/web/templates/`, extending `base.html`.
5. If it needs a nav entry, add it to the `<nav>` block in
   `app/web/templates/base.html`, gated the same way the existing ones are:
   `{% if current_user.has_permission('x.y') %}`.
6. Any state-changing (POST/PUT/DELETE) endpoint needs
   `dependencies=[Depends(verify_csrf)]`. A page rendering a form can just
   use `request.state.csrf_token` (set for every request by
   `app.auth.middleware`) rather than calling `get_or_create_csrf_token()`
   itself — that function still exists and is still used by
   routes written before the middleware did this centrally (see
   `app/web/routes/machines.py`), and stays consistent with it if you use
   it in a new route, but a new route doesn't need to.
7. If it mutates something (or refuses to because a safeguard tripped),
   call `app.audit.log_event(...)` right after — see "Recording a new
   action in the audit log" below. Every existing mutating route already
   does this; a new one that doesn't is the exception, not the rule.

## 🔐 Adding a new permission

1. Add a member to the `Permission` enum in `app/db/models/role.py`,
   `lowercase.dot.separated` (mirroring the resource it gates, same
   convention as audit action codes).
2. If it's a `MANAGE` permission with a matching `VIEW` one, add the pair to
   `_MANAGE_IMPLIES_VIEW` in `app/db/models/user.py` — see that module's
   docstring for why (a role granted MANAGE but not the matching VIEW
   would otherwise 403 on the page listing the very thing it can manage).
3. Add a migration: the `permission` Postgres enum type needs the new value
   (`ALTER TYPE permission ADD VALUE ...` — Postgres requires this can't run
   inside the same transaction as other DDL, so give it its own
   `op.execute(...)` in the migration; see any migration touching
   `role_permissions` for the existing enum's shape). Existing roles don't
   get the new permission automatically — an admin grants it explicitly on
   the **Roles** page, same as any other permission.
4. Gate the route(s) it protects with
   `Depends(require_permission(Permission.YOUR_NEW_ONE))` — see "Adding a
   new page / router" above.

## 🖧 Adding a new action against machines/groups

If a feature does something to one or more machines (like System updates,
Check for updates, or Power), put the "do this to a list of machines" part
in `app/services/machine_actions.py` (which takes **no `Request` and no
queue handle** — Celery tasks are importable objects, so it just calls
`some_task.delay(...)`) rather than inline in the route — that's what lets
both a human clicking a button *and* a cron schedule trigger the exact same
code path. Then:

1. Wire it into the per-machine and per-group/all-machines routes the same
   way `trigger_updates`/`trigger_check_updates`/`send_power_to_machines`
   already are in `app/web/routes/machines.py` and
   `app/web/routes/machine_groups.py`.
2. To make it **schedulable** too, write an `ActionRunFunc` (see
   `app/scheduling/actions.py`) and register a `ScheduledActionSpec` in
   `app/scheduling/builtin_actions.py`. That's the entire integration
   surface — the "New scheduled task" form, its validation, and the
   scheduler tick all read from that registry, not from a hardcoded list.
   Mark it `destructive=True` if it has no undo (like reboot/shutdown) so
   the form flags it with a ⚠.

## ⏱️ Adding a new background task

1. Write the real work as `async def _my_task(...)` in `app/tasks/jobs.py`,
   opening sessions as **`db_session.AsyncSessionLocal()`** — always through
   the module, never a `from app.db.session import AsyncSessionLocal`
   binding. See
   [Architecture](Architecture.md#fork-safety-the-db-engine-is-rebuilt-in-every-worker-child)
   for why that convention is not optional.
2. Add the one-line sync wrapper with an **explicit, stable name**:

   ```python
   @celery_app.task(name="app.tasks.jobs.my_task")
   def my_task(arg: str) -> dict[str, Any]:
       return asyncio.run(_my_task(arg))
   ```

   Give it its own `time_limit=` if it can legitimately outlive the
   60-second `task_time_limit` default.
3. Enqueue it with `my_task.delay(...)`. If a route must **wait** for the
   result, use
   `await asyncio.to_thread(async_result.get, timeout=...)` and catch
   `celery.exceptions.TimeoutError`, **not** the builtin.
4. If it should run periodically, add a `beat_schedule` entry in
   `app/tasks/celery_app.py`. Do **not** make the task re-enqueue itself —
   Beat owns cadence.
5. If you put it in a **new module** rather than `app/tasks/jobs.py` (as
   `app/tasks/ai_jobs.py` does), add that module to `celery_app`'s
   `include=[...]` list — that list is deliberately explicit rather than
   `autodiscover_tasks()`, so a module missing from it simply never
   registers its tasks and `.delay()` fails at runtime instead of at
   startup.

## 📝 Recording a new action in the audit log

`app.audit.log_event(db, request=request, action="...", summary="...", ...)`
is the only way `AuditLogEntry` rows get created — see `app/audit.py`'s
module docstring for the full parameter list (`outcome`, `target_type`/
`target_id`/`target_label`, `details`). Conventions to follow:

- Call it **after** your own `await db.commit()` — never before — so a
  logging failure (caught and swallowed inside `log_event`) can never roll
  back the action it's describing.
- For an endpoint that can be denied by a safeguard (a typed confirmation
  that didn't match, a missing pinned host key, invalid input), log that
  case too, with `outcome=AuditOutcome.DENIED` or `AuditOutcome.FAILURE`
  — see `power_action` in `app/web/routes/machines.py` for an example with
  both a denied and a successful path.
- Action codes are `lowercase.dot.separated`, mirroring the resource and
  what happened to it (`machine.power.reboot`, `scheduled_task.create`) —
  keep new ones consistent with what's already there so `/audit`'s search
  box stays useful.
- A background job with no `Request` (like a scheduled task firing on its
  own) passes `ip_address=None` implicitly and sets `actor=` to a fixed
  label instead — see `app/scheduling/jobs.py`'s `_SCHEDULER_ACTOR`.
- Routine, unattended sweeps (the per-minute reachability check, the
  facts/update-check Beat sweeps) are **not** logged — only a human- or
  schedule-triggered action, and the safeguard that blocked one. Don't add
  audit calls inside `app/tasks/jobs.py`'s periodic sweep functions
  themselves.

## 📐 Project conventions

- All code, comments, docstrings, commit messages, and documentation are
  in English.
- Prefer editing an existing pattern over inventing a new one — e.g. new
  CRUD routers should look like `app/web/routes/machine_groups.py`, new
  SQLAlchemy models should look like `app/db/models/machine_group.py`.
- Keep `pyproject.toml`'s dependency lower bounds close to what's
  actually installed (`uv.lock` pins the exact versions) — see
  [Architecture](Architecture.md#dependency-version-notes) for the
  reasoning, including why `redis-py` no longer carries an upper pin.
- Bump `APP_VERSION` in `app/core/version.py` **and** `version` in
  `pyproject.toml` together on every round of changes: patch for small
  fixes, minor for a feature or infrastructure change.

> [!TIP]
> **Anything CSP-adjacent must be verified in a real browser, not just by
> reading the code.** Vendored JS/CSS, a new inline `style=`/`<script>`, a
> third-party bundle's boot sequence — CSP violations and missing-file/
> wrong-global mistakes are silent at the Python layer (routes return 200,
> tests pass) and only ever show up as a blank widget and a console error
> in an actual browser. Two real examples from this codebase: an inline
> `style=` attribute on the SSH terminal's container was silently dropped
> under this app's strict CSP, collapsing it to zero height; and Swagger UI
> (`GET /api`) needs *two* vendored bundles, not the one some examples show
> — loading only `swagger-ui-bundle.js` renders a bare, chrome-less widget
> with a `Could not find component: StandaloneLayout` console warning,
> because the topbar/layout chrome ships in the separate
> `swagger-ui-standalone-preset.js`. Both were only caught by actually
> loading the page and reading the console, not by inspecting the HTML.
