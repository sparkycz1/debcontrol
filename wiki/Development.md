# Development

## Setup

```bash
uv sync
cp .env.example .env
python scripts/generate_secrets.py   # paste values into .env
docker compose up -d db redis
uv run alembic upgrade head
```

## Running the app

```bash
uv run uvicorn app.main:app --reload
# in a second terminal, if you're touching anything in app/tasks or app/ssh:
uv run arq app.tasks.worker.WorkerSettings
```

`DATABASE_URL`/`REDIS_URL` in `.env` should point at `localhost` (not the
Docker service names `db`/`redis`) when running the app itself outside
Docker like this, since `db`/`redis` are only resolvable from inside the
Compose network.

## Tests

```bash
uv run pytest
```

Tests never touch real Postgres/Redis: `tests/conftest.py` sets dummy
config values before `app.main` is imported, and overrides the `get_db`
dependency with an isolated in-memory SQLite session per test. This makes
the suite fast and independent of `docker compose` being up at all.

## Linting and type checking

```bash
uv run ruff check .
uv run ruff format --check .   # if/when formatting is enforced
uv run mypy app alembic tests
```

`mypy` runs in `strict` mode for `app/` and `alembic/`; `tests/` has a
relaxed override (see `pyproject.toml`) since annotating every fixture
adds little value.

## Database migrations

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

## Adding a new page / router

1. Add a route module under `app/web/routes/`.
2. Register its router in `app/main.py` (`app.include_router(...)`).
3. Add templates under `app/web/templates/`, extending `base.html`.
4. If it needs a nav entry, add it to the `<nav>` block in
   `app/web/templates/base.html`.
5. Any state-changing (POST/PUT/DELETE) endpoint needs
   `dependencies=[Depends(verify_csrf)]`, and any page rendering a form
   needs to obtain a CSRF token via `get_or_create_csrf_token()` — see
   `app/web/routes/machines.py` for the pattern.
6. If it mutates something (or refuses to because a safeguard tripped),
   call `app.audit.log_event(...)` right after — see "Recording a new
   action in the audit log" below. Every existing mutating route already
   does this; a new one that doesn't is the exception, not the rule.

## Adding a new action against machines/groups

If a feature does something to one or more machines (like System updates,
Check for updates, or Power), put the "do this to a list of machines" part
in `app/services/machine_actions.py` (taking the arq redis pool directly,
not a `Request`) rather than inline in the route — that's what lets both a
human clicking a button *and* a cron schedule trigger the exact same code
path. Then:

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

## Recording a new action in the audit log

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
  facts/update-check cron jobs) are **not** logged — only a human- or
  schedule-triggered action, and the safeguard that blocked one. Don't add
  audit calls inside `app/tasks/jobs.py`'s periodic sweep functions
  themselves.

## Project conventions

- All code, comments, docstrings, commit messages, and documentation are
  in English.
- Prefer editing an existing pattern over inventing a new one — e.g. new
  CRUD routers should look like `app/web/routes/machine_groups.py`, new
  SQLAlchemy models should look like `app/db/models/machine_group.py`.
- Keep `pyproject.toml`'s dependency lower bounds close to what's
  actually installed (`uv.lock` pins the exact versions) — see the root
  `README.md`'s "Dependency version notes" for the one deliberate
  exception (`redis-py` pinned below Redis server's own version line).
