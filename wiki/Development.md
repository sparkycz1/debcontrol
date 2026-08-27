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
uv run mypy app
```

`mypy` runs in `strict` mode for `app/`; `tests/` has a relaxed override
(see `pyproject.toml`) since annotating every fixture adds little value.

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
