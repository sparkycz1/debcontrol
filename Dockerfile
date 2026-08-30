# syntax=docker/dockerfile:1

# --- Stage 1: build the virtualenv with uv -----------------------------------
FROM python:3.14.7-slim AS builder

# Official static uv binary — no need to pip-install it into the image.
# Pinned to an exact version (same reasoning as Postgres/Redis/Caddy) —
# `:latest` would silently pick up a new uv release, and thus a possibly
# different dependency resolver/behavior, on every rebuild.
COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /build

# Manifests first — the dependency layer is cached separately from the source code.
COPY pyproject.toml uv.lock ./

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev

COPY app ./app

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

# --- Stage 2: minimal runtime image ------------------------------------------
FROM python:3.14.7-slim AS runtime

RUN groupadd --system app && useradd --system --gid app --home-dir /app --create-home app

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # uvicorn (web's CMD), celery (worker/beat's), and alembic (alembic.ini's
    # prepend_sys_path = .) both already make "app.*" importable relative
    # to the working directory on their own — a plain `python
    # scripts/create_admin.py` invocation (docker compose exec) doesn't
    # get that same treatment, so it needs /app on sys.path explicitly.
    PYTHONPATH=/app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=app:app app ./app
COPY --chown=app:app alembic ./alembic
COPY --chown=app:app alembic.ini ./alembic.ini
# create_admin.py / reset_account.py are meant to be run inside the
# container (docker compose exec web python scripts/...), per
# wiki/Installation.md — generate_secrets.py and upgrade.sh are host-only
# tools but harmless to have here too, and copying the whole directory is
# simpler than picking files apart.
COPY --chown=app:app scripts ./scripts

RUN mkdir -p /app/data && chown app:app /app/data

# Which commit this image was built from — the `.git` directory itself is
# never copied in, so this is the only way `app.core.version` can know at
# runtime. Passed via `docker compose build --build-arg` (docker-compose.yml
# sets it from the GIT_COMMIT shell variable, which scripts/upgrade.sh
# exports before building); defaults to "unknown" for a plain `docker build`
# with nothing passed.
ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=${GIT_COMMIT}

USER app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/healthz', timeout=3)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
