# 🖥️ debcontrol

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.14-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/web-FastAPI-009688?logo=fastapi&logoColor=white)
![Task queue](https://img.shields.io/badge/task%20queue-Celery-37814A?logo=celery&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/db-PostgreSQL%2018-336791?logo=postgresql&logoColor=white)
![Docker Compose](https://img.shields.io/badge/deploy-Docker%20Compose-2496ED?logo=docker&logoColor=white)

A web application for managing Debian machines over SSH. Officially
supported: Debian and its derivatives (e.g. Ubuntu), for as long as each
is supported by its own upstream — see the wiki:
[Managed Machine Requirements](wiki/Managed-Machine-Requirements.md#os).
Every page requires a login; access is controlled by custom roles (RBAC)
an admin defines, and accounts can authenticate locally, against LDAP, or
via OIDC SSO, with optional (or role-required) TOTP two-factor.

**Full documentation lives in the [wiki](wiki/Home.md)** — technology
choices and the full security model ([Architecture](wiki/Architecture.md)),
every feature in detail ([Home](wiki/Home.md)'s feature table), reverse
proxy guides, and local development/testing
([Development](wiki/Development.md)). This file only covers getting a
fresh instance running.

## 🚀 Quick start (Docker)

```bash
cp .env.example .env
python scripts/generate_secrets.py
```

Paste the printed values (`SECRET_KEY`, `ENCRYPTION_KEY`,
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`) into `.env`, and make sure
`DATABASE_URL`/`REDIS_URL` use the same passwords as
`POSTGRES_PASSWORD`/`REDIS_PASSWORD`. Optionally set `TZ` (e.g.
`Europe/Prague`) — it's applied to every container and only affects log
timestamps and local-time display; defaults to UTC.

**Without a reverse proxy in front (or if you already run your own):**

```bash
docker compose up -d --build
```

The app listens on port `8080` (plain HTTP, all interfaces — meant to sit
behind a TLS-terminating reverse proxy; firewall it off or bind it to
`127.0.0.1:8080:8080` in `docker-compose.yml` if you don't want that). Point
your own nginx/Traefik/Caddy at `127.0.0.1:8080` — see the reverse-proxy
guides in the wiki: [nginx](wiki/Reverse-Proxy-Nginx.md) ·
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

> [!WARNING]
> The app speaks **plain HTTP only** and publishes port `8080` on all
> interfaces. Always put TLS termination in front of it, and firewall that
> port off (or bind it to `127.0.0.1`) if you don't want it reachable
> directly.

## 🔑 First login

**Create the first administrator account** — every debcontrol account
is created inside the app itself, so there's no other way in on a fresh
deployment:

```bash
docker compose exec web python scripts/create_admin.py --username admin
```

It prompts for a password (at least 12 characters) and creates an
"Administrator" role with every permission if one doesn't exist yet. You'll
be asked to change that password on first login. See
[wiki/Installation.md](wiki/Installation.md) for the full walkthrough
(what the Compose stack brings up, environment variables, LDAP/OIDC setup,
and account recovery if you ever get locked out) and
[wiki/Installation.md#updating](wiki/Installation.md#updating) for
upgrading later (`./scripts/upgrade.sh`).

## 🛠️ Local development without Docker

```bash
uv sync
docker compose up -d db redis
uv run alembic upgrade head
uv run python scripts/create_admin.py --username admin
uv run uvicorn app.main:app --reload
# second terminal — background tasks:
uv run celery -A app.tasks.celery_app worker --loglevel=info
# third terminal — periodic sweeps and the scheduled-task tick (optional):
uv run celery -A app.tasks.celery_app beat --loglevel=info
```

> [!IMPORTANT]
> Run **exactly one** `beat` process, here and in production. Every replica
> publishes the same schedule, so a second one makes each periodic sweep and
> daily purge fire twice.

See [wiki/Development.md](wiki/Development.md) for running tests
(`uv run pytest`), linting/type-checking, adding a migration, and other
project conventions.

## 📄 License

[MIT](LICENSE)
