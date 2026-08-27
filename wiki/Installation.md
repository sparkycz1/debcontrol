# Installation

debcontrol ships as a Docker Compose stack: PostgreSQL 18, Redis 8.8, the
web app, a background worker, and an optional Caddy reverse proxy.

## Prerequisites

- Docker and Docker Compose v2 (the `docker compose` subcommand, not the
  old standalone `docker-compose`).
- A domain name pointing at this host, **only if** you want to use the
  bundled Caddy for automatic HTTPS. Not needed if you already have a
  reverse proxy, or you're just trying this out over plain HTTP locally.

## 1. Configure

```bash
cp .env.example .env
python scripts/generate_secrets.py
```

Copy the printed `SECRET_KEY`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD`, and
`REDIS_PASSWORD` values into `.env`. Then make sure `DATABASE_URL` and
`REDIS_URL` embed the *same* passwords you just set for
`POSTGRES_PASSWORD` / `REDIS_PASSWORD` — they're separate variables
because Postgres/Redis images and the app read them differently, but the
values must match.

The app validates configuration at startup and **refuses to start** if any
secret still looks like a placeholder from `.env.example` — that's
intentional.

### Environment variables

| Variable | Used by | Purpose |
|---|---|---|
| `APP_ENV` | app | `development` or `production`. Controls `/docs` exposure and HSTS. |
| `SECRET_KEY` | app | Reserved for future session/signing use. |
| `ENCRYPTION_KEY` | app | Fernet key encrypting stored SSH passwords/private keys. |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | db | Postgres container credentials. |
| `DATABASE_URL` | app | Full async SQLAlchemy URL to Postgres. |
| `REDIS_PASSWORD` | redis | Redis container password (`--requirepass`). |
| `REDIS_URL` | app | Full Redis URL (cache + arq queue). |
| `SSH_DATA_DIR` | app | Reserved data directory inside the container. |
| `SSH_CONNECT_TIMEOUT` | app | SSH connection timeout, in seconds. |
| `FACTS_REFRESH_INTERVAL_SECONDS` | worker | How often (seconds) OS/kernel/CPU/RAM/disk facts are refreshed per machine. Default 3600. |
| `INFORM_TOKEN` | app | Bearer token required by `POST /api/inform` (self-registration). |
| `LOG_LEVEL` | app | Python logging level. |
| `DOMAIN` | caddy | Public hostname to request a certificate for (Caddy stack only). |
| `ACME_EMAIL` | caddy | Contact email for Let's Encrypt (Caddy stack only). |

## 2. Run

### Option A — behind your own reverse proxy (or no proxy, local testing)

```bash
docker compose up -d --build
```

This starts Postgres, Redis, runs migrations once (`migrate` service), then
starts `web` and `worker`. The app listens on `127.0.0.1:8000` — plain
HTTP, loopback-only. If you have your own nginx/Traefik/Caddy already
running on this host, point it at `127.0.0.1:8000`; see:
[nginx](Reverse-Proxy-Nginx.md), [Traefik](Reverse-Proxy-Traefik.md),
[Caddy](Reverse-Proxy-Caddy.md).

If your reverse proxy runs in its own separate Docker Compose project, it
needs to join this project's network instead of using the loopback
address — see the relevant guide for details.

### Option B — with the bundled Caddy (automatic HTTPS)

Set `DOMAIN` and `ACME_EMAIL` in `.env`, point that domain's DNS A/AAAA
record at this host's public IP, and make sure ports `80/tcp`, `443/tcp`,
and `443/udp` are reachable from the internet (443/udp is required for
HTTP/3). Then:

```bash
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

See [Reverse Proxy: Caddy](Reverse-Proxy-Caddy.md) for details,
TLS/HTTP-3 verification, and troubleshooting.

## 3. Verify

```bash
docker compose ps
docker compose logs -f web
```

Open the app (via whichever reverse proxy / port you configured) and check
`/healthz` returns `{"status": "ok"}`.

## Updating

```bash
git pull
docker compose up -d --build
# or, with Caddy:
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

The `migrate` service re-runs on every `up`, applying any new Alembic
migrations before `web`/`worker` start.
