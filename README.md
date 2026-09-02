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
[Machine Requirements](wiki/Machine-Requirements.md#os).
Every page requires a login; access is controlled by custom roles (RBAC)
an admin defines, and accounts can authenticate locally, against LDAP, or
via OIDC SSO, with optional (or role-required) TOTP two-factor. Everything
in the web UI is also available as a full read/write REST API, with
interactive [Swagger](https://swagger.io/tools/swagger-ui/) docs at `/api`
once logged in.

**Full documentation lives in the [wiki](wiki/Home.md)** — technology
choices and the full security model ([Architecture](wiki/Architecture.md)),
every feature in detail ([Home](wiki/Home.md)'s feature table), reverse
proxy guides, and local development/testing
([Development](wiki/Development.md)). This file only covers getting a
fresh instance running.

## 🚀 Quick start (Docker)

**Recommended — one interactive script does everything:**

```bash
git clone https://github.com/sparkycz1/debcontrol.git
cd debcontrol
python scripts/setup.py
```

It generates every secret, asks a handful of questions (timezone, whether
to use the bundled Caddy reverse proxy, background-check intervals, the
Administrator password — or auto-generates one — and the host port), then
brings the stack up and creates the first admin account for you. Full
details: [wiki/Installation.md](wiki/Installation.md).

**Manual setup**, if you'd rather configure everything by hand:

```bash
cp .env.example .env
python scripts/generate_secrets.py
```

Paste the printed values (`SECRET_KEY`, `ENCRYPTION_KEY`,
`POSTGRES_PASSWORD`, `REDIS_PASSWORD`) into `.env`. Optionally set `TZ`
(e.g. `Europe/Prague`) — it's applied to every container and used by the
app to display timestamps in the UI in that timezone; defaults to UTC.
Then:

```bash
docker compose up -d --build
```

The app listens on `APP_PORT` (default `8080`, plain HTTP, all interfaces
— meant to sit behind a TLS-terminating reverse proxy; firewall it off or
bind it to `127.0.0.1` in `docker-compose.yml` if you don't want that).
Point your own nginx/Traefik/Caddy at it — see the reverse-proxy guides in
the wiki: [nginx](wiki/Reverse-Proxy-Nginx.md) ·
[Traefik](wiki/Reverse-Proxy-Traefik.md) ·
[Caddy (standalone)](wiki/Reverse-Proxy-Caddy.md). Or use the **bundled
Caddy** (automatic HTTPS via Let's Encrypt, TLS 1.3 only, HTTP/3): set
`DOMAIN` and `ACME_EMAIL` in `.env`, point that domain's DNS at this host,
open ports 80/tcp, 443/tcp and 443/udp, then
`docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build`
— see [wiki/Reverse-Proxy-Caddy.md](wiki/Reverse-Proxy-Caddy.md).

Then create the first administrator account yourself:

```bash
docker compose exec web python scripts/create_admin.py --username admin
```

> [!WARNING]
> The app speaks **plain HTTP only**. Always put TLS termination in front
> of it, and firewall its port off (or bind it to `127.0.0.1`) if you don't
> want it reachable directly.

See [wiki/Installation.md](wiki/Installation.md) for the full walkthrough
(environment variables, LDAP/OIDC setup, account recovery if you ever get
locked out) and [wiki/Installation.md#updating](wiki/Installation.md#updating)
for upgrading later (`./scripts/upgrade.sh`). See
[wiki/Development.md](wiki/Development.md) for running the test suite,
linting/type-checking, adding a migration, and other project conventions.

## 🔒 Security

See [.github/SECURITY.md](.github/SECURITY.md) — supported versions and how to report a vulnerability. Dependency updates and security alerts are automated via [Dependabot](.github/dependabot.yml).

## 📄 License

[MIT](LICENSE)
