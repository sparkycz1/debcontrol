# Installation

debcontrol ships as a Docker Compose stack: PostgreSQL 18.6, Redis 8.10.1, the
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
| `SECRET_KEY` | app | Signs the OIDC-flow session cookie and the pending-TOTP token between login steps. |
| `ENCRYPTION_KEY` | app | Fernet key encrypting stored SSH passwords/private keys. |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | db | Postgres container credentials. |
| `DATABASE_URL` | app | Full async SQLAlchemy URL to Postgres. |
| `REDIS_PASSWORD` | redis | Redis container password (`--requirepass`). |
| `REDIS_URL` | app | Full Redis URL (cache + arq queue). |
| `SSH_DATA_DIR` | app | Reserved data directory inside the container. |
| `SSH_CONNECT_TIMEOUT` | app | SSH connection timeout, in seconds. |
| `FACTS_REFRESH_INTERVAL_SECONDS` | worker | How often (seconds) OS/kernel/CPU/RAM/disk facts are refreshed per machine. Default 3600. |
| `REACHABILITY_CHECK_INTERVAL_SECONDS` | worker | How often (seconds) the online/offline status badge's TCP-only reachability sweep runs per machine. Default 60. |
| `UPDATE_TIMEOUT_SECONDS` | worker | Max time (seconds) for one machine's full update/upgrade/autoremove/autoclean run. Default 1800. |
| `INFORM_TOKEN` | app | Bearer token required by `POST /api/inform` (self-registration). |
| `LOG_LEVEL` | app | Python logging level. |
| `TZ` | db, redis, app, worker, caddy | IANA timezone (e.g. `Europe/Prague`) applied to every container. Affects log timestamps and local-time display only — data is always stored as UTC, and Scheduling's cron expressions are always interpreted as UTC regardless of this. Defaults to UTC if unset. |
| `DOMAIN` | caddy | Public hostname to request a certificate for (Caddy stack only). |
| `ACME_EMAIL` | caddy | Contact email for Let's Encrypt (Caddy stack only). |

Not every setting lives here: the audit log's retention policy (how many
days of entries to keep before a daily purge), and LDAP/OIDC login
configuration (server, bind account, search filter / issuer, client
credentials), are set from the **Settings** page in the app itself, not
environment variables — see
[Architecture](Architecture.md#audit-log-retention-the-first-setting-editable-through-the-ui)
and [Architecture](Architecture.md#authentication--rbac).

## 2. Run

### Option A — behind your own reverse proxy (or no proxy, local testing)

```bash
docker compose up -d --build
```

This starts Postgres, Redis, runs migrations once (`migrate` service), then
starts `web` and `worker`. The app listens on port `8080` — plain HTTP,
published on all interfaces (block it at the firewall, or bind
`docker-compose.yml`'s `web.ports` to `127.0.0.1:8080:8080`, if you don't
want it reachable directly). If you have your own nginx/Traefik/Caddy
already running on this host, point it at `127.0.0.1:8080`; see:
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

## 3. Create the first administrator

Every debcontrol account is created inside the app itself — there's no
auto-provisioning from LDAP or OIDC, and every page requires a login — so
this is the one way into a brand new deployment:

```bash
docker compose exec web python scripts/create_admin.py --username admin
```

It prompts for a password (at least 12 characters; typed twice to confirm)
and creates an "Administrator" role with every permission if one doesn't
exist yet. You'll be asked to change that password on first login. See
[Architecture](Architecture.md#authentication--rbac) for how login, roles,
and permissions work, and [Development](Development.md) for adding a new
permission.

If any account (including this one) later gets locked out with no way in at
all — a forgotten password, a lost TOTP device — `scripts/reset_account.py`
is the same kind of console-only tool, but for an existing account instead
of creating a new one:

```bash
docker compose exec web python scripts/reset_account.py --username admin --disable-totp
```

Always resets the password (prompted, or `DEBCONTROL_RESET_PASSWORD` in the
environment) and clears any lockout; `--disable-totp` additionally turns off
two-factor. See the script's own `--help`/module docstring for the full
set of options.

## 4. Verify

```bash
docker compose ps
docker compose logs -f web
```

Open the app (via whichever reverse proxy / port you configured) and check
`/healthz` returns `{"status": "ok"}`. `/login` should be the only page
reachable without a session.

## Updating

```bash
./scripts/upgrade.sh
```

Does the whole thing: refuses to run with uncommitted local changes or
outside a git checkout, `git fetch`/`git pull --ff-only` on the current
branch (fails loudly rather than merging or silently diverging), detects
whether the bundled Caddy is currently running and includes
`docker-compose.caddy.yml` automatically if so, then `docker compose build`
+ `docker compose up -d` and prints `docker compose ps` at the end. Safe to
run again if something looks off partway through — every step it takes is
already idempotent.

Equivalent by hand, if you'd rather see each step yourself:

```bash
git pull
docker compose up -d --build
# or, with Caddy:
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

Either way, the `migrate` service re-runs on every `up`, applying any new
Alembic migrations before `web`/`worker` start — there's no separate
"run migrations" step.

Postgres, Redis, and Caddy are pinned to exact versions in
`docker-compose.yml`/`docker-compose.caddy.yml` (`postgres:18.6`,
`redis:8.10.1`, `caddy:2.11.4`) precisely so that an upgrade — scripted or
by hand — never silently bumps any of them. Bumping one of those versions
is a deliberate, separate step: edit the tag, test against it, and commit
that change on its own.

### If `db` refuses to start with a "pg_ctlcluster" / "unused mount/volume" error

Only affects a checkout from before the `db` volume mount was corrected —
current `docker-compose.yml` already mounts it right. The `postgres:18`
image expects its volume mounted at `/var/lib/postgresql` (it manages a
major-version-specific subdirectory itself, `/var/lib/postgresql/18/docker`)
rather than directly at `/var/lib/postgresql/data`, the older convention;
an old checkout that initialized its `pg_data` volume the old way leaves
real data sitting at the legacy path once you update — the image refuses
to start rather than risk quietly initializing an empty cluster next to
it. If that volume has nothing worth keeping (a fresh test deployment),
the fix is a reset:

```bash
docker compose down -v   # drops pg_data (and redis_data, ssh_data) entirely
git pull                 # picks up the corrected mount
docker compose up -d --build
```

If it holds real data you need to keep, don't run the above — instead
move the volume's existing contents into the layout the image now expects
(no `pg_upgrade` needed, it's still the same 18.6): stop the stack, run a
throwaway container with the `pg_data` volume mounted at
`/var/lib/postgresql`, and inside it `mkdir -p 18 && mv data 18/docker`
(adjust if you'd already customized `PGDATA`/cluster name), then bring the
stack back up with the corrected `docker-compose.yml`.
