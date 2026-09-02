# 📦 Installation

debcontrol ships as a Docker Compose stack: PostgreSQL 18.6, Redis 8.10.1,
the web app, a **Celery worker**, a **Celery Beat scheduler**, and an
optional Caddy reverse proxy.

## ✅ Prerequisites

- Docker and Docker Compose v2 (the `docker compose` subcommand, not the
  old standalone `docker-compose`).
- A domain name pointing at this host, **only if** you want to use the
  bundled Caddy for automatic HTTPS. Not needed if you already have a
  reverse proxy, or you're just trying this out over plain HTTP locally.
- Python 3 on the host, **only for the automated setup below** (stdlib
  only — nothing else to install first).

## 🚀 Option A — automated setup (recommended)

```bash
git clone https://github.com/sparkycz1/debcontrol.git
cd debcontrol
python scripts/setup.py
```

One interactive wizard does everything: copies `.env.example` to `.env`
and fills in every secret with a freshly generated random value
(`SECRET_KEY`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`,
`INFORM_TOKEN`), then asks:

1. **Timezone** (IANA name, e.g. `Europe/Prague`) — used both for every
   container's own clock and for how the app displays timestamps in the
   UI. Defaults to UTC.
2. **Whether to use the bundled Caddy** reverse proxy for automatic HTTPS
   — if yes, the domain name and an email address for Let's Encrypt.
3. **The facts-refresh and reachability-check intervals**, in seconds
   (defaults 3600 and 60).
4. **The Administrator account's password** — leave it empty and one is
   generated and printed once at the end.
5. **The host port** to publish the app on (default 8080).

It then writes `.env`, runs `docker compose up -d --build` (adding
`docker-compose.caddy.yml` too if Caddy was chosen), waits for the app to
report healthy, and creates the `admin` account with the password from
step 4. The final output prints the URL, username, and password (if one
was generated) — save that password now, it's shown once.

Re-running it on an existing `.env` asks before overwriting it. If you say
yes, it also runs `docker compose down -v` for you before starting the
stack back up — a fresh `POSTGRES_PASSWORD` means nothing if the old
`pg_data` volume is still around with the *previous* password baked into
it (Postgres only ever applies that variable while initializing an empty
data directory), so replacing `.env`'s secrets and keeping the old volume
would otherwise leave every container failing to connect with "password
authentication failed" the moment `migrate` runs.

## 🔧 Option B — manual setup

```bash
cp .env.example .env
python scripts/generate_secrets.py
```

Copy the printed `SECRET_KEY`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD`, and
`REDIS_PASSWORD` values into `.env`. Each password is written once — the app
builds its Postgres/Redis connection URLs from these values itself. Set
`DATABASE_URL`/`REDIS_URL` directly instead only if you need a URL these
parts can't express (a different host/port, a managed database).

Also set `TZ` (IANA name, e.g. `Europe/Prague` — defaults to UTC) and, if
you want the bundled Caddy reverse proxy, `DOMAIN` and `ACME_EMAIL`.
`FACTS_REFRESH_INTERVAL_SECONDS`, `REACHABILITY_CHECK_INTERVAL_SECONDS`,
and `APP_PORT` all have working defaults and only need changing if you
want something other than 3600s/60s/8080.

The app validates configuration at startup and **refuses to start** if any
secret still looks like a placeholder from `.env.example`.

Then start the stack and create the first admin account yourself — see
"2. Run" and "3. Create the first administrator" below — instead of
running `scripts/setup.py`.

### 🗂️ Environment variables

| Variable | Used by | Purpose |
|---|---|---|
| `APP_ENV` | app | `development` or `production`. Controls `/docs` exposure and HSTS. |
| `SECRET_KEY` | app | Signs the OIDC-flow session cookie and the pending-TOTP token between login steps. |
| `ENCRYPTION_KEY` | app | Fernet key encrypting stored SSH passwords/private keys. |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` | db, app | Postgres credentials, and the parts the app builds its connection URL from. `POSTGRES_HOST`/`POSTGRES_PORT` (default `db`/`5432`) override the host/port. |
| `DATABASE_URL` | app | Optional — set to fully override the built Postgres URL. |
| `REDIS_PASSWORD` | redis, app | Redis password (`--requirepass`), and the part the app builds its connection URL from. `REDIS_HOST`/`REDIS_PORT`/`REDIS_DB` (default `redis`/`6379`/`0`) override the rest. |
| `REDIS_URL` | app | Optional — set to fully override the built Redis URL. Redis serves as Celery's broker and result backend, and backs the login rate limiter. |
| `SSH_DATA_DIR` | app | Reserved data directory inside the container. |
| `SSH_CONNECT_TIMEOUT` | app | SSH connection timeout, in seconds. |
| `FACTS_REFRESH_INTERVAL_SECONDS` | beat | How often (seconds) OS/kernel/CPU/RAM/disk facts are refreshed per machine. Default 3600. |
| `REACHABILITY_CHECK_INTERVAL_SECONDS` | beat | How often (seconds) the online/offline status badge's TCP-only reachability sweep runs per machine. Default 60. |
| `UPDATE_TIMEOUT_SECONDS` | worker | Max time (seconds) for one machine's full update/upgrade/autoremove/autoclean run. Default 1800. |
| `INFORM_TOKEN` | app | Bearer token required by `POST /api/inform` (self-registration). |
| `LOG_LEVEL` | app | Python logging level. |
| `TZ` | db, redis, app, worker, beat, caddy | IANA timezone (e.g. `Europe/Prague`) applied to every container's own clock, **and used by the app to display every timestamp in the UI** (audit log, "last refreshed"/"last run" times, etc.) in that timezone instead of UTC. Data is always stored as UTC regardless of this, and Scheduling's cron expressions are always interpreted as UTC regardless of this too. Defaults to UTC if unset. |
| `APP_PORT` | web | Host port the app is published on. Default 8080. |
| `APP_BIND_ADDRESS` | web | Host interface the port above is published on. Default `0.0.0.0` (every interface); set to `127.0.0.1` to only allow local connections, no `docker-compose.yml` edit needed. |
| `DOMAIN` | caddy | Public hostname to request a certificate for (Caddy stack only). |
| `ACME_EMAIL` | caddy | Contact email for Let's Encrypt (Caddy stack only). |

Not every setting lives here: the audit log's retention policy (how many
days of entries to keep before a daily purge), and LDAP/OIDC login
configuration (server, bind account, search filter / issuer, client
credentials), are set from the **Settings** page in the app itself, not
environment variables — see
[Architecture](Architecture.md#audit-log-retention-the-first-setting-editable-through-the-ui)
and [Architecture](Architecture.md#authentication--rbac).

## ▶️ 2. Run (manual setup only — Option A's script already does this)

### Without Caddy — behind your own reverse proxy, or no proxy at all

```bash
docker compose up -d --build
```

This starts Postgres, Redis, runs migrations once (`migrate` service), then
starts `web`, `worker`, and `beat`. The app listens on `APP_PORT` (default
8080) — plain HTTP, published on every interface by default
(`APP_BIND_ADDRESS=0.0.0.0`). Set `APP_BIND_ADDRESS=127.0.0.1` in `.env` if
you don't want it reachable directly (no `docker-compose.yml` edit
needed), or block the port at the firewall instead. If you have your own
nginx/Traefik/Caddy already running on this host, point it at
`127.0.0.1:${APP_PORT}`; see: [nginx](Reverse-Proxy-Nginx.md),
[Traefik](Reverse-Proxy-Traefik.md), [Caddy](Reverse-Proxy-Caddy.md).

> [!IMPORTANT]
> The `beat` service is the periodic scheduler, and **exactly one instance
> of it must ever run**. Never `--scale beat=N`: every replica publishes the
> same schedule, so the daily audit-log purge and fleet snapshot would fire
> once per replica. The `worker` service, by contrast, is safe to scale.

> [!NOTE]
> `beat` reads `FACTS_REFRESH_INTERVAL_SECONDS` and
> `REACHABILITY_CHECK_INTERVAL_SECONDS` **once, at startup**. Restart that
> service after changing either — the running app will not pick them up.

If your reverse proxy runs in its own separate Docker Compose project, it
needs to join this project's network instead of using the loopback
address — see the relevant guide for details.

### With the bundled Caddy (automatic HTTPS)

Set `DOMAIN` and `ACME_EMAIL` in `.env`, point that domain's DNS A/AAAA
record at this host's public IP, and make sure ports `80/tcp`, `443/tcp`,
and `443/udp` are reachable from the internet (443/udp is required for
HTTP/3). Then:

```bash
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

See [Reverse Proxy: Caddy](Reverse-Proxy-Caddy.md) for details,
TLS/HTTP-3 verification, and troubleshooting.

## 👤 3. Create the first administrator (manual setup only)

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

## 🔎 4. Verify

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
branch (fails loudly rather than merging or silently diverging), tops up
`.env` with whatever new variables the pulled version's `.env.example`
added that this deployment's `.env` predates (`scripts/env_sync.py` —
never touches a line already there, only ever appends what's missing),
detects whether the bundled Caddy is currently running and includes
`docker-compose.caddy.yml` automatically if so, then `docker compose build`
+ `docker compose up -d` and prints `docker compose ps` at the end. Safe to
run again if something looks off partway through — every step it takes is
already idempotent.

`scripts/setup.py` does the same `.env` top-up if you run it again on a
deployment that already has one and answer "no" to overwriting it — useful
if you'd rather re-run the interactive installer than switch to
`upgrade.sh`.

Equivalent by hand, if you'd rather see each step yourself:

```bash
git pull
docker compose up -d --build
# or, with Caddy:
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

Either way, the `migrate` service re-runs on every `up`, applying any new
Alembic migrations before `web`/`worker`/`beat` start — there's no separate
"run migrations" step.

Postgres, Redis, and Caddy are pinned to exact versions in
`docker-compose.yml`/`docker-compose.caddy.yml` (`postgres:18.6`,
`redis:8.10.1`, `caddy:2.11.4`), so an upgrade — scripted or by hand —
never silently bumps any of them. Bumping one is a deliberate, separate
step: edit the tag, test against it, and commit that change on its own.

### If `db` refuses to start with a "pg_ctlcluster" / "unused mount/volume" error

Only affects a checkout from before the `db` volume mount was corrected —
current `docker-compose.yml` already mounts it right. The `postgres:18`
image expects its volume mounted at `/var/lib/postgresql` (it manages a
major-version-specific subdirectory itself, `/var/lib/postgresql/18/docker`)
rather than directly at `/var/lib/postgresql/data`, the older convention.
An old checkout that initialized its `pg_data` volume the old way leaves
real data sitting at the legacy path once you update, and the image
refuses to start. If that volume has nothing worth keeping (a fresh test
deployment), the fix is a reset:

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
