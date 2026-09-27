# 📦 Installation

*One `docker compose up`, and the fleet-herding begins.*

debcontrol runs as a Docker Compose stack: PostgreSQL 18.6, Redis 8.10.2,
the web app, a Celery **worker**, a Celery **beat** scheduler and an
optional Caddy reverse proxy. There is no supported way to run it outside
Docker.

## ✅ Prerequisites

- Docker with Compose v2 (`docker compose`).
- A domain name — only for the bundled Caddy's automatic HTTPS.
- Python 3 on the host — only for the setup wizard (stdlib only).

## 🚀 Option A — setup wizard (recommended)

```bash
git clone https://github.com/sparkycz1/debcontrol.git
cd debcontrol
python3 scripts/setup.py
```

The wizard creates `.env` with fresh random secrets, asks for the time
zone, UI language, bundled Caddy (domain + Let's Encrypt email), whether
the app port is local-only, the check intervals, the admin password
(blank = generated) and the host port. It then runs `docker compose down
-v` (fresh secrets don't match an old database volume), starts the stack,
waits until it's healthy and creates `admin`. **Save the printed password
— it's shown once.**

Re-running on an existing `.env`: *overwrite* regenerates everything (and
wipes the volumes); *no* only adds missing variables and starts the stack.
If startup fails, the wizard reads `docker compose logs migrate` and
explains the likely cause.

## 🔧 Option B — manual setup

```bash
cp .env.example .env
python3 scripts/generate_secrets.py
```

Put the printed `SECRET_KEY`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD`,
`REDIS_PASSWORD` and `INFORM_TOKEN` into `.env`, set `TZ` (and
`DOMAIN`/`ACME_EMAIL` for Caddy), then follow *Run* and *Create the first
administrator* below. The app refuses to start
while a secret still looks like a placeholder.

### 🗂️ Environment variables

| Variable | Purpose |
|---|---|
| `APP_ENV` | `development` or `production` (HSTS, secure cookies). |
| `SECRET_KEY` | Signs short-lived tickets (pending 2FA, WebAuthn, OIDC flow). |
| `ENCRYPTION_KEY` | AES-256-GCM key for every stored secret. **Losing it makes them unreadable.** |
| `POSTGRES_USER` / `_PASSWORD` / `_DB` / `_HOST` / `_PORT` | Database credentials and location (default host `db:5432`). `DATABASE_URL` overrides everything. |
| `POSTGRES_SHARED_BUFFERS`, `_EFFECTIVE_CACHE_SIZE`, `_WORK_MEM`, `_MAINTENANCE_WORK_MEM`, `_AUTOVACUUM_*` | Postgres tuning — see [Host Requirements](Host-Requirements.md). |
| `REDIS_PASSWORD` / `_HOST` / `_PORT` / `_DB` | Redis (default `redis:6379/0`). `REDIS_URL` overrides everything. |
| `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `CELERY_WORKER_CONCURRENCY` | Capacity — see [Host Requirements](Host-Requirements.md). |
| `INFORM_TOKEN` | Shared bearer token for `POST /api/inform` (self-registration). |
| `TZ` | Container clocks, the time zone the UI shows and the default for new scheduled tasks. Data is stored in UTC. |
| `DEFAULT_LANGUAGE` | UI language for accounts that haven't chosen one (`en`, `cs`, …). |
| `APP_PORT` / `APP_BIND_ADDRESS` | Published port (8080) and interface (`0.0.0.0`; `127.0.0.1` = local only). |
| `TRUSTED_PROXY_IPS` | Proxies whose `X-Forwarded-Proto` is trusted (needed for passkeys and OIDC behind TLS). Default `*`. |
| `TRUST_FORWARDED_FOR` | Also trust `X-Forwarded-For` so the audit log and rate limiter see the real client. Default `true`; turn off (or narrow `TRUSTED_PROXY_IPS`) if the app port is reachable without the proxy. |
| `LOG_FILE_ALLOWED_PATHS` | Directories the Logs tab may read files from (default `/var/log,/var/lib/docker/containers`). |
| `CUSTOM_LOGO` / `CUSTOM_FAVICON` | Custom branding (below). |
| `BACKUP_DIR` / `BACKUP_RETENTION_DAYS` | `scripts/backup.sh` target and retention (14 days). |
| `LOG_LEVEL`, `SSH_DATA_DIR` | Logging level; data directory inside the container. |
| `DOMAIN` / `ACME_EMAIL` | Bundled Caddy only. |

Check intervals, timeouts, retention, sign-in policy, LDAP/OIDC, SMTP and
the rest are set in the app under **Settings** and apply without a
restart.

## ▶️ Run

```bash
docker compose up -d --build                    # without Caddy
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build   # with Caddy
```

`migrate` applies database migrations before `web`, `worker` and `beat`
start. Without Caddy the app listens on plain HTTP at `APP_PORT` on every
interface — set `APP_BIND_ADDRESS=127.0.0.1` or firewall it, and put your
own proxy in front: [nginx](Reverse-Proxy-Nginx.md),
[Traefik](Reverse-Proxy-Traefik.md), [Caddy](Reverse-Proxy-Caddy.md). For
the bundled Caddy, point DNS at the host and open 80/tcp, 443/tcp and
443/udp.

> [!IMPORTANT]
> Run exactly **one** `beat`; `worker` can be scaled.

> [!WARNING]
> **Passkeys and terminal clipboard need HTTPS** (or `http://localhost`);
> a plain LAN IP won't do. On a LAN, Caddy can self-sign — in
> `./Caddyfile`:
> ```
> :443 {
>     tls internal
>     reverse_proxy web:8080
> }
> ```
> then open `https://<LAN-IP>` (accept the warning, or install Caddy's CA
> with `docker compose exec caddy caddy trust`).
> Behind any TLS proxy the app must also *know* the request was HTTPS —
> `TRUSTED_PROXY_IPS` does that (on by default).

## 👤 Create the first administrator

Only needed with Option B:

```bash
docker compose exec web python scripts/create_admin.py --username admin
```

Creates an "Administrator" role with every permission and asks for a
password (12+ characters); a password change is forced at first login.
Locked out later?

```bash
docker compose exec web python scripts/reset_account.py --username admin --disable-totp
```

## 🔎 Verify

```bash
docker compose ps
docker compose logs -f web
```

`/healthz` returns `{"status": "ok"}`; `/login` is the only page reachable
without a session.

## 🎨 Custom branding

Set `CUSTOM_LOGO` / `CUSTOM_FAVICON` to a URL or a path inside the
container, e.g. mount `./branding` in a compose override file:

```yaml
services:
  web:
    volumes:
      - ./branding:/app/branding:ro
```

```bash
CUSTOM_LOGO=/app/branding/logo.svg
CUSTOM_FAVICON=/app/branding/favicon.png
```

Then `docker compose up -d`. Any browser-renderable format; files aren't
resized.

## Updating

```bash
./scripts/upgrade.sh
```

Refuses on uncommitted changes, fast-forwards the checkout, adds new
`.env.example` variables to `.env` (never changes existing ones), keeps
Caddy if it's running, rebuilds and restarts; `migrate` runs on every
start. Afterwards it **removes the images the stack no longer uses** — the
previous debcontrol build and any Postgres/Redis/Caddy version the new
release replaced — never another project's image or one still in use
(`--no-cleanup` skips this). Safe to re-run. By hand:
`git pull && docker compose up -d --build`, then `docker image prune`.

Images are pinned to exact versions (`postgres:18.6`, `redis:8.10.2`,
`caddy:2.11.4`), so an update never bumps them silently.

`./scripts/stop.sh` / `./scripts/start.sh` stop and start whatever is
running without rebuilding.

### `db` won't start with a "pg_ctlcluster" / "unused mount" error

Only on a checkout older than the corrected `db` volume mount
(`/var/lib/postgresql`). With nothing to keep: `docker compose down -v`,
`git pull`, `docker compose up -d --build`. With data to keep, move it
into the new layout from a throwaway container (`mkdir -p 18 && mv data
18/docker` inside the volume) and start again.

## Backups

```bash
./scripts/backup.sh
```

Creates a timestamped directory under `./backups/` with `db.sql.gz` (a
live `pg_dump`), `ssh_data.tar.gz` (the app's SSH identity — without it
the restored app can't log in anywhere) and `env.backup` (including
`ENCRYPTION_KEY` — without it stored passwords are unrecoverable). Older
backups are pruned after `BACKUP_RETENTION_DAYS`. **Backups contain
secrets** — copy them somewhere access-controlled, ideally off-host.

Nightly with cron (as a user with Docker access):

```cron
15 3 * * * cd /path/to/debcontrol && ./scripts/backup.sh >> /var/log/debcontrol-backup.log 2>&1
```

**Restore** (destructive; the current `.env` is kept as
`.env.pre-restore`; `--yes` skips the prompt):

```bash
./scripts/restore.sh backups/20260909T031500Z
```

Restore onto the version the backup came from, then upgrade.

## Upgrading stored secrets to AES-256-GCM

Values encrypted by versions before 0.45.0 (AES-128/Fernet) are still read
forever; to convert them in one optional pass:

```bash
docker compose exec web python scripts/reencrypt_secrets.py --dry-run
docker compose exec web python scripts/reencrypt_secrets.py
```

Same `ENCRYPTION_KEY`, idempotent — a format upgrade, not a key rotation.
See [FIPS alignment](Machine-Management.md#fips-alignment).
