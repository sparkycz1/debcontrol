# 📦 Installation

*One `docker compose up`, and the fleet-herding begins.*

debcontrol ships as a Docker Compose stack: PostgreSQL 18.6, Redis 8.10.1,
the web app, a **Celery worker**, a **Celery Beat scheduler**, and an
optional Caddy reverse proxy.

## ✅ Prerequisites

- Docker + Docker Compose v2 (`docker compose`, not the old standalone `docker-compose`).
- A domain name — **only** for the bundled Caddy's automatic HTTPS. Skip
  it with your own reverse proxy, or plain HTTP locally.
- Python 3 on the host — **only** for the automated setup below (stdlib only).

## 🚀 Option A — automated setup (recommended)

```bash
git clone https://github.com/sparkycz1/debcontrol.git
cd debcontrol
python3 scripts/setup.py
```

One interactive wizard does everything: copies `.env.example` to `.env`,
fills every secret with a fresh random value (`SECRET_KEY`,
`ENCRYPTION_KEY`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `INFORM_TOKEN`),
then asks:

1. **Timezone** (IANA, e.g. `Europe/Prague`) — container clocks + UI timestamps. Default UTC.
2. **Bundled Caddy?** — if yes, domain name + Let's Encrypt email.
3. **App port local-only?** (`APP_BIND_ADDRESS=127.0.0.1`) — defaults yes
   with Caddy (reaches it internally either way), no otherwise.
4. **Facts-refresh / reachability-check intervals**, seconds (defaults 600/60).
5. **Administrator password** — blank = generated + printed once at the end.
6. **Host port** (default 8080).

Then writes `.env`, `docker compose up -d --build` (+ Caddy overlay if
chosen), waits healthy, creates `admin`. Prints URL/username/password —
save it now, shown once.

Re-running on an existing `.env`:
- **Yes, overwrite** — regenerates every secret, asks everything again,
  **and runs `docker compose down -v` first**. Necessary: a fresh
  `POSTGRES_PASSWORD` means nothing against the *old* `pg_data` volume
  (Postgres only applies that variable to an empty data directory) —
  otherwise every container fails with "password authentication failed"
  the moment `migrate` runs.
- **No** — just tops `.env` up (adds missing `.env.example` vars, touches
  nothing existing) and starts the stack as-is. No secrets regenerated, no new admin.

## 🔧 Option B — manual setup

```bash
cp .env.example .env
python3 scripts/generate_secrets.py
```

Copy the printed `SECRET_KEY`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD`, and
`REDIS_PASSWORD` into `.env` — the app builds its connection URLs from
these. Set `DATABASE_URL`/`REDIS_URL` directly only for something these
parts can't express (different host/port, a managed database).

Also set `TZ` (default UTC), and `DOMAIN`/`ACME_EMAIL` if using the
bundled Caddy. `APP_PORT` has a working default (8080) — the background-
check intervals/timeouts below are configured from the app's own
**Settings → Checks & retention** page after first login, not `.env`.

The app **refuses to start** if any secret still looks like a
`.env.example` placeholder.

Then start the stack and create the first admin yourself — "2. Run" and
"3. Create the first administrator" below — instead of `scripts/setup.py`.

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
| `INFORM_TOKEN` | app | Bearer token required by `POST /api/inform` (self-registration). |
| `LOG_LEVEL` | app | Python logging level. |
| `TZ` | db, redis, app, worker, beat, caddy | IANA timezone (e.g. `Europe/Prague`) applied to every container's own clock, **and used by the app to display every timestamp in the UI** (audit log, "last refreshed"/"last run" times, etc.) in that timezone instead of UTC. Data is always stored as UTC regardless of this, and Scheduling's cron expressions are always interpreted as UTC regardless of this too. Defaults to UTC if unset. |
| `DEFAULT_LANGUAGE` | app | Locale code (e.g. `cs`, matching a filename under `app/i18n/locales/`) an account with no language of its own renders in — a fresh account, or an anonymous request before any account is known. Anyone can still switch for themselves at any time in My account → Language. Default `en`; an unrecognized code falls back to English. `scripts/setup.py` asks for this. |
| `APP_PORT` | web | Host port the app is published on. Default 8080. |
| `APP_BIND_ADDRESS` | web | Host interface the port above is published on. Default `0.0.0.0` (every interface); set to `127.0.0.1` to only allow local connections, no `docker-compose.yml` edit needed. |
| `TRUSTED_PROXY_IPS` | app | Which reverse proxy peers to trust `X-Forwarded-Proto` from, to fix WebAuthn/passkeys and OIDC login behind any TLS-terminating proxy (bundled Caddy or your own) — see the `[!WARNING]` above. Default `*` (any peer); narrow to a comma-separated IP/CIDR list to restrict it. |
| `TRUST_FORWARDED_FOR` | app | Also trust `X-Forwarded-For` from a `TRUSTED_PROXY_IPS` peer, so the audit log and the login/TOTP rate limiter see the real client's IP instead of the proxy's. Default `true` (a fresh install via `scripts/setup.py` assumes the bundled/your own reverse proxy is the only way in) — set back to `false`, or narrow `TRUSTED_PROXY_IPS` to your real proxy's address (not `*`), if this app's port could ever be reached directly, bypassing your proxy; see `app/core/proxy_headers.py`. |
| `DOMAIN` | caddy | Public hostname to request a certificate for (Caddy stack only). |
| `ACME_EMAIL` | caddy | Contact email for Let's Encrypt (Caddy stack only). |

Not everything lives here: the SSH connect/update-run timeouts, every
background-check interval and the reachability sweep's concurrency,
every retention policy, and LDAP/OIDC login config are all set from the
app's own **Settings** page instead — Settings → Checks & retention for
the first group, see
[Architecture](Audit-Log.md#audit-log-retention-the-first-setting-editable-through-the-ui)
and [Architecture](Authentication-RBAC.md) for the rest.

## ▶️ 2. Run (manual setup only — Option A's script already does this)

### Without Caddy — behind your own reverse proxy, or no proxy at all

```bash
docker compose up -d --build
```

Starts Postgres, Redis, runs migrations once (`migrate`), then `web`/
`worker`/`beat`. Listens on `APP_PORT` (default 8080), plain HTTP, every
interface by default. Set `APP_BIND_ADDRESS=127.0.0.1` in `.env` to stop
that (no compose edit needed), or firewall the port. Own nginx/Traefik/
Caddy already running? Point it at `127.0.0.1:${APP_PORT}` — see:
[nginx](Reverse-Proxy-Nginx.md), [Traefik](Reverse-Proxy-Traefik.md), [Caddy](Reverse-Proxy-Caddy.md).

> [!IMPORTANT]
> The `beat` service is the periodic scheduler, and **exactly one instance
> of it must ever run**. Never `--scale beat=N`: every replica publishes the
> same schedule, so the daily audit-log purge and fleet snapshot would fire
> once per replica. The `worker` service, by contrast, is safe to scale.

> [!NOTE]
> `beat` reads the facts-refresh/reachability-check/monitoring intervals
> (Settings → Checks & retention) from the database **once, at startup**
> — same "restart to pick up a change" contract these had back when they
> were environment variables. Restart the `beat` service after changing
> any of the three. The SSH connect timeout, update-run timeout, and
> reachability concurrency, by contrast, are read fresh on every check —
> no restart needed for those.

If your reverse proxy runs in its own separate Docker Compose project, it
needs to join this project's network instead of using the loopback
address — see the relevant guide for details.

> [!WARNING]
> Two features are browser-disabled outright on plain HTTP (any origin
> but `http://localhost`) — not restricted, entirely absent, no
> workaround: **WebAuthn/passkeys** and **web terminal clipboard**
> copy/paste (native Ctrl+V still works). Both need a real secure
> context — HTTPS, or `http://localhost` on debcontrol's own host. A
> plain LAN IP (`http://192.168.1.x:8080`) satisfies neither.
>
> **No public domain needed on a LAN-only deployment.** Any `https://`
> origin counts as secure even with an untrusted cert — one "proceed
> anyway" click per client. Bundled Caddy can self-sign: in `./Caddyfile`,
> ```
> :443 {
>     tls internal
>     reverse_proxy web:8080
> }
> ```
> then `docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build`,
> open `https://<LAN-IP>`. No `DOMAIN`/`ACME_EMAIL` needed. Install
> Caddy's local CA on clients (`docker compose exec caddy caddy trust`)
> to stop the browser warning permanently — purely cosmetic, everything
> already works once the page loads over `https://`.
>
> **Already have HTTPS and still seeing this?** The app also needs to
> *know* the request arrived as HTTPS, or it builds/verifies origins as
> if still plain HTTP — breaking WebAuthn ("Unexpected client data
> origin") and OIDC the same way. `TRUSTED_PROXY_IPS` (default `*`) fixes
> this, already on for every setup above.
>
> **Audit log / rate limiter showing the proxy's IP instead of the real
> client?** `TRUST_FORWARDED_FOR` fixes this — on by default for a fresh
> install. If this app's own port is ever reachable directly (bypassing
> your proxy), turn it back off or narrow `TRUSTED_PROXY_IPS` to your real
> proxy's address (not `*`) first — trusting `X-Forwarded-For` from just
> anyone lets an attacker spoof a fresh "source" per login attempt and
> dodge the rate limiter.

### With the bundled Caddy (automatic HTTPS)

Set `DOMAIN`/`ACME_EMAIL` in `.env`, point DNS A/AAAA at this host, open
`80/tcp`/`443/tcp`/`443/udp` (the last for HTTP/3). Then:

```bash
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

See [Reverse Proxy: Caddy](Reverse-Proxy-Caddy.md) for details,
TLS/HTTP-3 verification, and troubleshooting.

## 👤 3. Create the first administrator (manual setup only)

No auto-provisioning from LDAP/OIDC, every page needs a login — so this
is the one way into a brand new deployment:

```bash
docker compose exec web python scripts/create_admin.py --username admin
```

Prompts for a password (12+ chars, twice), creates an "Administrator"
role with every permission if none exists yet. Password change forced on
first login. See [Architecture](Authentication-RBAC.md).

Locked out later (forgotten password, lost TOTP device)?
`scripts/reset_account.py` is the same idea for an existing account:

```bash
docker compose exec web python scripts/reset_account.py --username admin --disable-totp
```

Resets the password (prompted, or `DEBCONTROL_RESET_PASSWORD`) and
clears lockout; `--disable-totp` also turns off 2FA. See `--help` for the rest.

## 🔎 4. Verify

```bash
docker compose ps
docker compose logs -f web
```

Open the app, check `/healthz` returns `{"status": "ok"}`. `/login`
should be the only page reachable without a session.

## 🎨 Custom branding

Swap the built-in icon+wordmark for your own via `CUSTOM_LOGO`/
`CUSTOM_FAVICON` in `.env` — see `app/web/branding.py` for the
URL-vs-local-path rule. A local file needs to be reachable inside the
container — bind-mount it (an override file, so it survives `git pull`):

```yaml
services:
  web:
    volumes:
      - ./branding:/app/branding:ro
```

then put your files in `./branding/` on the host and point at them:

```bash
CUSTOM_LOGO=/app/branding/logo.svg
CUSTOM_FAVICON=/app/branding/favicon.png
```

`docker compose up -d` (no rebuild — just `.env`/mount changed) picks it
up. Any browser-renderable format (SVG/PNG/ICO/...) — no
resizing/processing, so size it sensibly yourself.

## Updating

```bash
./scripts/upgrade.sh
```

Does the whole thing: refuses on uncommitted changes or outside a git
checkout, `git fetch`/`pull --ff-only` (fails loudly rather than merging
or diverging), tops up `.env` with new `.env.example` vars
(`scripts/env_sync.py` — only ever appends, never touches an existing
line), auto-includes `docker-compose.caddy.yml` if Caddy's running, then
`build` + `up -d`. Idempotent — safe to re-run if something looks off.

`scripts/setup.py` does the same `.env` top-up if re-run on an existing
deployment and you answer "no" to overwriting — an alternative to `upgrade.sh`.

Equivalent by hand, if you'd rather see each step yourself:

```bash
git pull
docker compose up -d --build
# or, with Caddy:
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up -d --build
```

Either way, `migrate` re-runs on every `up`, applying new migrations
before `web`/`worker`/`beat` start — no separate migration step.

Postgres/Redis/Caddy are pinned to exact versions
(`postgres:18.6`/`redis:8.10.1`/`caddy:2.11.4`) — an upgrade never
silently bumps them. Bumping one is its own deliberate, tested, committed step.

## Stopping / starting the stack

```bash
./scripts/stop.sh
./scripts/start.sh
```

`docker compose stop`/`start` on whatever's running — nothing rebuilt or
removed, `start.sh` brings back exactly what `stop.sh` took down. Both
auto-detect Caddy like `upgrade.sh` does. By hand: `docker compose stop`
/ `start` (+ `-f docker-compose.caddy.yml` if running Caddy).

### If `db` refuses to start with a "pg_ctlcluster" / "unused mount/volume" error

Only affects a checkout from before the `db` volume mount was corrected
— current `docker-compose.yml` is fine. `postgres:18` expects its volume
at `/var/lib/postgresql` (manages `/var/lib/postgresql/18/docker` itself)
rather than directly at `.../data`, the older convention — an old volume
initialized the old way leaves data at the legacy path and refuses to
start. Nothing worth keeping (fresh test deployment)? Reset:

```bash
docker compose down -v   # drops pg_data (and redis_data, ssh_data) entirely
git pull                 # picks up the corrected mount
docker compose up -d --build
```

Real data to keep? Don't run that — instead move the volume's contents
into the new layout (still 18.6, no `pg_upgrade` needed): stop the
stack, run a throwaway container with `pg_data` mounted at
`/var/lib/postgresql`, `mkdir -p 18 && mv data 18/docker` inside it
(adjust for a customized `PGDATA`/cluster name), bring the stack back up.

## Backups

```bash
./scripts/backup.sh
```

One timestamped directory under `./backups/` (`BACKUP_DIR` overrides),
holding everything to rebuild this instance from nothing:

- `db.sql.gz` — a live `pg_dump` via Postgres's own MVCC snapshot — no need to stop the stack.
- `ssh_data.tar.gz` — the app's SSH identity keypair. Without it, a
  restored debcontrol can't SSH into a single machine — every host has
  this key's *old* public half in `authorized_keys`.
- `env.backup` — a copy of `.env`. In particular `ENCRYPTION_KEY`: a
  database restored under a *different* one turns every
  `AuthMethod.PASSWORD` credential into permanently unreadable
  ciphertext — no recovery, not even by hand.

Pruned automatically — older than `BACKUP_RETENTION_DAYS` (default 14)
gets deleted every run, safe to leave unattended forever.

**Holds secrets in the clear** (`chmod 600`-ish, protects only against
other local accounts). Copy it somewhere access-controlled and ideally
off-host — losing the host and `./backups/` together is the same as
never having backed up at all.

### Automating it with cron

Daily at, say, 03:15 — as the user that normally runs `docker compose`
(needs Docker socket access), logged rather than silently discarded so a
failure doesn't go unnoticed:

```bash
crontab -e
```

```cron
15 3 * * * cd /path/to/debcontrol && ./scripts/backup.sh >> /var/log/debcontrol-backup.log 2>&1
```

Adjust the path (`pwd` from inside the checkout), make sure the log path
is writable by that user. Check the log after the first run and
periodically after — a silently-broken cron job is worse than no backup
job at all, since it looks fine right up until the day you need it.

Want backups shipped off-host automatically? Append an `rsync`/`scp`/
`aws s3 sync` of the fresh directory (or the whole `BACKUP_DIR`) to the
same cron line or a follow-up one.

### Restoring

```bash
./scripts/restore.sh backups/20260909T031500Z
```

**Destructive** — replaces the database, `ssh_data`, and `.env` outright
(current `.env` saved as `.env.pre-restore` first, never discarded).
Types `restore` to confirm (`--yes` skips it, for a scripted DR
runbook). Stops `web`/`worker`/`beat`, restores everything, restarts.
Restore onto a checkout at the version the backup was taken from — `upgrade.sh` afterward if needed.

## Upgrading stored secrets to AES-256-GCM

Every secret this app stores (machine passwords, its own SSH key, TOTP
secrets, third-party API keys) has used AES-256-GCM since debcontrol
0.45.0 — see [Architecture → FIPS alignment](Machine-Management.md#fips-alignment).
A value encrypted by an older version is still read transparently forever
(nothing breaks by doing nothing), but a deployment that would rather not
carry any of the older AES-128 ciphertext going forward can upgrade every
remaining one in a single optional pass:

```bash
docker compose exec web python scripts/reencrypt_secrets.py --dry-run  # see what would change
docker compose exec web python scripts/reencrypt_secrets.py            # actually upgrade it
```

Re-encrypts under the same `ENCRYPTION_KEY` — this is a format upgrade,
not a key rotation, and it's safe to run repeatedly (idempotent).
