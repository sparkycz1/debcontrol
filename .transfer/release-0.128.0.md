## Changes

### Choose the database: bundled PostgreSQL, bundled TimescaleDB or your own; Compose profiles (0.128.0) (#136)

Breaking for manual updates only
- What runs besides the app and Redis is now chosen with COMPOSE_PROFILES
  in .env: postgres or timescaledb (the bundled database; neither = your
  own PostgreSQL) and caddy (the bundled reverse proxy).
- scripts/upgrade.sh, Settings -> Update and scripts/setup.py add it to an
  existing .env by themselves: postgres, plus caddy when the bundled Caddy
  is running (setup.py: when DOMAIN is set), nothing when .env points at
  another database host. Nothing to do.
- Updating by hand with git pull: add COMPOSE_PROFILES=postgres to .env
  first (postgres,caddy if you ran -f docker-compose.caddy.yml). Without it
  migrate stops with a clear "No database" message; no data is touched.

Compose profiles
- docker-compose.yml holds every service; the profiles postgres (db),
  timescaledb and caddy switch the optional ones on. No -f or --profile
  flags needed any more.
- docker-compose.caddy.yml is now only a compatibility stub that switches
  the caddy profile on, so old commands keep working.
- scripts/start.sh, stop.sh and upgrade.sh follow COMPOSE_PROFILES;
  upgrade.sh stops a bundled database that is no longer selected.

Bundled TimescaleDB
- New optional service timescaledb: TimescaleDB 2.31.0 on PostgreSQL 18.6
  (timescale/timescaledb:2.31.0-pg18), volume ts_data, answers to the host
  name db like the bundled PostgreSQL. Telemetry off, no automatic tuning.
- For now it stores the same tables as PostgreSQL; hypertables,
  compression and continuous aggregates follow in the next release.

Your own PostgreSQL
- Leave both database profiles out and set POSTGRES_HOST/POSTGRES_PORT
  (or DATABASE_URL) and the credentials in .env. The setup wizard asks:
  bundled PostgreSQL, bundled TimescaleDB, or your own (host, port, name,
  user; the password is generated into .env, never typed in, and the
  wizard waits while you create the user with it).

Switching between PostgreSQL and TimescaleDB
- Automatic: change the profile and start the stack; the one-off services
  import-from-postgres / import-from-timescaledb start the old database
  from its volume inside their own container (local socket only), copy
  every table and sequence into the new one after migrate created its
  schema, and mark the old volume as moved. web, worker and beat wait for
  it. It only copies into a database nobody has used yet (or one moved
  away from before) and refuses, with a clear message, when both
  databases run, the old one was not shut down cleanly
  (DEBCONTROL_DB_IMPORT_FORCE=1 overrides for one start) or the two are at
  different migrations. The old volume stays as a backup.
- Manual: scripts/switch_db.sh postgres|timescaledb does it in the right
  order (stop app, bring the old database to the current migration,
  change the profile keeping caddy, stop the old database, start).
- migrate first checks the database: a clear message when no bundled
  database is selected or when both answer to db (app/db/precheck.py).

Tuning
- Both bundled databases are tuned for about 100 machines with the same
  POSTGRES_* variables; new POSTGRES_MAX_CONNECTIONS (100) so the limit can
  be raised without a command override. TimescaleDB adds
  TIMESCALEDB_MAX_BACKGROUND_WORKERS (4) and
  TIMESCALEDB_MAX_WORKER_PROCESSES (16).
- wiki/Host-Requirements has a table of what to raise for ~500, ~1 000
  and ~5 000 machines.

Backups
- scripts/backup.sh dumps whichever bundled database runs and records
  which (db-kind); with your own database it skips the dump and says so.
- scripts/restore.sh restores into PostgreSQL or TimescaleDB (TimescaleDB
  with timescaledb_pre_restore/post_restore), refuses a TimescaleDB backup
  into plain PostgreSQL, and keeps the current COMPOSE_PROFILES in the
  restored .env.

Upgrade notes
- No migration. New .env variables: COMPOSE_PROFILES (added automatically,
  see above), commented POSTGRES_MAX_CONNECTIONS, TIMESCALEDB_* and
  DEBCONTROL_DB_IMPORT_FORCE.
- No REST API or UI changes.

**Full diff:** https://github.com/sparkycz1/debcontrol/compare/v0.127.0...v0.128.0
