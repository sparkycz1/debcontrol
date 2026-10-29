## Changes

### TimescaleDB for real: compressed history, daily summaries, whole-day retention; schema drift fixed (0.129.0) (#137)

TimescaleDB (bundled profile timescaledb, or your own PostgreSQL with the
extension)
- The monitoring samples, availability (reachability) samples and
  endpoint check results become hypertables with one-day chunks; existing
  rows are moved into chunks on the first start.
- Chunks older than 7 days are compressed (columnstore, per machine or
  check). Monitoring samples wait one day past the downsampling age when
  downsampling is on at 7 days or more (default: compressed after 8 days),
  so they are thinned before they are compressed; on TimescaleDB
  downsampling only looks at the days since. Changing the downsampling age
  in Settings or through the API moves the compression age with it.
- Daily continuous aggregates of availability and endpoint check results
  (reachability_daily, endpoint_check_daily): the status page reads its
  uptime and day bars from them instead of counting every sample.
- Retention stays the app's own setting (per machine, audited): the
  nightly purge drops whole day chunks older than the longest retention
  any machine has (not while a machine keeps its history forever), and
  deletes what a shorter per-machine retention covers row by row as
  before. The audit entry says how many chunks went.
- Set up by the migrate service after the migrations
  (python -m app.db.timescale); does nothing on plain PostgreSQL. An own
  PostgreSQL gets the same after CREATE EXTENSION timescaledb.
- Settings -> Checks & retention shows the TimescaleDB version and the
  compression ages; GET /api/v1/settings returns them as `timescaledb`
  (null on PostgreSQL).
- Switching between PostgreSQL and TimescaleDB, scripts/backup.sh /
  restore.sh and the whole-application backup keep working with
  hypertables; the daily aggregates are refreshed after a move or a
  whole-application restore.

Schema
- The three history tables' primary keys become (id, time column), which
  hypertables require; on PostgreSQL only the key index is rebuilt.
- Old drift between migrations and models fixed: a redundant index on
  fleet_snapshots.snapshot_date dropped; machine_update_runs.
  snapshot_rolled_back_at, machines.host_key_changed_at and
  terminal_recordings.started_at are now timestamptz (stored values were
  UTC); the indexes on fleet_summaries.created_at and
  notification_conditions.rule_id are now declared in the models.
  `alembic check` is clean.

Upgrade notes
- Migration f2b4d6e8a0c1. Rebuilding the primary keys reads each history
  table once; on a large monitoring table the first start takes a little
  longer. On TimescaleDB the first start also moves the existing history
  into chunks.
- docker-compose.yml: migrate also runs python -m app.db.timescale (pulled
  in by scripts/upgrade.sh and Settings -> Update as usual).
- No setting changes.

**Full diff:** https://github.com/sparkycz1/debcontrol/compare/v0.128.0...v0.129.0
