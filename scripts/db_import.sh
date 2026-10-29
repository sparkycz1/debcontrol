#!/usr/bin/env bash
# Moves debcontrol's data from the other bundled database when the database
# profile changed (postgres <-> timescaledb). Runs as the `import-from-*`
# services in docker-compose.yml, inside the *old* database's image, with
#
#   /var/lib/postgresql   the old database's volume (the source)
#   /target-volume        the new database's volume (only for its marker)
#   TARGET_HOST           the new database, already running, with the
#                         empty schema `migrate` just created
#
# In the normal case (nothing to move) it exits within a second. Otherwise:
#
#   1. Refuses when the old database may still be running (its
#      postmaster.pid exists: two servers on one data directory would
#      corrupt it), unless DEBCONTROL_DB_IMPORT_FORCE=1.
#   2. Starts the old database inside this container (local socket only).
#   3. Refuses when the two schemas are at different migrations (start the
#      old profile once to upgrade it, then switch).
#   4. Imports only into a new database nobody has used yet (no accounts)
#      or one that was itself moved away earlier (its data is older):
#      every table is emptied and copied over, sequences follow.
#   5. Marks the old volume as moved (/var/lib/postgresql/.debcontrol-moved)
#      and stops the old database. Its files stay as a backup; delete the
#      volume by hand once happy (wiki/Installation).
#
# A failure leaves the new database as `migrate` left it and the old one
# untouched, and stops the stack from starting (web/worker/beat wait for
# this service), with the reason in `docker compose logs import-from-...`.

set -euo pipefail

SRC_ROOT=/var/lib/postgresql
PGDATA_DIR="${PGDATA:-/var/lib/postgresql/18/docker}"
MARKER="$SRC_ROOT/.debcontrol-moved"
TARGET_MARKER=/target-volume/.debcontrol-moved
SOCKET_DIR=/tmp/debcontrol-import

log() { echo "db-import: $*"; }
fail() { echo "db-import: ERROR: $*" >&2; exit 1; }

if [ ! -f "$PGDATA_DIR/PG_VERSION" ]; then
  log "no other bundled database to move data from — nothing to do."
  exit 0
fi
if [ -f "$MARKER" ]; then
  log "the other database was already moved ($(cat "$MARKER")) — nothing to do."
  exit 0
fi

# Two A records for the target name = both bundled databases are running.
addresses="$(getent ahostsv4 "$TARGET_HOST" | awk '{print $1}' | sort -u | wc -l)"
if [ "$addresses" -gt 1 ]; then
  fail "both bundled databases are running. Stop the one you are leaving (docker compose stop db, or docker compose stop timescaledb) and start again; only one of the profiles 'postgres' and 'timescaledb' may be on."
fi

if [ -f "$PGDATA_DIR/postmaster.pid" ] && [ "${DEBCONTROL_DB_IMPORT_FORCE:-}" != "1" ]; then
  fail "the old database looks like it is still running, or was not shut down cleanly ($PGDATA_DIR/postmaster.pid exists). Stop it first (docker compose stop db, or docker compose stop timescaledb), then start again. If it is definitely stopped, set DEBCONTROL_DB_IMPORT_FORCE=1 in .env for one start."
fi

export PGPASSWORD="$POSTGRES_PASSWORD"
target=(psql -X -q -v ON_ERROR_STOP=1 -h "$TARGET_HOST" -U "$POSTGRES_USER")
source_db=(psql -X -q -v ON_ERROR_STOP=1 -h "$SOCKET_DIR" -U "$POSTGRES_USER" -d "$POSTGRES_DB")

mkdir -p "$SOCKET_DIR"
chown postgres:postgres "$SOCKET_DIR"
log "starting the old database from its volume (local socket only)..."
gosu postgres pg_ctl -D "$PGDATA_DIR" -w -t 120 -l /tmp/debcontrol-import.log \
  -o "-c listen_addresses='' -c unix_socket_directories=$SOCKET_DIR" start \
  || { cat /tmp/debcontrol-import.log >&2; fail "the old database did not start."; }
stop_source() { gosu postgres pg_ctl -D "$PGDATA_DIR" -m fast -w stop >/dev/null 2>&1 || true; }
trap stop_source EXIT

scalar_source() { "${source_db[@]}" -At -c "$1"; }
scalar_target() { "${target[@]}" -d "$POSTGRES_DB" -At -c "$1"; }

if [ "$(scalar_source "SELECT to_regclass('public.alembic_version') IS NOT NULL")" != "t" ]; then
  log "the old database holds no debcontrol data — nothing to move."
  exit 0
fi

source_rev="$(scalar_source "SELECT version_num FROM alembic_version")"
target_rev="$(scalar_target "SELECT version_num FROM alembic_version")"
if [ "$source_rev" != "$target_rev" ]; then
  fail "the old database is at migration $source_rev, the new one at $target_rev. Switch the profile back, start once so the old database is upgraded, then switch again (scripts/switch_db.sh does this in the right order)."
fi

target_users="$(scalar_target "SELECT count(*) FROM users")"
target_moved="$(test -f "$TARGET_MARKER" && echo yes || echo no)"
if [ "$target_users" != "0" ] && [ "$target_moved" != "yes" ]; then
  log "WARNING: both databases hold debcontrol data and neither was moved before."
  log "WARNING: keeping the new one as it is and leaving the old one untouched."
  exit 0
fi

tables="$(scalar_target "SELECT string_agg(format('%I', c.relname), ' ' ORDER BY c.relname)
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname <> 'alembic_version'
    AND NOT c.relispartition")"

log "moving every table into the new database..."
truncate_list="$(echo "$tables" | sed 's/ /, /g')"
scalar_target "TRUNCATE $truncate_list CASCADE" >/dev/null

for table in $tables; do
  # Only the columns both sides have, in the target's order.
  columns="$(scalar_target "SELECT string_agg(format('%I', a.attname), ', ' ORDER BY a.attnum)
    FROM pg_attribute a
    WHERE a.attrelid = 'public.$table'::regclass AND a.attnum > 0 AND NOT a.attisdropped
      AND a.attgenerated = ''")"
  source_columns="$(scalar_source "SELECT string_agg(format('%I', attname), ',')
    FROM pg_attribute WHERE attrelid = to_regclass('public.$table') AND attnum > 0
      AND NOT attisdropped")"
  if [ -z "$source_columns" ]; then
    continue
  fi
  shared=""
  IFS=', ' read -r -a target_cols <<<"$columns"
  for column in "${target_cols[@]}"; do
    if [[ ",$source_columns," == *",$column,"* ]]; then
      shared="${shared:+$shared, }$column"
    fi
  done
  [ -n "$shared" ] || continue
  "${source_db[@]}" -c "\\copy (SELECT $shared FROM public.$table) TO STDOUT WITH (FORMAT binary)" \
    | "${target[@]}" -d "$POSTGRES_DB" \
        -c "SET session_replication_role = replica" \
        -c "\\copy public.$table ($shared) FROM STDIN WITH (FORMAT binary)"
done

# Sequences (identity and serial columns) continue where the old ones were.
scalar_source "SELECT format('SELECT setval(%L, %s, %s);', format('%I.%I', schemaname, sequencename), last_value, 'true')
  FROM pg_sequences WHERE schemaname = 'public' AND last_value IS NOT NULL" \
  | while IFS= read -r statement; do
      [ -n "$statement" ] && scalar_target "$statement" >/dev/null
    done

moved_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "moved to $TARGET_HOST at $moved_at" >"$MARKER"
rm -f "$TARGET_MARKER"
log "done: data moved at $moved_at. The old volume is kept as a backup."
