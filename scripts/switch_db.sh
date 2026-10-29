#!/usr/bin/env bash
# Switch the bundled database between PostgreSQL and TimescaleDB, data
# included:
#
#   ./scripts/switch_db.sh timescaledb     # or: postgres
#
# What it does, in order:
#   1. Stops web, worker and beat, so nothing writes while the data moves.
#   2. Brings the current database's schema up to date (`migrate`), so both
#      sides end up at the same migration.
#   3. Puts the new profile into COMPOSE_PROFILES in .env (other profiles,
#      e.g. caddy, stay) and stops the old database cleanly.
#   4. `docker compose up -d`: the new database starts, `migrate` creates its
#      schema, `import-from-postgres` / `import-from-timescaledb` copies all
#      data over (scripts/db_import.sh), then the app starts again.
#
# The old database's volume is kept untouched as a backup (pg_data or
# ts_data); switching back later moves the newer data back the same way.
# Changing COMPOSE_PROFILES by hand works too: stop the old database
# (docker compose stop db / timescaledb) before `docker compose up -d`.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
# shellcheck source=scripts/compose_profiles.sh
. scripts/compose_profiles.sh

case "${1:-}" in
  postgres) new_service=db ;;
  timescaledb) new_service=timescaledb ;;
  *) echo "usage: $0 postgres|timescaledb" >&2; exit 2 ;;
esac
new_profile="$1"

if [ ! -f .env ]; then
  echo "error: no .env here — run this from the debcontrol checkout." >&2
  exit 1
fi
ensure_compose_profiles
profiles="$(current_profiles)"
old_service="$(database_service)"
if [ -z "$old_service" ]; then
  echo "error: COMPOSE_PROFILES ('$profiles') has no bundled database — this stack" >&2
  echo "       uses your own database, which this script does not move." >&2
  exit 1
fi
old_profile=postgres
[ "$old_service" = "timescaledb" ] && old_profile=timescaledb
if [ "$old_service" = "$new_service" ]; then
  echo "==> Already on $new_profile — nothing to do."
  exit 0
fi

echo "==> Stopping web, worker and beat..."
docker compose stop web worker beat

echo "==> Bringing the current database ($old_service) up to date..."
docker compose up -d --wait "$old_service"
docker compose run --rm --no-deps migrate

echo "==> Switching COMPOSE_PROFILES to $new_profile..."
new_profiles="$(echo ",$profiles," | sed -e 's/,postgres,/,/g' -e 's/,timescaledb,/,/g' -e 's/^,//' -e 's/,$//')"
new_profiles="$new_profile${new_profiles:+,$new_profiles}"
sed -i "s/^[[:space:]]*COMPOSE_PROFILES=.*/COMPOSE_PROFILES=$new_profiles/" .env
stop_unused_database

echo "==> Starting on $new_profile (the data moves over before the app starts)..."
export GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
if ! docker compose up -d; then
  docker compose logs "import-from-$old_profile" >&2 || true
  echo "error: the switch did not finish — see the log above. The old database is untouched;" >&2
  echo "       './scripts/switch_db.sh $old_profile' goes back." >&2
  exit 1
fi
docker compose logs --no-log-prefix "import-from-$old_profile" | grep 'db-import' || true

echo "==> Status:"
docker compose ps
