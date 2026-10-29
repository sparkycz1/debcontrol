#!/usr/bin/env bash
# Restore a debcontrol instance from a backup made by scripts/backup.sh.
# DESTRUCTIVE: replaces the current database, ssh_data volume, and .env
# outright. Meant for disaster recovery (lost/corrupted host) or standing up
# a replacement server from another instance's backup — not for everyday use.
#
#   ./scripts/restore.sh backups/20260909T120000Z
#
# What it does, in order:
#   1. Refuses to run without an explicit "yes, overwrite everything" typed
#      confirmation (skip with --yes for unattended/scripted DR).
#   2. Stops web/worker/beat (keeps db/redis containers up, since pg_dump's
#      restore target — the running db service — still needs to be reachable).
#   3. Drops and recreates the target database (the bundled `db`, or
#      `timescaledb` with that profile), then loads db.sql.gz into it. A
#      backup taken on TimescaleDB only restores into TimescaleDB. With your
#      own database (no database profile) this step is left to you.
#   4. Replaces the ssh_data volume's contents with the backup's.
#   5. Replaces .env (the current one is saved alongside as .env.pre-restore
#      first, never silently discarded), keeping the current COMPOSE_PROFILES.
#   6. Starts the stack back up (migrate → web/worker/beat), same as
#      scripts/start.sh.
#
# This does NOT install/rebuild the app itself — run this against a checkout
# already on the version the backup was taken from (or upgrade.sh afterward).

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

skip_confirm=0
backup_path=""
for arg in "$@"; do
  case "$arg" in
    --yes) skip_confirm=1 ;;
    *) backup_path="$arg" ;;
  esac
done

if [ -z "$backup_path" ]; then
  echo "usage: $0 [--yes] <path to a backup dir from scripts/backup.sh>" >&2
  exit 1
fi

for f in ssh_data.tar.gz env.backup; do
  if [ ! -f "${backup_path}/${f}" ]; then
    echo "error: ${backup_path}/${f} not found — is this a valid backup.sh directory?" >&2
    exit 1
  fi
done

if [ ! -f docker-compose.yml ]; then
  echo "error: docker-compose.yml not found here — run this from the debcontrol checkout." >&2
  exit 1
fi

echo "This will PERMANENTLY REPLACE:"
echo "  - the current database"
echo "  - the ssh_data volume (the app's SSH identity key)"
echo "  - .env (the current one is saved as .env.pre-restore first)"
echo "with the contents of: ${backup_path}"
if [ "$skip_confirm" -ne 1 ]; then
  read -r -p "Type 'restore' to continue: " confirm
  if [ "$confirm" != "restore" ]; then
    echo "Aborted — nothing was changed." >&2
    exit 1
  fi
fi

# shellcheck disable=SC1091
source .env
postgres_user="${POSTGRES_USER}"
postgres_db="${POSTGRES_DB}"

# The database is restored into this stack's bundled database (`db`, or
# `timescaledb` with that profile — COMPOSE_PROFILES in the current .env,
# which the restored .env keeps).
# shellcheck source=scripts/compose_profiles.sh
. scripts/compose_profiles.sh
ensure_compose_profiles
profiles="$(current_profiles)"
db_service="$(database_service)"
compose_files=(-f docker-compose.yml)
backup_kind="$(cat "${backup_path}/db-kind" 2>/dev/null || echo db)"

echo "==> Stopping web/worker/beat (the database and redis stay up)..."
docker compose "${compose_files[@]}" stop web worker beat 2>/dev/null || true

if [ -z "$db_service" ]; then
  echo "==> No bundled database (COMPOSE_PROFILES='${profiles}'): restore your own database"
  echo "    with its own tools (from db.sql.gz, if the backup has one). Restoring the rest."
elif [ ! -f "${backup_path}/db.sql.gz" ]; then
  echo "error: ${backup_path}/db.sql.gz not found — is this a valid backup.sh directory?" >&2
  exit 1
elif [ "$backup_kind" = "timescaledb" ] && [ "$db_service" != "timescaledb" ]; then
  echo "error: this backup comes from TimescaleDB and only restores into it. Switch this" >&2
  echo "       stack first (./scripts/switch_db.sh timescaledb), then restore again." >&2
  exit 1
else
  echo "==> Making sure ${db_service} is up..."
  docker compose "${compose_files[@]}" up -d "$db_service"
  docker compose "${compose_files[@]}" exec -T "$db_service" sh -c \
    "until pg_isready -U '${postgres_user}' >/dev/null 2>&1; do sleep 1; done"

  echo "==> Dropping and recreating ${postgres_db}..."
  docker compose "${compose_files[@]}" exec -T "$db_service" psql -U "${postgres_user}" -d postgres -c \
    "DROP DATABASE IF EXISTS \"${postgres_db}\";"
  docker compose "${compose_files[@]}" exec -T "$db_service" psql -U "${postgres_user}" -d postgres -c \
    "CREATE DATABASE \"${postgres_db}\" OWNER \"${postgres_user}\";"

  # TimescaleDB restores its own catalog only in restore mode.
  if [ "$db_service" = "timescaledb" ]; then
    docker compose "${compose_files[@]}" exec -T "$db_service" psql -q -U "${postgres_user}" -d "${postgres_db}" \
      -c "CREATE EXTENSION IF NOT EXISTS timescaledb" -c "SELECT timescaledb_pre_restore()" >/dev/null
  fi
  echo "==> Loading db.sql.gz..."
  gunzip -c "${backup_path}/db.sql.gz" \
    | docker compose "${compose_files[@]}" exec -T "$db_service" psql -q -U "${postgres_user}" -d "${postgres_db}"
  if [ "$db_service" = "timescaledb" ]; then
    docker compose "${compose_files[@]}" exec -T "$db_service" psql -q -U "${postgres_user}" -d "${postgres_db}" \
      -c "SELECT timescaledb_post_restore()" >/dev/null
  fi
fi

echo "==> Replacing the ssh_data volume..."
docker run --rm -v "debcontrol_ssh_data:/data" alpine:3 sh -c "rm -rf /data/* /data/.[!.]*" 2>/dev/null || true
docker run --rm \
  -v "debcontrol_ssh_data:/data" \
  -v "$(cd "$backup_path" && pwd):/backup:ro" \
  alpine:3 \
  tar xzf /backup/ssh_data.tar.gz -C /data

echo "==> Replacing .env (previous saved as .env.pre-restore)..."
cp .env .env.pre-restore
cp "${backup_path}/env.backup" .env
# Keep this stack's profiles (the database the data was just loaded into).
sed -i '/^[[:space:]]*COMPOSE_PROFILES=/d' .env
printf '\n# Kept from the .env before the restore (scripts/restore.sh).\nCOMPOSE_PROFILES=%s\n' "$profiles" >> .env

echo "==> Starting the stack..."
export GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
docker compose "${compose_files[@]}" up -d

echo "==> Status:"
docker compose "${compose_files[@]}" ps

echo
echo "Done. Verify the app comes up correctly, then remove .env.pre-restore"
echo "once you're satisfied the restore is correct."
