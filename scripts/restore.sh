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
#   3. Drops and recreates the target database, then loads db.sql.gz into it.
#   4. Replaces the ssh_data volume's contents with the backup's.
#   5. Replaces .env (the current one is saved alongside as .env.pre-restore
#      first, never silently discarded).
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

for f in db.sql.gz ssh_data.tar.gz env.backup; do
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

compose_files=(-f docker-compose.yml)
if [ -f docker-compose.caddy.yml ] && docker ps -a \
    --filter "label=com.docker.compose.project=debcontrol" \
    --filter "label=com.docker.compose.service=caddy" \
    --format '{{.Names}}' | grep -q .; then
  compose_files+=(-f docker-compose.caddy.yml)
fi

echo "==> Stopping web/worker/beat (db and redis stay up)..."
docker compose "${compose_files[@]}" stop web worker beat 2>/dev/null || true

echo "==> Making sure db is up..."
docker compose "${compose_files[@]}" up -d db
docker compose "${compose_files[@]}" exec -T db sh -c \
  "until pg_isready -U '${postgres_user}' >/dev/null 2>&1; do sleep 1; done"

echo "==> Dropping and recreating ${postgres_db}..."
docker compose "${compose_files[@]}" exec -T db psql -U "${postgres_user}" -d postgres -c \
  "DROP DATABASE IF EXISTS \"${postgres_db}\";"
docker compose "${compose_files[@]}" exec -T db psql -U "${postgres_user}" -d postgres -c \
  "CREATE DATABASE \"${postgres_db}\" OWNER \"${postgres_user}\";"

echo "==> Loading db.sql.gz..."
gunzip -c "${backup_path}/db.sql.gz" \
  | docker compose "${compose_files[@]}" exec -T db psql -U "${postgres_user}" -d "${postgres_db}"

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

echo "==> Starting the stack..."
export GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
docker compose "${compose_files[@]}" up -d

echo "==> Status:"
docker compose "${compose_files[@]}" ps

echo
echo "Done. Verify the app comes up correctly, then remove .env.pre-restore"
echo "once you're satisfied the restore is correct."
