#!/usr/bin/env bash
# Back up everything a running debcontrol instance needs to be restored from
# scratch: the Postgres database, the app's own SSH identity key (used to
# connect to every managed machine — without it, restoring the DB alone gets
# you a fleet debcontrol can no longer reach), and `.env` (holds
# ENCRYPTION_KEY, without which every stored machine password is
# unrecoverable ciphertext, plus SECRET_KEY, POSTGRES_PASSWORD,
# REDIS_PASSWORD).
#
# Run this from the git checkout on the server, as whichever user normally
# runs `docker compose` here:
#
#   ./scripts/backup.sh
#
# What it does, in order:
#   1. `docker compose exec db pg_dump` — a live, consistent snapshot via
#      Postgres's own MVCC; the stack does NOT need to be stopped for this.
#   2. Archives the `ssh_data` Docker volume (the app's SSH keypair, see
#      SSH_DATA_DIR in .env.example) with a short-lived helper container —
#      also doesn't need the stack stopped, the key file is never rewritten
#      in place.
#   3. Copies `.env` as-is.
#   4. Writes everything into one timestamped directory under
#      `BACKUP_DIR` (default ./backups), `chmod 600`'d — this holds
#      unencrypted secrets and machine credentials once decrypted with
#      ENCRYPTION_KEY, treat it exactly like a `.env` file.
#   5. Prunes backup directories older than `BACKUP_RETENTION_DAYS`
#      (default 14) so this is safe to run unattended from cron forever
#      without slowly filling the disk — see wiki/Installation
#      ("Backups") for a ready-to-use crontab line.
#
# Restoring: ./scripts/restore.sh <path to one timestamped backup dir>

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -f docker-compose.yml ]; then
  echo "error: docker-compose.yml not found here — run this from the debcontrol checkout." >&2
  exit 1
fi

if [ ! -f .env ]; then
  echo "error: .env not found here — nothing to back up (is this a real deployment?)." >&2
  exit 1
fi

# shellcheck disable=SC1091
source .env

backup_dir="${BACKUP_DIR:-./backups}"
retention_days="${BACKUP_RETENTION_DAYS:-14}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
dest="${backup_dir}/${timestamp}"

mkdir -p "$dest"

if ! docker compose ps db --format '{{.State}}' 2>/dev/null | grep -q .; then
  echo "error: the 'db' service isn't running (docker compose ps). Start the stack first." >&2
  exit 1
fi

echo "==> Dumping database (${POSTGRES_DB:-debcontrol})..."
docker compose exec -T db pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB}" \
  | gzip > "${dest}/db.sql.gz"

echo "==> Archiving the ssh_data volume (app's SSH identity key)..."
docker run --rm \
  -v "debcontrol_ssh_data:/data:ro" \
  -v "$(cd "$dest" && pwd):/backup" \
  alpine:3 \
  tar czf /backup/ssh_data.tar.gz -C /data .

echo "==> Copying .env..."
cp .env "${dest}/env.backup"

chmod -R go-rwx "$dest"

echo "==> Pruning backups older than ${retention_days} day(s) in ${backup_dir}..."
find "$backup_dir" -mindepth 1 -maxdepth 1 -type d -mtime "+${retention_days}" -print -exec rm -rf {} \;

echo
echo "Done: ${dest}"
echo "  db.sql.gz     — $(du -h "${dest}/db.sql.gz" | cut -f1)"
echo "  ssh_data.tar.gz — $(du -h "${dest}/ssh_data.tar.gz" | cut -f1)"
echo "  env.backup    — $(du -h "${dest}/env.backup" | cut -f1)"
echo
echo "This directory contains secrets in the clear (env.backup, and the SSH"
echo "private key inside ssh_data.tar.gz) — copy it somewhere access-controlled"
echo "(off this host, ideally) rather than leaving it only in ./backups."
