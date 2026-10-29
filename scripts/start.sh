#!/usr/bin/env bash
# Start a previously-stopped debcontrol stack back up — `docker compose
# start` on whatever `stop.sh` left in place (no build, no migration step;
# for that, `docker compose up -d` or `upgrade.sh`). Run this from the git
# checkout on the server:
#
#   ./scripts/start.sh
#
# Starts what COMPOSE_PROFILES in .env names (the bundled database and,
# if chosen, Caddy) together with the app.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -f docker-compose.yml ]; then
  echo "error: docker-compose.yml not found here — run this from the debcontrol checkout." >&2
  exit 1
fi

# Which services belong to this stack (database, Caddy) is
# COMPOSE_PROFILES in .env; an .env from before 0.128.0 gets it here.
# shellcheck source=scripts/compose_profiles.sh
. scripts/compose_profiles.sh
ensure_compose_profiles
compose_files=(-f docker-compose.yml)

echo "==> Starting..."
docker compose "${compose_files[@]}" start

echo "==> Status:"
docker compose "${compose_files[@]}" ps
