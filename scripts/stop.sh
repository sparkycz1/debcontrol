#!/usr/bin/env bash
# Stop the running debcontrol stack — `docker compose stop`, nothing
# removed (containers, volumes, and networks all stay in place; `start.sh`
# brings the same stack straight back up). Run this from the git checkout
# on the server:
#
#   ./scripts/stop.sh
#
# Auto-detects whether the bundled Caddy reverse proxy is currently
# running and stops it too, the same detection `upgrade.sh` already uses
# (a running container labeled for the "caddy" compose service) — so this
# never leaves half a stack up because the extra `-f` was forgotten.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -f docker-compose.yml ]; then
  echo "error: docker-compose.yml not found here — run this from the debcontrol checkout." >&2
  exit 1
fi

compose_files=(-f docker-compose.yml)
if docker ps \
    --filter "label=com.docker.compose.project=debcontrol" \
    --filter "label=com.docker.compose.service=caddy" \
    --format '{{.Names}}' | grep -q .; then
  echo "==> Bundled Caddy reverse proxy detected — including docker-compose.caddy.yml."
  compose_files+=(-f docker-compose.caddy.yml)
fi

echo "==> Stopping..."
docker compose "${compose_files[@]}" stop

echo "==> Status:"
docker compose "${compose_files[@]}" ps
