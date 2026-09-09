#!/usr/bin/env bash
# Start a previously-stopped debcontrol stack back up — `docker compose
# start` on whatever `stop.sh` left in place (no build, no migration step;
# for that, `docker compose up -d` or `upgrade.sh`). Run this from the git
# checkout on the server:
#
#   ./scripts/start.sh
#
# Auto-detects whether the bundled Caddy reverse proxy is part of this
# stack and starts it too. Unlike `stop.sh`/`upgrade.sh`'s detection (a
# *running* container to catch), everything here is stopped by
# definition, so this looks at every container for the project instead of
# just running ones (`docker ps -a`, not `docker ps`).

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -f docker-compose.yml ]; then
  echo "error: docker-compose.yml not found here — run this from the debcontrol checkout." >&2
  exit 1
fi

compose_files=(-f docker-compose.yml)
if docker ps -a \
    --filter "label=com.docker.compose.project=debcontrol" \
    --filter "label=com.docker.compose.service=caddy" \
    --format '{{.Names}}' | grep -q .; then
  echo "==> Bundled Caddy reverse proxy detected — including docker-compose.caddy.yml."
  compose_files+=(-f docker-compose.caddy.yml)
fi

echo "==> Starting..."
docker compose "${compose_files[@]}" start

echo "==> Status:"
docker compose "${compose_files[@]}" ps
