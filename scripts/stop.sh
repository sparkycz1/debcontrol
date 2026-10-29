#!/usr/bin/env bash
# Stop the running debcontrol stack — `docker compose stop`, nothing
# removed (containers, volumes, and networks all stay in place; `start.sh`
# brings the same stack straight back up). Run this from the git checkout
# on the server:
#
#   ./scripts/stop.sh
#
# Stops every service of the project, whichever profiles are on, so
# nothing is left half up.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -f docker-compose.yml ]; then
  echo "error: docker-compose.yml not found here — run this from the debcontrol checkout." >&2
  exit 1
fi

# Every service of the project, whatever its profile: also a database
# whose profile was switched off but still runs.
compose_files=(-f docker-compose.yml --profile '*')

echo "==> Stopping..."
docker compose "${compose_files[@]}" stop

echo "==> Status:"
docker compose "${compose_files[@]}" ps
