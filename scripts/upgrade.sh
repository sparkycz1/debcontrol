#!/usr/bin/env bash
# Pull the latest debcontrol release and rebuild/redeploy the running stack.
#
# Run this from the git checkout on the server, as whichever user normally
# runs `docker compose` here:
#
#   ./scripts/upgrade.sh
#
# What it does, in order:
#   1. Refuses to run with uncommitted local changes, or if this isn't a
#      git checkout at all (a downloaded tarball can't be `git pull`ed).
#   2. `git fetch` + `git pull --ff-only` on the current branch — fails
#      loudly instead of creating a merge commit or silently diverging.
#   3. Detects whether the bundled Caddy reverse proxy is currently running
#      and rebuilds/restarts with the same compose file combination, so it
#      doesn't get silently dropped.
#   4. `docker compose build` (stamped with GIT_COMMIT so the Settings page
#      can show exactly which commit is running — see app/core/version.py)
#      then `docker compose up -d` — the `migrate` service runs
#      automatically as part of the `web`/`worker` dependency chain (see
#      docker-compose.yml) and must complete successfully before either of
#      them starts. There's no separate "run migrations" step.
#   5. Prints `docker compose ps` so you can see everything came back up.
#
# Postgres/Redis/Caddy images are pinned to exact versions in
# docker-compose.yml and are NOT touched by this script — bumping those is
# a deliberate, separate step (see the wiki: Installation, "Updating").

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [ ! -f docker-compose.yml ]; then
  echo "error: docker-compose.yml not found here — run this from the debcontrol checkout." >&2
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: this isn't a git checkout, so there's nothing to 'git pull'." >&2
  echo "       Clone the repo with git instead of downloading a tarball/zip." >&2
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  echo "error: uncommitted local changes in this checkout (see 'git status')." >&2
  echo "       Commit, stash, or discard them first — refusing to risk 'git pull'" >&2
  echo "       silently merging over or conflicting with a local edit." >&2
  exit 1
fi

branch="$(git rev-parse --abbrev-ref HEAD)"
echo "==> Fetching origin/${branch}..."
git fetch origin "$branch"

if [ -z "$(git log "HEAD..origin/${branch}" --oneline)" ]; then
  echo "==> Already up to date."
else
  echo "==> Pulling..."
  git pull --ff-only origin "$branch"
fi

compose_files=(-f docker-compose.yml)
if docker ps \
    --filter "label=com.docker.compose.project=debcontrol" \
    --filter "label=com.docker.compose.service=caddy" \
    --format '{{.Names}}' | grep -q .; then
  echo "==> Bundled Caddy reverse proxy detected — including docker-compose.caddy.yml."
  compose_files+=(-f docker-compose.caddy.yml)
fi

echo "==> Building images..."
export GIT_COMMIT="$(git rev-parse HEAD)"
docker compose "${compose_files[@]}" build

echo "==> Applying migrations and restarting services..."
docker compose "${compose_files[@]}" up -d

echo "==> Status:"
docker compose "${compose_files[@]}" ps

echo
echo "Done. If anything looks wrong: docker compose logs -f web"
