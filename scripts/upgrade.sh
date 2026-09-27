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
#   3. Adds whatever `.env.example` variables the newly-pulled version
#      introduced but this deployment's `.env` predates (scripts/env_sync.py
#      — only ever appends what's missing, never touches an existing line).
#   4. Detects whether the bundled Caddy reverse proxy is currently running
#      and rebuilds/restarts with the same compose file combination, so it
#      doesn't get silently dropped.
#   5. `docker compose build` (stamped with GIT_COMMIT so the Settings page
#      can show exactly which commit is running — see app/core/version.py)
#      then `docker compose up -d` — the `migrate` service runs
#      automatically as part of the `web`/`worker` dependency chain (see
#      docker-compose.yml) and must complete successfully before either of
#      them starts. There's no separate "run migrations" step.
#   6. Prints `docker compose ps` so you can see everything came back up.
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

# Options (parsed only here, below the `git pull` above: bash keeps reading
# this file from disk while it runs, so everything up to that point must
# stay byte-for-byte unchanged between releases, or the copy that is doing
# the upgrade would continue at the wrong place in the newly pulled file):
#   --no-cleanup   keep the images the stack no longer uses (see below).
cleanup=1
for arg in "$@"; do
  case "$arg" in
    --no-cleanup) cleanup=0 ;;
    *) echo "usage: $0 [--no-cleanup]" >&2; exit 2 ;;
  esac
done

# A newer release can add variables to .env.example that this deployment's
# existing .env predates (a new background-check interval, a new feature's
# own setting, ...) — scripts/env_sync.py only ever appends what's missing,
# never touches a line already there, so this is safe to run on every
# upgrade unconditionally, whether or not this pull actually changed
# .env.example.
if command -v python3 >/dev/null 2>&1; then
  echo "==> Checking .env against .env.example for anything new..."
  python3 scripts/env_sync.py
else
  echo "==> Skipping .env sync — no python3 on PATH. Diff .env.example by hand if unsure." >&2
fi

compose_files=(-f docker-compose.yml)
if docker ps \
    --filter "label=com.docker.compose.project=debcontrol" \
    --filter "label=com.docker.compose.service=caddy" \
    --format '{{.Names}}' | grep -q .; then
  echo "==> Bundled Caddy reverse proxy detected — including docker-compose.caddy.yml."
  compose_files+=(-f docker-compose.caddy.yml)
fi

# What this stack runs on *before* the upgrade. Afterwards, the previous
# debcontrol image and any image the stack used before but no longer does
# (e.g. `redis:8.10.1` after a bump to `redis:8.10.2`) are removed. Only
# images this stack itself used are touched, never another project's; one
# still in use is simply left alone.
old_app_image="$(docker image inspect -f '{{.Id}}' debcontrol:local 2>/dev/null || true)"
old_images="$(docker compose "${compose_files[@]}" ps -a --format '{{.Image}}' 2>/dev/null | sort -u || true)"

echo "==> Building images..."
export GIT_COMMIT="$(git rev-parse HEAD)"
docker compose "${compose_files[@]}" build

echo "==> Applying migrations and restarting services..."
docker compose "${compose_files[@]}" up -d

if [ "$cleanup" -eq 1 ]; then
  echo "==> Removing images this stack no longer uses..."
  new_images="$(docker compose "${compose_files[@]}" config --images 2>/dev/null | sort -u || true)"
  removed=0
  while IFS= read -r image; do
    [ -z "$image" ] && continue
    [ "$image" = "debcontrol:local" ] && continue
    if ! grep -qxF "$image" <<<"$new_images"; then
      # Fails (and is skipped) if anything else still uses it.
      if docker image rm "$image" >/dev/null 2>&1; then
        echo "    removed $image"
        removed=$((removed + 1))
      fi
    fi
  done <<<"$old_images"
  new_app_image="$(docker image inspect -f '{{.Id}}' debcontrol:local 2>/dev/null || true)"
  if [ -n "$old_app_image" ] && [ "$old_app_image" != "$new_app_image" ]; then
    if docker image rm "$old_app_image" >/dev/null 2>&1; then
      echo "    removed the previous debcontrol image"
      removed=$((removed + 1))
    fi
  fi
  # Older untagged debcontrol builds left behind by earlier upgrades.
  docker image prune -f --filter "label=io.debcontrol.image=app" >/dev/null 2>&1 || true
  if [ "$removed" -eq 0 ]; then echo "    nothing to remove"; fi
fi

echo "==> Status:"
docker compose "${compose_files[@]}" ps

echo
echo "Done. If anything looks wrong: docker compose logs -f web"
