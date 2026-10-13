# Cleaning up after an upgrade — sourced by scripts/upgrade.sh.
#
# Only what belongs to debcontrol is touched:
#   - images this stack used at some point and no longer does (an older
#     Postgres/Redis/Caddy after a pin moved). Which ones those are is
#     remembered in data/upgrade-images, so an image left behind by an
#     upgrade that was interrupted, or run with --no-cleanup, is still
#     removed by a later one;
#   - previous debcontrol builds (recognised by their own label);
#   - stopped one-off containers of this project (`docker compose run`
#     leftovers) — never a service's own container;
#   - build cache older than a day (cache only; anything rebuilds from it).
# Never a volume, never a running container, never an image a container
# of any project still uses (`docker image rm` refuses those), and never
# an image debcontrol did not use itself.

# cleanup_images <state file> <images in use before> <images in use now>
# Both lists are newline-separated `repo:tag` names.
cleanup_images() {
  local state_file="$1" before="$2" now="$3" image removed=0 known

  # Everything this stack is known to have used: what was remembered,
  # what ran before this upgrade, what runs now.
  known="$(
    { [ -f "$state_file" ] && cat "$state_file"; printf '%s\n%s\n' "$before" "$now"; } \
      | grep -v '^[[:space:]]*$' | sort -u
  )"

  while IFS= read -r image; do
    [ -z "$image" ] && continue
    [ "$image" = "debcontrol:local" ] && continue
    if grep -qxF "$image" <<<"$now"; then
      continue
    fi
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      continue
    fi
    # Refused (and skipped) while any container still uses it.
    if docker image rm "$image" >/dev/null 2>&1; then
      echo "    removed $image"
      removed=$((removed + 1))
    else
      echo "    kept $image (still in use)"
    fi
  done <<<"$known"

  # Remember what is in use now, plus whatever could not be removed yet.
  {
    printf '%s\n' "$now"
    while IFS= read -r image; do
      [ -z "$image" ] && continue
      if ! grep -qxF "$image" <<<"$now" && docker image inspect "$image" >/dev/null 2>&1; then
        printf '%s\n' "$image"
      fi
    done <<<"$known"
  } | grep -v '^[[:space:]]*$' | sort -u >"$state_file.tmp" && mv "$state_file.tmp" "$state_file"

  return "$((removed > 0 ? 0 : 1))"
}

# cleanup_app_builds <image id before the build>
cleanup_app_builds() {
  local old_id="$1" new_id pruned
  new_id="$(docker image inspect -f '{{.Id}}' debcontrol:local 2>/dev/null || true)"
  if [ -n "$old_id" ] && [ "$old_id" != "$new_id" ]; then
    if docker image rm "$old_id" >/dev/null 2>&1; then
      echo "    removed the previous debcontrol image"
    fi
  fi
  # Untagged debcontrol builds left behind by earlier upgrades.
  pruned="$(docker image prune -f --filter "label=io.debcontrol.image=app" 2>/dev/null \
    | grep -c '^deleted:' || true)"
  if [ "${pruned:-0}" -gt 0 ]; then
    echo "    removed older debcontrol builds"
  fi
}

# cleanup_leftovers — stopped one-off containers of this project and old
# build cache.
cleanup_leftovers() {
  local container reclaimed
  # `docker compose run` containers carry oneoff=True; a service's own
  # container (even a finished `migrate`) carries oneoff=False.
  while IFS= read -r container; do
    [ -z "$container" ] && continue
    if docker rm "$container" >/dev/null 2>&1; then
      echo "    removed a finished one-off container"
    fi
  done < <(docker ps -aq \
    --filter "label=com.docker.compose.project=debcontrol" \
    --filter "label=com.docker.compose.oneoff=True" \
    --filter "status=exited" 2>/dev/null || true)

  reclaimed="$(docker builder prune -f --filter "until=24h" 2>/dev/null \
    | sed -n 's/^Total reclaimed space: //p' || true)"
  if [ -n "$reclaimed" ] && [ "$reclaimed" != "0B" ]; then
    echo "    build cache: freed $reclaimed"
  fi
}
