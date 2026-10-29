# shellcheck shell=bash
# Shared by upgrade.sh, start.sh, stop.sh, restore.sh, backup.sh and
# switch_db.sh (sourced, from the checkout's root): which bundled services
# this stack runs is COMPOSE_PROFILES in .env (see docker-compose.yml).

# The value of COMPOSE_PROFILES in .env ("" when unset).
current_profiles() {
  [ -f .env ] || return 0
  sed -n 's/^[[:space:]]*COMPOSE_PROFILES=//p' .env | tail -n 1 | tr -d '"'"'"' \r'
}

# Whether `$1` is one of the comma-separated profiles in `$2`.
has_profile() {
  case ",$2," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

# The bundled database service of this stack: db, timescaledb or "" (own
# database).
database_service() {
  local profiles
  profiles="$(current_profiles)"
  if has_profile timescaledb "$profiles"; then
    echo timescaledb
  elif has_profile postgres "$profiles"; then
    echo db
  fi
}

# A running container of this compose project's service `$1`, if any.
running_container() {
  docker ps -q \
    --filter "label=com.docker.compose.project=debcontrol" \
    --filter "label=com.docker.compose.service=$1" | head -n 1
}

# Gives an .env from before 0.128.0 its COMPOSE_PROFILES, matching what the
# stack ran so far: the bundled PostgreSQL (unless .env points at another
# database host) and Caddy if it is running now. Never touches an .env that
# already mentions COMPOSE_PROFILES (commented out or not).
ensure_compose_profiles() {
  [ -f .env ] || return 0
  if grep -qE '^[[:space:]]*#?[[:space:]]*COMPOSE_PROFILES=' .env; then
    return 0
  fi
  local profiles="" host url
  host="$(sed -n 's/^[[:space:]]*POSTGRES_HOST=//p' .env | tail -n 1 | tr -d '"'"'"' \r')"
  url="$(sed -n 's/^[[:space:]]*DATABASE_URL=//p' .env | tail -n 1 | tr -d '"'"'"' \r')"
  if [ -n "$url" ]; then
    case "$url" in *@db:*|*@db/*) profiles="postgres" ;; esac
  elif [ -z "$host" ] || [ "$host" = "db" ]; then
    profiles="postgres"
  fi
  if [ -n "$(running_container caddy)" ]; then
    profiles="${profiles:+$profiles,}caddy"
  fi
  {
    echo
    echo "# Which bundled services run (Compose profiles, comma-separated):"
    echo "# postgres or timescaledb (the bundled database; neither = your own,"
    echo "# set POSTGRES_HOST or DATABASE_URL) and caddy (the bundled reverse"
    echo "# proxy). Added by scripts/upgrade.sh in 0.128.0 from what ran so far."
    echo "COMPOSE_PROFILES=$profiles"
  } >>.env
  echo "==> .env had no COMPOSE_PROFILES yet: set to '${profiles}' (what this stack ran so far)."
}

# Stops the bundled database this stack no longer uses, if it still runs
# (Compose leaves a service of a profile that was switched off running).
stop_unused_database() {
  local keep other container
  keep="$(database_service)"
  for other in db timescaledb; do
    [ "$other" = "$keep" ] && continue
    container="$(running_container "$other")"
    if [ -n "$container" ]; then
      echo "==> Stopping the bundled database no longer in use ($other)..."
      docker stop "$container" >/dev/null
    fi
  done
}
