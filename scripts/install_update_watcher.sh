#!/usr/bin/env bash
# Install (or remove) the host-side watcher behind Settings -> Update, so
# debcontrol can be updated from its own web UI.
#
# Run once on the host, from the debcontrol checkout, as root:
#
#   sudo ./scripts/install_update_watcher.sh            # install / reinstall
#   sudo ./scripts/install_update_watcher.sh --uninstall
#
# What it sets up:
#   - self-update/request/  writable by the `web` container (and nothing
#     else but the checkout's owner): a button in the web UI drops an empty
#     `check` or `upgrade` file here;
#   - self-update/status/   owned by the checkout's owner, mounted
#     read-only into the container: results, the upgrade log;
#   - debcontrol-update.path    systemd watches self-update/request/ and,
#     as soon as something appears, starts
#   - debcontrol-update.service which runs scripts/self_update.py
#     (`scripts/upgrade.sh` for an upgrade) as the checkout's owner;
#   - debcontrol-update-check.timer  a daily `git fetch`, so the page can
#     say an update is waiting without anybody pressing a button.
#
# The checkout's owner must be able to run `docker` (root, or a member of
# the `docker` group) — exactly what running scripts/upgrade.sh by hand
# needs. The unit files only point at scripts in this checkout, so later
# releases update the logic without reinstalling.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
root="$(pwd -P)"
base="$root/self-update"

units=(debcontrol-update.path debcontrol-update.service
       debcontrol-update-check.service debcontrol-update-check.timer)
unit_dir=/etc/systemd/system

if [ "$(id -u)" -ne 0 ]; then
  echo "error: run this as root (sudo $0)." >&2
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "error: no systemd here — update with ./scripts/upgrade.sh instead." >&2
  exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now debcontrol-update.path debcontrol-update-check.timer 2>/dev/null || true
  for unit in "${units[@]}"; do rm -f "$unit_dir/$unit"; done
  systemctl daemon-reload
  rm -f "$base/status/watcher.json"
  echo "Removed. Settings -> Update now shows how to update by hand."
  exit 0
elif [ $# -gt 0 ]; then
  echo "usage: $0 [--uninstall]" >&2
  exit 2
fi

case "$root" in
  *[[:space:]]*)
    echo "error: the checkout's path contains whitespace, which systemd units can't watch: $root" >&2
    exit 1 ;;
esac
if [ ! -f docker-compose.yml ] || [ ! -f scripts/self_update.py ]; then
  echo "error: run this from the debcontrol checkout." >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 is needed on the host (apt install python3)." >&2
  exit 1
fi

owner="$(stat -c %U "$root")"
group="$(stat -c %G "$root")"
if [ "$owner" != root ] && ! id -nG "$owner" | tr ' ' '\n' | grep -qx docker; then
  echo "warning: $owner (who owns the checkout) is not in the docker group;" >&2
  echo "         an upgrade from the web UI would fail the same way" >&2
  echo "         ./scripts/upgrade.sh fails for them. Fix: usermod -aG docker $owner" >&2
fi

# The uid the app runs as inside the image (a system user, so not fixed).
if ! docker image inspect debcontrol:local >/dev/null 2>&1; then
  echo "error: the debcontrol image isn't built yet — run 'docker compose up -d --build' first." >&2
  exit 1
fi
app_uid="$(docker run --rm --network none --entrypoint id debcontrol:local -u)"

mkdir -p "$base/request" "$base/status"
chown "$owner:$group" "$base"
chown -R "$owner:$group" "$base/status"
chmod 0755 "$base" "$base/status"
chown "$app_uid:$group" "$base/request"
chmod 0770 "$base/request"
find "$base/request" -mindepth 1 -delete

cat >"$unit_dir/debcontrol-update.path" <<EOF
[Unit]
Description=debcontrol: watch for update requests from the web UI

[Path]
DirectoryNotEmpty=$base/request
Unit=debcontrol-update.service

[Install]
WantedBy=multi-user.target
EOF

cat >"$unit_dir/debcontrol-update.service" <<EOF
[Unit]
Description=debcontrol: check for or install an update requested from the web UI
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=$owner
Group=$group
WorkingDirectory=$root
ExecStart=/usr/bin/env python3 $root/scripts/self_update.py handle-requests
TimeoutStartSec=2h
EOF

cat >"$unit_dir/debcontrol-update-check.service" <<EOF
[Unit]
Description=debcontrol: check whether an update is available
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=$owner
Group=$group
WorkingDirectory=$root
ExecStart=/usr/bin/env python3 $root/scripts/self_update.py check
TimeoutStartSec=10min
EOF

cat >"$unit_dir/debcontrol-update-check.timer" <<EOF
[Unit]
Description=debcontrol: daily check whether an update is available

[Timer]
OnBootSec=10min
OnUnitActiveSec=1d
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

installed_at="$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"
runuser -u "$owner" -- python3 - "$base/status/watcher.json" "$owner" "$installed_at" <<'EOF'
import json, os, sys, tempfile
path, owner, installed_at = sys.argv[1:4]
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
with os.fdopen(fd, "w") as handle:
    json.dump({"installed_at": installed_at, "user": owner}, handle)
os.chmod(tmp, 0o644)
os.replace(tmp, path)
EOF

systemctl daemon-reload
systemctl enable --now debcontrol-update.path debcontrol-update-check.timer
# A first check right away, so the page has something to show.
systemctl start --no-block debcontrol-update-check.service

web_container="$(docker ps -q --filter "label=com.docker.compose.project=debcontrol" \
    --filter "label=com.docker.compose.service=web" | head -n 1)"
if [ -z "$web_container" ] || ! docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$web_container" \
    | grep -q "$base/request"; then
  echo "note: the running web container predates this release's self-update mounts —"
  echo "      run 'docker compose up -d' (or ./scripts/upgrade.sh) once."
fi

echo "Installed. Settings -> Update can now check for and install updates."
echo "Runs as: $owner. Logs: journalctl -u debcontrol-update.service"
