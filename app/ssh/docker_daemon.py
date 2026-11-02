"""Reading and writing `/etc/docker/daemon.json`, and restarting the Docker
daemon (Docker → Settings, `app.services.docker_daemon`).

Each script runs through `app.ssh.docker_cli.run_script` (the Docker
access probe in front, `with_root_shim` around it). Writing the file and
restarting Docker need root: `sudo -n` (no password prompt; a no-op when
the account is root). The new file's content arrives on standard input —
never in the command line — and is written to a temporary file first,
checked with `dockerd --validate` where that exists (Docker 23+), the old
file copied to `daemon.json.debcontrol.bak`, then moved into place.

Restarting asks systemd (or `service` without it) and waits until
`docker info` answers again; when it doesn't within the time, the backup
is put back and Docker restarted once more, so a setting the daemon
refuses can't leave the machine without Docker.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

DAEMON_JSON = "/etc/docker/daemon.json"
BACKUP = "/etc/docker/daemon.json.debcontrol.bak"
MAX_DAEMON_JSON = 65536
RESTART_WAIT_SECONDS = 90

READ_SCRIPT = (
    "echo @@BEGIN; "
    f"if [ -e {DAEMON_JSON} ]; then "
    f"(cat {DAEMON_JSON} 2>/dev/null || sudo -n cat {DAEMON_JSON}) | head -c {MAX_DAEMON_JSON}; "
    "echo; echo @@END present; else echo; echo @@END missing; fi"
)

# stdin = the new file. `dockerd --validate` exits 0 when the file is fine;
# an older dockerd doesn't know the flag ("unknown flag") — then the check
# is skipped and said so.
WRITE_SCRIPT = f"""set -u
tmp=$(mktemp) || exit 20
trap 'rm -f "$tmp"' EXIT
cat > "$tmp"
if command -v dockerd >/dev/null 2>&1; then
  out=$(dockerd --validate --config-file "$tmp" 2>&1); rc=$?
  if [ $rc -eq 0 ]; then echo "@@VALID yes";
  elif printf '%s' "$out" | grep -qi 'unknown flag'; then echo "@@VALID unsupported";
  else echo "@@INVALID"; printf '%s\\n' "$out" | tail -n 5; exit 21; fi
else
  echo "@@VALID unsupported"
fi
sudo -n mkdir -p /etc/docker || exit 22
if [ -e {DAEMON_JSON} ]; then sudo -n cp -p {DAEMON_JSON} {BACKUP} || exit 23; fi
sudo -n install -m 0644 "$tmp" {DAEMON_JSON} || exit 24
echo "@@WRITTEN"
"""

RESTART_SCRIPT = f"""set -u
restart() {{
  if command -v systemctl >/dev/null 2>&1; then sudo -n systemctl restart docker 2>&1;
  else sudo -n service docker restart 2>&1; fi
}}
wait_up() {{
  i=0
  while [ $i -lt {RESTART_WAIT_SECONDS // 3} ]; do
    if $D info >/dev/null 2>&1; then return 0; fi
    sleep 3; i=$((i + 1))
  done
  return 1
}}
# Without root nothing restarts, and Docker answering afterwards would
# look like success.
sudo -n true 2>/dev/null || {{ echo "@@NO_ROOT"; exit 5; }}
restart || echo "@@RESTART_FAILED"
if wait_up; then echo "@@UP"; exit 0; fi
echo "@@DOWN"
if [ -e {BACKUP} ]; then
  sudo -n cp -p {BACKUP} {DAEMON_JSON} && echo "@@RESTORED"
  restart
  if wait_up; then echo "@@UP_AFTER_RESTORE"; exit 3; fi
fi
exit 4
"""


@dataclass
class DaemonFile:
    present: bool
    content: dict[str, Any]
    error: str | None = None


def parse_read(output: str) -> DaemonFile:
    """`READ_SCRIPT`'s output: the file as a dict. An unreadable or invalid
    file is reported, never guessed at (writing over it would lose what
    the admin put there)."""
    if "@@BEGIN" not in output or "@@END" not in output:
        return DaemonFile(False, {}, "unreadable")
    body = output.split("@@BEGIN", 1)[1]
    text, tail = body.rsplit("@@END", 1)
    present = tail.strip().startswith("present")
    text = text.strip()
    if not present or not text:
        return DaemonFile(present, {})
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return DaemonFile(True, {}, "invalid")
    if not isinstance(data, dict):
        return DaemonFile(True, {}, "invalid")
    return DaemonFile(True, data)


def render(content: dict[str, Any]) -> str:
    return json.dumps(content, indent=2, sort_keys=True) + "\n"


def validated(output: str) -> str:
    """"yes" (dockerd checked it) or "unsupported" (it couldn't)."""
    for line in output.splitlines():
        if line.startswith("@@VALID "):
            return line.split(" ", 1)[1].strip()
    return "unsupported"


def restart_outcome(output: str) -> str:
    """"up", "restored" (Docker came back only with the old file),
    "no_root" (nothing was restarted) or "down"."""
    if "@@NO_ROOT" in output:
        return "no_root"
    if "@@UP_AFTER_RESTORE" in output:
        return "restored"
    if "@@UP" in output:
        return "up"
    return "down"
