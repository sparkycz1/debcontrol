"""Reading what the Docker host check needs (`app.services.docker_host_check`):
`docker info`, `/etc/docker/daemon.json`, a few `HostConfig` fields of
every container, and the container log files over `BIG_LOG_BYTES`.

One read-only command over the machine's pooled SSH connection, run with
root rights where the machine allows it (`with_root_shim`: the log files
under /var/lib/docker are root's). Everything is parsed defensively and
capped: it comes from the machine.
"""

from __future__ import annotations

import json
from typing import Any

from app.db.models.machine import Machine
from app.ssh.logs import DOCKER_ACCESS_PROBE, DOCKER_NO_ACCESS_MARKER
from app.ssh.pool import machine_connection
from app.ssh.shell import with_root_shim

BIG_LOG_BYTES = 100 * 1024 * 1024
_MAX_DAEMON_JSON = 65536
_MAX_CONTAINERS = 500
_MAX_LOGS = 50

# The Go template prints one JSON object per container; only fields the
# check uses, so a container with hundreds of mounts stays a short line.
# "socket" is true when the Docker socket is mounted into the container.
_INSPECT_FORMAT = (
    '{"id":{{json .Id}},"name":{{json .Name}},"running":{{json .State.Running}},'
    '"memory":{{json .HostConfig.Memory}},"log":{{json .HostConfig.LogConfig}},'
    '"privileged":{{json .HostConfig.Privileged}},"network":{{json .HostConfig.NetworkMode}},'
    '"pid":{{json .HostConfig.PidMode}},'
    '"socket":{{range .Mounts}}{{if or (eq .Source "/var/run/docker.sock") '
    '(eq .Source "/run/docker.sock")}}true,"_":{{end}}{{end}}false}'
)

# Docker through `$D` (`DOCKER_ACCESS_PROBE`: the docker group or a sudo
# rule for docker). The log files are only readable as root; for another
# account "@@LOGS" says "unreadable" and the size check is left out.
HOST_CHECK_COMMAND = (
    "export LC_ALL=C; "
    + DOCKER_ACCESS_PROBE
    + "echo @@INFO; $D info --format '{{json .}}' 2>/dev/null; "
    f"echo @@DAEMON; head -c {_MAX_DAEMON_JSON} /etc/docker/daemon.json 2>/dev/null; echo; "
    f"echo @@INSPECT; ids=$($D ps -aq 2>/dev/null | head -n {_MAX_CONTAINERS}); "
    f"[ -n \"$ids\" ] && $D inspect --format '{_INSPECT_FORMAT}' $ids 2>/dev/null; "
    "echo @@LOGS; root=$($D info --format '{{.DockerRootDir}}' 2>/dev/null); "
    'if [ -n "$root" ] && [ -r "$root/containers" ] && [ -x "$root/containers" ]; then '
    'find "$root/containers" -maxdepth 2 -name "*-json.log" '
    f"-size +{BIG_LOG_BYTES // 1024}k -printf '%s %f\\n' 2>/dev/null | head -n {_MAX_LOGS}; "
    "else echo unreadable; fi; "
    "echo @@END"
)


def _sections(raw: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in raw.splitlines():
        marker = line.strip()
        if marker.startswith("@@") and marker[2:].isalpha():
            current = sections.setdefault(marker[2:], [])
        elif current is not None:
            current.append(line)
    return sections


def _json(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def parse_host_output(raw: str) -> dict[str, Any]:
    """{"no_access", "info", "daemon_json", "daemon_json_error",
    "containers", "big_logs", "logs_readable"}."""
    if DOCKER_NO_ACCESS_MARKER in raw:
        return {"no_access": True}
    sections = _sections(raw)
    info_text = "\n".join(sections.get("INFO") or []).strip()
    info = _json(info_text) if info_text else None
    daemon_text = "\n".join(sections.get("DAEMON") or []).strip()
    daemon: Any = None
    daemon_error = False
    if daemon_text:
        daemon = _json(daemon_text)
        if not isinstance(daemon, dict):
            daemon, daemon_error = None, True
    containers: list[dict[str, Any]] = []
    for line in sections.get("INSPECT") or []:
        row = _json(line.strip()) if line.strip() else None
        if isinstance(row, dict) and row.get("name"):
            containers.append(row)
    logs: list[dict[str, Any]] = []
    log_lines = [line.strip() for line in sections.get("LOGS") or [] if line.strip()]
    for line in log_lines:
        size, _, filename = line.strip().partition(" ")
        container_id = filename.removesuffix("-json.log")
        if size.isdigit() and container_id.isalnum():
            logs.append({"id": container_id[:64], "bytes": int(size)})
    return {
        "no_access": False,
        "logs_readable": "unreadable" not in log_lines,
        "info": info if isinstance(info, dict) else None,
        "daemon_json": daemon,
        "daemon_json_error": daemon_error,
        "containers": containers[:_MAX_CONTAINERS],
        "big_logs": logs[:_MAX_LOGS],
    }


async def read_host(machine: Machine, secret: str | None, timeout_seconds: int) -> dict[str, Any]:
    async with machine_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(
            with_root_shim(HOST_CHECK_COMMAND), check=False, timeout=timeout_seconds + 60
        )
    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode("utf-8", "replace")
    return parse_host_output(raw)
