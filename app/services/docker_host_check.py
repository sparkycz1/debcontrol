"""The Docker host check: how the Docker Engine on a machine is set up, and
what in it is a common cause of trouble (Docker → Host).

Read with every image update check (`app.tasks.jobs.
_check_machine_image_updates`, so "Check now" refreshes it too) by
`app.ssh.docker_host` and stored on the machine
(`Machine.docker_host_check`). Each finding has a `code`, a `level`
("warn" or "info") and its `items` (container names, values); the page
words it (`docker.host.finding.<code>`).

What is checked:
- log_rotation: the json-file log driver (Docker's default) without
  `max-size` — the logs grow until the disk is full; per container and
  for the daemon's default (`/etc/docker/daemon.json` `log-opts`);
- big_logs: container log files over 100 MB (only when the account can
  read them, i.e. root);
- engine_update: a newer Docker Engine package is waiting (from the
  machine's last package check: docker-ce, docker.io, moby-engine);
- no_memory_limit: running containers without a memory limit;
- privileged / docker_socket / host_namespace: containers running
  privileged, with the Docker socket mounted (root on the host), or in the
  host's network or PID namespace;
- storage_driver: a deprecated storage driver (devicemapper, aufs,
  overlay, vfs);
- daemon_json_invalid: /etc/docker/daemon.json is not valid JSON (the
  daemon won't start after its next restart);
- live_restore: containers stop while the daemon restarts or upgrades;
- docker_warnings: what `docker info` itself warns about.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.db.models.machine import Machine
from app.services import docker_daemon

ENGINE_PACKAGES = ("docker-ce", "docker.io", "moby-engine", "docker-engine")
DEPRECATED_DRIVERS = frozenset({"devicemapper", "aufs", "overlay", "vfs"})
_MAX_ITEMS = 50
LEVELS = ("warn", "info")


def _finding(code: str, level: str, items: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    return {"code": code, "level": level, "items": (items or [])[:_MAX_ITEMS], **extra}


def _name(row: dict[str, Any]) -> str:
    return str(row.get("name") or "").lstrip("/")[:255]


def _rotated(log: Any, daemon_opts: dict[str, Any], daemon_driver: str) -> bool:
    """Whether a container's logs are capped: a driver other than
    json-file ("local" rotates by default, journald/syslog are the
    system's), or json-file with max-size (its own or the daemon's)."""
    if not isinstance(log, dict):
        return True
    driver = str(log.get("Type") or daemon_driver or "json-file")
    if driver != "json-file":
        return True
    config = log.get("Config")
    own = config.get("max-size") if isinstance(config, dict) else None
    return bool(own or daemon_opts.get("max-size"))


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{value:.0f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def evaluate(host: dict[str, Any], machine: Machine) -> dict[str, Any]:
    """The stored check: {"at", "ok", "error", "facts", "findings"}."""
    now = datetime.now(UTC).isoformat()
    if host.get("no_access"):
        return {"at": now, "ok": False, "error": "no_access", "facts": {}, "findings": []}
    info = host.get("info") or {}
    if not info:
        return {"at": now, "ok": False, "error": "no_info", "facts": {}, "findings": []}
    raw_daemon = host.get("daemon_json")
    daemon: dict[str, Any] = raw_daemon if isinstance(raw_daemon, dict) else {}
    daemon_driver = str(daemon.get("log-driver") or info.get("LoggingDriver") or "json-file")
    raw_opts = daemon.get("log-opts")
    daemon_opts: dict[str, Any] = raw_opts if isinstance(raw_opts, dict) else {}
    containers = [c for c in host.get("containers") or [] if isinstance(c, dict)]
    names_by_id = {str(c.get("id") or ""): _name(c) for c in containers}
    findings: list[dict[str, Any]] = []

    if host.get("daemon_json_error"):
        findings.append(_finding("daemon_json_invalid", "warn"))

    unrotated = [
        _name(c) for c in containers if not _rotated(c.get("log"), daemon_opts, daemon_driver)
    ]
    default_unrotated = daemon_driver == "json-file" and not daemon_opts.get("max-size")
    if unrotated or default_unrotated:
        findings.append(_finding("log_rotation", "warn", unrotated, default=default_unrotated))

    big = sorted(host.get("big_logs") or [], key=lambda log: -int(log.get("bytes") or 0))
    if big:
        findings.append(
            _finding(
                "big_logs",
                "warn",
                [
                    f"{names_by_id.get(str(log.get('id')), str(log.get('id'))[:12])}: "
                    f"{_human(int(log.get('bytes') or 0))}"
                    for log in big
                ],
            )
        )

    for package in machine.apt_upgradable_packages or []:
        if isinstance(package, dict) and package.get("name") in ENGINE_PACKAGES:
            findings.append(
                _finding(
                    "engine_update",
                    "warn",
                    [f"{package.get('name')} {package.get('new_version') or ''}".strip()],
                )
            )
            break

    running = [c for c in containers if c.get("running")]
    no_limit = [_name(c) for c in running if not c.get("memory")]
    if no_limit:
        findings.append(_finding("no_memory_limit", "info", no_limit))
    privileged = [_name(c) for c in containers if c.get("privileged")]
    if privileged:
        findings.append(_finding("privileged", "warn", privileged))
    socket = [_name(c) for c in containers if c.get("socket") is True]
    if socket:
        findings.append(_finding("docker_socket", "info", socket))
    host_ns = [
        _name(c) for c in containers if c.get("network") == "host" or c.get("pid") == "host"
    ]
    if host_ns:
        findings.append(_finding("host_namespace", "info", host_ns))

    driver = str(info.get("Driver") or "")
    if driver in DEPRECATED_DRIVERS:
        findings.append(_finding("storage_driver", "warn", [driver]))
    raw_swarm = info.get("Swarm")
    swarm_state = raw_swarm.get("LocalNodeState") if isinstance(raw_swarm, dict) else None
    if not info.get("LiveRestoreEnabled") and swarm_state != "active":
        findings.append(_finding("live_restore", "info"))
    warnings = [str(w)[:300] for w in info.get("Warnings") or [] if w]
    if warnings:
        findings.append(_finding("docker_warnings", "info", warnings))

    findings.sort(key=lambda f: LEVELS.index(f["level"]))
    facts = {
        "version": str(info.get("ServerVersion") or "")[:40],
        "storage_driver": driver[:40],
        "logging_driver": daemon_driver[:40],
        "log_max_size": str(daemon_opts.get("max-size") or "")[:20],
        "cgroup_version": str(info.get("CgroupVersion") or "")[:4],
        "root_dir": str(info.get("DockerRootDir") or "")[:200],
        "containers": len(containers),
        "running": len(running),
        "live_restore": bool(info.get("LiveRestoreEnabled")),
        "logs_readable": bool(host.get("logs_readable")),
        "daemon_json": bool(daemon),
        # The keys Docker → Settings manage, as this file has them.
        "daemon_config": docker_daemon.managed_view(daemon),
        "daemon_started_at": _started_at(host.get("daemon_uptime")),
    }
    return {"at": now, "ok": True, "error": None, "facts": facts, "findings": findings}


def _started_at(uptime: Any) -> str | None:
    if not isinstance(uptime, int) or uptime < 0:
        return None
    return (datetime.now(UTC) - timedelta(seconds=uptime)).isoformat()


def failed(error: str) -> dict[str, Any]:
    return {
        "at": datetime.now(UTC).isoformat(),
        "ok": False,
        "error": error[:500],
        "facts": {},
        "findings": [],
    }


def warn_count(check: dict[str, Any] | None) -> int:
    return sum(1 for f in (check or {}).get("findings") or [] if f.get("level") == "warn")
