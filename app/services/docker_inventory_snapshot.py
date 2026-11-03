"""A machine's images, volumes, networks and Compose projects as last read,
stored on the machine (`Machine.docker_inventory`) so the fleet-wide
Docker pages (Docker -> Images, Volumes, Networks, Stacks) list every
machine at once without asking any of them over SSH.

Filled whenever these are read anyway: a machine's own Docker pages
(`app.tasks.docker_jobs.docker_inventory`), every image update check
(hourly sweep and *Check now*) and *Refresh* on a fleet page
(`app.tasks.docker_jobs.refresh_docker_inventory`, one Celery task per
machine). Everything is trimmed and capped: it comes from the machine.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.db.models.machine import Machine

# What one read needs for every list here (`app.ssh.docker_inventory`).
SECTIONS: tuple[str, ...] = ("images", "volumes", "networks", "compose", "inspect")
KINDS = ("images", "volumes", "networks", "projects")
_CAP = 500
_NAMES_CAP = 50


def _names(value: Any) -> list[str]:
    return [str(v)[:255] for v in (value or [])][:_NAMES_CAP]


def _image(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row.get("id") or "")[:80],
        "ref": str(row.get("ref") or "")[:255],
        "repository": str(row.get("repository") or "")[:255],
        "tag": str(row.get("tag") or "")[:128],
        "size_bytes": row.get("size_bytes") if isinstance(row.get("size_bytes"), int) else None,
        "created": str(row.get("created") or "")[:40],
        "in_use": bool(row.get("in_use")),
        "dangling": bool(row.get("dangling")),
    }


def _volume(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(row.get("name") or "")[:255],
        "driver": str(row.get("driver") or "")[:64],
        "compose_project": str(row.get("compose_project") or "")[:255],
        "anonymous": bool(row.get("anonymous")),
        "used_by": _names(row.get("used_by")),
        "size_bytes": row.get("size_bytes") if isinstance(row.get("size_bytes"), int) else None,
    }


def _network(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row.get("id") or "")[:64],
        "name": str(row.get("name") or "")[:255],
        "driver": str(row.get("driver") or "")[:64],
        "scope": str(row.get("scope") or "")[:16],
        "internal": bool(row.get("internal")),
        "builtin": bool(row.get("builtin")),
        "containers": _names(row.get("containers")),
    }


def projects_of(compose: list[Any], containers: list[Any]) -> list[dict[str, Any]]:
    working_dirs: dict[str, str] = {}
    for container in containers:
        if isinstance(container, dict) and container.get("compose_project"):
            working_dirs.setdefault(
                str(container["compose_project"]), str(container.get("compose_working_dir") or "")
            )
    return [
        {
            "name": str(row.get("name") or "")[:255],
            "status": str(row.get("status") or "")[:255],
            "config_files": [str(f)[:1024] for f in row.get("config_files") or []][:20],
            "working_dir": working_dirs.get(str(row.get("name") or ""), "")[:1024],
        }
        for row in compose
        if isinstance(row, dict) and row.get("name")
    ]


def store(machine: Machine, inventory: dict[str, Any], sections: tuple[str, ...]) -> bool:
    """Keep what this read (`sections`) covered; the rest stays as it was.
    Without "inspect" the in-use flags and users can't be trusted, so
    nothing is stored. True when something changed."""
    if "inspect" not in sections:
        return False
    snapshot: dict[str, Any] = dict(machine.docker_inventory or {})
    if "images" in sections:
        snapshot["images"] = [_image(i) for i in inventory.get("images") or []][:_CAP]
    if "volumes" in sections:
        snapshot["volumes"] = [_volume(v) for v in inventory.get("volumes") or []][:_CAP]
    if "networks" in sections:
        snapshot["networks"] = [_network(n) for n in inventory.get("networks") or []][:_CAP]
    if "compose" in sections:
        snapshot["projects"] = projects_of(
            inventory.get("compose") or [], inventory.get("containers") or []
        )[:_CAP]
    previous = dict(machine.docker_inventory or {})
    changed = {k: v for k, v in snapshot.items() if k != "at"} != {
        k: v for k, v in previous.items() if k != "at"
    }
    snapshot["at"] = datetime.now(UTC).isoformat()
    machine.docker_inventory = snapshot
    return changed


def rows(machine: Machine, kind: str) -> list[dict[str, Any]]:
    """The stored list of one kind, [] before the first read."""
    if kind not in KINDS:
        return []
    return [r for r in (machine.docker_inventory or {}).get(kind) or [] if isinstance(r, dict)]


def read_at(machine: Machine) -> datetime | None:
    try:
        return datetime.fromisoformat(str((machine.docker_inventory or {}).get("at")))
    except ValueError:
        return None


def project(machine: Machine, name: str) -> dict[str, Any] | None:
    return next((p for p in rows(machine, "projects") if p.get("name") == name), None)
