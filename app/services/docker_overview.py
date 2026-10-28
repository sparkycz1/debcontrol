"""The containers page at a glance: each container's state group (what
the tiles above the table count and filter by) and its links — shared by
the Docker tab and its REST equivalent so both say the same thing."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from app.db.models.machine import Machine
from app.services.container_links import image_links, web_links

# Order of the tiles. "unhealthy" wins over the container's own state: a
# running container whose health check fails is a problem, not "running".
STATE_GROUPS = ("running", "unhealthy", "restarting", "paused", "exited", "created")


def row_state(container: dict[str, Any]) -> str:
    if container.get("health") == "unhealthy":
        return "unhealthy"
    state = str(container.get("state") or "")
    if state in ("exited", "dead"):
        return "exited"
    if state in STATE_GROUPS:
        return state
    return "created" if state in ("", "removing") else state


def state_counts(containers: list[dict[str, Any]]) -> dict[str, int]:
    counts = dict.fromkeys(STATE_GROUPS, 0)
    for container in containers:
        group = row_state(container)
        counts[group] = counts.get(group, 0) + 1
    return counts


def containers_of(machine: Machine) -> list[dict[str, Any]]:
    """The latest sample's containers, or [] when Docker isn't readable."""
    if machine.docker_status != "ok":
        return []
    return [c for c in machine.docker_containers or [] if isinstance(c, dict)]


def describe(machine: Machine, container: dict[str, Any]) -> dict[str, Any]:
    """`row_state`, `web_links` and `image_links` for one container."""
    return {
        "row_state": row_state(container),
        "web_links": [asdict(link) for link in web_links(container, machine.ip_address)],
        "image_links": asdict(image_links(str(container.get("image") or ""), container)),
    }
