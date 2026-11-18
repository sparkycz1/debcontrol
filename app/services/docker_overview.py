"""The containers page at a glance: each container's state group (what
the tiles above the table count and filter by) and its links — shared by
the Docker tab and its REST equivalent so both say the same thing."""

from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import asdict
from typing import Any

from app.db.models.machine import Machine
from app.services.container_links import image_links, web_links

# Order of the tiles. "unhealthy" wins over the container's own state: a
# running container whose health check fails is a problem, not "running".
# "completed" is a one-shot container (a migration, an import, a backup
# job: restart policy "no" or "on-failure") that finished with exit code
# 0 — done, not down, so it never makes its stack look half-stopped.
STATE_GROUPS = (
    "running",
    "unhealthy",
    "restarting",
    "paused",
    "exited",
    "completed",
    "created",
)
# Restart policies of a container meant to run once and stop ("" is what
# Docker reports for a container created without one, i.e. "no").
ONE_SHOT_POLICIES = frozenset({"", "no", "on-failure"})
# `docker ps` status of a stopped container: "Exited (0) 2 hours ago".
_EXITED_RE = re.compile(r"Exited \((\d{1,3})\)")


def exit_code(container: dict[str, Any]) -> int | None:
    """The exit code of a stopped container: `docker inspect`'s own, else
    the one in `docker ps`'s status text; None while it runs or unknown."""
    if str(container.get("state") or "") not in ("exited", "dead"):
        return None
    code = container.get("exit_code")
    if isinstance(code, int) and not isinstance(code, bool):
        return code
    match = _EXITED_RE.search(str(container.get("status") or ""))
    return int(match.group(1)) if match else None


def one_shot_names(machine: Machine) -> frozenset[str]:
    """Names of the machine's containers whose restart policy says "run
    once", as last read with `docker inspect` (the stored inventory)."""
    return one_shot_from((machine.docker_inventory or {}).get("one_shot"))


def one_shot_from(stored: Any) -> frozenset[str]:
    """`one_shot_names` from the stored list itself (a query that selects
    only that part of the inventory)."""
    if not isinstance(stored, list):
        return frozenset()
    return frozenset(str(n) for n in stored)


def is_one_shot(container: dict[str, Any], one_shot: Collection[str] = ()) -> bool:
    """Meant to run once: an inspected container carries its own restart
    policy; a sampled one (`docker ps` has none) is looked up by name."""
    if "restart_policy" in container:
        return str(container.get("restart_policy") or "") in ONE_SHOT_POLICIES
    return str(container.get("name") or "") in one_shot


def row_state(container: dict[str, Any], one_shot: Collection[str] = ()) -> str:
    if container.get("health") == "unhealthy":
        return "unhealthy"
    state = str(container.get("state") or "")
    if state in ("exited", "dead"):
        if exit_code(container) == 0 and is_one_shot(container, one_shot):
            return "completed"
        return "exited"
    if state in STATE_GROUPS:
        return state
    return "created" if state in ("", "removing") else state


def state_counts(
    containers: list[dict[str, Any]], one_shot: Collection[str] = ()
) -> dict[str, int]:
    counts = dict.fromkeys(STATE_GROUPS, 0)
    for container in containers:
        group = row_state(container, one_shot)
        counts[group] = counts.get(group, 0) + 1
    return counts


def stack_summary(states: list[str], names: list[str] | None = None) -> dict[str, Any]:
    """A Compose project at a glance from its containers' `row_state`s:
    how many of its long-running services run, how many one-shot ones
    finished, and one word for the whole stack — "running" (every service
    that should run does), "partial", "stopped", or "completed" (nothing
    but finished one-shot jobs). With `names` (each container's service,
    in the same order) it also says which services are down."""
    completed = sum(1 for s in states if s == "completed")
    services = len(states) - completed
    running = sum(1 for s in states if s in ("running", "unhealthy", "restarting"))
    problems = sum(1 for s in states if s in ("unhealthy", "restarting"))
    if not states:
        state = "stopped"
    elif services == 0:
        state = "completed"
    elif running == services:
        state = "running"
    else:
        state = "partial" if running else "stopped"
    return {
        "state": state,
        "running": running,
        "services": services,
        "completed": completed,
        "stopped": services - running,
        "problems": problems,
        "total": len(states),
        "down": sorted(
            name
            for name, s in zip(names or [], states, strict=False)
            if s not in ("running", "unhealthy", "restarting", "completed")
        )[:20],
    }


def containers_of(machine: Machine) -> list[dict[str, Any]]:
    """The latest sample's containers, or [] when Docker isn't readable."""
    if machine.docker_status != "ok":
        return []
    return [c for c in machine.docker_containers or [] if isinstance(c, dict)]


def links_of(container: dict[str, Any], address: str) -> list[dict[str, Any]]:
    """The container's web links (`web_links`) as plain dicts."""
    return [asdict(link) for link in web_links(container, address)]


def describe(
    machine: Machine, container: dict[str, Any], one_shot: Collection[str] | None = None
) -> dict[str, Any]:
    """`row_state`, `web_links` and `image_links` for one container."""
    if one_shot is None:
        one_shot = one_shot_names(machine)
    return {
        "row_state": row_state(container, one_shot),
        "web_links": links_of(container, machine.ip_address),
        "image_links": asdict(image_links(str(container.get("image") or ""), container)),
    }


def _service(container: dict[str, Any]) -> str:
    return str(container.get("compose_service") or container.get("name") or "")


def by_stack(
    containers: list[dict[str, Any]], one_shot: Collection[str] = ()
) -> list[dict[str, Any]]:
    """The containers grouped by Compose project for a table that shows a
    heading row per stack: [{"name", "summary", "containers"}], stacks by
    name, each one's services by name, containers of no stack ("") last."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for container in containers:
        groups.setdefault(str(container.get("compose_project") or ""), []).append(container)
    return [
        {
            "name": name,
            "summary": stack_summary(
                [row_state(c, one_shot) for c in members], [_service(c) for c in members]
            ),
            "containers": sorted(
                members,
                key=lambda c: str(c.get("compose_service") or c.get("name") or "").lower(),
            ),
        }
        for name, members in sorted(groups.items(), key=lambda g: (g[0] == "", g[0].lower()))
    ]
