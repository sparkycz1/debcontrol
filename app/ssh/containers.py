"""Start/stop/restart one or more Docker containers on a managed machine
— the Docker tab's container actions (one row, or the selected rows at
once) and their REST equivalents — and remove stopped ones.

Same Docker access as monitoring and container logs
(`app.ssh.logs.DOCKER_ACCESS_PROBE`). The container name is validated
against Docker's own naming rule before it ever reaches the machine, then
shell-quoted like every other argument.
"""

from __future__ import annotations

import shlex
from typing import Literal

from app.db.models.machine import Machine
from app.ssh.client import open_connection
from app.ssh.logs import (
    DOCKER_ACCESS_PROBE,
    DOCKER_NO_ACCESS_MARKER,
    is_container_name_valid,
)
from app.ssh.shell import with_root_shim

ContainerAction = Literal["start", "stop", "restart"]
CONTAINER_ACTIONS: tuple[ContainerAction, ...] = ("start", "stop", "restart")
# What the selected rows can do at once: the same, plus removing a stopped
# container (`docker rm` without `-f` refuses a running one). Removing needs
# `action.updates`, not `action.power` — see the callers.
BULK_ACTIONS: tuple[str, ...] = (*CONTAINER_ACTIONS, "remove")
_DOCKER_VERB = {"start": "start", "stop": "stop", "restart": "restart", "remove": "rm"}
MAX_BULK_CONTAINERS = 100

# Exit status of the docker command itself, echoed after its output so a
# failure (no such container, daemon error) is told apart from success
# without trusting the SSH channel's own exit status through the probe.
_EXIT_MARKER = "@@EXIT "


class ContainerActionError(Exception):
    """The action was refused before running (bad name/action, no Docker
    access) or docker reported a failure."""


def build_container_action_command(action: str, container: str) -> str:
    if action not in CONTAINER_ACTIONS:
        raise ContainerActionError(f'Unknown container action "{action}".')
    return build_containers_action_command(action, [container])


def build_containers_action_command(action: str, containers: list[str]) -> str:
    """One docker command for every container (docker runs them side by
    side); the names are validated, then shell-quoted."""
    if action not in BULK_ACTIONS:
        raise ContainerActionError(f'Unknown container action "{action}".')
    if not containers or len(containers) > MAX_BULK_CONTAINERS:
        raise ContainerActionError("Choose between 1 and 100 containers.")
    for container in containers:
        if not is_container_name_valid(container):
            raise ContainerActionError(f'"{container}" is not a valid container name.')
    names = " ".join(shlex.quote(c) for c in containers)
    return (
        f"{DOCKER_ACCESS_PROBE}"
        f"$D {_DOCKER_VERB[action]} {names} 2>&1; "
        f'echo "{_EXIT_MARKER}$?"'
    )


def parse_container_action_output(raw: str) -> str:
    """Returns docker's own output on success; raises `ContainerActionError`
    (with docker's message) otherwise."""
    if raw.strip() == DOCKER_NO_ACCESS_MARKER:
        raise ContainerActionError(
            "This account can't reach the Docker daemon (re-run onboarding, or add it "
            "to the docker group)."
        )
    lines = raw.rstrip().splitlines()
    exit_code: int | None = None
    if lines and lines[-1].startswith(_EXIT_MARKER):
        code = lines[-1][len(_EXIT_MARKER) :].strip()
        exit_code = int(code) if code.isdigit() else None
        lines = lines[:-1]
    output = "\n".join(lines).strip()
    if exit_code != 0:
        raise ContainerActionError(output or "docker reported a failure.")
    return output


async def run_container_action(
    machine: Machine,
    secret: str | None,
    timeout_seconds: int,
    *,
    action: str,
    container: str = "",
    containers: list[str] | None = None,
) -> str:
    """Requires a pinned host key. A `stop`/`restart` waits for docker's own
    stop timeout (10 s by default), hence the extra room on top of the
    connect timeout."""
    names = list(containers) if containers else [container]
    command = build_containers_action_command(action, names)
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(with_root_shim(command), check=False, timeout=timeout_seconds + 60)
    stdout = result.stdout or ""
    return parse_container_action_output(stdout if isinstance(stdout, str) else stdout.decode())

