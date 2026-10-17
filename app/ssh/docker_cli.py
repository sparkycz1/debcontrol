"""What every Docker command debcontrol runs on a machine shares: the
access probe (`$D` — plain `docker`, or `sudo -n docker` through the
grant onboarding adds), validation of every name that reaches a command
line, the helper images, and running one short script over SSH.

**Names are validated, then quoted.** A container, volume, network,
image or Compose project name is checked against what Docker itself
accepts before it is ever put into a command (`is_*_valid`), and quoted
with `shlex.quote` on top of that. Nothing a user types reaches a shell
unquoted, and nothing starting with `-` reaches docker as a name.

**Helper images.** A few jobs run a tool in a throwaway container instead
of needing it installed on the machine: the vulnerability scanners, restic,
git, curl (to talk to the Docker Engine API when a container has to be
recreated) and busybox (to look into a volume). They come from Docker Hub;
the scanners and restic are pulled before every run (falling back to the
copy already on the machine when Docker Hub can't be reached), so their
programs and vulnerability databases are the newest available. The
machine needs to reach Docker Hub for those features, nothing else does.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any

import asyncssh

from app.db.models.machine import Machine
from app.ssh.client import open_connection
from app.ssh.exceptions import SSHConnectionError
from app.ssh.logs import (
    DOCKER_ACCESS_PROBE,
    DOCKER_NO_ACCESS_MARKER,
    is_container_name_valid,
)
from app.ssh.shell import with_root_shim

__all__ = [
    "DOCKER_ACCESS_PROBE",
    "DOCKER_NO_ACCESS_MARKER",
    "DockerAccessError",
    "DockerCommandError",
    "is_container_name_valid",
]

# The Engine API socket, mounted into the helpers that need it.
DOCKER_SOCKET = "/var/run/docker.sock"

TRIVY_IMAGE = "aquasec/trivy:latest"
GRYPE_IMAGE = "anchore/grype:latest"
RESTIC_IMAGE = "restic/restic:latest"
GIT_IMAGE = "alpine/git:latest"
CURL_IMAGE = "curlimages/curl:latest"
BUSYBOX_IMAGE = "busybox:latest"

# Named volumes the scanners keep their databases in between runs, so a
# scan downloads only what changed.
TRIVY_CACHE_VOLUME = "debcontrol-trivy-cache"
GRYPE_CACHE_VOLUME = "debcontrol-grype-cache"

# Labels on every helper container, so one left behind is recognisable.
HELPER_LABEL = "io.debcontrol.helper=1"

EXIT_MARKER = "@@DC_EXIT "

_PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_VOLUME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,254}$")
_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# Docker's own reference grammar is wider in places (IPv6 registries) but
# nothing a real image uses falls outside this: registry/path:tag@digest,
# no whitespace, no shell metacharacters, never a leading "-".
_IMAGE_REF_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@+-]{0,511}$")


def is_project_name_valid(name: str) -> bool:
    """A Compose project name (`docker compose -p`): lowercase letters,
    digits, `_` and `-`, starting with a letter or digit."""
    return bool(_PROJECT_RE.match(name))


def is_volume_name_valid(name: str) -> bool:
    return bool(_VOLUME_RE.match(name))


def is_network_name_valid(name: str) -> bool:
    return bool(_VOLUME_RE.match(name))


def is_image_id_valid(value: str) -> bool:
    return bool(_IMAGE_ID_RE.match(value))


def is_image_ref_valid(value: str) -> bool:
    return bool(_IMAGE_REF_RE.match(value)) and ".." not in value


def is_image_valid(value: str) -> bool:
    """An image id (`sha256:...`) or a reference (`nginx:1.27`)."""
    return is_image_id_valid(value) or is_image_ref_valid(value)


def as_dict(value: object) -> dict[str, Any]:
    """`value` when it is a dict, else an empty one (for untrusted JSON)."""
    return value if isinstance(value, dict) else {}


def as_list(value: object) -> list[Any]:
    """`value` when it is a list, else an empty one (for untrusted JSON)."""
    return value if isinstance(value, list) else []


def q(value: str) -> str:
    """`shlex.quote` — short, because every name in this package goes
    through it."""
    return shlex.quote(value)


class DockerAccessError(Exception):
    """This account can't reach the Docker daemon."""


class DockerCommandError(Exception):
    """A command was refused before it ran, or docker reported a failure."""


NO_ACCESS_MESSAGE = (
    "This account can't reach the Docker daemon (re-run onboarding, or add it to the docker group)."
)


@dataclass(frozen=True)
class CommandOutput:
    exit_status: int | None
    output: str


def wrap(script: str) -> str:
    """`script` after the access probe, its exit status echoed last. It runs
    in a subshell, so an `exit` inside it still reports its status."""
    return f'{DOCKER_ACCESS_PROBE}( {script}\n) 2>&1; echo "{EXIT_MARKER}$?"'


def parse_wrapped(raw: str) -> CommandOutput:
    """Split `wrap`'s output into the script's output and exit status.
    Raises `DockerAccessError` for the probe's no-access answer."""
    if raw.strip() == DOCKER_NO_ACCESS_MARKER:
        raise DockerAccessError(NO_ACCESS_MESSAGE)
    lines = raw.rstrip("\n").split("\n")
    exit_status: int | None = None
    if lines and lines[-1].startswith(EXIT_MARKER):
        code = lines[-1][len(EXIT_MARKER) :].strip()
        exit_status = int(code) if code.lstrip("-").isdigit() else None
        lines = lines[:-1]
    return CommandOutput(exit_status=exit_status, output="\n".join(lines))


async def run_script(
    machine: Machine,
    secret: str | None,
    connect_timeout_seconds: int,
    script: str,
    *,
    run_timeout_seconds: int = 60,
    stdin: str | bytes | None = None,
) -> CommandOutput:
    """Run one short Docker script (`wrap`) and return its output and exit
    status. For anything that may run for minutes use a detached job
    (`app.ssh.detached_jobs`) instead."""
    try:
        async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
            result = await conn.run(
                with_root_shim(wrap(script)),
                input=stdin,
                check=False,
                timeout=connect_timeout_seconds + run_timeout_seconds,
            )
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SSHConnectionError(f"Docker command failed on {machine.name}: {exc}") from exc
    stdout = result.stdout or ""
    text = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
    return parse_wrapped(text)


async def run_binary(
    machine: Machine,
    secret: str | None,
    connect_timeout_seconds: int,
    script: str,
    *,
    run_timeout_seconds: int = 120,
    stdin: bytes | None = None,
) -> tuple[int | None, bytes, str]:
    """Run a script whose standard output is binary (a tar stream). Returns
    (exit status, stdout, stderr). The access probe's no-access answer
    raises `DockerAccessError`."""
    try:
        async with await open_connection(machine, secret, connect_timeout_seconds) as conn:
            result = await conn.run(
                with_root_shim(DOCKER_ACCESS_PROBE + script),
                input=stdin,
                check=False,
                encoding=None,
                timeout=connect_timeout_seconds + run_timeout_seconds,
            )
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SSHConnectionError(f"Docker command failed on {machine.name}: {exc}") from exc
    out = result.stdout or b""
    err = result.stderr or b""
    out_bytes = out if isinstance(out, bytes) else out.encode()
    err_text = err.decode(errors="replace") if isinstance(err, bytes) else err
    if out_bytes.strip() == DOCKER_NO_ACCESS_MARKER.encode():
        raise DockerAccessError(NO_ACCESS_MESSAGE)
    status = result.exit_status if isinstance(result.exit_status, int) else None
    return status, out_bytes, err_text


# What a container shell runs inside the container: bash when it has one.
_CONTAINER_SHELL = "if command -v bash >/dev/null 2>&1; then exec bash -l; else exec sh -l; fi"


def build_shell_command(container: str) -> str:
    """The command a container shell (the Docker tab's "Shell", over the
    terminal WebSocket) runs on the machine: `docker exec -it` into the
    container, as root inside it — the same as `docker exec` by hand."""
    if not is_container_name_valid(container):
        raise DockerCommandError("Invalid container name.")
    probe = DOCKER_ACCESS_PROBE.replace(
        f"echo {DOCKER_NO_ACCESS_MARKER}; exit 0",
        f"echo {q(NO_ACCESS_MESSAGE)}; exit 3",
    )
    return with_root_shim(
        f"{probe}exec $D exec -it -e TERM=xterm-256color {q(container)} "
        f"sh -c {q(_CONTAINER_SHELL)}"
    )
