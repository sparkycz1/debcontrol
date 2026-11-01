"""Moving or cloning a Compose stack to another machine, with its data
(`app.services.docker_transfer`, the `stack_transfer` job).

**What is copied.** The named volumes Compose created for the project
(`com.docker.compose.project` label, `local` driver without options -
a volume on NFS or a bind-type volume lives elsewhere and is left out),
and the host paths the project's containers bind-mount from inside the
stack's directory (`./data`, `./config/nginx.conf`); a Git stack's
`repo/` comes from the repository instead. Other host paths
(`/srv/media`) are listed, never copied: they are not the stack's to take.

**How.** The data streams through debcontrol, never between the
machines: `tar` in a throwaway busybox container on the source writes to
SSH standard output, debcontrol hands each chunk to `tar` in a busybox
container on the target over a second SSH connection. No storage both
machines can reach, no SSH key from one machine to the other. Ownership,
permissions and timestamps are kept (both run as root inside their
container, like Docker itself).

Every name reaching a command line is validated and quoted
(`docker_cli`); the relative paths come from the source's own mount
list and are checked again before use.
"""

from __future__ import annotations

import asyncio
import json
import posixpath
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import asyncssh

from app.db.models.machine import Machine
from app.ssh.client import open_connection
from app.ssh.docker_cli import (
    BUSYBOX_IMAGE,
    DOCKER_ACCESS_PROBE,
    HELPER_LABEL,
    DockerCommandError,
    is_project_name_valid,
    is_volume_name_valid,
    q,
)
from app.ssh.docker_compose import STACK_MARKER, stack_dir_shell
from app.ssh.exceptions import SSHConnectionError
from app.ssh.shell import with_root_shim

PROJECT_LABEL = "com.docker.compose.project"
WORKING_DIR_LABEL = "com.docker.compose.project.working_dir"
MAX_VOLUMES = 50
MAX_BIND_PATHS = 100
CHUNK = 1 << 20
# No data from the source for this long ends the copy.
IDLE_TIMEOUT = 300
_LABEL_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}\Z")
_REL_PATH_RE = re.compile(r"^[A-Za-z0-9._@+=-][A-Za-z0-9._@+=/ -]{0,1023}\Z")
_HELPER = f"$D run --rm --pull missing --label {HELPER_LABEL} --log-driver none"


@dataclass
class SourceInventory:
    """What the source machine has of the project."""

    volumes: list[dict[str, Any]] = field(default_factory=list)
    # Volumes left out, with why: {"name", "reason"} (driver / options).
    skipped_volumes: list[dict[str, str]] = field(default_factory=list)
    working_dir: str = ""
    # Host paths bind-mounted into the project's containers.
    bind_sources: list[str] = field(default_factory=list)
    running: int = 0


def build_inventory_script(project: str) -> str:
    """The project's volumes (inspected) and its containers' mounts and
    working directory, as marked lines."""
    if not is_project_name_valid(project):
        raise DockerCommandError(f'"{project}" is not a valid Compose project name.')
    flt = q(f"label={PROJECT_LABEL}={project}")
    return "\n".join(
        [
            f"for v in $($D volume ls -q --filter {flt}); do",
            "  printf '@@VOL %s\\n' \"$($D volume inspect --format '{{json .}}' \"$v\")\"",
            "done",
            f"ids=\"$($D ps -aq --filter {flt})\"",
            'if [ -n "$ids" ]; then',
            "  $D inspect --format "
            + q(
                "@@CT {{.State.Running}}\t"
                f'{{{{index .Config.Labels "{WORKING_DIR_LABEL}"}}}}\t'
                "{{json .Mounts}}"
            )
            + " $ids",
            "fi",
            "echo @@END",
        ]
    )


def _labels(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {
        str(k): str(v)[:1024]
        for k, v in raw.items()
        if _LABEL_KEY_RE.match(str(k)) and "\n" not in str(v)
    }


def parse_inventory(raw: str, project: str) -> SourceInventory:
    inventory = SourceInventory()
    sources: set[str] = set()
    for line in raw.splitlines():
        if line.startswith("@@VOL "):
            try:
                volume = json.loads(line[6:])
            except ValueError:
                continue
            if not isinstance(volume, dict):
                continue
            name = str(volume.get("Name") or "")
            labels = _labels(volume.get("Labels"))
            if not is_volume_name_valid(name) or labels.get(PROJECT_LABEL) != project:
                continue
            if str(volume.get("Driver") or "local") != "local":
                inventory.skipped_volumes.append({"name": name, "reason": "driver"})
            elif volume.get("Options"):
                inventory.skipped_volumes.append({"name": name, "reason": "options"})
            elif len(inventory.volumes) < MAX_VOLUMES:
                inventory.volumes.append({"name": name, "labels": labels})
        elif line.startswith("@@CT "):
            parts = line[5:].split("\t", 2)
            if len(parts) < 3:
                continue
            if parts[0].strip() == "true":
                inventory.running += 1
            working_dir = parts[1].strip()
            if working_dir.startswith("/") and not inventory.working_dir:
                inventory.working_dir = posixpath.normpath(working_dir)
            try:
                mounts = json.loads(parts[2])
            except ValueError:
                continue
            for mount in mounts if isinstance(mounts, list) else []:
                if isinstance(mount, dict) and mount.get("Type") == "bind":
                    source = str(mount.get("Source") or "")
                    if source.startswith("/"):
                        sources.add(posixpath.normpath(source))
    inventory.bind_sources = sorted(sources)
    return inventory


def bind_paths(
    inventory: SourceInventory, stack_dir: str, *, git: bool
) -> tuple[list[str], list[str]]:
    """Split the bind-mounted host paths into those inside the stack's
    directory (relative to it, to copy) and the rest (absolute, listed
    only). For a Git stack, `repo/` comes from the repository."""
    inside: list[str] = []
    outside: list[str] = []
    base = posixpath.normpath(stack_dir) if stack_dir.startswith("/") else ""
    for source in inventory.bind_sources:
        if base and source.startswith(base + "/"):
            rel = source[len(base) + 1 :]
            if (
                _REL_PATH_RE.match(rel)
                and ".." not in rel.split("/")
                and rel not in (STACK_MARKER, ".env", "compose.yaml")
                and not (git and (rel == "repo" or rel.startswith("repo/")))
            ):
                inside.append(rel)
                continue
            if git and (rel == "repo" or rel.startswith("repo/")):
                continue
        outside.append(source)
    # A path inside another one is copied with it.
    kept = [p for p in inside if not any(p.startswith(o + "/") for o in inside if o != p)]
    return kept[:MAX_BIND_PATHS], outside


def source_dir_script(name: str, directory: str) -> str:
    """The source stack directory's absolute path (empty when missing)."""
    return f"cd {stack_dir_shell(name, directory)} 2>/dev/null && pwd -P || true"


def target_prepare_script(name: str, directory: str, volumes: list[str]) -> str:
    """On the target: refuse when a volume of that name exists or the
    stack's directory holds other files; otherwise create the directory
    with its marker and print its absolute path."""
    for volume in volumes:
        if not is_volume_name_valid(volume):
            raise DockerCommandError(f'"{volume}" is not a valid volume name.')
    lines = [f"dir={stack_dir_shell(name, directory)}"]
    lines += [
        f"if $D volume inspect {q(volume)} >/dev/null 2>&1; then "
        f"echo {q('@@EXISTS ' + volume)}; fi"
        for volume in volumes
    ]
    lines += [
        f'if [ -d "$dir" ] && [ "$(cat "$dir/{STACK_MARKER}" 2>/dev/null)" != {q(name)} ] && '
        '[ -n "$(ls -A "$dir" 2>/dev/null)" ]; then echo @@DIR_NOT_EMPTY; fi',
        'mkdir -p "$dir" && cd "$dir" && '
        f'printf "%s\\n" {q(name)} > "$dir/{STACK_MARKER}" && echo "@@DIR $(pwd -P)"',
    ]
    return "\n".join(lines)


@dataclass(frozen=True)
class TargetState:
    existing_volumes: list[str]
    dir_not_empty: bool
    directory: str


def parse_target_state(raw: str) -> TargetState:
    existing = [line[9:].strip() for line in raw.splitlines() if line.startswith("@@EXISTS ")]
    directory = ""
    for line in raw.splitlines():
        if line.startswith("@@DIR "):
            directory = line[6:].strip()
    return TargetState(
        existing_volumes=existing,
        dir_not_empty="@@DIR_NOT_EMPTY" in raw.splitlines(),
        directory=directory if directory.startswith("/") else "",
    )


def build_volume_create(volume: str, labels: dict[str, str]) -> str:
    if not is_volume_name_valid(volume):
        raise DockerCommandError(f'"{volume}" is not a valid volume name.')
    label_args = " ".join(f"--label {q(f'{k}={v}')}" for k, v in sorted(_labels(labels).items()))
    return f"$D volume create {label_args} {q(volume)} >/dev/null".replace("  ", " ")


def source_volume_command(volume: str) -> str:
    if not is_volume_name_valid(volume):
        raise DockerCommandError(f'"{volume}" is not a valid volume name.')
    return f"{_HELPER} -v {q(volume + ':/from:ro')} {BUSYBOX_IMAGE} tar -C /from -cf - ."


def target_volume_command(volume: str) -> str:
    if not is_volume_name_valid(volume):
        raise DockerCommandError(f'"{volume}" is not a valid volume name.')
    return f"{_HELPER} -i -v {q(volume + ':/to')} {BUSYBOX_IMAGE} tar -C /to -xf -"


def _check_paths(directory: str, paths: list[str]) -> None:
    if not directory.startswith("/") or ".." in directory.split("/"):
        raise DockerCommandError("Invalid stack directory.")
    for path in paths:
        if not _REL_PATH_RE.match(path) or ".." in path.split("/"):
            raise DockerCommandError(f'"{path}" is not a path to copy.')


def source_paths_command(directory: str, paths: list[str]) -> str:
    _check_paths(directory, paths)
    names = " ".join(q("./" + p) for p in paths)
    return f"{_HELPER} -v {q(directory + ':/from:ro')} {BUSYBOX_IMAGE} tar -C /from -cf - {names}"


def target_paths_command(directory: str) -> str:
    _check_paths(directory, [])
    return f"{_HELPER} -i -v {q(directory + ':/to')} {BUSYBOX_IMAGE} tar -C /to -xf -"


class TransferStoppedError(Exception):
    """Cancelled on request while copying."""


@dataclass
class Endpoint:
    machine: Machine
    secret: str | None


async def stream(
    source: Endpoint,
    target: Endpoint,
    connect_timeout: int,
    source_command: str,
    target_command: str,
    *,
    progress: Callable[[int], Awaitable[None]],
    stop_requested: Callable[[], Awaitable[bool]],
) -> int:
    """Pipe `source_command`'s standard output into `target_command`'s
    standard input, through debcontrol. Returns the bytes copied; raises
    `DockerCommandError` when either side fails."""
    copied = 0
    try:
        async with (
            await open_connection(source.machine, source.secret, connect_timeout) as src_conn,
            await open_connection(target.machine, target.secret, connect_timeout) as dst_conn,
        ):
            reader = await src_conn.create_process(
                with_root_shim(DOCKER_ACCESS_PROBE + source_command), encoding=None
            )
            writer = await dst_conn.create_process(
                with_root_shim(DOCKER_ACCESS_PROBE + target_command), encoding=None
            )
            last = time.monotonic()
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.stdout.read(CHUNK), IDLE_TIMEOUT)
                    if not chunk:
                        break
                    writer.stdin.write(chunk)
                    await writer.stdin.drain()
                    copied += len(chunk)
                    if time.monotonic() - last >= 5:
                        last = time.monotonic()
                        await progress(copied)
                        if await stop_requested():
                            raise TransferStoppedError
                writer.stdin.write_eof()
                src_done = await asyncio.wait_for(reader.wait(check=False), 120)
                dst_done = await asyncio.wait_for(writer.wait(check=False), 600)
            finally:
                reader.close()
                writer.close()
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        raise SSHConnectionError(f"Copying failed: {exc}") from exc
    for side, done in (("source", src_done), ("target", dst_done)):
        if done.exit_status != 0:
            err = done.stderr or b""
            text = err.decode(errors="replace") if isinstance(err, bytes) else str(err)
            raise DockerCommandError(
                f"tar on the {side} machine failed: {text.strip()[-400:] or done.exit_status}"
            )
    await progress(copied)
    return copied
