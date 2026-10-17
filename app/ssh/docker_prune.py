"""Cleaning up a machine's Docker: unused images, stopped containers,
unused networks and volumes, and the build cache (`docker <x> prune`).

What each option removes is what Docker itself removes for that command —
the Images page shows the same selection beforehand (from
`app.ssh.docker_inventory`), so nothing is a surprise:

- `images`: dangling images (untagged layers) only; with `all_images`,
  every image no container uses.
- `containers`: stopped containers.
- `networks`: networks no container uses (never the built-in ones).
- `volumes`: unused anonymous volumes; with `all_volumes`, every volume
  no container uses — named ones too, which is data and is asked for
  separately (`build_prune_script` refuses `all_volumes` without
  `volumes`).
- `build_cache`: the builder's cache.

Containers debcontrol starts for its own work (scanners, restic, git) are
removed when they end (`--rm`) and carry `docker_cli.HELPER_LABEL`; their
cache volumes are named and in use only during a job, so a plain volume
prune leaves them, and `all_volumes` removes them like any other unused
volume (they are refilled on the next job).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.ssh.docker_cli import DockerCommandError
from app.ssh.monitoring import parse_docker_size

PRUNE_TARGETS = ("containers", "images", "networks", "volumes", "build_cache")

_RECLAIMED_RE = re.compile(r"^Total reclaimed space:\s*(\S+)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class PruneOptions:
    containers: bool = False
    images: bool = False
    all_images: bool = False
    networks: bool = False
    volumes: bool = False
    all_volumes: bool = False
    build_cache: bool = False

    @property
    def anything(self) -> bool:
        return any((self.containers, self.images, self.networks, self.volumes, self.build_cache))

    def as_dict(self) -> dict[str, bool]:
        return {
            "containers": self.containers,
            "images": self.images,
            "all_images": self.all_images,
            "networks": self.networks,
            "volumes": self.volumes,
            "all_volumes": self.all_volumes,
            "build_cache": self.build_cache,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> PruneOptions:
        data = data or {}
        return cls(**{key: bool(data.get(key)) for key in cls().as_dict()})


def build_prune_script(options: PruneOptions) -> str:
    """The detached job: each selected prune in turn (containers first, so
    what they used becomes unused), each printing `@@DC_PRUNE <what>`
    before Docker's own output."""
    if not options.anything:
        raise DockerCommandError("Nothing selected to clean up.")
    if options.all_volumes and not options.volumes:
        raise DockerCommandError("Removing all unused volumes needs volumes selected.")
    steps: list[tuple[str, str]] = []
    if options.containers:
        steps.append(("containers", "$D container prune -f"))
    if options.images:
        steps.append(("images", "$D image prune -f" + (" -a" if options.all_images else "")))
    if options.networks:
        steps.append(("networks", "$D network prune -f"))
    if options.volumes:
        steps.append(("volumes", "$D volume prune -f" + (" -a" if options.all_volumes else "")))
    if options.build_cache:
        steps.append(("build_cache", "$D builder prune -f"))
    lines = ["failed=0"]
    for name, command in steps:
        lines += [
            f"echo '@@DC_PRUNE {name}'",
            f"{command} || {{ echo '@@DC_FAILED {name}'; failed=1; }}",
        ]
    lines.append('exit "$failed"')
    return "\n".join(lines) + "\n"


def parse_reclaimed_bytes(raw: str) -> int:
    """The sum of every "Total reclaimed space" Docker printed."""
    total = 0
    for match in _RECLAIMED_RE.finditer(raw):
        size = parse_docker_size(match.group(1))
        if size:
            total += int(size)
    return total


def parse_removed_counts(raw: str) -> dict[str, int]:
    """How many objects each prune removed — the lines Docker lists under
    "Deleted ..." until the next blank line or marker."""
    counts: dict[str, int] = {}
    current: str | None = None
    listing = False
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("@@DC_PRUNE "):
            current = stripped.split(" ", 1)[1]
            if current not in PRUNE_TARGETS:
                current = None
            counts.setdefault(current or "", 0)
            listing = False
        elif current is None:
            continue
        elif stripped.startswith(("Deleted ", "Untagged:", "deleted:")) and stripped.endswith(":"):
            listing = True
        elif not stripped or stripped.startswith(("Total reclaimed", "@@DC_")):
            listing = False
        elif listing or stripped.startswith(("deleted: ", "untagged: ")):
            counts[current] = counts.get(current, 0) + 1
    counts.pop("", None)
    return counts
