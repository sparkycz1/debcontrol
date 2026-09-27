"""Is a newer image available for a running container? Compares each
running image's local repo digest(s) with the registry's current digest
for the same tag — `docker buildx imagetools inspect` (the buildx plugin
ships with docker-ce) reads just the manifest, nothing is pulled.

Digest-pinned references (`image@sha256:…`) and locally built images (no
repo digest at all) can't be compared and are reported as "unknown", as
is any image the registry won't answer for (private registry this
machine isn't logged in to, network down, no buildx).

Registry manifest requests count toward Docker Hub's anonymous rate limit
— which is why this runs once a day per machine, one request per
distinct image.
"""

from __future__ import annotations

from typing import Any, Literal

from app.db.models.machine import Machine
from app.ssh.logs import DOCKER_ACCESS_PROBE, DOCKER_NO_ACCESS_MARKER
from app.ssh.pool import machine_connection
from app.ssh.shell import with_root_shim

ImageStatus = Literal["update", "current", "unknown"]

IMAGE_UPDATE_COMMAND = (
    f"{DOCKER_ACCESS_PROBE}"
    "for img in $($D ps --format '{{.Image}}' 2>/dev/null | sort -u); do "
    'l="$($D image inspect --format \'{{join .RepoDigests " "}}\' "$img" 2>/dev/null)"; '
    'r="$($D buildx imagetools inspect "$img" 2>/dev/null '
    "| awk '/^Digest:/{print $2; exit}')\"; "
    "printf '%s\\t%s\\t%s\\n' \"$img\" \"$r\" \"$l\"; "
    "done"
)


class ImageCheckError(Exception):
    pass


def _digest(ref: str) -> str:
    return ref.rsplit("@", 1)[-1].strip()


def parse_image_update_output(raw: str) -> dict[str, ImageStatus]:
    """`{image: status}` from `IMAGE_UPDATE_COMMAND`'s tab-separated
    `image<TAB>remote digest<TAB>local repo digests (space-separated)`."""
    if raw.strip() == DOCKER_NO_ACCESS_MARKER:
        raise ImageCheckError("This account can't reach the Docker daemon.")
    statuses: dict[str, ImageStatus] = {}
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or not fields[0].strip():
            continue
        image, remote, local = (f.strip() for f in fields)
        local_digests = {_digest(ref) for ref in local.split() if "@" in ref}
        status: ImageStatus
        if "@sha256:" in image or not remote.startswith("sha256:") or not local_digests:
            status = "unknown"
        elif remote in local_digests:
            status = "current"
        else:
            status = "update"
        statuses[image] = status
    return statuses


async def check_image_updates(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> dict[str, ImageStatus]:
    """Requires a pinned host key. One registry round trip per distinct
    running image, hence the generous timeout."""
    async with machine_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(
            with_root_shim(IMAGE_UPDATE_COMMAND), check=False, timeout=timeout_seconds + 120
        )
    stdout = result.stdout or ""
    return parse_image_update_output(stdout if isinstance(stdout, str) else stdout.decode())


def count_updates(image_updates: dict[str, Any] | None) -> int:
    return sum(1 for status in (image_updates or {}).values() if status == "update")
