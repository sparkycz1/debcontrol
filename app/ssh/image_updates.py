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

VERSION_LABEL = "org.opencontainers.image.version"

IMAGE_UPDATE_COMMAND = (
    f"{DOCKER_ACCESS_PROBE}"
    "for img in $($D ps --format '{{.Image}}' 2>/dev/null | sort -u); do "
    'l="$($D image inspect --format \'{{join .RepoDigests " "}}\' "$img" 2>/dev/null)"; '
    'r="$($D buildx imagetools inspect "$img" 2>/dev/null '
    "| awk '/^Digest:/{print $2; exit}')\"; "
    # The version the image declares about itself, for the local copy and
    # — only when the registry has a different one, to spare a request —
    # for the registry's (app.services.image_versions).
    f"lv=\"$($D image inspect --format '{{{{index .Config.Labels \"{VERSION_LABEL}\"}}}}' "
    '"$img" 2>/dev/null)"; '
    "rv=; "
    'if [ -n "$r" ] && ! printf \'%s\' "$l" | grep -qF "$r"; then '
    "rv=\"$($D buildx imagetools inspect \"$img\" --format '{{json .Image}}' 2>/dev/null "
    f"| tr -d '\\n' | grep -o '\"{VERSION_LABEL}\": *\"[^\"]*\"' | head -n 1 "
    "| cut -d'\"' -f4)\"; "
    "fi; "
    "printf '%s\\t%s\\t%s\\t%s\\t%s\\n' \"$img\" \"$r\" \"$l\" \"$lv\" \"$rv\"; "
    "done"
)


class ImageCheckError(Exception):
    pass


def _digest(ref: str) -> str:
    return ref.rsplit("@", 1)[-1].strip()


def parse_image_update_output(raw: str) -> dict[str, ImageStatus]:
    """`{image: status}` from `IMAGE_UPDATE_COMMAND`'s tab-separated
    `image<TAB>remote digest<TAB>local repo digests (space-separated)`
    (two more fields, the declared versions, follow — see
    `parse_image_versions`)."""
    if raw.strip() == DOCKER_NO_ACCESS_MARKER:
        raise ImageCheckError("This account can't reach the Docker daemon.")
    statuses: dict[str, ImageStatus] = {}
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) not in (3, 5) or not fields[0].strip():
            continue
        image, remote, local = (f.strip() for f in fields[:3])
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


def _label(value: str) -> str:
    text = value.strip()
    return "" if text in ("<no value>", "<nil>") else text[:80]


def parse_image_versions(raw: str) -> dict[str, dict[str, str]]:
    """`{image: {"local_version": ..., "remote_version": ...}}` — the
    version each image declares (`VERSION_LABEL`), where it declares one."""
    versions: dict[str, dict[str, str]] = {}
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) != 5 or not fields[0].strip():
            continue
        found = {
            key: value
            for key, value in (
                ("local_version", _label(fields[3])),
                ("remote_version", _label(fields[4])),
            )
            if value
        }
        if found:
            versions[fields[0].strip()] = found
    return versions


async def check_images(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> tuple[dict[str, ImageStatus], dict[str, dict[str, str]]]:
    """(status per image, declared versions per image). Requires a pinned
    host key. One registry round trip per distinct running image (two for
    one with an update), hence the generous timeout."""
    async with machine_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(
            with_root_shim(IMAGE_UPDATE_COMMAND), check=False, timeout=timeout_seconds + 120
        )
    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_image_update_output(raw), parse_image_versions(raw)


async def check_image_updates(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> dict[str, ImageStatus]:
    """Only the statuses — see `check_images`."""
    return (await check_images(machine, secret, timeout_seconds))[0]


def count_updates(image_updates: dict[str, Any] | None) -> int:
    return sum(1 for status in (image_updates or {}).values() if status == "update")
