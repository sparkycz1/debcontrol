"""Is a newer image available for a running container? Compares each
running image's local repo digest(s) with the registry's current digest
for the same tag — `docker buildx imagetools inspect` (the buildx plugin
ships with docker-ce) reads just the manifest, nothing is pulled.

Digest-pinned references (`image@sha256:…`) and locally built images (no
repo digest at all) can't be compared and are reported as "unknown"
without asking the registry at all, as is any image the registry won't
answer for (private registry this machine isn't logged in to, Docker
Hub's rate limit, network down, no buildx) — each with the reason
(`parse_unknown_reasons`), so the Docker tab can say why.

Registry manifest requests count toward Docker Hub's anonymous rate limit
(per IP address) — which is why this runs once a day per machine by
default (Settings → Checks & retention, `docker_image_check_interval_hours`),
one request per distinct image.
"""

from __future__ import annotations

from typing import Any, Literal

from app.db.models.machine import Machine
from app.ssh.logs import DOCKER_ACCESS_PROBE, DOCKER_NO_ACCESS_MARKER
from app.ssh.pool import machine_connection
from app.ssh.shell import with_root_shim

ImageStatus = Literal["update", "current", "unknown"]

# Why an image's status is "unknown" (`parse_unknown_reasons`).
UNKNOWN_REASONS: tuple[str, ...] = (
    "pinned",  # referenced by digest: nothing newer under it by definition
    "local",  # built on the machine, never pulled: no registry to ask
    "rate_limited",  # Docker Hub's (or another registry's) rate limit
    "auth",  # the registry wants a login this machine doesn't have
    "not_found",  # the registry doesn't know the image or tag
    "no_buildx",  # `docker buildx` isn't installed
    "network",  # the registry couldn't be reached
    "error",  # anything else
)

VERSION_LABEL = "org.opencontainers.image.version"

IMAGE_UPDATE_COMMAND = (
    f"{DOCKER_ACCESS_PROBE}"
    "for img in $($D ps --format '{{.Image}}' 2>/dev/null | sort -u); do "
    'l="$($D image inspect --format \'{{join .RepoDigests " "}}\' "$img" 2>/dev/null)"; '
    "r=; o=; e=; "
    # Only ask the registry about an image it could answer for: not one
    # referenced by digest, not one built here (no repo digest) — each
    # request counts toward Docker Hub's rate limit.
    'case "$img" in *@sha256:*) ;; *) if [ -n "$l" ]; then '
    'o="$($D buildx imagetools inspect "$img" 2>&1)"; '
    "r=\"$(printf '%s\\n' \"$o\" | awk '/^Digest:/{print $2; exit}')\"; "
    "fi;; esac; "
    # Why the registry didn't answer: the start of what buildx said, on one
    # line (`parse_unknown_reasons` reads it).
    'if [ -z "$r" ] && [ -n "$o" ]; then '
    "e=\"$(printf '%s' \"$o\" | tr '\\t\\r\\n' '   ' | cut -c1-300)\"; "
    "fi; "
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
    "printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' \"$img\" \"$r\" \"$l\" \"$lv\" \"$rv\" \"$e\"; "
    "done"
)


class ImageCheckError(Exception):
    pass


def _digest(ref: str) -> str:
    return ref.rsplit("@", 1)[-1].strip()


def parse_image_update_output(raw: str) -> dict[str, ImageStatus]:
    """`{image: status}` from `IMAGE_UPDATE_COMMAND`'s tab-separated
    `image<TAB>remote digest<TAB>local repo digests (space-separated)`
    (more fields follow: the declared versions — see
    `parse_image_versions` — and why the registry didn't answer — see
    `parse_unknown_reasons`; output of older versions had 3 or 5)."""
    if raw.strip() == DOCKER_NO_ACCESS_MARKER:
        raise ImageCheckError("This account can't reach the Docker daemon.")
    statuses: dict[str, ImageStatus] = {}
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) not in (3, 5, 6) or not fields[0].strip():
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
        if len(fields) not in (5, 6) or not fields[0].strip():
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


def _reason_from_error(text: str) -> str:
    lowered = text.lower()
    checks: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("rate_limited", ("toomanyrequests", "too many requests", "rate limit", " 429")),
        ("no_buildx", ("is not a docker command", "unknown command", "unknown flag")),
        (
            "auth",
            ("unauthorized", "denied", "authentication required", "no basic auth", "forbidden"),
        ),
        ("not_found", ("manifest unknown", "not found", "no such manifest")),
        (
            "network",
            (
                "no such host",
                "timeout",
                "timed out",
                "connection refused",
                "network is unreachable",
                "connection reset",
                "tls:",
                "x509:",
            ),
        ),
    )
    for reason, needles in checks:
        if any(needle in lowered for needle in needles):
            return reason
    return "error"


def parse_unknown_reasons(raw: str) -> dict[str, str]:
    """`{image: reason}` (`UNKNOWN_REASONS`) for every image
    `parse_image_update_output` reports as "unknown"."""
    reasons: dict[str, str] = {}
    statuses = parse_image_update_output(raw)
    for line in raw.splitlines():
        fields = line.split("\t")
        image = fields[0].strip() if fields else ""
        if statuses.get(image) != "unknown":
            continue
        local = fields[2].strip() if len(fields) > 2 else ""
        if "@sha256:" in image:
            reasons[image] = "pinned"
        elif not any("@" in ref for ref in local.split()):
            reasons[image] = "local"
        else:
            reasons[image] = _reason_from_error(fields[5] if len(fields) == 6 else "")
    return reasons


def is_docker_hub(image: str) -> bool:
    """Whether a reference names an image on Docker Hub (no registry host,
    or docker.io) — the registry whose anonymous rate limit counts each
    check's requests."""
    first, _, rest = image.partition("/")
    if not rest:
        return True
    host = first.lower()
    if "." not in host and ":" not in host and host != "localhost":
        return True
    return host in ("docker.io", "index.docker.io", "registry-1.docker.io")


async def check_images(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> tuple[dict[str, ImageStatus], dict[str, dict[str, str]], dict[str, str]]:
    """(status per image, declared versions per image, why each "unknown"
    one is unknown). Requires a pinned host key. One registry round trip
    per distinct running image (two for one with an update), hence the
    generous timeout."""
    async with machine_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run(
            with_root_shim(IMAGE_UPDATE_COMMAND), check=False, timeout=timeout_seconds + 120
        )
    stdout = result.stdout or ""
    raw = stdout if isinstance(stdout, str) else stdout.decode()
    return parse_image_update_output(raw), parse_image_versions(raw), parse_unknown_reasons(raw)


def count_updates(image_updates: dict[str, Any] | None) -> int:
    return sum(1 for status in (image_updates or {}).values() if status == "update")
