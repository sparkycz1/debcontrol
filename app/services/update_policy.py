"""How far an automatic container update may go (`UpdatePolicy`, set per
container on the Docker tab): any newer image, or only a newer minor or
patch version — never a new major version.

Two parts, both only for scheduled ("Update Docker containers" with
"containers set to update automatically") updates; an update someone
starts by hand is not limited:

- **The guard**, for every container: after the pull, the version the new
  image declares (`org.opencontainers.image.version`) must stay within
  the policy compared with the running image's. When either version
  can't be told, a restrictive policy does not update (the image is put
  back under its tag, like an update the vulnerability gate stops).
- **The tag bump**, for a container not created by Compose and running a
  version tag (`nginx:1.27.3`): the newest tag of the same shape within
  the policy (`1.27.4` for "patch", `1.29.0` for "minor") is pulled and
  the container recreated on it. A Compose container keeps its tag (its
  compose file is the source of truth); the Docker tab shows the newer
  allowed tag as a hint instead (`allowed_tag`).
"""

from __future__ import annotations

import re

from app.db.models.docker import UpdatePolicy
from app.services import image_versions

POLICIES: tuple[str, ...] = tuple(p.value for p in UpdatePolicy)

# A version at the start of a label or tag: "1.27.3", "v2.4", "2024.10.1-alpine".
_LEADING_VERSION_RE = re.compile(r"^v?(\d{1,8}(?:\.\d{1,8}){0,3})(?:$|[-+_~])")


def normalize_policy(value: str | None) -> str:
    return value if value in POLICIES else UpdatePolicy.ANY.value


def parse_version(text: str | None) -> tuple[int, ...] | None:
    """The numbers of a version label or tag; None when it doesn't start
    with one ("latest", a commit hash)."""
    match = _LEADING_VERSION_RE.match((text or "").strip())
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _padded(version: tuple[int, ...]) -> tuple[int, ...]:
    return version + (0,) * (4 - len(version))


def within(policy: str, old: tuple[int, ...] | None, new: tuple[int, ...] | None) -> bool:
    """Whether going from version `old` to `new` keeps to `policy`. "any"
    always does; otherwise both must be known, `new` not older, and the
    same major ("minor") or major.minor ("patch") version."""
    policy = normalize_policy(policy)
    if policy == UpdatePolicy.ANY:
        return True
    if old is None or new is None or _padded(new) < _padded(old):
        return False
    if policy == UpdatePolicy.MINOR:
        return new[0] == old[0]
    return len(old) >= 2 and len(new) >= 2 and new[:2] == old[:2]


def allowed_tag(policy: str, current: str, tags: list[str]) -> str | None:
    """The newest tag shaped like `current` (same "v", flavour and number
    of parts, `image_versions.newer_tags`' rule) that is newer and within
    `policy`; None when there is none or `current` is not a version tag."""
    policy = normalize_policy(policy)
    if policy == UpdatePolicy.ANY:
        return None
    mine = image_versions.parse_tag(current)
    if mine is None:
        return None
    prefix, numbers, flavour = mine
    best: tuple[tuple[int, ...], str] | None = None
    for tag in tags:
        other = image_versions.parse_tag(tag)
        if other is None or other[0] != prefix or other[2] != flavour:
            continue
        candidate = other[1]
        if len(candidate) != len(numbers) or candidate <= numbers:
            continue
        if not within(policy, numbers, candidate):
            continue
        if best is None or candidate > best[0]:
            best = (candidate, tag)
    return best[1] if best else None


def with_tag(ref: str, tag: str) -> str:
    """`ref` with its tag replaced (`nginx:1.27.3` -> `nginx:1.27.4`)."""
    name = ref
    if ":" in ref.rsplit("/", 1)[-1]:
        name = ref.rsplit(":", 1)[0]
    return f"{name}:{tag}"


async def bump_target(ref: str, policy: str) -> str | None:
    """The reference a policy-limited update of a container on `ref`
    moves to, when a newer allowed tag exists in its (public) registry
    (`image_versions.list_tags`); None otherwise."""
    if normalize_policy(policy) == UpdatePolicy.ANY:
        return None
    parsed = image_versions.parse_image(ref)
    if parsed is None or image_versions.parse_tag(parsed.tag) is None:
        return None
    tags = await image_versions.fetch_tags(parsed)
    target = allowed_tag(policy, parsed.tag, tags or [])
    return with_tag(ref, target) if target else None
