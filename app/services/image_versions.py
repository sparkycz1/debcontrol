"""Which newer version of a container image exists.

The daily image check (`app.ssh.image_updates`) says *that* a running image
has an update. This adds *what*:

- for a version tag (`nginx:1.27.1`, `postgres:16.4-alpine`), the newer
  tags of the same shape in the registry — the newest of the same series
  (`1.27.3`) and the newest overall (`1.29.0`);
- the version the image itself declares
  (`org.opencontainers.image.version`), read on the machine for the local
  and the registry copy — the only thing to go by for `:latest`.

Tags are listed by debcontrol's own server straight from the registry's
read-only API, anonymously, and only from the public registries named in
`REGISTRIES`: an image on any other host (a private or internal registry)
is never contacted from here, so a machine cannot make the server call an
address of its choosing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx2

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 15.0
_PAGE_SIZE = 1000
_MAX_PAGES = 10
_MAX_TAG_LENGTH = 128


@dataclass(frozen=True)
class Registry:
    api: str
    # Where an anonymous pull token comes from; None = no token needed.
    token_url: str | None = None
    service: str | None = None


REGISTRIES: dict[str, Registry] = {
    "docker.io": Registry(
        "https://registry-1.docker.io", "https://auth.docker.io/token", "registry.docker.io"
    ),
    "ghcr.io": Registry("https://ghcr.io", "https://ghcr.io/token", "ghcr.io"),
    "quay.io": Registry("https://quay.io", "https://quay.io/v2/auth", "quay.io"),
    "registry.k8s.io": Registry("https://registry.k8s.io"),
    "mcr.microsoft.com": Registry("https://mcr.microsoft.com"),
    "gcr.io": Registry("https://gcr.io", "https://gcr.io/v2/token", "gcr.io"),
}
# Names that are another registry's content under a different host.
_ALIASES = {
    "index.docker.io": "docker.io",
    "registry-1.docker.io": "docker.io",
    "lscr.io": "ghcr.io",
}

_REPO_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$")
# 1 to 4 numeric parts, an optional leading "v", an optional flavour
# ("-alpine", "-bookworm-slim"). Anything else is not a version tag.
_TAG_RE = re.compile(r"^(v?)(\d{1,8}(?:\.\d{1,8}){0,3})(-[A-Za-z][A-Za-z0-9._-]{0,60})?$")


@dataclass(frozen=True)
class ImageRef:
    registry: str
    repository: str
    tag: str


def parse_image(image: str) -> ImageRef | None:
    """`nginx:1.27` -> docker.io / library/nginx / 1.27. None for a
    digest-pinned or malformed reference."""
    text = image.strip()
    if not text or "@" in text or len(text) > 400:
        return None
    name, tag = text, "latest"
    last = text.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = text.rsplit(":", 1)
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, repository = first.lower(), rest
    else:
        registry, repository = "docker.io", name
    registry = _ALIASES.get(registry, registry)
    if registry == "docker.io" and "/" not in repository:
        repository = f"library/{repository}"
    if not _REPO_RE.match(repository) or not tag or len(tag) > _MAX_TAG_LENGTH:
        return None
    return ImageRef(registry=registry, repository=repository, tag=tag)


def _version(tag: str) -> tuple[str, tuple[int, ...], str] | None:
    match = _TAG_RE.match(tag)
    if match is None:
        return None
    return (
        match.group(1),
        tuple(int(part) for part in match.group(2).split(".")),
        match.group(3) or "",
    )


def newer_tags(current: str, tags: list[str]) -> dict[str, str]:
    """`{"series": ..., "newest": ...}` — the newest tag of the same series
    (same leading parts, e.g. another 1.27.x) and the newest of all, among
    tags shaped like `current` (same "v", same flavour, same number of
    parts). Empty when `current` is not a version tag or nothing is newer;
    `newest` is left out when it is the same as `series`."""
    mine = _version(current)
    if mine is None:
        return {}
    prefix, numbers, flavour = mine
    best_series: tuple[tuple[int, ...], str] | None = None
    best_all: tuple[tuple[int, ...], str] | None = None
    for tag in tags:
        other = _version(tag)
        if other is None or other[0] != prefix or other[2] != flavour:
            continue
        candidate = other[1]
        if len(candidate) != len(numbers) or candidate <= numbers:
            continue
        if best_all is None or candidate > best_all[0]:
            best_all = (candidate, tag)
        if (
            len(numbers) > 1
            and candidate[:-1] == numbers[:-1]
            and (best_series is None or candidate > best_series[0])
        ):
            best_series = (candidate, tag)
    result: dict[str, str] = {}
    if best_series is not None:
        result["series"] = best_series[1]
    if best_all is not None and (best_series is None or best_all[1] != best_series[1]):
        result["newest"] = best_all[1]
    return result


async def _token(client: httpx2.AsyncClient, registry: Registry, repository: str) -> str | None:
    if registry.token_url is None:
        return None
    response = await client.get(
        registry.token_url,
        params={"service": registry.service or "", "scope": f"repository:{repository}:pull"},
    )
    response.raise_for_status()
    data = response.json()
    token = data.get("token") or data.get("access_token") if isinstance(data, dict) else None
    return str(token) if token else None


async def list_tags(ref: ImageRef, client: httpx2.AsyncClient) -> list[str] | None:
    """Every tag of `ref`'s repository, or None when its registry is not
    one of `REGISTRIES` or does not answer."""
    registry = REGISTRIES.get(ref.registry)
    if registry is None:
        return None
    try:
        token = await _token(client, registry, ref.repository)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        tags: list[str] = []
        last = ""
        for _page in range(_MAX_PAGES):
            params: dict[str, str] = {"n": str(_PAGE_SIZE)}
            if last:
                params["last"] = last
            response = await client.get(
                f"{registry.api}/v2/{ref.repository}/tags/list", params=params, headers=headers
            )
            response.raise_for_status()
            data = response.json()
            page = data.get("tags") if isinstance(data, dict) else None
            if not isinstance(page, list) or not page:
                break
            names = [str(tag) for tag in page if isinstance(tag, str)]
            tags.extend(names)
            if len(names) < _PAGE_SIZE or names[-1] == last:
                break
            last = names[-1]
        return tags
    except (httpx2.HTTPError, ValueError) as exc:
        logger.info("image_versions: no tags for %s/%s: %s", ref.registry, ref.repository, exc)
        return None


async def describe(
    images: dict[str, dict[str, str]], transport: httpx2.AsyncBaseTransport | None = None
) -> dict[str, dict[str, Any]]:
    """`{image: {"local_version", "remote_version", "series", "newest"}}`
    (only the keys that are known) for the machine-side findings in
    `images` — `{image: {"local_version": ..., "remote_version": ...}}`.
    One tag listing per distinct repository."""
    result: dict[str, dict[str, Any]] = {}
    listed: dict[tuple[str, str], list[str] | None] = {}
    async with httpx2.AsyncClient(
        timeout=_TIMEOUT_SECONDS, follow_redirects=False, transport=transport
    ) as client:
        for image, found in images.items():
            entry: dict[str, Any] = {
                key: value[:80]
                for key, value in found.items()
                if key in ("local_version", "remote_version") and value
            }
            ref = parse_image(image)
            if ref is not None and _version(ref.tag) is not None:
                key = (ref.registry, ref.repository)
                if key not in listed:
                    listed[key] = await list_tags(ref, client)
                entry.update(newer_tags(ref.tag, listed[key] or []))
            if entry:
                result[image] = entry
    return result
