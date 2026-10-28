"""Links for a container on the Docker tab: where its web interface is,
and where its image comes from.

Web links come from what the container itself declares, read with the
monitoring sample (`app.ssh.monitoring.link_labels_of`):

- `debcontrol.url` — one or more URLs (comma-separated) set by the admin
  in the compose file; when present, these are the only web links shown;
- Traefik routers (`traefik.http.routers.<name>.rule` with `Host(...)`)
  and caddy-docker-proxy (`caddy=<host>`) — the public name;
- published TCP ports — `http(s)://<machine address>:<host port>`; a
  port bound to the loopback address only is left out, and
  `debcontrol.https=8443,9443` marks ports to open with https
  (443 and 8443 already are). `debcontrol.hide-ports=true` drops them.

Image links: the image's page in its registry (Docker Hub, GHCR, Quay)
and, from the image's own `org.opencontainers.image.source` label, its
source repository and release notes (GitHub, GitLab, Codeberg).

Every value here comes from a label on a managed machine, so nothing is
trusted: only `http`/`https` URLs without credentials, host names checked
part by part, and the template renders them escaped, opening in a new tab
with `rel="noopener noreferrer"`. Nothing here is fetched by the server.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote, urlsplit

from app.services.image_versions import parse_image

LinkKind = Literal["custom", "proxy", "port"]

MAX_WEB_LINKS = 6
_MAX_URL_LENGTH = 400
_HTTPS_PORTS = frozenset({443, 8443})
_LOOPBACK = frozenset({"127.0.0.1", "::1", "[::1]"})
_WILDCARD = frozenset({"", "0.0.0.0", "::", "[::]"})  # noqa: S104 - parsing, not binding

# One published port as `docker ps` prints it: `0.0.0.0:8080->80/tcp`,
# `[::]:8080->80/tcp`, `192.168.1.5:8080->80/tcp`.
_PORT_RE = re.compile(
    r"^(?:(?P<ip>[0-9.]+|\[[0-9A-Fa-f:.]+\]|::):)?(?P<host>\d{1,5})->(?P<ctr>\d{1,5})/tcp$"
)
_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9-]{1,63}$")
_RULE_HOST_RE = re.compile(r"Host\(([^)]{0,600})\)")
_RULE_PATH_RE = re.compile(r"PathPrefix\(\s*[`\"']([^`\"']{1,200})[`\"']")
_QUOTED_RE = re.compile(r"[`\"']([^`\"']{1,253})[`\"']")
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{0,199}$")
_REPO_PATH_RE = re.compile(r"^/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})")

_SOURCE_HOSTS = {
    "github.com": "/releases",
    "gitlab.com": "/-/releases",
    "codeberg.org": "/releases",
}


@dataclass(frozen=True)
class WebLink:
    url: str
    label: str
    kind: LinkKind


@dataclass(frozen=True)
class ImageLinks:
    registry_url: str | None = None
    source_url: str | None = None
    releases_url: str | None = None


def is_hostname(value: str) -> bool:
    """A DNS name checked label by label (no regex with nested repeats)."""
    name = value.strip().rstrip(".")
    if not name or len(name) > 253:
        return False
    for part in name.split("."):
        if not _HOST_LABEL_RE.match(part) or part.startswith("-") or part.endswith("-"):
            return False
    return True


def safe_url(value: str) -> str | None:
    """`value` as a link target, or None: http(s) only, a host name or IP,
    no user name or password, nothing over `_MAX_URL_LENGTH`."""
    text = value.strip()
    if not text or len(text) > _MAX_URL_LENGTH or any(ch.isspace() for ch in text):
        return None
    try:
        parts = urlsplit(text)
        _ = parts.port  # raises ValueError for a port that is not a number
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    host = parts.hostname
    if not is_hostname(host):
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return None
    return text


def _url_host(address: str) -> str | None:
    """The machine's address as the host part of a URL."""
    text = address.strip().strip("[]")
    if not text:
        return None
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return text.lower() if is_hostname(text) else None
    return f"[{ip}]" if ip.version == 6 else str(ip)


def _https_ports(labels: dict[str, str]) -> set[int]:
    ports = set(_HTTPS_PORTS)
    for piece in labels.get("debcontrol.https", "").split(","):
        if piece.strip().isdigit():
            ports.add(int(piece.strip()))
    return ports


def _port_links(ports: str, address: str, labels: dict[str, str]) -> list[WebLink]:
    if labels.get("debcontrol.hide-ports", "").strip().lower() in ("1", "true", "yes"):
        return []
    machine_host = _url_host(address)
    https_ports = _https_ports(labels)
    links: list[WebLink] = []
    seen: set[int] = set()
    for piece in ports.split(","):
        match = _PORT_RE.match(piece.strip())
        if match is None:
            continue
        ip = match.group("ip") or ""
        host_port = int(match.group("host"))
        if ip in _LOOPBACK or host_port in seen or not 0 < host_port < 65536:
            continue
        # "0.0.0.0" is docker's wildcard bind: the machine's own address.
        host = machine_host if ip in _WILDCARD else _url_host(ip)
        if host is None:
            continue
        seen.add(host_port)
        container_port = int(match.group("ctr"))
        scheme = "https" if {host_port, container_port} & https_ports else "http"
        links.append(WebLink(f"{scheme}://{host}:{host_port}", f":{host_port}", "port"))
    return links


def _traefik_links(labels: dict[str, str]) -> list[WebLink]:
    if labels.get("traefik.enable", "").strip().lower() == "false":
        return []
    links: list[WebLink] = []
    prefix = "traefik.http.routers."
    for key, rule in labels.items():
        if not key.startswith(prefix) or not key.endswith(".rule"):
            continue
        router = key[len(prefix) : -len(".rule")]
        base = f"{prefix}{router}"
        entrypoints = labels.get(f"{base}.entrypoints", "").lower()
        tls = labels.get(f"{base}.tls", "").strip().lower() == "true" or bool(
            labels.get(f"{base}.tls.certresolver")
        )
        # Plain http only when the router is on a plain-http entrypoint and
        # has no TLS; most setups terminate TLS on the entrypoint itself.
        plain = not tls and entrypoints != "" and all(
            ep.strip() in ("web", "http", "80") for ep in entrypoints.split(",")
        )
        scheme = "http" if plain else "https"
        path_match = _RULE_PATH_RE.search(rule)
        path = path_match.group(1) if path_match and _PATH_RE.match(path_match.group(1)) else ""
        hosts = [
            host.lower()
            for group in _RULE_HOST_RE.findall(rule)
            for host in _QUOTED_RE.findall(group)
            if is_hostname(host)
        ]
        links.extend(WebLink(f"{scheme}://{host}{path}", host, "proxy") for host in hosts)
    return links


def _caddy_links(labels: dict[str, str]) -> list[WebLink]:
    links: list[WebLink] = []
    for key, value in labels.items():
        # `caddy`, `caddy_0`, `caddy_1` — the site address; not the
        # directives under it (`caddy.reverse_proxy`).
        if key != "caddy" and not (key.startswith("caddy_") and key[6:].isdigit()):
            continue
        for address in re.split(r"[,\s]+", value):
            scheme = "https"
            host = address
            if address.startswith(("http://", "https://")):
                scheme, _, host = address.partition("://")
            host = host.split("/", 1)[0].split(":", 1)[0]
            if host and not host.startswith("*") and is_hostname(host):
                links.append(WebLink(f"{scheme}://{host.lower()}", host.lower(), "proxy"))
    return links


def _custom_links(labels: dict[str, str]) -> list[WebLink]:
    urls = (safe_url(piece) for piece in labels.get("debcontrol.url", "").split(","))
    return [WebLink(url, urlsplit(url).netloc, "custom") for url in urls if url is not None]


def web_links(container: dict[str, Any], address: str) -> list[WebLink]:
    """Where this container's web interface can be opened, best first."""
    labels = container.get("link_labels")
    labels = labels if isinstance(labels, dict) else {}
    labels = {str(k): str(v) for k, v in labels.items()}
    custom = _custom_links(labels)
    if custom:
        candidates = custom
    else:
        candidates = [
            *_traefik_links(labels),
            *_caddy_links(labels),
            *_port_links(str(container.get("ports") or ""), address, labels),
        ]
    unique: dict[str, WebLink] = {}
    for link in candidates:
        unique.setdefault(link.url, link)
    return list(unique.values())[:MAX_WEB_LINKS]


def _registry_url(image: str) -> str | None:
    ref = parse_image(image)
    if ref is None:
        return None
    repo = ref.repository
    if ref.registry == "docker.io":
        if repo.startswith("library/"):
            return f"https://hub.docker.com/_/{quote(repo[len('library/'):])}"
        return f"https://hub.docker.com/r/{quote(repo)}"
    if ref.registry == "ghcr.io":
        return f"https://ghcr.io/{quote(repo)}"
    if ref.registry == "quay.io":
        return f"https://quay.io/repository/{quote(repo)}"
    return None


def _source(labels: dict[str, str]) -> tuple[str | None, str | None]:
    raw = labels.get("org.opencontainers.image.source", "")
    url = safe_url(raw)
    if url is None or not url.startswith("https://"):
        return None, None
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    suffix = _SOURCE_HOSTS.get(host)
    match = _REPO_PATH_RE.match(parts.path)
    if suffix is None or match is None:
        return url, None
    owner, repo = match.group(1), match.group(2).removesuffix(".git")
    base = f"https://{host}/{owner}/{repo}"
    return base, base + suffix


def image_links(image: str, container: dict[str, Any] | None = None) -> ImageLinks:
    """The registry page of `image`, and its source/release notes when the
    container's labels name them."""
    labels: dict[str, str] = {}
    if container is not None and isinstance(container.get("link_labels"), dict):
        labels = {str(k): str(v) for k, v in container["link_labels"].items()}
    source_url, releases_url = _source(labels)
    return ImageLinks(
        registry_url=_registry_url(image), source_url=source_url, releases_url=releases_url
    )
