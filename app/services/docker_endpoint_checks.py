"""Endpoint checks made from what containers declare (Settings → Checks &
retention → "Endpoint checks for container web links", off by default).

With it on, every web link of a running container (the same links the
Docker tab shows, `app.services.container_links.web_links`: Traefik and
Caddy host names, `debcontrol.url`, published web ports) gets an HTTP
endpoint check, kept in step with each monitoring sample:

- a link that appears gets a check; one that disappears (the container
  stopped, was removed, or no longer offers it) loses its check, history
  included;
- `debcontrol.check=false` on a container leaves it out;
  `debcontrol.check-path=/health` checks that path instead of the link's;
- a person may change such a check (interval, expected text, turn it
  off); only its existence follows the container. Turning the setting off
  removes them all.

Each check runs **from the container's machine** (`source_machine_id`),
over its SSH connection, never from the debcontrol server: the URLs come
from labels on that machine, so they are not trusted to point anywhere the
server should send requests. The machine reaches its own services anyway.
HTTPS on a published port is checked without certificate verification
(usually a self-signed certificate); a host name behind a proxy with it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.machine import Machine
from app.services.container_links import web_links

# At most this many automatic checks per machine (the rest are left out).
MAX_PER_MACHINE = 40
INTERVAL_SECONDS = 300
_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/?=&%-]{0,199}$")
_OFF = ("0", "false", "no", "off")


@dataclass(frozen=True)
class Wanted:
    key: str
    name: str
    url: str
    verify_tls: bool


def _labels(container: dict[str, Any]) -> dict[str, str]:
    raw = container.get("link_labels")
    return {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}


def _with_path(url: str, path: str) -> str:
    parts = urlsplit(url)
    path_part, _, query = path.partition("?")
    return urlunsplit((parts.scheme, parts.netloc, path_part, query, ""))


def wanted_checks(machine: Machine) -> list[Wanted]:
    """The checks the machine's running containers call for, in a stable
    order (by container, then link)."""
    wanted: list[Wanted] = []
    for container in machine.docker_containers or []:
        if not isinstance(container, dict) or container.get("state") != "running":
            continue
        name = str(container.get("name") or "")
        labels = _labels(container)
        if not name or labels.get("debcontrol.check", "").strip().lower() in _OFF:
            continue
        path = labels.get("debcontrol.check-path", "").strip()
        path = path if _PATH_RE.match(path) and not path.startswith("//") else ""
        for link in web_links(container, machine.ip_address):
            url = _with_path(link.url, path) if path else link.url
            wanted.append(
                Wanted(
                    key=f"{name}|{url}"[:500],
                    name=f"{name} · {link.label}"[:100],
                    url=url,
                    verify_tls=link.kind != "port",
                )
            )
    return wanted[:MAX_PER_MACHINE]


async def sync(db: AsyncSession, machine: Machine, *, enabled: bool) -> tuple[int, int]:
    """Create and remove the machine's automatic checks to match its
    latest sample. Returns (created, removed); commits only on a change."""
    existing = {
        check.auto_key: check
        for check in (
            await db.execute(
                select(EndpointCheck).where(
                    EndpointCheck.source_machine_id == machine.id,
                    EndpointCheck.auto_key.is_not(None),
                )
            )
        )
        .scalars()
        .all()
    }
    wanted = {w.key: w for w in wanted_checks(machine)} if enabled else {}
    gone = [check.id for key, check in existing.items() if key not in wanted]
    new = [w for key, w in wanted.items() if key not in existing]
    if not gone and not new:
        return 0, 0
    if gone:
        await db.execute(delete(EndpointCheck).where(EndpointCheck.id.in_(gone)))
    for w in new:
        db.add(
            EndpointCheck(
                name=w.name,
                kind="http",
                target=w.url,
                verify_tls=w.verify_tls,
                source_machine_id=machine.id,
                interval_seconds=INTERVAL_SECONDS,
                timeout_seconds=10,
                auto_key=w.key,
            )
        )
    await db.commit()
    return len(new), len(gone)
