"""The sign-in policy set on Settings -> Security: session lifetime, the
failed-attempt lockout, and which networks may reach the app at all.

The session lifetime and the network allowlist are consulted on every
authenticated request (`app.auth.middleware`), so the policy is cached in
process for a few seconds instead of costing an extra `app_settings`
query per request. A save on the Settings page (or `PATCH
/api/v1/settings`) calls `invalidate()` so the process that handled it
applies the change at once; other worker processes pick it up within
`_CACHE_TTL_SECONDS`.
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.websockets import WebSocket

from app.core.app_settings import get_or_create_app_settings

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_CACHE_TTL_SECONDS = 10.0

# Same values the migration seeds (and the constants these replaced).
DEFAULT_IDLE_TIMEOUT = timedelta(minutes=720)
DEFAULT_ABSOLUTE_MAX = timedelta(hours=720)


@dataclass(frozen=True)
class SignInPolicy:
    idle_timeout: timedelta = DEFAULT_IDLE_TIMEOUT
    absolute_max: timedelta = DEFAULT_ABSOLUTE_MAX
    max_failed_attempts: int = 5
    lockout_duration: timedelta = timedelta(minutes=15)
    # Empty = requests from anywhere are accepted.
    allowed_networks: tuple[IPNetwork, ...] = field(default_factory=tuple)

    def allows_ip(self, ip: str | None) -> bool:
        return ip_allowed(ip, self.allowed_networks)


_cached: tuple[float, SignInPolicy] | None = None


def parse_networks(raw: str | None) -> tuple[tuple[IPNetwork, ...], list[str]]:
    """Pure: `raw` (IPs/CIDRs separated by newlines, commas or spaces) into
    networks, plus every entry that isn't one. A bare address becomes a
    single-host network; host bits in a CIDR are tolerated
    (`192.168.1.10/24` means `192.168.1.0/24`)."""
    networks: list[IPNetwork] = []
    invalid: list[str] = []
    for entry in re.split(r"[\s,]+", raw or ""):
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            invalid.append(entry)
    return tuple(networks), invalid


def ip_allowed(ip: str | None, networks: tuple[IPNetwork, ...]) -> bool:
    """Pure: an empty allowlist admits everyone; otherwise the address must
    fall in one of the networks (an unknown/unparsable address never
    does)."""
    if not networks:
        return True
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(address in network for network in networks)


async def load_policy(db: AsyncSession) -> SignInPolicy:
    global _cached
    now = time.monotonic()
    if _cached is not None and now - _cached[0] < _CACHE_TTL_SECONDS:
        return _cached[1]
    app_settings = await get_or_create_app_settings(db)
    networks, _invalid = parse_networks(app_settings.login_allowed_networks)
    policy = SignInPolicy(
        idle_timeout=timedelta(minutes=app_settings.session_idle_timeout_minutes),
        absolute_max=timedelta(hours=app_settings.session_absolute_max_hours),
        max_failed_attempts=app_settings.login_max_failed_attempts,
        lockout_duration=timedelta(minutes=app_settings.login_lockout_minutes),
        allowed_networks=networks,
    )
    _cached = (now, policy)
    return policy


def fresh_cached_policy() -> SignInPolicy | None:
    """The cached policy if it's still within its TTL — lets the middleware
    skip opening a database session at all on the common path."""
    if _cached is not None and time.monotonic() - _cached[0] < _CACHE_TTL_SECONDS:
        return _cached[1]
    return None


def last_known_policy() -> SignInPolicy:
    """The most recently loaded policy (defaults if none yet) — for the
    synchronous cookie helper, which always runs right after a
    `load_policy` in the same request."""
    return _cached[1] if _cached is not None else SignInPolicy()


async def websocket_network_allowed(websocket: WebSocket) -> bool:
    """The network allowlist for a WebSocket handshake — `app.auth.
    middleware` never runs for those (see terminal_ws.py's docstring), so
    each socket handler calls this next to its own session check."""
    policy = fresh_cached_policy()
    if policy is None:
        async with websocket.app.state.db_session_factory() as db:
            policy = await load_policy(db)
    client = getattr(websocket, "client", None)
    return policy.allows_ip(client.host if client else None)


def invalidate() -> None:
    global _cached
    _cached = None
