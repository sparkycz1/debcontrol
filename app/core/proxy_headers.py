"""Trust `X-Forwarded-Proto` (always, from a trusted peer) and, opt-in only,
`X-Forwarded-For` — two independent corrections a reverse proxy in front of
this app needs, with two very different risk profiles, which is why only
one of them defaults to on.

**Scheme** (`X-Forwarded-Proto`) — always corrected for a trusted peer.
A TLS-terminating reverse proxy (the bundled Caddy, or any other, on this
host or a different one entirely) forwards to this app in plain HTTP, so
the ASGI server never sees the TLS the browser actually used:
`request.url.scheme` is always "http", `request.url_for(...)` builds
`http://` URLs, no matter what the browser's address bar says. Two real
consequences, both bugs this fixes:

- **WebAuthn/passkeys** (`app.auth.webauthn.rp_id_and_origin`) compares its
  own idea of the origin against the exact origin the browser signed into
  `clientDataJSON`. A scheme mismatch fails every ceremony with "Unexpected
  client data origin".
- **OIDC login** (`request.url_for("oidc_callback")` in
  `app/web/routes/auth.py`) builds the `redirect_uri` sent to the
  provider — a scheme mismatch means it no longer matches what's
  registered, and the provider rejects the whole login attempt.

Trusting a forged scheme from an untrusted direct client is not a
privilege-escalation risk despite being a "trust boundary" nominally: the
only things built from it are checked against something the attacker
cannot forge (a browser-signed WebAuthn origin, an OIDC provider's
pre-registered `redirect_uri`) — a forged scheme can only make those
checks *fail*, the same as a real misconfiguration would, never succeed
for anything it shouldn't. Governed by `Settings.trusted_proxy_ips`
(default `"*"` — safe for exactly this reason).

**Client IP** (`X-Forwarded-For`) — opt-in, `Settings.trust_forwarded_for`,
default off. Without correcting it, `request.client.host` (used for the
audit log's `ip_address` column and the login/TOTP rate limiter's
per-source bucket key — `app/auth/rate_limit.py`) is the proxy's own IP
for every request once one sits in front of this app, not the real
client's. Unlike scheme, this one *is* a real risk to default on: the
rate limiter's whole point is capping attempts *per source*, and a
client that can set an arbitrary `X-Forwarded-For` on each request (true
of anyone reaching this app directly, bypassing the real proxy, e.g. if
its port is also exposed) could make every brute-force attempt look
like a different source and defeat it entirely. So this only takes
effect when explicitly turned on — and turning it on is only actually
safe once `TRUSTED_PROXY_IPS` is narrowed to your real proxy's own
address rather than left at the default `"*"`, which this module can't
enforce for you. See `Settings.trust_forwarded_for`'s own docstring.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable
from typing import Any

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[Any]]
Send = Callable[[Any], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_WS_SCHEME_FOR = {"http": "ws", "https": "wss"}


def _first_forwarded_value(scope: Scope, header_name: bytes) -> str | None:
    """The leftmost entry of a comma-separated `X-Forwarded-*` header —
    for both `-Proto` and `-For`, that's the value the *original* client
    supplied (each hop *appends* its own after it), so this is correct
    whether there's one proxy in front of this app or a short chain of
    them."""
    for key, value in scope.get("headers", ()):
        if key == header_name:
            decoded: str = bytes(value).decode("latin-1")
            return decoded.split(",")[0].strip()
    return None


class ProxyHeadersMiddleware:
    """Pure ASGI middleware (not `@app.middleware("http")`, which never
    sees `scope["type"] == "websocket"` — see `app.auth.middleware`'s own
    docstring for that same distinction) so this applies uniformly to both
    an ordinary request and the terminal/live-updates WebSocket upgrades."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        trust_all: bool,
        trusted_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
        trust_forwarded_for: bool,
    ) -> None:
        self.app = app
        self.trust_all = trust_all
        self.trusted_networks = trusted_networks
        self.trust_forwarded_for = trust_forwarded_for

    def _is_trusted(self, scope: Scope) -> bool:
        if self.trust_all:
            return True
        client = scope.get("client")
        if not client:
            return False
        try:
            peer = ipaddress.ip_address(client[0])
        except ValueError:
            return False
        return any(peer in network for network in self.trusted_networks)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket") or not self._is_trusted(scope):
            await self.app(scope, receive, send)
            return

        forwarded_proto = _first_forwarded_value(scope, b"x-forwarded-proto")
        if forwarded_proto is not None:
            forwarded_proto = forwarded_proto.lower()
        if scope["type"] == "http" and forwarded_proto in ("http", "https"):
            scope["scheme"] = forwarded_proto
        elif scope["type"] == "websocket" and forwarded_proto in _WS_SCHEME_FOR:
            scope["scheme"] = _WS_SCHEME_FOR[forwarded_proto]

        if self.trust_forwarded_for:
            forwarded_for = _first_forwarded_value(scope, b"x-forwarded-for")
            if forwarded_for:
                try:
                    ipaddress.ip_address(forwarded_for)
                except ValueError:
                    pass
                else:
                    original_client = scope.get("client")
                    port = original_client[1] if original_client else 0
                    scope["client"] = (forwarded_for, port)

        await self.app(scope, receive, send)
