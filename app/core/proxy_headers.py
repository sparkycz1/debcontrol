"""Trust `X-Forwarded-Proto` from a reverse proxy to correct the *scheme*
Starlette sees for a request — nothing else needs correcting, since a
reverse proxy passes the original `Host` header through untouched by
default, and this app never runs behind one that rewrites it.

Why this matters: a TLS-terminating reverse proxy (the bundled Caddy, or
any other) forwards to this app in plain HTTP over the Docker network (or,
for a proxy on a different host entirely, over whatever plain-HTTP
connection reaches this app's published port) — the ASGI server never sees
the TLS the browser actually used, so `request.url.scheme` is always
"http", `request.url_for(...)` builds `http://` URLs, and `Request.url` is
"http" too, no matter what the browser's address bar says. Two real
consequences, both bugs this middleware fixes:

- **WebAuthn/passkeys** (`app.auth.webauthn.rp_id_and_origin`) compares its
  own idea of the origin against the exact origin the browser signed into
  `clientDataJSON`. If the app thinks it's "http://x" while the browser
  (correctly) says "https://x", every ceremony fails with "Unexpected
  client data origin" — exactly what happens without this fix.
- **OIDC login** (`request.url_for("oidc_callback")` in
  `app/web/routes/auth.py`) builds the `redirect_uri` sent to the
  provider — a scheme mismatch there means it no longer matches what's
  registered with the provider, and the provider rejects the whole login
  attempt.

Trusting a forged `X-Forwarded-Proto` from an untrusted direct client
(rather than a real proxy) is not a privilege-escalation risk despite
being a "trust boundary" nominally: the only things built from the
corrected scheme are values that get checked against something the
attacker cannot forge (a browser-signed WebAuthn origin, an OIDC
provider's pre-registered `redirect_uri`) — a forged scheme can only make
those checks *fail*, the same as a real proxy misconfiguration would, not
succeed for anything it shouldn't. See `Settings.trusted_proxy_ips`'s own
docstring for the default and how to narrow it.
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
    ) -> None:
        self.app = app
        self.trust_all = trust_all
        self.trusted_networks = trusted_networks

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

        forwarded_proto = None
        for key, value in scope.get("headers", ()):
            if key == b"x-forwarded-proto":
                # A comma-separated chain (multiple proxies) — the first
                # entry is the one the original client actually used.
                forwarded_proto = value.decode("latin-1").split(",")[0].strip().lower()
                break

        if scope["type"] == "http" and forwarded_proto in ("http", "https"):
            scope["scheme"] = forwarded_proto
        elif scope["type"] == "websocket" and forwarded_proto in _WS_SCHEME_FOR:
            scope["scheme"] = _WS_SCHEME_FOR[forwarded_proto]

        await self.app(scope, receive, send)
