"""Cross-Site WebSocket Hijacking (CSWSH) guard for the three cookie-
authenticated WebSockets (`terminal_ws.py`, `logs_ws.py`, `live_ws.py`).

A WebSocket handshake is not subject to CORS and never passes through
`app.core.csrf` (no form, no token), so the session cookie is the only
thing standing between a hostile page and a live shell on a managed
machine. `SameSite=Strict` on that cookie already stops a *cross-site*
page from riding it — but "site" is the registrable domain, so a page on
a sibling subdomain (`evil.example.com` next to `debcontrol.example.com`)
is same-site and would still get the cookie attached. Browsers always send
an `Origin` header on a WebSocket handshake and page scripts can't forge
it, so requiring it to name this very host closes that gap.

A handshake with no `Origin` at all is let through: that is never a
browser (so no ambient cookie to hijack), and such a client still needs a
valid session cookie of its own to get any further.

The comparison is against the request's own `Host` header — the same
assumption `app.auth.webauthn.rp_id_and_origin` already makes (a reverse
proxy must pass `Host` through unchanged; every proxy recipe in the wiki
does).
"""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def _normalize(host: str, port: int | None, scheme: str) -> tuple[str, int | None]:
    if port is None:
        port = _DEFAULT_PORTS.get(scheme)
    return host.lower(), port


def is_same_origin(headers: Mapping[str, str]) -> bool:
    """False only when an `Origin` header is present and names a different
    host/port than the handshake's own `Host` header."""
    origin = headers.get("origin")
    if origin is None:
        return True
    host_header = headers.get("host")
    if not host_header:
        return False
    try:
        origin_parts = urlsplit(origin)
        origin_host, origin_port = origin_parts.hostname, origin_parts.port
        scheme = origin_parts.scheme
        # `Host` carries no scheme; parse it the same way by borrowing the
        # Origin's, so a default port on either side compares equal.
        host_parts = urlsplit(f"{scheme}://{host_header}")
        request_host, request_port = host_parts.hostname, host_parts.port
    except ValueError:
        return False
    if not origin_host or not request_host:
        return False
    return _normalize(origin_host, origin_port, scheme) == _normalize(
        request_host, request_port, scheme
    )
