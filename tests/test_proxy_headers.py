"""`app.core.proxy_headers.ProxyHeadersMiddleware` — trusts
`X-Forwarded-Proto` from a reverse proxy to correct the scheme Starlette
sees, fixing WebAuthn's origin check and OIDC's redirect_uri (see that
module's own docstring for the full story). Pure ASGI, tested directly
against a fake scope/receive/send rather than through the full app."""

from __future__ import annotations

import ipaddress
from typing import Any

from app.core.proxy_headers import ProxyHeadersMiddleware


async def _noop_receive() -> dict[str, Any]:
    return {"type": "http.disconnect"}


class _RecordingSend:
    def __init__(self) -> None:
        self.messages: list[Any] = []

    async def __call__(self, message: Any) -> None:
        self.messages.append(message)


def _make_middleware(
    *,
    trust_all: bool = True,
    trusted_networks: list[Any] | None = None,
    trust_forwarded_for: bool = False,
) -> tuple[ProxyHeadersMiddleware, dict[str, Any]]:
    seen_scope: dict[str, Any] = {}

    async def inner_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        seen_scope.update(scope)

    middleware = ProxyHeadersMiddleware(
        inner_app,
        trust_all=trust_all,
        trusted_networks=trusted_networks or [],
        trust_forwarded_for=trust_forwarded_for,
    )
    return middleware, seen_scope


def _scope(
    scope_type: str = "http",
    *,
    client: tuple[str, int] | None = ("10.0.0.5", 54321),
    proto: str | None = "https",
) -> dict[str, Any]:
    headers = [(b"x-forwarded-proto", proto.encode())] if proto else []
    return {
        "type": scope_type,
        "scheme": "http" if scope_type == "http" else "ws",
        "headers": headers,
        "client": client,
    }


async def test_trust_all_rewrites_http_scheme_from_forwarded_proto() -> None:
    middleware, seen = _make_middleware(trust_all=True)
    await middleware(_scope("http", proto="https"), _noop_receive, _RecordingSend())
    assert seen["scheme"] == "https"


async def test_trust_all_rewrites_websocket_scheme_to_wss() -> None:
    middleware, seen = _make_middleware(trust_all=True)
    await middleware(_scope("websocket", proto="https"), _noop_receive, _RecordingSend())
    assert seen["scheme"] == "wss"


async def test_no_forwarded_proto_header_leaves_scheme_untouched() -> None:
    middleware, seen = _make_middleware(trust_all=True)
    await middleware(_scope("http", proto=None), _noop_receive, _RecordingSend())
    assert seen["scheme"] == "http"


async def test_untrusted_client_is_not_rewritten() -> None:
    middleware, seen = _make_middleware(
        trust_all=False, trusted_networks=[ipaddress.ip_network("172.20.0.0/16")]
    )
    await middleware(
        _scope("http", client=("203.0.113.9", 1234), proto="https"), _noop_receive, _RecordingSend()
    )
    assert seen["scheme"] == "http"


async def test_client_inside_trusted_network_is_rewritten() -> None:
    middleware, seen = _make_middleware(
        trust_all=False, trusted_networks=[ipaddress.ip_network("172.20.0.0/16")]
    )
    await middleware(
        _scope("http", client=("172.20.0.3", 1234), proto="https"), _noop_receive, _RecordingSend()
    )
    assert seen["scheme"] == "https"


async def test_a_comma_separated_forwarded_chain_uses_the_first_entry() -> None:
    middleware, seen = _make_middleware(trust_all=True)
    scope = _scope("http", proto=None)
    scope["headers"] = [(b"x-forwarded-proto", b"https, http")]
    await middleware(scope, _noop_receive, _RecordingSend())
    assert seen["scheme"] == "https"


async def test_non_http_websocket_scope_types_are_passed_through_unchanged() -> None:
    middleware, seen = _make_middleware(trust_all=True)
    await middleware({"type": "lifespan"}, _noop_receive, _RecordingSend())
    assert seen == {"type": "lifespan"}


async def test_a_bogus_client_ip_is_treated_as_untrusted_not_a_crash() -> None:
    middleware, seen = _make_middleware(
        trust_all=False, trusted_networks=[ipaddress.ip_network("172.20.0.0/16")]
    )
    scope = _scope("http", proto="https")
    scope["client"] = ("not-an-ip", 1234)
    await middleware(scope, _noop_receive, _RecordingSend())
    assert seen["scheme"] == "http"


async def test_forwarded_for_is_ignored_by_default_even_from_a_trusted_peer() -> None:
    middleware, seen = _make_middleware(trust_all=True, trust_forwarded_for=False)
    scope = _scope("http", proto=None)
    scope["headers"] = [(b"x-forwarded-for", b"203.0.113.9")]
    await middleware(scope, _noop_receive, _RecordingSend())
    assert seen["client"] == ("10.0.0.5", 54321)


async def test_forwarded_for_rewrites_client_when_enabled_and_trusted() -> None:
    middleware, seen = _make_middleware(trust_all=True, trust_forwarded_for=True)
    scope = _scope("http", proto=None)
    scope["headers"] = [(b"x-forwarded-for", b"203.0.113.9")]
    await middleware(scope, _noop_receive, _RecordingSend())
    assert seen["client"] == ("203.0.113.9", 54321)


async def test_forwarded_for_uses_the_leftmost_entry_of_a_chain() -> None:
    middleware, seen = _make_middleware(trust_all=True, trust_forwarded_for=True)
    scope = _scope("http", proto=None)
    scope["headers"] = [(b"x-forwarded-for", b"203.0.113.9, 172.20.0.4")]
    await middleware(scope, _noop_receive, _RecordingSend())
    assert seen["client"] == ("203.0.113.9", 54321)


async def test_forwarded_for_is_not_applied_from_an_untrusted_peer_even_when_enabled() -> None:
    middleware, seen = _make_middleware(
        trust_all=False,
        trusted_networks=[ipaddress.ip_network("172.20.0.0/16")],
        trust_forwarded_for=True,
    )
    scope = _scope("http", client=("203.0.113.9", 1234), proto=None)
    scope["headers"] = [(b"x-forwarded-for", b"198.51.100.1")]
    await middleware(scope, _noop_receive, _RecordingSend())
    assert seen["client"] == ("203.0.113.9", 1234)


async def test_a_bogus_forwarded_for_value_leaves_client_untouched() -> None:
    middleware, seen = _make_middleware(trust_all=True, trust_forwarded_for=True)
    scope = _scope("http", proto=None)
    scope["headers"] = [(b"x-forwarded-for", b"not-an-ip")]
    await middleware(scope, _noop_receive, _RecordingSend())
    assert seen["client"] == ("10.0.0.5", 54321)
