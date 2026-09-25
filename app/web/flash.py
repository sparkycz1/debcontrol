"""Signed one-line messages carried across a POST → redirect → GET in the
redirect's query string (`?bulk_error=<token>`), for the handful of routes
that report an outcome that way instead of re-rendering the form.

Signed rather than plain text so the message a page shows is always one
this app itself put there: an unsigned `?bulk_error=...` would render
whatever text a crafted link carried, inside a trusted admin page
("Your session expired — re-enter your password at ..."). A tampered or
foreign value just shows nothing. Messages are already translated when
signed (the redirecting request's locale — the same account that follows
the redirect).

Not a session-backed flash store on purpose: nothing server-side to clean
up, and the message survives a reload the same way the old plain query
parameter did.
"""

from __future__ import annotations

from fastapi import Request
from itsdangerous import BadSignature, URLSafeSerializer

from app.core.config import get_settings

_SALT = "debcontrol.flash-message"
# Long docker/SSH error output is cut here, before signing — a query string
# isn't the place for a whole stack trace.
MAX_MESSAGE_LENGTH = 300


def _serializer() -> URLSafeSerializer:
    return URLSafeSerializer(get_settings().secret_key.get_secret_value(), salt=_SALT)


def sign_flash(message: str) -> str:
    """The query-string value for `message`; `read_flash` turns it back. A
    `app.web.messages.LocalizedText` is signed in the viewer's language."""
    text = str(getattr(message, "localized", message))
    return _serializer().dumps(text[:MAX_MESSAGE_LENGTH])


def read_flash(request: Request, param: str) -> str | None:
    """The message signed into `?<param>=`, or `None` if it's missing or
    wasn't signed by this app."""
    raw = request.query_params.get(param)
    if not raw:
        return None
    try:
        value = _serializer().loads(raw)
    except BadSignature:
        return None
    return value if isinstance(value, str) else None
