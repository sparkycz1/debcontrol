"""`app.web.messages.LocalizedText` — English as a plain string (audit log
details), the viewer's language when rendered in a template."""

from __future__ import annotations

import json
from types import SimpleNamespace

from markupsafe import escape

from app.i18n import get_locale
from app.web.messages import LocalizedText


def _request(locale_code: str) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(locale=get_locale(locale_code)))


def test_is_english_as_a_string_and_localized_when_rendered() -> None:
    message = LocalizedText(_request("cs"), "common.error.job_timeout")  # type: ignore[arg-type]

    assert message == "The background job did not respond in time."
    assert json.dumps({"error": message}) == (
        '{"error": "The background job did not respond in time."}'
    )
    assert str(escape(message)) == "Úloha na pozadí neodpověděla včas."


def test_rendering_escapes_the_localized_text() -> None:
    message = LocalizedText(_request("en"), "users.error.username_taken", username="<b>")  # type: ignore[arg-type]
    assert "&lt;b&gt;" in str(escape(message))
