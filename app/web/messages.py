"""`LocalizedText` — one message, two audiences.

A route like "Refresh facts" puts the same `error` string in two places:
the page it renders (read by whoever clicked, in *their* language) and the
audit log entry's `details` (a curated, grep-able trail that stays
English regardless of who triggered it — see `app.audit`). A plain
`t(request, ...)` string would leak the clicker's language into the audit
log; a plain English literal would leave the page untranslated.

`LocalizedText` is a `str` whose value is the English text — so JSON
serialization, `log_event(details=...)`, logging and `==` comparisons all
see English — but which renders in the request's language inside a
template: Jinja's autoescaping calls `__html__` on any object that has
one, before falling back to `str()`.
"""

from __future__ import annotations

from fastapi import Request
from markupsafe import escape

from app.i18n import DEFAULT_LOCALE_CODE, get_locale, translate
from app.web.templating import t


class LocalizedText(str):
    _localized: str

    def __new__(cls, request: Request, key: str, **kwargs: object) -> LocalizedText:
        english = translate(get_locale(DEFAULT_LOCALE_CODE), key, **kwargs)
        obj = super().__new__(cls, english)
        obj._localized = t(request, key, **kwargs)
        return obj

    @property
    def localized(self) -> str:
        return self._localized

    def __html__(self) -> str:
        return str(escape(self._localized))
