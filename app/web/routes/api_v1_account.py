"""REST API for the logged-in account's own self-service settings — the
API-token equivalent of `/account/...` in `app/web/routes/auth.py`.

Needs only a valid API token, no particular `Permission` — same as the web
routes it mirrors: a locale (or a display name) is data about a specific
account, not something an admin's role-permission matrix gates. Currently
just the UI language (`app.i18n`); other self-service actions
(display name, password, TOTP, sessions, API tokens themselves) stay
web-UI-only for now — see `api_v1.py`'s module docstring for the reasoning
that applies to those (mostly: a token creating/managing tokens, or
resetting the very password it might be authenticated by proxy of, is
circular or session-bound in a way this doesn't have a clean answer for
yet).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user
from app.db.models.user import User
from app.db.session import get_db
from app.i18n import Locale, available_locales, get_locale

router = APIRouter(prefix="/api/v1")


def _locale_to_dict(locale: Locale) -> dict[str, object]:
    return {"code": locale.code, "label": locale.label}


@router.get("/locales")
async def list_locales_api(
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    """Every UI language currently available — what `/account`'s "Language"
    picker offers, and what `POST /api/v1/account/locale` accepts. English
    first, then alphabetized by native label — see `app.i18n.
    available_locales`."""
    return [_locale_to_dict(locale) for locale in available_locales()]


@router.get("/account")
async def get_account_api(user: User = Depends(get_api_token_user)) -> dict[str, object]:
    return {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "locale": user.locale or "en",
    }


class _LocaleUpdate(BaseModel):
    locale: str = Field(min_length=1)


@router.post("/account/locale")
async def update_own_locale_api(
    request: Request,
    payload: _LocaleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    """The API equivalent of `POST /account/locale` — an unrecognized code
    is silently treated as "use the default" rather than rejected, same
    reasoning as the web route."""
    account = await db.get(User, user.id)
    assert account is not None
    resolved = get_locale(payload.locale)
    account.locale = resolved.code
    await db.commit()
    await log_event(
        db,
        request=request,
        action="user.account.update",
        summary=f'"{account.username}" changed their language to "{resolved.label}"',
        target_type="user",
        target_id=account.id,
        target_label=account.username,
    )
    return {"locale": resolved.code}
