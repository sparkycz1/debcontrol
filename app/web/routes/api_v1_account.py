"""REST API for the logged-in account's own self-service settings — the
API-token equivalent of `/account/...` in `app/web/routes/auth.py`.

Needs only a valid API token, no particular `Permission` — same as the web
routes it mirrors: a locale, a saved machine-list view, or a display name
is data about a specific account, not something an admin's role-permission
matrix gates. Covers the UI language (`app.i18n`) and saved machine-list
views (`app.services.saved_views`); other self-service actions (display
name, password, TOTP, WebAuthn/passkeys, sessions, API tokens themselves)
stay web-UI-only for now — see `api_v1.py`'s module docstring for the
reasoning that applies to those (mostly: a token creating/managing
tokens, or resetting the very password it might be authenticated by
proxy of, is circular or session-bound in a way this doesn't have a
clean answer for yet). WebAuthn/passkeys specifically also needs a live
browser ceremony (`navigator.credentials.create()`/`.get()`) that has no
meaningful shape as a token-authenticated API call at all — there's no
"submit this JSON" equivalent a script could do instead, same reasoning
`api_v1.py` excludes the interactive SSH terminal for.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user
from app.db.models.saved_audit_view import SavedAuditView
from app.db.models.saved_machine_view import SavedMachineView
from app.db.models.user import User
from app.db.session import get_db
from app.i18n import Locale, available_locales, get_locale
from app.services.saved_audit_views import (
    DuplicateViewNameError as DuplicateAuditViewNameError,
)
from app.services.saved_audit_views import (
    build_query_string as build_audit_query_string,
)
from app.services.saved_audit_views import (
    create_saved_view as create_saved_audit_view,
)
from app.services.saved_audit_views import (
    delete_saved_view as delete_saved_audit_view,
)
from app.services.saved_audit_views import (
    list_saved_views as list_saved_audit_views,
)
from app.services.saved_views import (
    DuplicateViewNameError,
    build_query_string,
    create_saved_view,
    delete_saved_view,
    list_saved_views,
)

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


def _saved_view_to_dict(view: SavedMachineView) -> dict[str, object]:
    return {
        "id": str(view.id),
        "name": view.name,
        "query_string": view.query_string,
        "created_at": view.created_at.isoformat(),
    }


@router.get("/account/saved-views")
async def list_saved_views_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    """The API equivalent of the machine list's "Saved views" chips — see
    `app.services.saved_views`. Per-account: this only ever lists the
    token owner's own."""
    views = await list_saved_views(db, user.id)
    return [_saved_view_to_dict(v) for v in views]


class _SavedViewCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    # Deliberately structured filters, not an arbitrary querystring — see
    # app.db.models.saved_machine_view's module docstring.
    q: str = ""
    # A single string is still accepted (and normalized to a one-item
    # list) for backward compatibility with callers built against the
    # pre-multi-tag API, which only ever sent one.
    tag: str | list[str] = Field(default_factory=list)
    tag_mode: str = "or"

    @field_validator("tag")
    @classmethod
    def _tag_as_list(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            return [value] if value else []
        return list(value)


@router.post("/account/saved-views", status_code=status.HTTP_201_CREATED)
async def create_saved_view_api(
    request: Request,
    payload: _SavedViewCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    query_string = build_query_string(
        {"q": payload.q, "tag": payload.tag, "tag_mode": payload.tag_mode}
    )
    try:
        view = await create_saved_view(db, user.id, payload.name, query_string)
    except DuplicateViewNameError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'A saved view named "{payload.name}" already exists.',
        ) from None
    await log_event(
        db,
        request=request,
        action="user.saved_view.create",
        summary=f'"{user.username}" saved a machine-list view ("{view.name}")',
        target_type="saved_machine_view",
        target_id=view.id,
        target_label=view.name,
    )
    return _saved_view_to_dict(view)


@router.delete("/account/saved-views/{view_id}")
async def delete_saved_view_api(
    request: Request,
    view_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    deleted = await delete_saved_view(db, user.id, view_id)
    if deleted:
        await log_event(
            db,
            request=request,
            action="user.saved_view.delete",
            summary=f'"{user.username}" deleted a saved machine-list view',
            target_type="saved_machine_view",
            target_id=view_id,
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _saved_audit_view_to_dict(view: SavedAuditView) -> dict[str, object]:
    return {
        "id": str(view.id),
        "name": view.name,
        "query_string": view.query_string,
        "created_at": view.created_at.isoformat(),
    }


@router.get("/account/saved-audit-views")
async def list_saved_audit_views_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, object]]:
    """The API equivalent of the Audit log's "Saved views" chips — see
    `app.services.saved_audit_views`. Per-account: this only ever lists
    the token owner's own."""
    views = await list_saved_audit_views(db, user.id)
    return [_saved_audit_view_to_dict(v) for v in views]


class _SavedAuditViewCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    q: str = ""
    outcome: str = ""
    target_type: str = ""
    target_id: str = ""


@router.post("/account/saved-audit-views", status_code=status.HTTP_201_CREATED)
async def create_saved_audit_view_api(
    request: Request,
    payload: _SavedAuditViewCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    query_string = build_audit_query_string(
        {
            "q": payload.q,
            "outcome": payload.outcome,
            "target_type": payload.target_type,
            "target_id": payload.target_id,
        }
    )
    try:
        view = await create_saved_audit_view(db, user.id, payload.name, query_string)
    except DuplicateAuditViewNameError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f'A saved view named "{payload.name}" already exists.',
        ) from None
    await log_event(
        db,
        request=request,
        action="user.saved_audit_view.create",
        summary=f'"{user.username}" saved an audit log view ("{view.name}")',
        target_type="saved_audit_view",
        target_id=view.id,
        target_label=view.name,
    )
    return _saved_audit_view_to_dict(view)


@router.delete("/account/saved-audit-views/{view_id}")
async def delete_saved_audit_view_api(
    request: Request,
    view_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    deleted = await delete_saved_audit_view(db, user.id, view_id)
    if deleted:
        await log_event(
            db,
            request=request,
            action="user.saved_audit_view.delete",
            summary=f'"{user.username}" deleted a saved audit log view',
            target_type="saved_audit_view",
            target_id=view_id,
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
