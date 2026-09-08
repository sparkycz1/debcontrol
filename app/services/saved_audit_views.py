"""Per-account saved filters on the Audit log — see
`app.db.models.saved_audit_view`'s module docstring for the data model.
Same shape as `app.services.saved_views` (the Machines-list equivalent),
duplicated rather than shared since the two domains capture different,
fixed sets of filter parameters — see that module's own docstring for why
that's a deliberate choice, not an oversight.
"""

from __future__ import annotations

import uuid
from urllib.parse import urlencode

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.saved_audit_view import SavedAuditView

# The only query parameters a saved audit view may capture — mirrors
# `/audit`'s own filter fields exactly (see `app.web.routes.audit.
# list_audit_log`). Deny-by-default, same reasoning as
# `app.services.saved_views.ALLOWED_VIEW_PARAMS`: a saved view replays a
# *filter*, never an arbitrary querystring.
ALLOWED_VIEW_PARAMS = ("q", "outcome", "target_type", "target_id")

MAX_VIEW_NAME_LENGTH = 100


class DuplicateViewNameError(Exception):
    """Raised when this account already has a saved audit view with that
    name."""


def build_query_string(params: dict[str, str]) -> str:
    """`{"q": "reboot", "outcome": "failure"}` -> `"q=reboot&outcome=failure"`
    — only the recognized filter keys, in `ALLOWED_VIEW_PARAMS` order,
    blanks dropped. Empty when every filter is blank (a saved "no filter"
    view — legitimate, e.g. "everything, newest first")."""
    ordered: dict[str, str] = {}
    for key in ALLOWED_VIEW_PARAMS:
        value = params.get(key, "")
        if value.strip():
            ordered[key] = value
    return urlencode(ordered)


async def list_saved_views(db: AsyncSession, user_id: uuid.UUID) -> list[SavedAuditView]:
    result = await db.execute(
        select(SavedAuditView)
        .where(SavedAuditView.user_id == user_id)
        .order_by(SavedAuditView.name)
    )
    return list(result.scalars().all())


async def create_saved_view(
    db: AsyncSession, user_id: uuid.UUID, name: str, query_string: str
) -> SavedAuditView:
    """Raises `DuplicateViewNameError` if this account already has a view
    with that name — the unique constraint is the actual guarantee; this
    just turns the resulting `IntegrityError` into something callers can
    catch by type instead of sniffing a database error message."""
    view = SavedAuditView(
        user_id=user_id, name=name.strip()[:MAX_VIEW_NAME_LENGTH], query_string=query_string
    )
    db.add(view)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise DuplicateViewNameError(name) from None
    await db.refresh(view)
    return view


async def delete_saved_view(db: AsyncSession, user_id: uuid.UUID, view_id: uuid.UUID) -> bool:
    """`True` if a view was actually deleted — scoped to `user_id`, so one
    account can never delete another's."""
    result = await db.execute(
        select(SavedAuditView).where(
            SavedAuditView.id == view_id, SavedAuditView.user_id == user_id
        )
    )
    view = result.scalar_one_or_none()
    if view is None:
        return False
    await db.delete(view)
    await db.commit()
    return True
