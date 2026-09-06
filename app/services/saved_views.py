"""Per-account saved filters on the machine list — see
`app.db.models.saved_machine_view`'s module docstring for the data model.
Shared between the web routes (`app/web/routes/machines.py`) and the REST
API (`app/web/routes/api_v1_account.py`), same "one service function, two
doors" convention as `app.services.machine_actions`.
"""

from __future__ import annotations

import uuid
from urllib.parse import urlencode

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.saved_machine_view import SavedMachineView

# The only query parameters a saved view may capture — the machine list's
# actual filters, in a fixed, stable order so two views built from the
# same filters always produce byte-identical query_string values. Deny-
# by-default rather than "whatever was on the URL": a saved view replays a
# *filter*, not an arbitrary querystring (see the model's own docstring).
# `tag` is repeatable (a view can capture more than one tag); everything
# else is single-valued.
ALLOWED_VIEW_PARAMS = ("q", "tag", "tag_mode")
_MULTI_VALUED_PARAMS = frozenset({"tag"})

MAX_VIEW_NAME_LENGTH = 100


class DuplicateViewNameError(Exception):
    """Raised when this account already has a saved view with that name."""


def build_query_string(params: dict[str, str | list[str]]) -> str:
    """`{"q": "web", "tag": ["prod", "web"], "tag_mode": "and"}` ->
    `"q=web&tag=prod&tag=web&tag_mode=and"` — only the recognized filter
    keys, in `ALLOWED_VIEW_PARAMS` order, blanks/empty lists dropped.
    Empty when every filter is blank (a saved "no filter" view —
    legitimate, e.g. "everything, sorted the way I like"). `tag_mode` is
    dropped whenever it wouldn't change anything — its own default
    (`"or"`), or fewer than two tags to have a mode between at all — so a
    single-tag view's query string looks exactly like it did before
    `tag_mode` existed.
    """
    ordered: dict[str, str | list[str]] = {}
    for key in ALLOWED_VIEW_PARAMS:
        value = params.get(key, "" if key not in _MULTI_VALUED_PARAMS else [])
        if isinstance(value, list):
            cleaned = [v for v in value if v.strip()]
            if cleaned:
                ordered[key] = cleaned
        elif value.strip():
            if key == "tag_mode" and (value != "and" or len(ordered.get("tag", [])) < 2):
                continue
            ordered[key] = value
    return urlencode(ordered, doseq=True)


async def list_saved_views(db: AsyncSession, user_id: uuid.UUID) -> list[SavedMachineView]:
    result = await db.execute(
        select(SavedMachineView)
        .where(SavedMachineView.user_id == user_id)
        .order_by(SavedMachineView.name)
    )
    return list(result.scalars().all())


async def create_saved_view(
    db: AsyncSession, user_id: uuid.UUID, name: str, query_string: str
) -> SavedMachineView:
    """Raises `DuplicateViewNameError` if this account already has a view
    with that name — the unique constraint is the actual guarantee; this
    just turns the resulting `IntegrityError` into something callers can
    catch by type instead of sniffing a database error message."""
    view = SavedMachineView(
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
    account can never delete another's, the same "not found, not
    forbidden" treatment `_get_machine_or_404` gives an out-of-scope id."""
    result = await db.execute(
        select(SavedMachineView).where(
            SavedMachineView.id == view_id, SavedMachineView.user_id == user_id
        )
    )
    view = result.scalar_one_or_none()
    if view is None:
        return False
    await db.delete(view)
    await db.commit()
    return True
