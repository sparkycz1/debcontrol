"""`GET /api/v1/search?q=` — the header search box as JSON
(`app.services.global_search`): the same kinds, the same per-kind
access rules as the web page. Shared word for word with the sister app —
see `shared-ui.json`."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_api_token_user
from app.db.models.user import User
from app.db.session import get_db
from app.services import global_search

router = APIRouter(prefix="/api/v1/search", tags=["search"])


@router.get("")
async def search_api(
    q: str = Query(
        min_length=global_search.MIN_QUERY_LENGTH, max_length=global_search.MAX_QUERY_LENGTH
    ),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, object]:
    groups = await global_search.search(db, user, q)
    return {
        "query": global_search.normalize(q),
        "results": [
            {
                "kind": group.kind,
                "has_more": group.has_more,
                "hits": [
                    {"label": hit.label, "detail": hit.detail, "href": hit.href}
                    for hit in group.hits
                ],
            }
            for group in groups
        ],
    }
