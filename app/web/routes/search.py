"""`/search` — the page behind the header's search box
(`app.services.global_search`). Any signed-in account may open it; what it
finds is limited to what that account can see anyway."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.db.models.user import User
from app.db.session import get_db
from app.services import global_search
from app.web.templating import templates

router = APIRouter(prefix="/search")


@router.get("")
async def search_page(
    request: Request,
    q: str = "",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    query = global_search.normalize(q)
    groups = await global_search.search(db, user, query)
    return templates.TemplateResponse(
        request,
        "search/index.html",
        {
            "query": query,
            "groups": groups,
            "too_short": bool(query) and len(query) < global_search.MIN_QUERY_LENGTH,
            "min_length": global_search.MIN_QUERY_LENGTH,
        },
    )
