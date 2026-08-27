"""Users — placeholder. There is no login/authentication yet (see README)."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from app.web.templating import templates

router = APIRouter(prefix="/users")


@router.get("")
async def list_users(request: Request) -> Response:
    return templates.TemplateResponse(request, "coming_soon.html", {"feature": "Users"})
