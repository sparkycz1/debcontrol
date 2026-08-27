"""Settings — placeholder. Nothing user-configurable exists yet (no auth)."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from app.web.templating import templates

router = APIRouter(prefix="/settings")


@router.get("")
async def show_settings(request: Request) -> Response:
    return templates.TemplateResponse(request, "coming_soon.html", {"feature": "Settings"})
