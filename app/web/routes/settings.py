"""Settings — currently read-only: the app's SSH identity and a couple of
configuration values. No user accounts to configure yet (no auth)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import get_db
from app.ssh.identity import get_or_create_identity
from app.web.templating import templates

router = APIRouter(prefix="/settings")


@router.get("")
async def show_settings(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    identity = await get_or_create_identity(db)
    return templates.TemplateResponse(
        request,
        "settings/index.html",
        {"identity": identity, "settings": get_settings()},
    )
