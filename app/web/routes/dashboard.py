"""Úvodní stránka."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.session import get_db
from app.web.templating import templates

router = APIRouter()


@router.get("/")
async def index(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    machine_count = await db.scalar(select(func.count()).select_from(Machine))
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"machine_count": machine_count or 0},
    )
