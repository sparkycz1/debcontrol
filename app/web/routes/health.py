"""The fleet's health in one place (nav: **Health**, `machine.view`): the
health score, how many machines are in each state, every machine with a
problem and its problems, and every snoozed problem — see
`app.services.machine_health`. Snoozing and clearing go through the
machine's own routes (`/machines/{id}/health/snooze`, `.../unsnooze`,
`machine.manage`), back to this page. Scoped to the machines the account
can see."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, require_permission
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import machine_health
from app.services.access_scope import allowed_group_ids
from app.web.templating import templates

router = APIRouter(dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))])


@router.get("/health")
async def fleet_health_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    scope = await allowed_group_ids(db, current_user)
    return templates.TemplateResponse(
        request,
        "health/index.html",
        {
            "fleet": await machine_health.fleet_health(db, scope),
            "machines": await machine_health.worst_machines(db, scope, limit=0),
            "snoozes": await machine_health.all_snoozes(db, scope),
            "snooze_choices": machine_health.SNOOZE_CHOICES,
            "can_manage": current_user.has_permission(Permission.MACHINE_MANAGE),
        },
    )
