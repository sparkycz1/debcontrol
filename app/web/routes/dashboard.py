"""The post-login landing page: a read-only overview aggregated from the
areas the current user has permission to see. No `Permission` gate at the
router level (unlike every other page) — anyone with a valid session gets
*a* dashboard, just with fewer sections, mirroring how `base.html`'s nav
already hides links a role can't use.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.db.models.audit_log import AuditLogEntry, AuditOutcome
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.pending_machine import PendingMachine
from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.user import User
from app.db.session import get_db
from app.web.templating import templates

router = APIRouter()


@router.get("/dashboard")
async def show_dashboard(
    request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)
) -> Response:
    context: dict[str, object] = {}

    if user.has_permission(Permission.MACHINE_VIEW):
        total = (await db.execute(select(func.count()).select_from(Machine))).scalar_one()
        online = (
            await db.execute(
                select(func.count()).select_from(Machine).where(Machine.is_reachable.is_(True))
            )
        ).scalar_one()
        offline = (
            await db.execute(
                select(func.count()).select_from(Machine).where(Machine.is_reachable.is_(False))
            )
        ).scalar_one()
        needs_updates = (
            await db.execute(
                select(func.count())
                .select_from(Machine)
                .where(
                    (Machine.upgradable_count > 0)
                    | (Machine.flatpak_upgradable_count > 0)
                    | (Machine.snap_upgradable_count > 0)
                )
            )
        ).scalar_one()
        needs_security_updates = (
            await db.execute(
                select(func.count())
                .select_from(Machine)
                .where(Machine.security_upgradable_count > 0)
            )
        ).scalar_one()
        needs_reboot = (
            await db.execute(
                select(func.count()).select_from(Machine).where(Machine.reboot_required.is_(True))
            )
        ).scalar_one()
        pending_count = (
            await db.execute(select(func.count()).select_from(PendingMachine))
        ).scalar_one()
        context["machine_stats"] = {
            "total": total,
            "online": online,
            "offline": offline,
            "needs_updates": needs_updates,
            "needs_security_updates": needs_security_updates,
            "needs_reboot": needs_reboot,
            "pending_count": pending_count,
        }

    if user.has_permission(Permission.GROUP_VIEW):
        context["group_count"] = (
            await db.execute(select(func.count()).select_from(MachineGroup))
        ).scalar_one()

    if user.has_permission(Permission.SCHEDULING_VIEW):
        result = await db.execute(
            select(ScheduledTask)
            .where(ScheduledTask.is_enabled.is_(True))
            .order_by(ScheduledTask.next_run_at.is_(None), ScheduledTask.next_run_at.asc())
            .limit(5)
        )
        context["upcoming_tasks"] = list(result.scalars().all())
        context["enabled_task_count"] = (
            await db.execute(
                select(func.count())
                .select_from(ScheduledTask)
                .where(ScheduledTask.is_enabled.is_(True))
            )
        ).scalar_one()

    if user.has_permission(Permission.AUDIT_VIEW):
        result = await db.execute(
            select(AuditLogEntry).order_by(AuditLogEntry.created_at.desc()).limit(8)
        )
        context["recent_audit_entries"] = list(result.scalars().all())
        context["recent_denied_count"] = (
            await db.execute(
                select(func.count())
                .select_from(AuditLogEntry)
                .where(AuditLogEntry.outcome == AuditOutcome.DENIED)
            )
        ).scalar_one()

    return templates.TemplateResponse(request, "dashboard/index.html", context)
