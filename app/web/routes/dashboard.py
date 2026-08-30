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
from app.db.models.fleet_snapshot import FleetSnapshot
from app.db.models.pending_machine import PendingMachine
from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.user import User
from app.db.session import get_db
from app.scheduling.targets import task_within_scope
from app.services.access_scope import allowed_group_ids, count_visible_groups
from app.services.fleet_stats import compute_fleet_stats
from app.web.templating import templates

router = APIRouter()

# Only render the trend chart(s) once there's enough history to draw a line
# through — a single snapshot (or none, on a fresh install) is a point, not
# a trend.
_MIN_SNAPSHOTS_FOR_TREND = 2


@router.get("/dashboard")
async def show_dashboard(
    request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)
) -> Response:
    context: dict[str, object] = {}
    # `None` for an unrestricted account (the common case) — every count
    # below then behaves exactly as it did before this feature existed.
    scope = await allowed_group_ids(db, user)

    if user.has_permission(Permission.MACHINE_VIEW):
        stats = await compute_fleet_stats(db, scope)
        pending_count = (
            await db.execute(select(func.count()).select_from(PendingMachine))
        ).scalar_one()
        context["machine_stats"] = {**stats, "pending_count": pending_count}

        # Fleet trends (Task 4) — every retained daily snapshot, oldest
        # first, so the chart partials can draw a left-to-right timeline.
        # Retention itself is enforced by the daily purge job
        # (app.tasks.jobs.purge_old_fleet_snapshots), not filtered here —
        # whatever's left in the table is exactly what's meant to be shown.
        # Not shown to a restricted account at all: a snapshot is a stored
        # fleet-wide total recorded by a background job, so there is nothing
        # in it to narrow after the fact — rendering it would quietly
        # contradict the scoped counts right above it and leak the fleet's
        # real size. Only the live, per-request numbers can be scoped.
        if scope is None:
            snapshot_result = await db.execute(
                select(FleetSnapshot).order_by(FleetSnapshot.snapshot_date.asc())
            )
            snapshots = list(snapshot_result.scalars().all())
            if len(snapshots) >= _MIN_SNAPSHOTS_FOR_TREND:
                context["fleet_snapshots"] = snapshots

    if user.has_permission(Permission.GROUP_VIEW):
        context["group_count"] = await count_visible_groups(db, user)

    if user.has_permission(Permission.SCHEDULING_VIEW):
        # Filtered the same way `/scheduling` filters its own list — a
        # restricted account is shown only the schedules it could open.
        # Fetched unlimited then sliced, since the scope filter runs in
        # Python (see `app/web/routes/scheduling.py` for why).
        result = await db.execute(
            select(ScheduledTask)
            .where(ScheduledTask.is_enabled.is_(True))
            .order_by(ScheduledTask.next_run_at.is_(None), ScheduledTask.next_run_at.asc())
        )
        enabled_tasks = [
            task
            for task in result.scalars().all()
            if await task_within_scope(db, user, task)
        ]
        context["upcoming_tasks"] = enabled_tasks[:5]
        context["enabled_task_count"] = len(enabled_tasks)

    # Deliberately never scoped: `audit.view` is a single global permission
    # over the whole deployment's audit trail — a per-group audit view would
    # be a worse security control than none. See wiki/Architecture.md.
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
