"""The post-login landing page: a read-only overview aggregated from the
areas the current user has permission to see. No `Permission` gate at the
router level (unlike every other page) — anyone with a valid session gets
*a* dashboard, just with fewer sections, mirroring how `base.html`'s nav
already hides links a role can't use.
"""

from __future__ import annotations

from datetime import UTC, datetime, time

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditLogEntry, AuditOutcome
from app.db.models.fleet_snapshot import FleetSnapshot
from app.db.models.fleet_summary import FleetSummary
from app.db.models.pending_machine import PendingMachine
from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.user import User
from app.db.session import get_db
from app.scheduling.targets import task_within_scope
from app.services import dashboard_layout
from app.services.access_scope import allowed_group_ids, count_visible_groups
from app.services.dashboard_cache import cached_fleet_stats
from app.web.routes.fleet import fleet_grid_context
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
        redis = getattr(request.app.state, "redis", None)
        stats = await cached_fleet_stats(db, redis, scope)
        pending_count = (
            await db.execute(select(func.count()).select_from(PendingMachine))
        ).scalar_one()
        context["machine_stats"] = {**stats, "pending_count": pending_count}
        # The machine cards at the bottom of the page (formerly /fleet).
        context.update(await fleet_grid_context(db, user))

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
                # One point per day, drawn at midnight UTC — the same
                # hover charts the Monitoring tab uses need datetimes.
                context["trend_timestamps"] = [
                    datetime.combine(s.snapshot_date, time.min, tzinfo=UTC) for s in snapshots
                ]

            # Same "unrestricted accounts only" reasoning as fleet_snapshots
            # just above: this is a single fleet-wide report a background
            # job wrote with no "current user" to scope to (see
            # app.tasks.ai_jobs.generate_fleet_summary) — showing it to a
            # restricted account would leak facts about machines outside
            # their own scope.
            summary_result = await db.execute(
                select(FleetSummary).order_by(FleetSummary.created_at.desc()).limit(1)
            )
            context["fleet_summary"] = summary_result.scalar_one_or_none()

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
    # be a worse security control than none. See wiki/Architecture.
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

    # Which of those sections this account wants, and in what order.
    layout = dashboard_layout.resolve(user.dashboard_layout)
    context["layout"] = layout
    # Only what this account can see at all is offered for arranging — a
    # section it has no permission for is not even named.
    present = {
        "machines": "machine_stats" in context,
        "fleet": "machine_stats" in context,
        "summary": bool(context.get("fleet_summary")),
        "trends": "fleet_snapshots" in context,
        "scheduling": "upcoming_tasks" in context,
        "activity": "recent_audit_entries" in context,
    }
    context["arrangeable"] = [key for key in layout.order if present[key]]
    context["layout_open"] = request.query_params.get("arrange") == "1"
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    context["csrf_token"] = csrf_token
    response = templates.TemplateResponse(request, "dashboard/index.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/dashboard/layout", dependencies=[Depends(verify_csrf)])
async def update_dashboard_layout(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    action: str = Form(""),
    section: str = Form(""),
) -> Response:
    """One step of arranging the account's own Dashboard: move a section up
    or down, hide or show it, or go back to the default. Only the account's
    own preference changes, so it is not audited (like the theme and the
    list's view mode)."""
    layout = dashboard_layout.resolve(user.dashboard_layout)
    try:
        if action == "reset":
            layout = dashboard_layout.DEFAULT
        elif action in ("up", "down"):
            layout = dashboard_layout.move(layout, section, up=action == "up")
        elif action in ("hide", "show"):
            layout = dashboard_layout.set_hidden(layout, section, hidden=action == "hide")
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown action.")
    except dashboard_layout.UnknownSectionError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown section."
        ) from None
    # The signed-in user comes from the auth middleware's own session;
    # the change has to be made on this request's.
    account = await db.get(User, user.id)
    assert account is not None
    account.dashboard_layout = dashboard_layout.to_store(layout)
    await db.commit()
    return RedirectResponse(url="/dashboard?arrange=1", status_code=status.HTTP_303_SEE_OTHER)
