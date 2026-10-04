"""One search box for the whole app (the header's search field, `/search`,
`GET /api/v1/search`).

Looks for the query in the names (and a few other identifying fields) of
machines, machine groups, endpoint checks, scheduled tasks, notification
rules and users, and returns links to them, grouped by kind. Each kind is
searched only for an account that could open its list page anyway — the
same permission — and machines and groups are scope-filtered exactly like
their own lists (`app.services.access_scope`), so the search never shows
something the account could not otherwise see.

A plain `ILIKE '%q%'` per kind, a handful of rows each: fine at the fleet
sizes this app targets, and nothing to keep in sync with the data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.endpoint_check import EndpointCheck
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.notification_rule import NotificationRule
from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduledTask
from app.db.models.user import User
from app.services.access_scope import groups_visible_to, machines_visible_to
from app.web.machine_search import machine_search_clause

MIN_QUERY_LENGTH = 2
MAX_QUERY_LENGTH = 100
PER_KIND_LIMIT = 8


@dataclass(frozen=True)
class SearchHit:
    label: str
    detail: str
    href: str


@dataclass
class SearchGroup:
    # "machines", "groups", ... — also the i18n key suffix (`search.kind.*`).
    kind: str
    hits: list[SearchHit] = field(default_factory=list)
    # More matched than are shown; `more_href` is the kind's own filtered
    # list when it has one.
    has_more: bool = False
    more_href: str | None = None


def normalize(query: str) -> str:
    return " ".join(query.split())[:MAX_QUERY_LENGTH]


def _like(query: str) -> str:
    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _cut(rows: list[SearchHit]) -> tuple[list[SearchHit], bool]:
    return rows[:PER_KIND_LIMIT], len(rows) > PER_KIND_LIMIT


async def search(db: AsyncSession, user: User, query: str) -> list[SearchGroup]:
    """Matches for `query`, one group per kind the account may see, in the
    order of the main navigation. Empty for a query shorter than
    `MIN_QUERY_LENGTH`; groups with no match are left out."""
    query = normalize(query)
    if len(query) < MIN_QUERY_LENGTH:
        return []
    like = _like(query)
    limit = PER_KIND_LIMIT + 1
    groups: list[SearchGroup] = []

    def add(kind: str, hits: list[SearchHit], more_href: str | None = None) -> None:
        shown, has_more = _cut(hits)
        if shown:
            groups.append(SearchGroup(kind, shown, has_more, more_href if has_more else None))

    if user.has_permission(Permission.MACHINE_VIEW):
        machines = (
            await db.execute(
                (await machines_visible_to(db, user))
                .where(machine_search_clause(query))
                .order_by(Machine.name)
                .limit(limit)
            )
        ).scalars()
        add(
            "machines",
            [SearchHit(m.name, m.ip_address, f"/machines/{m.id}") for m in machines],
            f"/machines?q={quote(query)}",
        )

    if user.has_permission(Permission.GROUP_VIEW):
        machine_groups = (
            await db.execute(
                (await groups_visible_to(db, user))
                .where(MachineGroup.name.ilike(like, escape="\\"))
                .order_by(MachineGroup.name)
                .limit(limit)
            )
        ).scalars()
        add(
            "groups",
            [
                SearchHit(g.name, g.description or "", f"/machine-groups/{g.id}")
                for g in machine_groups
            ],
        )

    if user.has_permission(Permission.MACHINE_VIEW):
        checks = (
            await db.execute(
                select(EndpointCheck)
                .where(
                    or_(
                        EndpointCheck.name.ilike(like, escape="\\"),
                        EndpointCheck.target.ilike(like, escape="\\"),
                    )
                )
                .order_by(EndpointCheck.name)
                .limit(limit)
            )
        ).scalars()
        add("checks", [SearchHit(c.name, c.target, f"/checks/{c.id}") for c in checks])

    if user.has_permission(Permission.SCHEDULING_VIEW):
        tasks = (
            await db.execute(
                select(ScheduledTask)
                .where(ScheduledTask.name.ilike(like, escape="\\"))
                .order_by(ScheduledTask.name)
                .limit(limit)
            )
        ).scalars()
        add(
            "scheduled_tasks",
            [SearchHit(t.name, t.cron_expression, f"/scheduling/{t.id}/edit") for t in tasks],
        )

    if user.has_permission(Permission.NOTIFICATION_VIEW):
        rules = (
            await db.execute(
                select(NotificationRule)
                .where(NotificationRule.name.ilike(like, escape="\\"))
                .order_by(NotificationRule.name)
                .limit(limit)
            )
        ).scalars()
        add(
            "notification_rules",
            [
                SearchHit(r.name, r.description or "", f"/notifications/rules/{r.id}/edit")
                for r in rules
            ],
        )

    if user.has_permission(Permission.USER_MANAGE):
        users = (
            await db.execute(
                select(User)
                .where(
                    or_(
                        User.username.ilike(like, escape="\\"),
                        User.display_name.ilike(like, escape="\\"),
                        User.email.ilike(like, escape="\\"),
                    )
                )
                .order_by(User.username)
                .limit(limit)
            )
        ).scalars()
        add(
            "users",
            [
                SearchHit(u.username, u.display_name or u.email or "", f"/users/{u.id}/edit")
                for u in users
            ],
        )

    return groups
