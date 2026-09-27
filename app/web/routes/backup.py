"""Administration → Backup & restore (`/backup`): one page listing every
configuration export/import the app has — machines and groups, scheduled
tasks, roles, notification rules — instead of a button pair on each of
those pages.

The page itself only links; each export/import keeps its own route and its
own permission (the same one it always had), and a section is shown only
to an account that could use at least its export."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import APIRouter, Depends, Request, Response

from app.auth.dependencies import get_current_user
from app.db.models.role import Permission
from app.db.models.user import User
from app.web.templating import templates

router = APIRouter(prefix="/backup")


@dataclass(frozen=True)
class BackupSection:
    key: str
    view_permission: Permission
    manage_permission: Permission
    # (label key, href) pairs.
    exports: tuple[tuple[str, str], ...]
    import_href: str


SECTIONS: tuple[BackupSection, ...] = (
    BackupSection(
        key="machines",
        view_permission=Permission.MACHINE_VIEW,
        manage_permission=Permission.MACHINE_MANAGE,
        exports=(
            ("backup.export_json", "/machines/config/export?format=json"),
            ("backup.export_csv", "/machines/config/export?format=csv"),
        ),
        import_href="/machines/config/import",
    ),
    BackupSection(
        key="scheduling",
        view_permission=Permission.SCHEDULING_VIEW,
        manage_permission=Permission.SCHEDULING_MANAGE,
        exports=(("backup.export_json", "/scheduling/config/export"),),
        import_href="/scheduling/config/import",
    ),
    BackupSection(
        key="roles",
        view_permission=Permission.USER_MANAGE,
        manage_permission=Permission.USER_MANAGE,
        exports=(("backup.export_json", "/roles/config/export"),),
        import_href="/roles/config/import",
    ),
    BackupSection(
        key="notifications",
        view_permission=Permission.NOTIFICATION_VIEW,
        manage_permission=Permission.NOTIFICATION_MANAGE,
        exports=(("backup.export_yaml", "/notifications/rules/export"),),
        import_href="/notifications/rules/import",
    ),
)


def visible_sections(user: User) -> list[BackupSection]:
    return [s for s in SECTIONS if user.has_permission(s.view_permission)]


@router.get("")
async def backup_page(request: Request, user: User = Depends(get_current_user)) -> Response:
    return templates.TemplateResponse(
        request,
        "backup/index.html",
        {"sections": visible_sections(user)},
    )
