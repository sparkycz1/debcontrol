"""Export/import of role *configuration* — config-as-code for RBAC, same
"one service function, two doors" convention as `app.services.machine_config`
(web route + REST API). Lets an admin version a role matrix in git and
replay it onto another debcontrol instance (a staging/DR environment, or a
second deployment that should stay in sync), the same way machine/group
config already can.

Conflict handling mirrors machines: a role name that already exists is
**skipped**, not overwritten — silently changing what an existing role
grants (as a side effect of importing an unrelated file) is a worse default
than asking an operator to resolve the name clash by hand, especially since
a role's permissions gate real SSH access.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.role import Permission, Role, RolePermission
from app.schemas.role_config import RoleConfigExport, RoleExport


async def export_role_config(db: AsyncSession) -> RoleConfigExport:
    """Every `Role`, in the import-compatible shape. Not scoped by
    account — role management already requires `user.manage` fleet-wide,
    there's no per-role visibility restriction to respect (unlike machines/
    groups)."""
    result = await db.execute(select(Role).order_by(Role.name))
    roles = [
        RoleExport(
            name=role.name,
            description=role.description,
            require_totp=role.require_totp,
            permissions=sorted(p.value for p in role.permissions),
        )
        for role in result.scalars().all()
    ]
    return RoleConfigExport(roles=roles)


@dataclass
class RoleImportResult:
    created_roles: list[str] = field(default_factory=list)
    skipped_roles: list[dict[str, str]] = field(default_factory=list)
    unknown_permission_warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "created_roles": self.created_roles,
            "skipped_roles": self.skipped_roles,
            "unknown_permission_warnings": self.unknown_permission_warnings,
        }

    def summary(self) -> str:
        summary = f"Imported {len(self.created_roles)} role(s)"
        if self.skipped_roles:
            summary += f", skipped {len(self.skipped_roles)} role(s) (name already exists)"
        if self.unknown_permission_warnings:
            summary += f", {len(self.unknown_permission_warnings)} unknown permission(s) ignored"
        return summary


async def import_role_config(db: AsyncSession, payload: RoleConfigExport) -> RoleImportResult:
    """Create real `Role`/`RolePermission` rows directly from `payload`. A
    permission string this instance doesn't recognize (older debcontrol
    version than the one that produced the export) is dropped from that
    role rather than failing the whole import — noted in
    `unknown_permission_warnings` so an operator can revisit it after
    upgrading, same reasoning `MachineExport`'s auth-method fallback uses."""
    result = RoleImportResult()

    existing_names = set((await db.execute(select(Role.name))).scalars().all())
    unknown_seen: set[str] = set()

    for role_export in payload.roles:
        if role_export.name in existing_names:
            result.skipped_roles.append(
                {"name": role_export.name, "reason": "A role with this name already exists."}
            )
            continue

        permissions: list[Permission] = []
        for value in role_export.permissions:
            try:
                permissions.append(Permission(value))
            except ValueError:
                if value not in unknown_seen:
                    unknown_seen.add(value)
                    result.unknown_permission_warnings.append(value)

        role = Role(
            name=role_export.name,
            description=role_export.description,
            require_totp=role_export.require_totp,
        )
        db.add(role)
        role.permission_grants = [RolePermission(permission=p) for p in permissions]
        existing_names.add(role_export.name)
        result.created_roles.append(role_export.name)

    await db.commit()
    return result
