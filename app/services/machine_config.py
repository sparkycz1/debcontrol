"""Export/import of machine & group *configuration* (Task 1) — shared
between the web routes (`app/web/routes/machines.py`) and the REST API
(`app/web/routes/api_v1.py`), same "one service function, two doors"
convention as `app.services.machine_actions`.

**This is a structural/config export, not a credentials backup.** Consistent
with this app's "no blind trust" SSH security model (see
wiki/Architecture.md's host-key-pinning section), the export/import
deliberately never touches:

- `Machine.secret_encrypted` — the encrypted password/key material for
  `AuthMethod.PASSWORD` machines.
- `Machine.host_key_fingerprint` — the pinned SSH host key. An imported
  machine always starts with none, exactly like a freshly hand-added one:
  the normal "Discover key fingerprint" + manual outside-the-app
  confirmation flow applies before anything can connect to it.

Consequences of that for import:

- A machine whose original `auth_method` was `ssh_key` imports cleanly —
  the app's shared SSH identity key needs nothing machine-specific.
- A machine whose original `auth_method` was `password` can't be
  re-created with that method (there's no secret to import) — it's
  imported as `ssh_key` instead, and the machine's name is surfaced in
  `ImportResult.auth_method_warnings` so an operator knows to revisit its
  credentials.

Conflict handling: a machine name that already exists is **skipped**, not
overwritten — silently clobbering an existing machine's connection details
(and forcing host-key re-confirmation on it) is a worse default than asking
an operator to resolve the conflict by hand. Groups are the opposite case:
matched-or-created by name is harmless (there's no credential/trust state on
a group to lose), so an existing group is simply reused for membership.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.user import User
from app.schemas.machine_config import GroupExport, MachineConfigExport, MachineExport
from app.services.access_scope import groups_visible_to, machines_visible_to
from app.services.machine_tags import set_machine_tags

# Shown once per import result, regardless of how many machines were
# created — every one of them starts with no pinned host key.
HOST_KEY_WARNING = (
    "Every imported machine has no pinned host-key fingerprint, exactly like "
    "a freshly hand-added machine. Use \"Discover key fingerprint\" and confirm "
    "it (outside this app) before anything connects to it."
)


async def export_machine_config(db: AsyncSession, user: User) -> MachineConfigExport:
    """Every non-pending `Machine` and every `MachineGroup` **that `user` can
    see**, in the import-compatible shape. `PendingMachine` rows
    (self-registration / CSV bulk-import review queue) are never included —
    this is a snapshot of known, already-confirmed configuration, not
    undiscovered hosts.

    Scoped through `app.services.access_scope` like every other read path: an
    export is a listing, and a restricted account must not be able to read
    out the whole fleet's connection details through a download link. A
    group's `members` list is filtered to visible machines for the same
    reason (the machines are the scoped thing; naming them under a group the
    account *can* see would leak them anyway).

    Import is deliberately not scope-checked — it only ever creates brand-new
    rows, so there is nothing existing to check against. See
    `import_machine_config`."""
    machines_query = await machines_visible_to(db, user)
    machine_result = await db.execute(
        machines_query.options(selectinload(Machine.group)).order_by(Machine.name)
    )
    machines = [
        MachineExport(
            name=m.name,
            ip_address=m.ip_address,
            port=m.port,
            username=m.username,
            auth_method=m.auth_method,
            group=m.group.name if m.group else None,
            description=m.description,
            runbook=m.runbook,
            tags=[tag.name for tag in m.tags],
            is_active=m.is_active,
        )
        for m in machine_result.scalars().all()
    ]

    exported_machine_names = {m.name for m in machines}
    groups_query = await groups_visible_to(db, user)
    group_result = await db.execute(
        groups_query.options(selectinload(MachineGroup.machines)).order_by(MachineGroup.name)
    )
    groups = [
        GroupExport(
            name=g.name,
            description=g.description,
            members=sorted(
                m.name for m in g.machines if m.name in exported_machine_names
            ),
        )
        for g in group_result.scalars().all()
    ]

    return MachineConfigExport(machines=machines, groups=groups)


@dataclass
class ImportResult:
    created_machines: list[str] = field(default_factory=list)
    created_groups: list[str] = field(default_factory=list)
    skipped_machines: list[dict[str, str]] = field(default_factory=list)
    auth_method_warnings: list[str] = field(default_factory=list)
    host_key_warning: str = HOST_KEY_WARNING

    def to_dict(self) -> dict[str, object]:
        return {
            "created_machines": self.created_machines,
            "created_groups": self.created_groups,
            "skipped_machines": self.skipped_machines,
            "auth_method_warnings": self.auth_method_warnings,
            "host_key_warning": self.host_key_warning,
        }

    def summary(self) -> str:
        parts = [
            f"{len(self.created_machines)} machine(s)",
            f"{len(self.created_groups)} group(s)",
        ]
        summary = f"Imported {', '.join(parts)}"
        if self.skipped_machines:
            summary += f", skipped {len(self.skipped_machines)} machine(s) (name already exists)"
        if self.auth_method_warnings:
            summary += (
                f", {len(self.auth_method_warnings)} imported as ssh_key "
                "(original auth method was password)"
            )
        return summary


async def import_machine_config(db: AsyncSession, payload: MachineConfigExport) -> ImportResult:
    """Create real `Machine`/`MachineGroup` rows directly from `payload` —
    not the pending-review queue self-registration/CSV bulk-import use, since
    this is for restoring/migrating *known* configuration, not discovering
    unknown hosts. See the module docstring for the full conflict/security
    policy this implements."""
    result = ImportResult()

    existing_machine_names = set(
        (await db.execute(select(Machine.name))).scalars().all()
    )
    groups_by_name: dict[str, MachineGroup] = {
        g.name: g for g in (await db.execute(select(MachineGroup))).scalars().all()
    }

    # Create every group named anywhere in the payload first (either in the
    # `groups` list itself, or only referenced from a machine's `group`
    # field) so every machine below has somewhere to attach to.
    wanted_group_names = {g.name for g in payload.groups} | {
        m.group for m in payload.machines if m.group
    }
    group_descriptions = {g.name: g.description for g in payload.groups}
    for name in sorted(wanted_group_names):
        if name in groups_by_name:
            continue
        group = MachineGroup(name=name, description=group_descriptions.get(name))
        db.add(group)
        groups_by_name[name] = group
        result.created_groups.append(name)
    if result.created_groups:
        await db.flush()  # assign IDs before machines reference them below.

    for machine in payload.machines:
        if machine.name in existing_machine_names:
            result.skipped_machines.append(
                {"name": machine.name, "reason": "A machine with this name already exists."}
            )
            continue

        auth_method = machine.auth_method
        if auth_method == AuthMethod.PASSWORD:
            auth_method = AuthMethod.SSH_KEY
            result.auth_method_warnings.append(machine.name)

        new_machine = Machine(
            name=machine.name,
            ip_address=machine.ip_address,
            port=machine.port,
            username=machine.username,
            auth_method=auth_method,
            secret_encrypted=None,
            host_key_fingerprint=None,
            group_id=groups_by_name[machine.group].id if machine.group else None,
            description=machine.description,
            runbook=machine.runbook,
            is_active=machine.is_active,
        )
        db.add(new_machine)
        if machine.tags:
            await db.flush()  # assign an id before set_machine_tags needs one
            await set_machine_tags(db, new_machine, machine.tags)
        existing_machine_names.add(machine.name)
        result.created_machines.append(machine.name)

    await db.commit()
    return result
