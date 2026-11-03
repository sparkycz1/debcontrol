"""The actions of the fleet-wide Docker lists (stacks, images, backups,
hosts) and the fleet clean-up: the selected rows are grouped by machine and
each runs through exactly the per-machine code (`docker_ops`), with the
same permission, audit entries and refusals as on the machine's own page.
Shared by the web pages (`docker_fleet_pages`) and the REST API
(`api_v1_docker_fleet_lists`).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.docker import DockerJob
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.services import docker_backups
from app.services import docker_inventory_snapshot as inventory_snapshot
from app.services.access_scope import visible_machines_by_ids
from app.ssh.docker_cli import is_image_id_valid, is_image_valid, is_project_name_valid
from app.ssh.docker_prune import PruneOptions
from app.web.routes import docker_ops
from app.web.templating import t

# Every action a list offers, with the permissions it needs (all of them).
ACTIONS: dict[str, dict[str, tuple[Permission, ...]]] = {
    "stacks": {
        "start": (Permission.ACTION_POWER,),
        "stop": (Permission.ACTION_POWER,),
        "restart": (Permission.ACTION_POWER,),
        "down": (Permission.ACTION_POWER,),
        "up": (Permission.ACTION_UPDATES,),
        "update": (Permission.ACTION_UPDATES,),
    },
    "images": {
        "pull": (Permission.ACTION_UPDATES,),
        "scan": (Permission.ACTION_UPDATES,),
        "remove": (Permission.ACTION_UPDATES,),
    },
    "backups": {
        "run": (Permission.ACTION_UPDATES,),
        "check": (Permission.ACTION_UPDATES,),
        "forget": (Permission.ACTION_UPDATES,),
        "verify": (Permission.ACTION_UPDATES,),
    },
    "hosts": {
        "check": (Permission.MACHINE_MANAGE,),
        "apply": (Permission.SETTINGS_MANAGE, Permission.ACTION_TERMINAL),
        "restart": (Permission.ACTION_POWER,),
    },
}
# One request acts on at most this many rows.
MAX_ITEMS = 200


@dataclass
class FleetOutcome:
    done: int = 0
    errors: list[str] = field(default_factory=list)
    jobs: list[DockerJob] = field(default_factory=list)
    # Rows that were not found or not valid (dropped before anything ran).
    skipped: int = 0


def allowed(user: User, kind: str, action: str) -> bool | None:
    """None for an unknown action, else whether `user` may run it."""
    needs = ACTIONS.get(kind, {}).get(action)
    if needs is None:
        return None
    return all(user.has_permission(p) for p in needs)


def parse_keys(values: list[str]) -> dict[uuid.UUID, list[str]]:
    """Checkbox values `<machine id>/<ident>` → `{machine id: [idents]}`."""
    grouped: dict[uuid.UUID, list[str]] = {}
    count = 0
    for value in values:
        machine_part, sep, ident = value.partition("/")
        if not sep or not ident or count >= MAX_ITEMS:
            continue
        try:
            machine_id = uuid.UUID(machine_part)
        except ValueError:
            continue
        idents = grouped.setdefault(machine_id, [])
        if ident not in idents:
            idents.append(ident[:300])
            count += 1
    return grouped


def _message(error: object) -> str:
    return str(getattr(error, "localized", error))


class _Recorder:
    def __init__(self, machine: Machine, outcome: FleetOutcome) -> None:
        self.machine = machine
        self.outcome = outcome

    def __call__(self, op: docker_ops.Op, label: str = "") -> None:
        if op.ok:
            self.outcome.done += 1
            if op.job is not None:
                self.outcome.jobs.append(op.job)
        elif op.error:
            prefix = f"{self.machine.name}{' ' + label if label else ''}"
            self.outcome.errors.append(f"{prefix}: {_message(op.error)}")


async def _images(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    user: User,
    action: str,
    idents: list[str],
    note: _Recorder,
) -> None:
    stored = {
        str(i.get("ref") or i.get("id")): i for i in inventory_snapshot.rows(machine, "images")
    }
    if action == "scan":
        images = {
            ident: str(stored[ident].get("id"))
            for ident in idents
            if ident in stored
            and stored[ident].get("ref")
            and is_image_valid(ident)
            and is_image_id_valid(str(stored[ident].get("id")))
        }
        note.outcome.skipped += len(idents) - len(images)
        if images:
            note(await docker_ops.image_scan(request, db, machine, user, images=images))
        return
    for ident in idents:
        if not is_image_valid(ident) or (action == "pull" and ident.startswith("sha256:")):
            note.outcome.skipped += 1
        elif action == "pull":
            note(await docker_ops.image_pull(request, db, machine, user, ident), ident)
        else:
            note(await docker_ops.image_remove(request, db, machine, ident), ident)


async def _backups(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    user: User,
    action: str,
    idents: list[str],
    note: _Recorder,
) -> None:
    for ident in idents:
        try:
            backup = await docker_backups.get_backup(db, machine.id, uuid.UUID(ident))
        except ValueError:
            backup = None
        if backup is None:
            note.outcome.skipped += 1
            continue
        note(
            await docker_ops.backup_job(request, db, machine, user, backup, action), backup.name
        )


async def _on_machine(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    user: User,
    kind: str,
    action: str,
    idents: list[str],
    outcome: FleetOutcome,
) -> None:
    note = _Recorder(machine, outcome)
    if kind == "stacks":
        for project in idents:
            if not is_project_name_valid(project):
                outcome.skipped += 1
                continue
            note(
                await docker_ops.project_action(request, db, machine, user, project, action),
                project,
            )
    elif kind == "images":
        await _images(request, db, machine, user, action, idents, note)
    elif kind == "backups":
        await _backups(request, db, machine, user, action, idents, note)
    elif action == "check":
        note(await docker_ops.check_now(request, db, machine))
    elif action == "apply":
        note(await docker_ops.daemon_apply(request, db, machine, user))
    else:
        note(await docker_ops.daemon_restart(request, db, machine, user))


async def run(
    request: Request,
    db: AsyncSession,
    user: User,
    kind: str,
    action: str,
    selected: dict[uuid.UUID, list[str]],
) -> FleetOutcome:
    """Run `action` on the selected rows, machine by machine. The caller
    checked `allowed`. Machines the account can't see are left out."""
    outcome = FleetOutcome()
    if kind == "hosts":
        # A host row's ident is the machine itself.
        selected = {m: [str(m)] for m in selected}
    machines = await visible_machines_by_ids(db, user, list(selected))
    outcome.skipped += sum(len(v) for k, v in selected.items()) - sum(
        len(selected[m.id]) for m in machines
    )
    for machine in sorted(machines, key=lambda m: m.name.lower()):
        if not machine.host_key_fingerprint:
            outcome.errors.append(f"{machine.name}: {t(request, 'docker_fleet.no_host_key')}")
            continue
        await _on_machine(request, db, machine, user, kind, action, selected[machine.id], outcome)
    return outcome


async def prune(
    request: Request,
    db: AsyncSession,
    user: User,
    machines: list[Machine],
    options: PruneOptions,
) -> FleetOutcome:
    """The clean-up on each of `machines`. Removing every unused named
    volume needs each machine's name typed, so it is never offered across
    machines: `options.all_volumes` is refused here."""
    outcome = FleetOutcome()
    if options.all_volumes:
        outcome.errors.append(t(request, "docker_fleet.prune_no_named_volumes"))
        return outcome
    for machine in sorted(machines, key=lambda m: m.name.lower()):
        if not machine.host_key_fingerprint:
            continue
        op = await docker_ops.prune(request, db, machine, user, options)
        if op.job is not None:
            outcome.done += 1
            outcome.jobs.append(op.job)
        elif op.error:
            outcome.errors.append(f"{machine.name}: {_message(op.error)}")
    return outcome
