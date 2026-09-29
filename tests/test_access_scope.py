"""Per-user, per-machine-group visibility scoping — the security boundary
added on top of RBAC.

Treated with the same rigor as `tests/test_rbac.py`, and organized the same
way: the unrestricted (default) case is asserted as a regression alongside
every restricted one, because "nothing changed for existing accounts" is
half of this feature's contract. See `app/services/access_scope.py` and
`app/db/models/user_machine_group_access.py`.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import select

from app.ai.base import ToolCall
from app.ai.tools import (
    LIST_GROUPS,
    LIST_MACHINES,
    REBOOT,
    build_pending_action,
    execute_read_only_tool,
    load_machines,
    resolve_target,
)
from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType
from app.db.models.user import User
from app.db.models.user_machine_group_access import UserMachineGroupAccess
from app.services.machine_config import export_machine_config
from tests.conftest import ADMIN_USERNAME

# Everything a scoped account could plausibly need, so a test's own
# `login_as(...)` call is only ever about the *scope*, never the permissions.
_ALL_PERMISSIONS = set(Permission)


@dataclass
class Fixture:
    """The two-group fleet every test below is written against: one group
    the restricted account is granted, one it isn't, plus a machine in no
    group at all (never visible to a restricted account, by design)."""

    group_a: uuid.UUID
    group_b: uuid.UUID
    machine_a: uuid.UUID
    machine_b: uuid.UUID
    machine_orphan: uuid.UUID


async def _seed(db_session_factory: Any) -> Fixture:
    async with db_session_factory() as db:
        group_a = MachineGroup(name="group-a")
        group_b = MachineGroup(name="group-b")
        db.add_all([group_a, group_b])
        await db.flush()

        def _machine(name: str, ip: str, group_id: uuid.UUID | None) -> Machine:
            return Machine(
                name=name,
                ip_address=ip,
                port=22,
                username="root",
                auth_method=AuthMethod.SSH_KEY,
                group_id=group_id,
                # Pinned, so bulk/AI actions treat these as eligible targets
                # rather than skipping them for an unrelated reason.
                host_key_fingerprint="SHA256:testonlyfingerprint",
            )

        machine_a = _machine("machine-a", "10.90.0.1", group_a.id)
        machine_b = _machine("machine-b", "10.90.0.2", group_b.id)
        machine_orphan = _machine("machine-orphan", "10.90.0.3", None)
        db.add_all([machine_a, machine_b, machine_orphan])
        await db.commit()

        return Fixture(
            group_a=group_a.id,
            group_b=group_b.id,
            machine_a=machine_a.id,
            machine_b=machine_b.id,
            machine_orphan=machine_orphan.id,
        )


async def _api_token(client: Any) -> dict[str, str]:
    """A bearer token for whoever `client` is currently logged in as."""

    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/account/api-tokens", data={"name": "scope-test", "csrf_token": csrf_token}
    )
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", response.text)
    assert match is not None, response.text
    return {"Authorization": f"Bearer {match.group(1)}"}


# --- The default: no rows means unrestricted (regression) --------------------


async def test_unrestricted_user_sees_every_machine_and_group(client, db_session_factory):
    """The common case, unchanged: an account with no grant rows sees the
    whole fleet, ungrouped machines included."""
    await _seed(db_session_factory)

    machines_page = await client.get("/machines")
    assert machines_page.status_code == 200
    assert "machine-a" in machines_page.text
    assert "machine-b" in machines_page.text
    assert "machine-orphan" in machines_page.text

    groups_page = await client.get("/machine-groups")
    assert "group-a" in groups_page.text
    assert "group-b" in groups_page.text


async def test_unrestricted_user_can_open_any_machine(client, db_session_factory):
    seeded = await _seed(db_session_factory)
    for machine_id in (seeded.machine_a, seeded.machine_b, seeded.machine_orphan):
        assert (await client.get(f"/machines/{machine_id}")).status_code == 200
    for group_id in (seeded.group_a, seeded.group_b):
        assert (await client.get(f"/machine-groups/{group_id}")).status_code == 200


# --- Listing surfaces --------------------------------------------------------


async def test_restricted_machines_list_shows_only_granted_groups(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    page = await client.get("/machines")
    assert page.status_code == 200
    assert "machine-a" in page.text
    assert "machine-b" not in page.text
    # Ungrouped machines are never visible to a restricted account.
    assert "machine-orphan" not in page.text


async def test_restricted_groups_list_shows_only_granted_groups(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    page = await client.get("/machine-groups")
    assert page.status_code == 200
    assert "group-a" in page.text
    assert "group-b" not in page.text


async def test_restricted_all_machines_page_covers_only_the_granted_groups(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    page = await client.get("/machine-groups/all")
    assert page.status_code == 200
    assert "machine-a" in page.text
    assert "machine-b" not in page.text
    assert "machine-orphan" not in page.text


async def test_restricted_package_search_never_reaches_other_groups(
    client, login_as, db_session_factory
):
    from app.db.models.machine_package import MachinePackage
    from app.ssh.packages import PackageSource

    seeded = await _seed(db_session_factory)
    async with db_session_factory() as db:
        db.add_all(
            [
                MachinePackage(
                    machine_id=seeded.machine_a,
                    source=PackageSource.APT,
                    name="scopetest-pkg",
                    version="1.0",
                ),
                MachinePackage(
                    machine_id=seeded.machine_b,
                    source=PackageSource.APT,
                    name="scopetest-pkg",
                    version="2.0",
                ),
            ]
        )
        await db.commit()

    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})
    page = await client.get("/security/packages?q=scopetest-pkg")
    assert page.status_code == 200
    assert "machine-a" in page.text
    assert "machine-b" not in page.text


async def test_restricted_config_export_covers_only_granted_groups(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    export = (await client.get("/machines/config/export?format=json")).json()
    assert [m["name"] for m in export["machines"]] == ["machine-a"]
    assert [g["name"] for g in export["groups"]] == ["group-a"]


async def test_export_service_is_unscoped_for_an_unrestricted_user(db_session_factory):
    """The service function itself, not just the route — `None` scope must
    still mean the whole fleet."""
    await _seed(db_session_factory)
    async with db_session_factory() as db:
        from app.db.models.role import Role, RolePermission
        from app.db.models.user import AuthProvider

        role = Role(name="export-role")
        role.permission_grants = [RolePermission(permission=Permission.MACHINE_VIEW)]
        db.add(role)
        await db.flush()
        user = User(
            username="exporter", auth_provider=AuthProvider.LOCAL, is_active=True, role=role
        )
        db.add(user)
        await db.commit()

        export = await export_machine_config(db, user)
    assert {m.name for m in export.machines} == {"machine-a", "machine-b", "machine-orphan"}


# --- Detail routes: 404, never 403, never the data ---------------------------


@pytest.mark.parametrize("attribute", ["machine_b", "machine_orphan"])
async def test_out_of_scope_machine_is_404(client, login_as, db_session_factory, attribute):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    response = await client.get(f"/machines/{getattr(seeded, attribute)}")
    assert response.status_code == 404
    assert "machine-b" not in response.text
    assert "machine-orphan" not in response.text


async def test_out_of_scope_group_is_404(client, login_as, db_session_factory):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    response = await client.get(f"/machine-groups/{seeded.group_b}")
    assert response.status_code == 404
    assert "group-b" not in response.text


async def test_in_scope_machine_and_group_still_open(client, login_as, db_session_factory):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    assert (await client.get(f"/machines/{seeded.machine_a}")).status_code == 200
    assert (await client.get(f"/machine-groups/{seeded.group_a}")).status_code == 200


async def test_out_of_scope_machine_actions_are_404(client, login_as, db_session_factory):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    await client.get(f"/machines/{seeded.machine_a}")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/machines/{seeded.machine_b}/check-updates", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 404


# --- Bulk endpoints must not trust client-submitted ids ----------------------


async def test_bulk_check_updates_drops_out_of_scope_ids(
    client, login_as, db_session_factory, celery_calls
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    await client.get("/machines")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/machines/bulk/check-updates",
        data={
            "machine_ids": [
                str(seeded.machine_a),
                str(seeded.machine_b),
                str(seeded.machine_orphan),
            ],
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303
    targeted = {args[0] for name, args, _ in celery_calls if "check_machine_updates" in name}
    assert targeted == {str(seeded.machine_a)}


async def test_bulk_updates_with_only_out_of_scope_ids_does_nothing(
    client, login_as, db_session_factory, celery_calls
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    await client.get("/machines")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/machines/bulk/updates",
        data={
            "machine_ids": [str(seeded.machine_b)],
            "strategy": "dist_upgrade",
            "csrf_token": csrf_token,
        },
    )
    # Reads exactly like "you selected nothing" — no error naming an id the
    # caller isn't supposed to know exists.
    assert response.status_code == 303
    assert "bulk_error" in response.headers["location"]
    assert not [name for name in celery_calls.names if "run_machine_update" in name]


async def test_group_scoped_action_on_another_group_is_404(client, login_as, db_session_factory):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    await client.get("/machine-groups")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/machine-groups/{seeded.group_b}/check-updates", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 404


async def test_all_machines_action_stays_inside_scope(
    client, login_as, db_session_factory, celery_calls
):
    """The live "All machines" page is narrowed, not refused — acting on it
    must never reach past the boundary."""
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    await client.get("/machine-groups/all")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/machine-groups/all/check-updates", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 303
    targeted = {args[0] for name, args, _ in celery_calls if "check_machine_updates" in name}
    assert targeted == {str(seeded.machine_a)}


async def test_adding_an_out_of_scope_machine_to_a_group_is_404(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    await client.get(f"/machine-groups/{seeded.group_a}")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/machine-groups/{seeded.group_a}/machines",
        data={"machine_id": str(seeded.machine_b), "csrf_token": csrf_token},
    )
    assert response.status_code == 404


# --- Scheduling --------------------------------------------------------------


async def _post_schedule(client: Any, target: str, name: str = "sched") -> Any:
    await client.get("/scheduling/new")
    csrf_token = client.cookies.get("csrftoken")
    return await client.post(
        "/scheduling",
        data={
            "name": name,
            "action": "check_updates",
            "target": target,
            "cron_expression": "0 3 * * *",
            "is_enabled": "on",
            "csrf_token": csrf_token,
        },
    )


async def test_restricted_user_cannot_schedule_against_all_machines(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    response = await _post_schedule(client, "all")
    assert response.status_code == 422
    assert "restricted to specific machine groups" in response.text

    async with db_session_factory() as db:
        assert (await db.execute(select(ScheduledTask))).scalars().first() is None


async def test_restricted_user_cannot_schedule_against_another_group(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    response = await _post_schedule(client, f"group:{seeded.group_b}")
    assert response.status_code == 422


async def test_restricted_user_cannot_schedule_against_an_out_of_scope_machine(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    response = await _post_schedule(client, f"machine:{seeded.machine_b}")
    assert response.status_code == 422


async def test_restricted_user_can_schedule_inside_its_own_scope(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    response = await _post_schedule(client, f"group:{seeded.group_a}", name="in-scope")
    assert response.status_code == 303
    async with db_session_factory() as db:
        task = (await db.execute(select(ScheduledTask))).scalars().one()
    assert task.target_group_id == seeded.group_a


async def test_all_machines_option_is_absent_from_a_restricted_users_form(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})

    page = await client.get("/scheduling/new")
    assert page.status_code == 200
    assert '<option value="all"' not in page.text
    assert f'value="group:{seeded.group_a}"' in page.text
    assert f'value="group:{seeded.group_b}"' not in page.text


async def test_unrestricted_user_still_gets_the_all_machines_option(client, db_session_factory):
    await _seed(db_session_factory)
    page = await client.get("/scheduling/new")
    assert '<option value="all"' in page.text


async def test_out_of_scope_scheduled_tasks_are_hidden_and_404(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    async with db_session_factory() as db:
        fleet_wide = ScheduledTask(
            name="fleet-wide-task",
            action="check_updates",
            target_type=ScheduleTargetType.ALL_MACHINES,
            cron_expression="0 3 * * *",
        )
        other_group = ScheduledTask(
            name="other-group-task",
            action="check_updates",
            target_type=ScheduleTargetType.GROUP,
            target_group_id=seeded.group_b,
            cron_expression="0 4 * * *",
        )
        mine = ScheduledTask(
            name="my-task",
            action="check_updates",
            target_type=ScheduleTargetType.GROUP,
            target_group_id=seeded.group_a,
            cron_expression="0 5 * * *",
        )
        db.add_all([fleet_wide, other_group, mine])
        await db.commit()
        hidden_ids = [fleet_wide.id, other_group.id]
        visible_id = mine.id

    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})
    page = await client.get("/scheduling")
    assert "my-task" in page.text
    assert "fleet-wide-task" not in page.text
    assert "other-group-task" not in page.text

    for task_id in hidden_ids:
        assert (await client.get(f"/scheduling/{task_id}/edit")).status_code == 404
    assert (await client.get(f"/scheduling/{visible_id}/edit")).status_code == 200


# --- The AI assistant --------------------------------------------------------


async def test_ai_list_machines_tool_is_scoped(client, login_as, db_session_factory):
    seeded = await _seed(db_session_factory)
    restricted = await login_as(
        client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a}, username="ai-restricted"
    )

    async with db_session_factory() as db:
        user = await db.get(User, restricted.id)
        assert user is not None
        summary = await execute_read_only_tool(
            db, user, ToolCall(id="1", name=LIST_MACHINES, arguments={})
        )
    assert "machine-a" in summary
    assert "machine-b" not in summary
    assert "machine-orphan" not in summary


async def test_ai_list_groups_tool_is_scoped(client, login_as, db_session_factory):
    seeded = await _seed(db_session_factory)
    restricted = await login_as(
        client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a}, username="ai-restricted"
    )

    async with db_session_factory() as db:
        user = await db.get(User, restricted.id)
        assert user is not None
        summary = await execute_read_only_tool(
            db, user, ToolCall(id="1", name=LIST_GROUPS, arguments={})
        )
    assert "group-a" in summary
    assert "group-b" not in summary


async def test_ai_list_machines_by_out_of_scope_group_name_reads_as_nonexistent(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    restricted = await login_as(
        client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a}, username="ai-restricted"
    )

    async with db_session_factory() as db:
        user = await db.get(User, restricted.id)
        assert user is not None
        summary = await execute_read_only_tool(
            db, user, ToolCall(id="1", name=LIST_MACHINES, arguments={"group_name": "group-b"})
        )
    assert summary == 'No machine group named "group-b" exists.'


async def test_ai_resolve_target_refuses_an_out_of_scope_machine(
    client, login_as, db_session_factory
):
    """A crafted tool call naming a real machine the account can't see must
    resolve to "does not exist", not to that machine."""
    seeded = await _seed(db_session_factory)
    restricted = await login_as(
        client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a}, username="ai-restricted"
    )

    async with db_session_factory() as db:
        user = await db.get(User, restricted.id)
        assert user is not None
        with pytest.raises(Exception, match=re.escape('No machine named "machine-b" exists.')):
            await resolve_target(db, user, "machine", "machine-b")
        # ...and the in-scope one still resolves.
        resolved = await resolve_target(db, user, "machine", "machine-a")
    assert [m.name for m in resolved.machines] == ["machine-a"]


async def test_ai_pending_action_for_an_out_of_scope_group_is_denied(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    restricted = await login_as(
        client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a}, username="ai-restricted"
    )

    async with db_session_factory() as db:
        user = await db.get(User, restricted.id)
        assert user is not None
        entry = await build_pending_action(
            db,
            user,
            ToolCall(
                id="1",
                name=REBOOT,
                arguments={"target_type": "group", "target_name": "group-b"},
            ),
        )
    assert entry["status"] == "denied"
    assert "machine_ids" not in entry


async def test_ai_load_machines_refilters_by_scope_at_confirm_time(
    client, login_as, db_session_factory
):
    """A proposal written while unrestricted must not still execute against
    machines the account has since lost access to."""
    seeded = await _seed(db_session_factory)
    restricted = await login_as(
        client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a}, username="ai-restricted"
    )

    async with db_session_factory() as db:
        user = await db.get(User, restricted.id)
        assert user is not None
        machines = await load_machines(
            db, user, [str(seeded.machine_a), str(seeded.machine_b)]
        )
    assert [m.name for m in machines] == ["machine-a"]


# --- Setting the scope: the Users page ---------------------------------------


async def test_admin_can_restrict_another_account(client, login_as, db_session_factory):
    seeded = await _seed(db_session_factory)
    target = await login_as(
        client, permissions={Permission.MACHINE_VIEW}, username="scope-target"
    )
    # Back to the fully-permissioned admin the `client` fixture created.
    async with db_session_factory() as db:
        admin = (
            await db.execute(select(User).where(User.username == ADMIN_USERNAME))
        ).scalar_one()
        role_id = admin.role_id
        from app.auth.sessions import create_session

        _session, raw_token = await create_session(
            db, admin, ip_address="testclient", user_agent="pytest"
        )
        await db.commit()
    client.cookies.set("session", raw_token)

    await client.get(f"/users/{target.id}/edit")
    csrf_token = client.cookies.get("csrftoken")
    async with db_session_factory() as db:
        target_row = await db.get(User, target.id)
        assert target_row is not None
        target_role_id = target_row.role_id
    assert role_id != target_role_id

    response = await client.post(
        f"/users/{target.id}/edit",
        data={
            "username": "scope-target",
            "display_name": "",
            "auth_provider": "local",
            "password": "",
            "role_id": str(target_role_id),
            "is_active": "on",
            "group_access": [str(seeded.group_a)],
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        rows = (
            (
                await db.execute(
                    select(UserMachineGroupAccess.group_id).where(
                        UserMachineGroupAccess.user_id == target.id
                    )
                )
            )
            .scalars()
            .all()
        )
        actions = (
            (await db.execute(select(AuditLogEntry.action))).scalars().all()
        )
    assert set(rows) == {seeded.group_a}
    assert "user.group_access.update" in actions


async def test_admin_cannot_change_their_own_group_scope(client, db_session_factory):
    """Mirrors the existing "can't change your own role" guard — an admin
    must not be able to lock themselves out while editing something else."""
    seeded = await _seed(db_session_factory)
    async with db_session_factory() as db:
        admin = (
            await db.execute(select(User).where(User.username == ADMIN_USERNAME))
        ).scalar_one()

    await client.get(f"/users/{admin.id}/edit")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/users/{admin.id}/edit",
        data={
            "username": ADMIN_USERNAME,
            "display_name": "",
            "auth_provider": "local",
            "password": "",
            "role_id": str(admin.role_id),
            "is_active": "on",
            "api_access_enabled": "on",
            "group_access": [str(seeded.group_a)],
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 403
    assert "own machine-group access" in response.text

    async with db_session_factory() as db:
        rows = (
            (
                await db.execute(
                    select(UserMachineGroupAccess).where(
                        UserMachineGroupAccess.user_id == admin.id
                    )
                )
            )
            .scalars()
            .all()
        )
    assert rows == []


async def test_saving_an_admins_own_edit_without_touching_scope_still_works(
    client, db_session_factory
):
    """The self-protection guard fires on a *change*, not on every save."""
    await _seed(db_session_factory)
    async with db_session_factory() as db:
        admin = (
            await db.execute(select(User).where(User.username == ADMIN_USERNAME))
        ).scalar_one()

    await client.get(f"/users/{admin.id}/edit")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/users/{admin.id}/edit",
        data={
            "username": ADMIN_USERNAME,
            "display_name": "Renamed",
            "auth_provider": "local",
            "password": "",
            "role_id": str(admin.role_id),
            "is_active": "on",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303


# --- The REST API mirrors the web UI -----------------------------------------


async def test_api_machine_list_and_detail_are_scoped(client, login_as, db_session_factory):
    seeded = await _seed(db_session_factory)
    await login_as(
        client,
        permissions=_ALL_PERMISSIONS,
        group_ids={seeded.group_a},
        username="api-restricted",
        api_access_enabled=True,
    )
    headers = await _api_token(client)

    listing = await client.get("/api/v1/machines", headers=headers)
    assert listing.status_code == 200
    assert {m["name"] for m in listing.json()} == {"machine-a"}

    assert (
        await client.get(f"/api/v1/machines/{seeded.machine_b}", headers=headers)
    ).status_code == 404
    assert (
        await client.get(f"/api/v1/machines/{seeded.machine_a}", headers=headers)
    ).status_code == 200


async def test_api_group_list_is_scoped(client, login_as, db_session_factory):
    seeded = await _seed(db_session_factory)
    await login_as(
        client,
        permissions=_ALL_PERMISSIONS,
        group_ids={seeded.group_a},
        username="api-restricted",
        api_access_enabled=True,
    )
    headers = await _api_token(client)

    listing = await client.get("/api/v1/machine-groups", headers=headers)
    assert {g["name"] for g in listing.json()} == {"group-a"}
    assert (
        await client.get(f"/api/v1/machine-groups/{seeded.group_b}", headers=headers)
    ).status_code == 404


async def test_api_scheduling_rejects_all_machines_for_a_restricted_account(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)
    await login_as(
        client,
        permissions=_ALL_PERMISSIONS,
        group_ids={seeded.group_a},
        username="api-restricted",
        api_access_enabled=True,
    )
    headers = await _api_token(client)

    response = await client.post(
        "/api/v1/scheduling",
        headers=headers,
        json={
            "name": "api-all",
            "action": "check_updates",
            "action_params": {},
            "target_type": "all_machines",
            "cron_expression": "0 3 * * *",
            "is_enabled": True,
        },
    )
    assert response.status_code == 403

    ok = await client.post(
        "/api/v1/scheduling",
        headers=headers,
        json={
            "name": "api-in-scope",
            "action": "check_updates",
            "action_params": {},
            "target_type": "group",
            "target_group_id": str(seeded.group_a),
            "cron_expression": "0 3 * * *",
            "is_enabled": True,
        },
    )
    assert ok.status_code == 201


async def test_api_dashboard_trends_are_empty_for_a_restricted_account(
    client, login_as, db_session_factory
):
    """Snapshots are stored fleet-wide totals with nothing left to narrow —
    withheld rather than reported to an account that can't see the fleet."""
    import datetime as dt

    from app.db.models.fleet_snapshot import FleetSnapshot

    seeded = await _seed(db_session_factory)
    async with db_session_factory() as db:
        db.add(
            FleetSnapshot(
                snapshot_date=dt.date(2026, 1, 1),
                total_machines=3,
                online_machines=1,
                offline_machines=1,
                needs_updates=0,
                needs_security_updates=0,
                needs_reboot=0,
            )
        )
        await db.commit()

    await login_as(
        client,
        permissions=_ALL_PERMISSIONS,
        group_ids={seeded.group_a},
        username="api-restricted",
        api_access_enabled=True,
    )
    headers = await _api_token(client)
    assert (await client.get("/api/v1/dashboard/trends", headers=headers)).json() == {
        "snapshots": []
    }


# --- The Dashboard -----------------------------------------------------------


def _stat_values(html: str) -> list[str]:

    return [v.strip() for v in re.findall(r'<span class="stat-value">([^<]+)</span>', html)]


def _group_count(html: str) -> str:

    match = re.search(r'href="/machine-groups">\s*(\d+) groups?\b', html)
    assert match is not None, html
    return match.group(1)


async def test_dashboard_counts_reflect_only_the_visible_fleet(
    client, login_as, db_session_factory
):
    seeded = await _seed(db_session_factory)

    unrestricted = await client.get("/dashboard")
    assert unrestricted.status_code == 200
    # Total machines is the first stat tile.
    assert _stat_values(unrestricted.text)[0] == "3"
    assert _group_count(unrestricted.text) == "2"

    await login_as(client, permissions=_ALL_PERMISSIONS, group_ids={seeded.group_a})
    page = await client.get("/dashboard")
    assert page.status_code == 200
    assert _stat_values(page.text)[0] == "1"
    assert _group_count(page.text) == "1"


# --- The audit log is deliberately NOT scoped --------------------------------


async def test_audit_log_is_not_group_scoped(client, login_as, db_session_factory):
    """`audit.view` stays a single global permission. A restricted account
    holding it still sees every entry — including ones about machines it
    can't otherwise see. This is the deliberate exception to the rule the
    rest of this file asserts; see `app/services/access_scope.py`."""
    seeded = await _seed(db_session_factory)
    async with db_session_factory() as db:
        db.add(
            AuditLogEntry(
                actor="someone-else",
                action="machine.updates.run",
                summary="Ran updates on machine-b",
                target_type="machine",
                target_id=str(seeded.machine_b),
                target_label="machine-b",
            )
        )
        await db.commit()

    await login_as(
        client,
        permissions={Permission.AUDIT_VIEW},
        group_ids={seeded.group_a},
        username="scoped-auditor",
    )
    page = await client.get("/audit")
    assert page.status_code == 200
    assert "Ran updates on machine-b" in page.text


def test_audit_queries_perform_no_group_filtering():
    """A belt-and-braces check on the code itself: nothing in the audit
    routes reaches for the scoping service at all. Deliberate — see
    `app/services/access_scope.py`'s module docstring."""
    from pathlib import Path

    for module in ("app/web/routes/audit.py", "app/web/routes/api_v1_audit.py"):
        source = Path(module).read_text(encoding="utf-8")
        assert "access_scope" not in source, module
        assert "UserMachineGroupAccess" not in source, module
