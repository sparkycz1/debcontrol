"""A route that waits for a background job and then reloads the machine must
see what the job wrote — the request's own session otherwise hands back the
object it already holds, with the values from before the job (the reason
"Check for updates now" needed a page refresh)."""

from __future__ import annotations

from sqlalchemy import select

from app.db.models.machine import AuthMethod, Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.web.routes.machines_common import _get_machine_or_404
from tests.conftest import _create_user_with_permissions


async def test_reloading_a_machine_sees_changes_committed_elsewhere(db_session_factory):
    async with db_session_factory() as setup:
        machine = Machine(
            name="m1",
            ip_address="10.0.0.1",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            upgradable_count=0,
        )
        setup.add(machine)
        await setup.commit()
        machine_id = machine.id
    created, _ = await _create_user_with_permissions(
        db_session_factory, username="viewer", permissions={Permission.MACHINE_VIEW}
    )
    user_id = created.id

    async with db_session_factory() as request_db:
        user = (await request_db.execute(select(User).where(User.id == user_id))).scalar_one()
        first = await _get_machine_or_404(machine_id, request_db, user)
        assert first.upgradable_count == 0

        # The background job, in its own session.
        async with db_session_factory() as job_db:
            row = await job_db.get(Machine, machine_id)
            assert row is not None
            row.upgradable_count = 12
            await job_db.commit()

        again = await _get_machine_or_404(machine_id, request_db, user)
        assert again.upgradable_count == 12
