"""A machine that answers with a different SSH host key than the pinned
one: the monitoring sample records what it presented, the pages say so,
and an operator can accept the new key. Nothing is trusted on its own."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import Machine
from app.ssh.exceptions import HostKeyMismatchError, SSHConnectionError
from app.tasks import jobs
from tests.test_homelab_round import _add_machine

_NEW = "SHA256:" + "n" * 43
_OLD = "SHA256:" + "o" * 43


async def _state(db_session_factory: Any, machine_id: Any) -> tuple[str | None, str | None]:
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        return machine.host_key_fingerprint, machine.host_key_changed_fingerprint


async def test_monitoring_records_a_changed_key_and_nothing_else(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _add_machine(db_session_factory, host_key_fingerprint=_OLD)
    errors: list[Exception] = [
        SSHConnectionError("Connection refused"),
        HostKeyMismatchError("different key", presented_fingerprint=_NEW),
    ]

    async def failing_sample(*args: object, **kwargs: object) -> dict[str, Any]:
        raise errors.pop(0)

    monkeypatch.setattr(jobs, "gather_monitoring_sample", failing_sample)

    await jobs._sample_machine_monitoring(str(machine_id))
    after_plain_failure = await _state(db_session_factory, machine_id)
    await jobs._sample_machine_monitoring(str(machine_id))
    after_mismatch = await _state(db_session_factory, machine_id)

    # An unreachable machine is not a changed key.
    assert after_plain_failure == (_OLD, None)
    # The pin itself is never touched.
    assert after_mismatch == (_OLD, _NEW)


async def test_pages_report_the_change_and_accepting_clears_it(
    client: AsyncClient, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _add_machine(
        db_session_factory,
        host_key_fingerprint=_OLD,
        host_key_changed_fingerprint=_NEW,
        host_key_changed_at=datetime.now(UTC),
    )

    overview = await client.get(f"/machines/{machine_id}")
    listing = await client.get("/machines")
    match = re.search(r'name="csrf_token" value="([^"]+)"', overview.text)
    assert match is not None
    accepted = await client.post(
        f"/machines/{machine_id}/trust-host-key",
        data={"csrf_token": match.group(1), "fingerprint": _NEW},
        follow_redirects=False,
    )
    after = await client.get(f"/machines/{machine_id}")

    assert "The SSH host key changed." in overview.text
    assert _NEW in overview.text and "Accept the new key" in overview.text
    assert "SSH key changed" in listing.text
    assert accepted.status_code == 303
    assert await _state(db_session_factory, machine_id) == (_NEW, None)
    assert "The SSH host key changed." not in after.text
    async with db_session_factory() as db:
        entry = (
            await db.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "machine.host_key.trust")
            )
        ).scalar_one()
    assert entry.details == {"fingerprint": _NEW, "previous_fingerprint": _OLD}


async def test_api_reports_the_changed_key(client: AsyncClient, db_session_factory: Any) -> None:
    from tests.test_update_history import _api_token

    machine_id = await _add_machine(
        db_session_factory,
        host_key_fingerprint=_OLD,
        host_key_changed_fingerprint=_NEW,
        host_key_changed_at=datetime.now(UTC),
    )
    headers = await _api_token(client)

    machine = (await client.get(f"/api/v1/machines/{machine_id}", headers=headers)).json()

    assert machine["host_key_changed_fingerprint"] == _NEW
    assert machine["host_key_changed_at"] is not None
