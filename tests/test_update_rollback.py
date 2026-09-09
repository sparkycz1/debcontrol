"""Rolling back an update run — snapshot capture (`app.ssh.updates.
capture_package_snapshot`, taken before every real update run) and the
rollback itself (`app.tasks.jobs._rollback_machine_update`, which diffs a
fresh snapshot against the source run's stored one and re-installs only
what changed). See `app/web/routes/machines.py`'s
`rollback_machine_update_endpoint` and `app/web/routes/api_v1.py`'s
`rollback_machine_update_api` for the two trigger points.
"""

from __future__ import annotations

import json
import uuid

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.ssh.updates import build_rollback_command, parse_package_snapshot
from app.tasks.jobs import _rollback_machine_update
from tests.test_web import _create_machine, _pin_host_key

# --- parse_package_snapshot / build_rollback_command: pure, no I/O -----


def test_parse_package_snapshot_reads_tab_separated_pairs():
    raw = "bash\t5.2.15-2\ncoreutils\t9.4-3\n"
    assert parse_package_snapshot(raw) == {"bash": "5.2.15-2", "coreutils": "9.4-3"}


def test_parse_package_snapshot_ignores_blank_and_malformed_lines():
    raw = "bash\t5.2.15-2\n\nno-tab-here\ncoreutils\t9.4-3\n"
    assert parse_package_snapshot(raw) == {"bash": "5.2.15-2", "coreutils": "9.4-3"}


def test_build_rollback_command_pins_exact_versions():
    command = build_rollback_command({"bash": "5.2.15-1", "coreutils": "9.4-2"})

    assert "bash=5.2.15-1" in command
    assert "coreutils=9.4-2" in command
    assert "--allow-downgrades" in command
    assert "install" in command


def test_build_rollback_command_quotes_each_spec():
    command = build_rollback_command({"pkg": "1.0; rm -rf /"})

    assert "'pkg=1.0; rm -rf /'" in command


# --- _rollback_machine_update: mocked SSH, no network -------------------


class _FakeResult:
    def __init__(self, stdout: str, exit_status: int) -> None:
        self.stdout = stdout
        self.exit_status = exit_status


class _FakeConnection:
    """Routes each `conn.run(command, ...)` to a canned result by whether
    `command` looks like the dpkg snapshot query or the apt-get rollback
    install — same call signature both `capture_package_snapshot` and
    `run_rollback` use."""

    def __init__(self, *, snapshot_stdout: str, install_result: _FakeResult | None) -> None:
        self._snapshot_stdout = snapshot_stdout
        self._install_result = install_result
        self.install_called = False

    async def run(self, command: str, **kwargs: object) -> _FakeResult:
        if "dpkg-query" in command:
            return _FakeResult(self._snapshot_stdout, 0)
        self.install_called = True
        assert self._install_result is not None, "apt-get install run but none was expected"
        return self._install_result

    async def __aenter__(self) -> _FakeConnection:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


async def _make_machine_with_run(
    db_session_factory: async_sessionmaker[AsyncSession], *, snapshot: dict[str, str] | None
) -> tuple[uuid.UUID, uuid.UUID]:
    async with db_session_factory() as session:
        machine = Machine(
            name="rollback-target",
            ip_address="10.9.9.20",
            port=22,
            username="root",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        session.add(machine)
        await session.flush()

        source_run = MachineUpdateRun(
            machine_id=machine.id,
            strategy=UpgradeStrategy.DIST_UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
            package_snapshot=json.dumps(snapshot) if snapshot is not None else None,
        )
        session.add(source_run)
        await session.flush()

        rollback_run = MachineUpdateRun(
            machine_id=machine.id,
            strategy=source_run.strategy,
            rollback_of_run_id=source_run.id,
        )
        session.add(rollback_run)
        await session.commit()
        return machine.id, rollback_run.id


async def test_rollback_reinstalls_only_changed_packages(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    _machine_id, run_id = await _make_machine_with_run(
        db_session_factory, snapshot={"bash": "5.2.15-1", "coreutils": "9.4-2"}
    )

    # Current state: bash was upgraded since the snapshot, coreutils wasn't
    # touched, and there's a package on the machine the snapshot never knew
    # about (irrelevant to this rollback).
    fake_conn = _FakeConnection(
        snapshot_stdout="bash\t5.2.15-2\ncoreutils\t9.4-2\nvim\t9.1-1\n",
        install_result=_FakeResult("Setting up bash (5.2.15-1) ...\n", 0),
    )

    async def fake_open_connection(machine: object, secret: object, timeout_seconds: int) -> object:
        return fake_conn

    monkeypatch.setattr("app.ssh.updates.open_connection", fake_open_connection)

    await _rollback_machine_update(str(run_id))

    assert fake_conn.install_called is True
    async with db_session_factory() as session:
        run = await session.get(MachineUpdateRun, run_id)
        assert run is not None
        assert run.status == UpdateRunStatus.SUCCEEDED
        assert "bash (5.2.15-1)" in (run.output or "")


async def test_rollback_is_a_no_op_when_nothing_changed(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    _machine_id, run_id = await _make_machine_with_run(
        db_session_factory, snapshot={"bash": "5.2.15-2"}
    )

    fake_conn = _FakeConnection(snapshot_stdout="bash\t5.2.15-2\n", install_result=None)

    async def fake_open_connection(machine: object, secret: object, timeout_seconds: int) -> object:
        return fake_conn

    monkeypatch.setattr("app.ssh.updates.open_connection", fake_open_connection)

    await _rollback_machine_update(str(run_id))

    assert fake_conn.install_called is False
    async with db_session_factory() as session:
        run = await session.get(MachineUpdateRun, run_id)
        assert run is not None
        assert run.status == UpdateRunStatus.SUCCEEDED
        assert "Nothing to roll back" in (run.output or "")


async def test_rollback_fails_without_a_source_snapshot(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    _machine_id, run_id = await _make_machine_with_run(db_session_factory, snapshot=None)

    await _rollback_machine_update(str(run_id))

    async with db_session_factory() as session:
        run = await session.get(MachineUpdateRun, run_id)
        assert run is not None
        assert run.status == UpdateRunStatus.FAILED
        assert run.error


# --- The web/API endpoints: dispatch only, real SSH stays mocked out ----


async def test_rollback_endpoint_creates_a_new_run_and_enqueues_it(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(
        client, csrf_token, name="rollback-web", ip_address="10.9.9.21"
    )
    await _pin_host_key(db_session_factory, machine_id)

    async with db_session_factory() as session:
        source_run = MachineUpdateRun(
            machine_id=machine_id,
            strategy=UpgradeStrategy.DIST_UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
            package_snapshot=json.dumps({"bash": "5.2.15-1"}),
        )
        session.add(source_run)
        await session.commit()
        await session.refresh(source_run)
        source_run_id = source_run.id

    response = await client.post(
        f"/machines/{machine_id}/updates/{source_run_id}/rollback",
        data={"csrf_token": csrf_token},
    )
    assert response.status_code == 303

    async with db_session_factory() as session:
        result = await session.execute(
            MachineUpdateRun.__table__.select().where(
                MachineUpdateRun.rollback_of_run_id == source_run_id
            )
        )
        rollback_rows = result.fetchall()
        assert len(rollback_rows) == 1


async def test_rollback_endpoint_requires_a_snapshot(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(
        client, csrf_token, name="no-snapshot", ip_address="10.9.9.22"
    )
    await _pin_host_key(db_session_factory, machine_id)

    async with db_session_factory() as session:
        source_run = MachineUpdateRun(
            machine_id=machine_id,
            strategy=UpgradeStrategy.DIST_UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
        )
        session.add(source_run)
        await session.commit()
        await session.refresh(source_run)
        source_run_id = source_run.id

    response = await client.post(
        f"/machines/{machine_id}/updates/{source_run_id}/rollback",
        data={"csrf_token": csrf_token},
    )
    assert response.status_code == 400


async def test_rollback_endpoint_requires_action_updates_permission(
    client, login_as, db_session_factory
):
    from app.db.models.role import Permission

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(
        client, csrf_token, name="perm-check", ip_address="10.9.9.23"
    )
    await _pin_host_key(db_session_factory, machine_id)

    async with db_session_factory() as session:
        source_run = MachineUpdateRun(
            machine_id=machine_id,
            strategy=UpgradeStrategy.DIST_UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
            package_snapshot=json.dumps({"bash": "5.2.15-1"}),
        )
        session.add(source_run)
        await session.commit()
        await session.refresh(source_run)
        source_run_id = source_run.id

    await login_as(client, permissions={Permission.MACHINE_VIEW})
    response = await client.post(
        f"/machines/{machine_id}/updates/{source_run_id}/rollback",
        data={"csrf_token": csrf_token},
    )
    assert response.status_code == 403


async def test_api_rollback_endpoint(client, db_session_factory):
    import re

    await client.get("/account")
    csrf_token = client.cookies.get("csrftoken")
    token_response = await client.post(
        "/account/api-tokens", data={"name": "rollback-test", "csrf_token": csrf_token}
    )
    match = re.search(r"<textarea readonly rows=\"2\">([^<]+)</textarea>", token_response.text)
    assert match is not None
    headers = {"Authorization": f"Bearer {match.group(1)}"}

    await client.get("/machines/new")
    machine_id = await _create_machine(
        client, csrf_token, name="api-rollback", ip_address="10.9.9.24"
    )
    await _pin_host_key(db_session_factory, machine_id)

    async with db_session_factory() as session:
        source_run = MachineUpdateRun(
            machine_id=machine_id,
            strategy=UpgradeStrategy.DIST_UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
            package_snapshot=json.dumps({"bash": "5.2.15-1"}),
        )
        session.add(source_run)
        await session.commit()
        await session.refresh(source_run)
        source_run_id = source_run.id

    response = await client.post(
        f"/api/v1/machines/{machine_id}/updates/{source_run_id}/rollback", headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["rollback_of_run_id"] == str(source_run_id)
