"""A Proxmox snapshot of the guest before its update
(`app.services.update_snapshots`, `app.ssh.proxmox_snapshots`): taken only
for a recognised guest, the update does not run when it fails, going back
is manual and confirmed, and old snapshots are listed, never deleted."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.scheduling.builtin_actions import _run_system_update
from app.services import update_snapshots
from app.ssh import detached_updates, proxmox, proxmox_snapshots
from app.tasks import jobs
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token

GUESTS = '[{"vmid":111,"name":"web1","type":"qemu","status":"running","node":"pve1"}]'
NAME = "debcontrol-20261001-030000"


async def _pair(db_session_factory: Any) -> tuple[uuid.UUID, uuid.UUID]:
    """A Proxmox host and the machine that is its guest 111."""
    host = await _add_machine(
        db_session_factory,
        name="pve1",
        ip_address="10.0.3.1",
        is_physical=True,
        pve_version="8.3.1",
        pve_guests=proxmox.parse_guests(GUESTS),
    )
    guest = await _add_machine(
        db_session_factory, name="web1", ip_address="10.0.3.2", is_physical=False
    )
    return host, guest


def test_names_carry_their_time_and_commands_refuse_anything_else() -> None:
    name = proxmox_snapshots.snapshot_name(datetime(2026, 10, 1, 3, 0, tzinfo=UTC))

    assert name == NAME
    assert proxmox_snapshots.snapshot_taken_at(name) == datetime(2026, 10, 1, 3, 0, tzinfo=UTC)
    assert proxmox_snapshots.snapshot_taken_at("before-upgrade") is None
    create = proxmox_snapshots.build_create_command("pve1", "qemu", 111, name)
    assert f"pvesh create /nodes/pve1/qemu/111/snapshot --snapname {name} " in create
    rollback = proxmox_snapshots.build_rollback_command("pve1", "lxc", 112, name)
    assert f"/nodes/pve1/lxc/112/snapshot/{name}/rollback" in rollback
    assert rollback.endswith("/nodes/pve1/lxc/112/status/start >/dev/null 2>&1; exit 0")
    for bad in (
        ("pve1; rm -rf /", "qemu", 111, name),
        ("pve1", "docker", 111, name),
        ("pve1", "qemu", 0, name),
        ("pve1", "qemu", 111, "mine; reboot"),
    ):
        with pytest.raises(ValueError):
            proxmox_snapshots.build_create_command(*bad)


def test_listing_tells_gone_from_unreadable() -> None:
    raw = (
        "===SNAP qemu 111===\n"
        f'[{{"name":"{NAME}"}},{{"name":"mine"}},{{"name":"current"}}]\n'
        "===SNAP lxc 112===\n\n"
        "===SNAP qemu 113===\n[]\n"
    )

    listed = proxmox_snapshots.parse_list_output(raw)
    noted = [
        {"vmid": 111, "type": "qemu", "name": NAME},
        {"vmid": 111, "type": "qemu", "name": "debcontrol-20260101-000000"},
        {"vmid": 112, "type": "lxc", "name": NAME},
        {"vmid": 113, "type": "qemu", "name": NAME},
    ]

    assert listed == {("qemu", 111): [NAME], ("lxc", 112): None, ("qemu", 113): []}
    # Kept: still there, and the one whose guest could not be read.
    assert [(s["vmid"], s["name"]) for s in update_snapshots.reconcile(noted, listed)] == [
        (111, NAME),
        (112, NAME),
    ]


async def _run_update(
    db_session_factory: Any, monkeypatch: Any, machine_id: uuid.UUID, *, snapshot: Any
) -> tuple[MachineUpdateRun, list[str]]:
    """Run one update with `snapshot_before`; `snapshot` stands in for the
    SSH call to the Proxmox host. Returns the run and what was executed."""
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    done: list[str] = []

    async def fake_start(*_args: Any, **_kwargs: Any) -> bool:
        done.append("update")
        return True

    async def fake_follow(*_args: Any, **_kwargs: Any) -> Any:
        return detached_updates.FollowResult("finished", 0, "ok")

    async def fake_packages(*_args: Any, **_kwargs: Any) -> dict[str, str]:
        return {}

    async def fake_create(_host: Any, _secret: Any, guest: Any, name: str, _timeout: int) -> None:
        done.append(f"snapshot {guest['vmid']}")
        await snapshot(name)

    monkeypatch.setattr(detached_updates, "start", fake_start)
    monkeypatch.setattr(detached_updates, "follow", fake_follow)
    monkeypatch.setattr(jobs, "capture_package_snapshot", fake_packages)
    monkeypatch.setattr(proxmox_snapshots, "create_snapshot", fake_create)
    async with db_session_factory() as db:
        run = MachineUpdateRun(
            machine_id=machine_id, strategy=UpgradeStrategy.UPGRADE, snapshot_before=True
        )
        db.add(run)
        await db.commit()
        run_id = run.id
    await jobs._run_machine_update(str(run_id))
    async with db_session_factory() as db:
        stored = await db.get(MachineUpdateRun, run_id)
        assert stored is not None
        return stored, done


async def test_a_guest_is_snapshotted_then_updated(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    host_id, guest_id = await _pair(db_session_factory)

    async def ok(_name: str) -> None:
        return None

    run, done = await _run_update(db_session_factory, monkeypatch, guest_id, snapshot=ok)

    assert done == ["snapshot 111", "update"]
    assert run.status == UpdateRunStatus.SUCCEEDED
    assert run.snapshot_name is not None and run.snapshot_name.startswith("debcontrol-")
    assert (run.snapshot_host_id, run.snapshot_vmid, run.snapshot_type, run.snapshot_node) == (
        host_id,
        111,
        "qemu",
        "pve1",
    )
    async with db_session_factory() as db:
        host = await db.get(Machine, host_id)
        assert host is not None
        assert host.pve_debcontrol_snapshots == [
            {
                "vmid": 111,
                "type": "qemu",
                "node": "pve1",
                "name": run.snapshot_name,
                "machine_name": "web1",
            }
        ]


async def test_a_failed_snapshot_stops_the_update(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    _host_id, guest_id = await _pair(db_session_factory)

    async def refuse(_name: str) -> None:
        raise proxmox_snapshots.SnapshotError("snapshot feature is not available")

    run, done = await _run_update(db_session_factory, monkeypatch, guest_id, snapshot=refuse)

    assert done == ["snapshot 111"]
    assert run.status == UpdateRunStatus.FAILED
    assert "snapshot feature is not available" in (run.error or "")
    assert "Nothing was updated." in (run.error or "")
    assert run.snapshot_name is None


async def test_a_machine_that_is_no_guest_is_updated_without_one(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    lone = await _add_machine(db_session_factory, name="lone", ip_address="10.0.3.9")

    async def never(_name: str) -> None:
        raise AssertionError("no snapshot expected")

    run, done = await _run_update(db_session_factory, monkeypatch, lone, snapshot=never)

    assert done == ["update"]
    assert run.status == UpdateRunStatus.SUCCEEDED
    assert run.snapshot_note == update_snapshots.NOTE_NOT_A_GUEST


async def _finished_run(db_session_factory: Any, host_id: uuid.UUID, guest_id: uuid.UUID) -> Any:
    async with db_session_factory() as db:
        run = MachineUpdateRun(
            machine_id=guest_id,
            strategy=UpgradeStrategy.UPGRADE,
            status=UpdateRunStatus.SUCCEEDED,
            snapshot_before=True,
            snapshot_name=NAME,
            snapshot_host_id=host_id,
            snapshot_node="pve1",
            snapshot_type="qemu",
            snapshot_vmid=111,
            finished_at=datetime.now(UTC),
        )
        db.add(run)
        await db.commit()
        return run.id


async def test_rolling_back_needs_the_machines_name(
    client: AsyncClient, db_session_factory: Any, celery_calls: Any
) -> None:
    host_id, guest_id = await _pair(db_session_factory)
    run_id = await _finished_run(db_session_factory, host_id, guest_id)
    base = f"/machines/{guest_id}/updates/{run_id}"

    page = await client.get(base)
    csrf = client.cookies.get("csrftoken")
    wrong = await client.post(
        f"{base}/snapshot-rollback",
        data={"csrf_token": csrf, "confirm_name": "web"},
        follow_redirects=False,
    )
    right = await client.post(
        f"{base}/snapshot-rollback",
        data={"csrf_token": csrf, "confirm_name": "web1"},
        follow_redirects=False,
    )
    other = await client.post(
        f"/machines/{host_id}/updates/{run_id}/snapshot-rollback",
        data={"csrf_token": csrf, "confirm_name": "pve1"},
    )

    assert f"Proxmox snapshot {NAME} of VM 111 was taken" in page.text
    assert "Roll back the whole machine" in page.text
    assert wrong.status_code == 303 and "snapshot_error=" in wrong.headers["location"]
    assert right.status_code == 303 and "snapshot_notice=" in right.headers["location"]
    assert other.status_code == 404
    started = [c for c in celery_calls if c[0] == "app.tasks.jobs.rollback_to_snapshot"]
    assert [c[1] for c in started] == [(str(run_id),)]
    async with db_session_factory() as db:
        outcomes = [
            entry.outcome.value
            for entry in (
                await db.execute(
                    select(AuditLogEntry).where(
                        AuditLogEntry.action == "machine.update.snapshot_rollback"
                    )
                )
            )
            .scalars()
            .all()
        ]
    assert sorted(outcomes) == ["denied", "success"]


async def test_rollback_job_marks_the_run_and_reports_failure(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    host_id, guest_id = await _pair(db_session_factory)
    run_id = await _finished_run(db_session_factory, host_id, guest_id)
    calls: list[tuple[str, str, int, str]] = []

    async def fake_rollback(
        _host: Any, _secret: Any, node: str, kind: str, vmid: int, name: str, _timeout: int
    ) -> None:
        calls.append((node, kind, vmid, name))
        if len(calls) > 1:
            raise proxmox_snapshots.SnapshotError("snapshot does not exist")

    monkeypatch.setattr(proxmox_snapshots, "rollback_snapshot", fake_rollback)

    first = await jobs._rollback_to_snapshot(str(run_id))
    second = await jobs._rollback_to_snapshot(str(run_id))

    assert first == {"ok": True}
    assert second["ok"] is False and "snapshot does not exist" in second["error"]
    assert calls[0] == ("pve1", "qemu", 111, NAME)
    async with db_session_factory() as db:
        run = await db.get(MachineUpdateRun, run_id)
        assert run is not None and run.snapshot_rolled_back_at is not None


async def test_old_snapshots_are_listed_and_forgotten_once_removed(
    client: AsyncClient, db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    host_id, _guest_id = await _pair(db_session_factory)
    old = proxmox_snapshots.snapshot_name(datetime.now(UTC) - timedelta(days=20))
    fresh = proxmox_snapshots.snapshot_name(datetime.now(UTC) - timedelta(days=1))
    async with db_session_factory() as db:
        host = await db.get(Machine, host_id)
        assert host is not None
        host.pve_debcontrol_snapshots = [
            {"vmid": 111, "type": "qemu", "node": "pve1", "name": name, "machine_name": "web1"}
            for name in (old, fresh)
        ]
        await db.commit()
    headers = await _api_token(client)

    page = await client.get(f"/machines/{host_id}/proxmox")
    api = (await client.get(f"/api/v1/machines/{host_id}/proxmox", headers=headers)).json()

    async def fake_list(*_args: Any, **_kwargs: Any) -> dict[tuple[str, int], list[str] | None]:
        return {("qemu", 111): [fresh]}

    monkeypatch.setattr(proxmox_snapshots, "list_snapshots", fake_list)
    left = await jobs._check_debcontrol_snapshots(str(host_id))
    after = await client.get(f"/machines/{host_id}/proxmox")

    assert "Snapshots left from updates" in page.text
    assert old in page.text and fresh not in page.text
    assert "20 days old" in page.text
    assert [s["name"] for s in api["debcontrol_snapshots"]] == [old, fresh]
    assert left == 1
    assert "Snapshots left from updates" not in after.text


async def test_every_way_of_starting_an_update_carries_the_option(
    client: AsyncClient, db_session_factory: Any, celery_calls: Any
) -> None:
    _host_id, guest_id = await _pair(db_session_factory)
    headers = await _api_token(client)
    await client.get("/machines")
    csrf = client.cookies.get("csrftoken")

    history = await client.get(f"/machines/{guest_id}/updates")
    await client.post(
        f"/machines/{guest_id}/updates",
        data={"csrf_token": csrf, "strategy": "upgrade", "snapshot_before": "true"},
    )
    await client.post(
        "/machines/bulk/updates",
        data={
            "csrf_token": csrf,
            "strategy": "upgrade",
            "machine_ids": str(guest_id),
            "snapshot_before": "true",
        },
    )
    await client.post(
        f"/api/v1/machines/{guest_id}/updates",
        headers=headers,
        json={"strategy": "upgrade", "snapshot_before": True},
    )
    plain = await client.post(
        f"/api/v1/machines/{guest_id}/updates", headers=headers, json={"strategy": "upgrade"}
    )
    async with db_session_factory() as db:
        machines = list(
            (await db.execute(select(Machine).where(Machine.id == guest_id))).scalars().all()
        )
        await _run_system_update(db, machines, {"strategy": "upgrade", "snapshot": "proxmox"})
        await _run_system_update(db, machines, {"strategy": "upgrade"})
        flags = [
            run.snapshot_before
            for run in (
                await db.execute(select(MachineUpdateRun).order_by(MachineUpdateRun.created_at))
            )
            .scalars()
            .all()
        ]

    assert 'name="snapshot_before"' in history.text
    assert plain.json()["snapshot"]["requested"] is False
    assert sorted(flags) == [False, False, True, True, True, True]
