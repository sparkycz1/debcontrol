"""Tune-up ("Komplet", Health → Tune-up): the plan, starting and queueing
(`app.services.tune_up`), the task that walks the steps
(`app.tasks.tune_up`), the pages, the REST API and the scheduled action."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models import tune_up as model
from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus
from app.db.models.role import Permission
from app.db.models.security_audit import SecurityAudit, SecurityAuditStatus
from app.db.models.tune_up import TuneUpRun
from app.services import tune_up
from app.tasks import jobs
from app.tasks import tune_up as task
from tests.test_update_history import _api_token

TASK = "app.tasks.tune_up.run_tune_up"


async def _machine(
    db_session_factory: Any, name: str, *, pinned: bool = True, **extra: Any
) -> uuid.UUID:
    async with db_session_factory() as db:
        machine = Machine(
            name=name,
            ip_address=f"10.30.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250 + 1}",
            port=22,
            username="admin",
            auth_method=AuthMethod.SSH_KEY,
            host_key_fingerprint="SHA256:test" if pinned else None,
            **extra,
        )
        db.add(machine)
        await db.commit()
        return machine.id


async def _machines(db_session_factory: Any, *ids: uuid.UUID) -> list[Machine]:
    async with db_session_factory() as db:
        return [m for m in [await db.get(Machine, i) for i in ids] if m is not None]


async def _runs(db_session_factory: Any) -> list[TuneUpRun]:
    async with db_session_factory() as db:
        return list((await db.execute(select(TuneUpRun))).scalars().all())


def _queued(celery_calls: Any) -> list[str]:
    return [args[0] for name, args, _kw in celery_calls if name == TASK]


# --- Plan and options ---------------------------------------------------------


def test_plan_skips_what_was_not_chosen() -> None:
    steps = tune_up.plan(tune_up.Options(docker_prune=False))
    by_key = {step["key"]: step for step in steps}
    assert [step["key"] for step in steps] == list(tune_up.STEPS)
    assert by_key["refresh"]["status"] == tune_up.STEP_PENDING
    assert by_key["final_refresh"]["status"] == tune_up.STEP_PENDING
    assert by_key["image_check"]["status"] == tune_up.STEP_PENDING
    assert by_key["docker_prune"]["status"] == tune_up.STEP_SKIPPED
    assert by_key["docker_prune"]["detail"] == {"code": "not_selected"}
    # Off unless asked for.
    assert by_key["reboot"]["status"] == tune_up.STEP_SKIPPED


def test_options_from_form_and_dict() -> None:
    options = tune_up.Options.from_form({"system_update": "1", "reboot": "on"})
    assert options.system_update and options.reboot
    assert not options.docker_update and not options.security_audit
    assert tune_up.Options.from_dict(None) == tune_up.Options()
    assert tune_up.Options.from_dict(options.as_dict()) == options


def test_prune_never_touches_volumes() -> None:
    assert task.PRUNE.all_images and task.PRUNE.images and task.PRUNE.build_cache
    assert not getattr(task.PRUNE, "volumes", False)


# --- Starting, queueing, stopping ----------------------------------------------


async def test_start_skips_busy_and_unpinned_and_caps_parallel_runs(
    db_session_factory: Any, celery_calls: Any
) -> None:
    ids = [await _machine(db_session_factory, f"box-{i}") for i in range(6)]
    unpinned = await _machine(db_session_factory, "no-key", pinned=False)
    async with db_session_factory() as db:
        machines = await _machines(db_session_factory, *ids, unpinned)
        batch_id, skipped = await tune_up.start(
            db, machines, tune_up.Options(), started_by="admin"
        )
    assert batch_id is not None
    assert skipped == 1
    runs = await _runs(db_session_factory)
    assert len(runs) == 6
    assert len(_queued(celery_calls)) == tune_up.MAX_PARALLEL
    assert sum(1 for r in runs if r.queued_at is not None) == tune_up.MAX_PARALLEL

    # A second start finds every machine busy.
    async with db_session_factory() as db:
        again, skipped_again = await tune_up.start(
            db, await _machines(db_session_factory, *ids), tune_up.Options(), started_by="x"
        )
    assert again is None and skipped_again == 6


async def test_cancel_ends_waiting_runs_and_flags_running_ones(
    db_session_factory: Any,
) -> None:
    ids = [await _machine(db_session_factory, f"c-{i}") for i in range(2)]
    async with db_session_factory() as db:
        batch_id, _ = await tune_up.start(
            db, await _machines(db_session_factory, *ids), tune_up.Options(), started_by="a"
        )
        assert batch_id is not None
        first = (await db.execute(select(TuneUpRun).order_by(TuneUpRun.id))).scalars().first()
        assert first is not None
        assert await tune_up.claim(db, first.id)
        assert await tune_up.cancel_batch(db, batch_id, None, actor="admin") == 2
    runs = {r.id: r for r in await _runs(db_session_factory)}
    assert runs[first.id].status == model.RUNNING
    assert runs[first.id].cancel_requested_by == "admin"
    other = next(r for r in runs.values() if r.id != first.id)
    assert other.status == model.CANCELLED
    assert all(s["status"] in tune_up.STEP_FINAL for s in other.steps)


async def test_self_host_waits_for_the_rest(
    db_session_factory: Any, celery_calls: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    own = await _machine(db_session_factory, "debcontrol-host")
    other = await _machine(db_session_factory, "other")

    class _Own:
        def hold_order(self, machine_id: uuid.UUID) -> int | None:
            return 1 if machine_id == own else None

    async def _find(_db: Any) -> _Own:
        return _Own()

    monkeypatch.setattr("app.services.self_host.find", _find)
    async with db_session_factory() as db:
        await tune_up.start(
            db, await _machines(db_session_factory, own, other), tune_up.Options(), started_by="a"
        )
    runs = {r.machine_id: r for r in await _runs(db_session_factory)}
    assert _queued(celery_calls) == [str(runs[other].id)]
    assert runs[own].queued_at is None


# --- The task ------------------------------------------------------------------


def _fake_jobs(monkeypatch: pytest.MonkeyPatch, calls: list[str], **fail: str) -> None:
    def fake(name: str, extra: dict[str, Any] | None = None) -> Any:
        async def _run(machine_id: str, *args: Any) -> dict[str, Any]:
            calls.append(name)
            if name in fail:
                return {"ok": False, "error": fail[name]}
            return {"ok": True, **(extra or {})}

        return _run

    for name in (
        "_refresh_machine_facts",
        "_refresh_machine_packages",
        "_refresh_machine_services",
        "_check_machine_readiness",
        "_check_machine_updates",
        "_sample_machine_monitoring",
        "_send_machine_power_command",
    ):
        monkeypatch.setattr(jobs, name, fake(name))
    monkeypatch.setattr(jobs, "_check_machine_image_updates", fake("images", {"updates": 2}))


async def _one_run(db_session_factory: Any, machine_id: uuid.UUID, options: Any) -> uuid.UUID:
    async with db_session_factory() as db:
        await tune_up.start(
            db, await _machines(db_session_factory, machine_id), options, started_by="admin"
        )
        run = await db.scalar(select(TuneUpRun).where(TuneUpRun.machine_id == machine_id))
        assert run is not None
        return uuid.UUID(str(run.id))


async def test_run_walks_every_step(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    calls: list[str] = []
    _fake_jobs(monkeypatch, calls)

    async def fake_update(run_id: str) -> None:
        async with db_session_factory() as db:
            run = await db.get(MachineUpdateRun, uuid.UUID(run_id))
            assert run is not None
            run.status = UpdateRunStatus.SUCCEEDED
            await db.commit()

    async def fake_audit(audit_id: str) -> None:
        async with db_session_factory() as db:
            audit = await db.get(SecurityAudit, uuid.UUID(audit_id))
            assert audit is not None
            audit.status = SecurityAuditStatus.SUCCEEDED
            audit.hardening_index = 71
            audit.warnings = [{"id": "X"}]
            await db.commit()

    monkeypatch.setattr(jobs, "_run_machine_update", fake_update)
    monkeypatch.setattr(jobs, "_run_security_audit", fake_audit)
    machine_id = await _machine(db_session_factory, "walker", reboot_required=True)
    run_id = await _one_run(
        db_session_factory, machine_id, tune_up.Options(reboot=True)
    )

    await task._run_tune_up(str(run_id))

    async with db_session_factory() as db:
        run = await db.get(TuneUpRun, run_id)
        assert run is not None
        steps = {s["key"]: s for s in run.steps}
        assert run.status == model.SUCCEEDED, run.steps
        assert steps["system_update"]["status"] == tune_up.STEP_OK
        assert steps["system_update"]["ref"]["update_run_id"]
        # No Docker on this machine: the Docker steps say so.
        assert steps["docker_prune"]["detail"] == {"code": "no_docker"}
        assert steps["security_audit"]["detail"] == {"code": "audit", "index": 71, "warnings": 1}
        assert steps["reboot"]["detail"] == {"code": "rebooting"}
        assert run.finished_at is not None
    assert "_send_machine_power_command" in calls


async def test_unreachable_machine_stops_after_refresh(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    calls: list[str] = []
    _fake_jobs(monkeypatch, calls, _refresh_machine_facts="Connection refused")
    machine_id = await _machine(db_session_factory, "down")
    run_id = await _one_run(db_session_factory, machine_id, tune_up.Options())

    await task._run_tune_up(str(run_id))

    async with db_session_factory() as db:
        run = await db.get(TuneUpRun, run_id)
        assert run is not None
        assert run.status == model.FAILED
        assert run.error == "Connection refused"
        assert all(
            s["detail"] == {"code": "unreachable"} for s in run.steps if s["key"] != "refresh"
            and s["detail"] != {"code": "not_selected"}
        )
    assert calls == ["_refresh_machine_facts"]


async def test_cancel_between_steps(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    calls: list[str] = []
    _fake_jobs(monkeypatch, calls)
    machine_id = await _machine(db_session_factory, "stopper")
    run_id = await _one_run(db_session_factory, machine_id, tune_up.Options())

    async def update_then_cancel(_run_id: str) -> None:
        async with db_session_factory() as db:
            await tune_up.cancel_batch(
                db, (await db.get(TuneUpRun, run_id)).batch_id, None, actor="admin"
            )
        raise jobs._TryLaterError("busy")

    async def done_at_once(*_args: Any) -> bool:
        return True

    monkeypatch.setattr(jobs, "_run_machine_update", update_then_cancel)
    monkeypatch.setattr(task, "_wait", done_at_once)

    await task._run_tune_up(str(run_id))

    async with db_session_factory() as db:
        run = await db.get(TuneUpRun, run_id)
        assert run is not None
        assert run.status == model.CANCELLED
        steps = {s["key"]: s for s in run.steps}
        assert steps["security_audit"]["detail"] == {"code": "cancelled"}


async def test_resumed_run_does_not_start_the_update_twice(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    calls: list[str] = []
    _fake_jobs(monkeypatch, calls)
    machine_id = await _machine(db_session_factory, "resumer")
    started: list[str] = []

    async def no_second_update(run_id: str) -> None:
        started.append(run_id)

    monkeypatch.setattr(jobs, "_run_machine_update", no_second_update)
    options = tune_up.Options(
        docker_update=False, docker_prune=False, image_scan=False, security_audit=False
    )
    run_id = await _one_run(db_session_factory, machine_id, options)
    beat = datetime.now(UTC) - timedelta(minutes=20)
    async with db_session_factory() as db:
        update_run = MachineUpdateRun(
            machine_id=machine_id, strategy="full_upgrade", status=UpdateRunStatus.SUCCEEDED
        )
        db.add(update_run)
        await db.flush()
        run = await db.get(TuneUpRun, run_id)
        assert run is not None
        steps = [dict(s) for s in run.steps]
        steps[0]["status"] = tune_up.STEP_OK
        steps[1].update(status=tune_up.STEP_RUNNING, ref={"update_run_id": str(update_run.id)})
        run.steps = steps
        run.status = model.RUNNING
        run.heartbeat_at = beat
        await db.commit()
        stale_beat = (await db.get(TuneUpRun, run_id)).heartbeat_at

    # The reconcile sweep hands it on, with the heartbeat it saw.
    handed = await task._reconcile_tune_up_runs()
    assert handed == 1
    # A task with a different heartbeat (someone else took it) gives up.
    await task._run_tune_up(str(run_id), resume_from=(beat - timedelta(seconds=1)).isoformat())
    async with db_session_factory() as db:
        assert (await db.get(TuneUpRun, run_id)).status == model.RUNNING

    await task._run_tune_up(str(run_id), resume_from=stale_beat.isoformat())

    async with db_session_factory() as db:
        run = await db.get(TuneUpRun, run_id)
        assert run is not None
        assert run.status == model.SUCCEEDED, run.steps
    assert started == []
    assert "_refresh_machine_services" not in calls  # the first refresh was already done


# --- Pages ---------------------------------------------------------------------


async def test_page_and_start_and_cancel(
    client: AsyncClient, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await _machine(db_session_factory, "page-box")

    page = await client.get(f"/health/tune-up?machine={machine_id}")
    assert page.status_code == 200
    assert f'<option value="{machine_id}" selected>' in page.text
    assert 'href="/health/tune-up"' in page.text

    csrf = client.cookies.get("csrftoken")
    started = await client.post(
        "/health/tune-up",
        data={
            "csrf_token": csrf,
            "target": "machine",
            "machine_id": str(machine_id),
            "system_update": "1",
            "docker_prune": "1",
        },
    )
    assert started.status_code == 303
    location = started.headers["location"]
    assert location.startswith("/health/tune-up/")
    batch_id = location.split("/")[-1].split("?")[0]
    assert len(_queued(celery_calls)) == 1

    detail = await client.get(location)
    assert detail.status_code == 200
    assert "page-box" in detail.text
    assert f'hx-get="/health/tune-up/{batch_id}?partial=1"' in detail.text
    partial = await client.get(f"/health/tune-up/{batch_id}?partial=1")
    assert partial.status_code == 200 and "<html" not in partial.text

    runs = await _runs(db_session_factory)
    assert runs[0].options["docker_update"] is False
    assert runs[0].options["docker_prune"] is True

    stopped = await client.post(
        f"/health/tune-up/{batch_id}/cancel", data={"csrf_token": csrf}
    )
    assert stopped.status_code == 303
    async with db_session_factory() as db:
        actions = (await db.execute(select(AuditLogEntry.action))).scalars().all()
    assert "machine.tune_up.start" in actions
    assert "machine.tune_up.cancel" in actions

    listing = await client.get("/health/tune-up")
    assert f'href="/health/tune-up/{batch_id}"' in listing.text
    assert 'href="/health/tune-up"' in (await client.get("/health")).text


async def test_view_only_account_sees_no_form_and_cannot_start(
    client: AsyncClient, db_session_factory: Any, login_as: Any
) -> None:
    machine_id = await _machine(db_session_factory, "ro-box")
    await login_as(client, permissions={Permission.MACHINE_VIEW})
    page = await client.get("/health/tune-up")
    assert page.status_code == 200
    assert 'action="/health/tune-up"' not in page.text
    csrf = client.cookies.get("csrftoken")
    denied = await client.post(
        "/health/tune-up",
        data={"csrf_token": csrf, "target": "machine", "machine_id": str(machine_id)},
    )
    assert denied.status_code == 403
    assert await _runs(db_session_factory) == []


async def test_reboot_needs_power_permission(
    client: AsyncClient, db_session_factory: Any, login_as: Any
) -> None:
    await _machine(db_session_factory, "no-power")
    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_UPDATES})
    page = await client.get("/health/tune-up")
    assert 'name="reboot"' not in page.text
    csrf = client.cookies.get("csrftoken")
    await client.post(
        "/health/tune-up", data={"csrf_token": csrf, "target": "all", "reboot": "1"}
    )
    runs = await _runs(db_session_factory)
    assert len(runs) == 1 and runs[0].options["reboot"] is False


async def test_machine_overview_offers_tune_up(
    client: AsyncClient, db_session_factory: Any
) -> None:
    machine_id = await _machine(db_session_factory, "overview-box")
    panel = await client.get(f"/machines/{machine_id}/health-panel")
    assert f'href="/health/tune-up?machine={machine_id}"' in panel.text


# --- REST API ------------------------------------------------------------------


async def test_api_start_read_cancel(client: AsyncClient, db_session_factory: Any) -> None:
    headers = await _api_token(client)
    machine_id = await _machine(db_session_factory, "api-box")

    started = await client.post(
        "/api/v1/tune-ups",
        json={"target": "machine", "machine_id": str(machine_id), "options": {"reboot": True}},
        headers=headers,
    )
    assert started.status_code == 201, started.text
    body = started.json()
    assert body["skipped"] == 0
    assert body["options"]["reboot"] is True and body["options"]["docker_prune"] is True
    assert body["runs"][0]["machine_name"] == "api-box"
    batch_id = body["batch_id"]

    busy = await client.post(
        "/api/v1/tune-ups",
        json={"target": "machine", "machine_id": str(machine_id)},
        headers=headers,
    )
    assert busy.status_code == 409

    one = await client.get(f"/api/v1/tune-ups/{batch_id}", headers=headers)
    assert one.status_code == 200 and len(one.json()["runs"][0]["steps"]) == len(tune_up.STEPS)
    listing = await client.get("/api/v1/tune-ups", headers=headers)
    assert [b["batch_id"] for b in listing.json()] == [batch_id]

    stopped = await client.post(f"/api/v1/tune-ups/{batch_id}/cancel", headers=headers)
    assert stopped.json() == {"stopped": 1}
    missing = await client.get(f"/api/v1/tune-ups/{uuid.uuid4()}", headers=headers)
    assert missing.status_code == 404
    nothing = await client.post(
        "/api/v1/tune-ups",
        json={"target": "machine", "machine_id": str(uuid.uuid4())},
        headers=headers,
    )
    assert nothing.status_code == 404


# --- Scheduled action ----------------------------------------------------------


async def test_scheduled_action_starts_a_tune_up(db_session_factory: Any) -> None:
    from app.scheduling.actions import get_action
    from app.scheduling.builtin_actions import register_builtin_actions

    register_builtin_actions()

    machine_id = await _machine(db_session_factory, "sched-box")
    action = get_action("tune_up")
    assert action is not None
    async with db_session_factory() as db:
        result = await action.run(
            db, await _machines(db_session_factory, machine_id), {"tune_up_reboot": "never"}
        )
    assert result.attempted == 1
    runs = await _runs(db_session_factory)
    assert runs[0].started_by == "schedule" and runs[0].options["reboot"] is False
