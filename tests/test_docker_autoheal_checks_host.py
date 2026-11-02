"""Docker new features, part 3: scheduled start/stop/restart of containers
and stacks (`docker_actions.trigger_power`, the `docker_power` scheduled
action), autoheal (`app.services.autoheal`), endpoint checks made from
container web links (`app.services.docker_endpoint_checks`) and the
Docker host check (`app.ssh.docker_host`, `app.services.docker_host_check`)
— below the web layer and through the pages and the REST API."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.core.app_settings import get_or_create_app_settings
from app.db.models.docker import DockerContainerSetting, DockerJob
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.machine import Machine
from app.db.models.notification_rule import NotificationEventType
from app.db.models.role import Permission
from app.scheduling.actions import get_action
from app.scheduling.builtin_actions import register_builtin_actions
from app.services import (
    autoheal,
    docker_actions,
    docker_endpoint_checks,
    docker_host_check,
    image_versions,
    self_host,
)
from app.services.notifications import render_template
from app.ssh import docker_host, monitoring
from app.tasks import jobs
from tests.conftest import RecordedCeleryCalls
from tests.test_docker_tasks_jobs import _add, _get, _machine
from tests.test_docker_web_support import audit_entries, csrf_token, make_docker_machine
from tests.test_update_history import _api_token

RESTART_TASK = "app.tasks.jobs.run_container_action"


@pytest.fixture
def own_host(monkeypatch: pytest.MonkeyPatch) -> set[uuid.UUID]:
    """The machines debcontrol itself runs on (`self_host.find`)."""
    hosts: set[uuid.UUID] = set()

    async def fake_find(_db: Any) -> self_host.SelfHost:
        return self_host.SelfHost(hosts=frozenset(hosts))

    monkeypatch.setattr(self_host, "find", fake_find)
    return hosts


def _container(name: str, **extra: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "name": name,
        "state": "running",
        "health": None,
        "compose_project": "",
        "ports": "",
        "link_labels": {},
    }
    values.update(extra)
    return values


async def _rows(db_session_factory: Any, model: Any) -> list[Any]:
    async with db_session_factory() as db:
        return list((await db.execute(select(model))).scalars().all())


# --- Scheduled start / stop / restart -------------------------------------------


def test_names_are_split_on_commas_and_spaces() -> None:
    assert docker_actions.parse_names(" web, db  worker,web ") == ["web", "db", "worker"]
    assert docker_actions.parse_names("") == []
    assert len(docker_actions.parse_names(" ".join(f"c{i}" for i in range(80)))) == 50


def test_the_power_action_needs_action_power() -> None:
    register_builtin_actions()
    spec = get_action("docker_power")
    assert spec is not None
    assert spec.extra_permission == Permission.ACTION_POWER
    assert spec.destructive is True
    assert [p.key for p in spec.params] == [
        "docker_power_action",
        "docker_power_kind",
        "docker_names",
    ]


async def test_scheduled_stop_acts_on_named_containers_only_and_never_on_debcontrol(
    db_session_factory: Any, celery_calls: RecordedCeleryCalls, own_host: set[uuid.UUID]
) -> None:
    machine = _machine(
        docker_containers=[
            _container("web"),
            _container("db"),
            _container("debcontrol-app-1", compose_project="debcontrol"),
        ]
    )
    other = _machine(name="docker2", docker_containers=[_container("db")])
    without = _machine(name="docker3", docker_containers=[_container("cache")])
    await _add(db_session_factory, machine, other, without)
    own_host.add(machine.id)

    async with db_session_factory() as db:
        attempted, skipped = await docker_actions.trigger_power(
            db,
            [machine, other, without],
            action="stop",
            kind="containers",
            names=["web", "db", "debcontrol-app-1"],
            started_by="schedule",
        )

    calls = [c for c in celery_calls if c[0] == RESTART_TASK]
    assert (attempted, skipped) == (2, 1)
    assert calls[0][1] == (str(machine.id),)
    assert calls[0][2] == {"action": "stop", "containers": ["web", "db"]}
    assert calls[1][2] == {"action": "stop", "containers": ["db"]}


async def test_scheduled_start_may_start_debcontrol_itself(
    db_session_factory: Any, celery_calls: RecordedCeleryCalls, own_host: set[uuid.UUID]
) -> None:
    machine = _machine(
        docker_containers=[_container("debcontrol-app-1", compose_project="debcontrol")]
    )
    await _add(db_session_factory, machine)
    own_host.add(machine.id)

    async with db_session_factory() as db:
        await docker_actions.trigger_power(
            db,
            [machine],
            action="start",
            kind="containers",
            names=["debcontrol-app-1"],
            started_by="schedule",
        )

    assert [c[2]["containers"] for c in celery_calls if c[0] == RESTART_TASK] == [
        ["debcontrol-app-1"]
    ]


async def test_scheduled_stack_restart_queues_a_job_per_project(
    db_session_factory: Any, celery_calls: RecordedCeleryCalls
) -> None:
    machine = _machine(
        docker_containers=[
            _container("test-web-1", compose_project="test"),
            _container("test-db-1", compose_project="test"),
            _container("prod-web-1", compose_project="prod"),
        ]
    )
    await _add(db_session_factory, machine)

    async with db_session_factory() as db:
        attempted, _ = await docker_actions.trigger_power(
            db, [machine], action="restart", kind="stacks", names=["test"], started_by="schedule"
        )

    rows = await _rows(db_session_factory, DockerJob)
    assert attempted == 1
    assert [(j.kind, j.target, j.params, j.started_by) for j in rows] == [
        ("stack_action", "test", {"action": "restart"}, "schedule")
    ]


async def test_the_scheduled_action_without_names_does_nothing(
    db_session_factory: Any, celery_calls: RecordedCeleryCalls
) -> None:
    register_builtin_actions()
    spec = get_action("docker_power")
    assert spec is not None
    machine = _machine()
    await _add(db_session_factory, machine)
    async with db_session_factory() as db:
        result = await spec.run(db, [machine], {"docker_names": " , "})
    assert (result.attempted, result.skipped) == (0, 1)
    assert not [c for c in celery_calls if c[0] == RESTART_TASK]


# --- Autoheal ----------------------------------------------------------------------


def _setting(machine: Machine, name: str = "api", **extra: Any) -> DockerContainerSetting:
    values: dict[str, Any] = {
        "machine_id": machine.id,
        "name": name,
        "auto_update": False,
        "vulnerability_gate": "off",
        "update_policy": "any",
        "autoheal": True,
        "autoheal_max_per_hour": 3,
    }
    values.update(extra)
    return DockerContainerSetting(**values)


def test_autoheal_decides_restart_wait_or_give_up() -> None:
    now = datetime.now(UTC)
    machine = _machine()

    def ago(minutes: int) -> str:
        return (now - timedelta(minutes=minutes)).isoformat()

    assert autoheal.decide(_setting(machine), now) == "restart"
    # Too soon after the previous restart.
    assert autoheal.decide(_setting(machine, autoheal_restarts=[ago(1)]), now) == "wait"
    full = [ago(50), ago(30), ago(10)]
    assert autoheal.decide(_setting(machine, autoheal_restarts=full), now) == "give_up"
    gave_up = _setting(machine, autoheal_restarts=full, autoheal_gave_up_at=now)
    assert autoheal.decide(gave_up, now) == "wait"
    # Restarts older than an hour no longer count.
    old = [ago(90), ago(80), ago(70)]
    assert autoheal.decide(_setting(machine, autoheal_restarts=old), now) == "restart"
    assert autoheal.decide(_setting(machine, autoheal_restarts=["junk"]), now) == "restart"


async def test_autoheal_restarts_an_unhealthy_container_and_tells_about_it(
    db_session_factory: Any,
    celery_calls: RecordedCeleryCalls,
    monkeypatch: pytest.MonkeyPatch,
    own_host: set[uuid.UUID],
) -> None:
    machine = _machine(
        docker_containers=[
            _container("api", health="unhealthy"),
            _container("web", health="unhealthy"),  # autoheal off
            _container("ok", health="healthy"),
        ]
    )
    await _add(db_session_factory, machine, _setting(machine), _setting(machine, "ok"))
    sent: list[tuple[NotificationEventType, dict[str, Any]]] = []

    async def fake_notify(_db: Any, event: NotificationEventType, **kwargs: Any) -> None:
        sent.append((event, kwargs["context"]))

    monkeypatch.setattr(autoheal, "notify", fake_notify)

    async with db_session_factory() as db:
        outcome = await autoheal.apply(db, machine)

    assert outcome.restarted == ["api"] and outcome.gave_up == []
    calls = [c for c in celery_calls if c[0] == RESTART_TASK]
    assert calls == [
        (RESTART_TASK, (str(machine.id),), {"action": "restart", "containers": ["api"]})
    ]
    stored = {s.name: s for s in await _rows(db_session_factory, DockerContainerSetting)}
    assert len(stored["api"].autoheal_restarts or []) == 1
    assert stored["ok"].autoheal_restarts is None
    assert sent[0][0] == NotificationEventType.DOCKER_CONTAINER_AUTOHEAL
    assert "api: restarted (1 of 3 this hour)" in str(sent[0][1]["details"])
    entries = await audit_entries(db_session_factory, "machine.docker.container.autoheal")
    assert [(e.actor, (e.details or {})["result"]) for e in entries] == [
        ("autoheal (automatic)", "restarted")
    ]


async def test_autoheal_gives_up_once_after_the_hourly_limit(
    db_session_factory: Any,
    celery_calls: RecordedCeleryCalls,
    monkeypatch: pytest.MonkeyPatch,
    own_host: set[uuid.UUID],
) -> None:
    now = datetime.now(UTC)
    machine = _machine(docker_containers=[_container("api", health="unhealthy")])
    restarts = [(now - timedelta(minutes=m)).isoformat() for m in (40, 30, 20)]
    await _add(db_session_factory, machine, _setting(machine, autoheal_restarts=restarts))
    sent: list[Any] = []

    async def fake_notify(_db: Any, event: NotificationEventType, **kwargs: Any) -> None:
        sent.append(kwargs["context"])

    monkeypatch.setattr(autoheal, "notify", fake_notify)

    async with db_session_factory() as db:
        first = await autoheal.apply(db, machine)
    async with db_session_factory() as db:
        second = await autoheal.apply(db, machine)

    assert first.gave_up == ["api"] and not first.restarted
    assert not second.gave_up and not second.restarted
    assert len(sent) == 1 and "gave up" in sent[0]["details"]
    assert not [c for c in celery_calls if c[0] == RESTART_TASK]
    entries = await audit_entries(db_session_factory, "machine.docker.container.autoheal")
    assert [(e.details or {})["result"] for e in entries] == ["gave_up"]


async def test_autoheal_never_restarts_debcontrol_itself(
    db_session_factory: Any, celery_calls: RecordedCeleryCalls, own_host: set[uuid.UUID]
) -> None:
    machine = _machine(
        docker_containers=[
            _container("debcontrol-web-1", health="unhealthy", compose_project="debcontrol")
        ]
    )
    await _add(db_session_factory, machine, _setting(machine, "debcontrol-web-1"))
    own_host.add(machine.id)

    async with db_session_factory() as db:
        outcome = await autoheal.apply(db, machine)

    assert not outcome.restarted
    assert not [c for c in celery_calls if c[0] == RESTART_TASK]


async def test_autoheal_reads_nothing_when_all_is_healthy(db_session_factory: Any) -> None:
    machine = _machine(docker_containers=[_container("api", health="healthy")])

    class NoDb:
        async def execute(self, *_args: Any) -> Any:
            raise AssertionError("no query expected")

    outcome = await autoheal.apply(NoDb(), machine)  # type: ignore[arg-type]
    assert not outcome.restarted and not outcome.gave_up


@pytest.mark.parametrize("locale", ["en", "cs"])
def test_autoheal_notification_template(locale: str) -> None:
    context = {
        "containers": "api",
        "machine_name": "docker1",
        "machine_ip": "10.0.0.7",
        "timestamp": "2026-11-01T10:00:00Z",
        "details": "api: restarted (1 of 3 this hour)",
    }
    subject, body = render_template(
        NotificationEventType.DOCKER_CONTAINER_AUTOHEAL, None, context, locale=locale
    )
    assert "api" in subject and "docker1" in subject
    assert "api: restarted" in body and "{" not in subject + body


# --- Endpoint checks from container links ----------------------------------------


def test_wanted_checks_follow_the_running_containers_links() -> None:
    machine = _machine(
        docker_containers=[
            _container("web", ports="0.0.0.0:8080->80/tcp, 0.0.0.0:8443->443/tcp"),
            _container(
                "app",
                link_labels={"traefik.http.routers.app.rule": "Host(`app.example.com`)"},
            ),
            _container(
                "api",
                ports="0.0.0.0:9000->9000/tcp",
                link_labels={"debcontrol.check-path": "/healthz"},
            ),
            _container(
                "quiet", ports="0.0.0.0:81->80/tcp", link_labels={"debcontrol.check": "false"}
            ),
            _container("stopped", state="exited", ports="0.0.0.0:82->80/tcp"),
            _container("local", ports="127.0.0.1:83->80/tcp"),
        ]
    )

    wanted = docker_endpoint_checks.wanted_checks(machine)

    assert [(w.key, w.url, w.verify_tls) for w in wanted] == [
        ("web|http://10.0.0.7:8080", "http://10.0.0.7:8080", False),
        ("web|https://10.0.0.7:8443", "https://10.0.0.7:8443", False),
        ("app|https://app.example.com", "https://app.example.com", True),
        ("api|http://10.0.0.7:9000/healthz", "http://10.0.0.7:9000/healthz", False),
    ]
    assert wanted[0].name == "web · :8080"


def test_a_bad_check_path_is_ignored() -> None:
    machine = _machine(
        docker_containers=[
            _container(
                "api",
                ports="0.0.0.0:9000->9000/tcp",
                link_labels={"debcontrol.check-path": "//evil.example.com/x"},
            )
        ]
    )
    assert [w.url for w in docker_endpoint_checks.wanted_checks(machine)] == [
        "http://10.0.0.7:9000"
    ]


async def test_sync_creates_keeps_and_removes_automatic_checks(db_session_factory: Any) -> None:
    machine = _machine(docker_containers=[_container("web", ports="0.0.0.0:8080->80/tcp")])
    manual = EndpointCheck(name="mine", kind="http", target="http://10.0.0.7:8080")
    await _add(db_session_factory, machine, manual)

    async with db_session_factory() as db:
        assert await docker_endpoint_checks.sync(db, machine, enabled=True) == (1, 0)
    async with db_session_factory() as db:
        assert await docker_endpoint_checks.sync(db, machine, enabled=True) == (0, 0)
    checks = [c for c in await _rows(db_session_factory, EndpointCheck) if c.auto_key]
    assert [(c.kind, c.target, c.source_machine_id, c.interval_seconds) for c in checks] == [
        ("http", "http://10.0.0.7:8080", machine.id, 300)
    ]

    machine.docker_containers = []
    async with db_session_factory() as db:
        assert await docker_endpoint_checks.sync(db, machine, enabled=True) == (0, 1)
    machine.docker_containers = [_container("web", ports="0.0.0.0:8080->80/tcp")]
    async with db_session_factory() as db:
        await docker_endpoint_checks.sync(db, machine, enabled=True)
    async with db_session_factory() as db:
        assert await docker_endpoint_checks.sync(db, machine, enabled=False) == (0, 1)

    # The person's own check is never touched.
    assert [c.name for c in await _rows(db_session_factory, EndpointCheck)] == ["mine"]


async def test_a_monitoring_sample_runs_autoheal_and_the_check_sync(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine = _machine(docker_events_since=1767225600)
    await _add(db_session_factory, machine)
    async with db_session_factory() as db:
        settings = await get_or_create_app_settings(db)
        settings.docker_endpoint_checks = True
        await db.commit()
    ps_row = {
        "Names": "web",
        "ID": "abc",
        "Image": "nginx",
        "State": "running",
        "Status": "Up 1 hour (unhealthy)",
        "Ports": "0.0.0.0:8080->80/tcp",
        "Labels": "",
    }
    raw = "\n".join(["===DOCKER===", "@@PS", json.dumps(ps_row), "@@EVENTS", "1767225660"])
    healed: list[str] = []

    async def fake_sample(*_args: Any) -> Any:
        return monitoring.parse_monitoring_output(raw, is_physical=False)

    async def fake_credential(*_args: Any) -> None:
        return None

    async def fake_apply(_db: Any, m: Machine) -> autoheal.AutohealOutcome:
        healed.extend(c["name"] for c in m.docker_containers or [] if c["health"] == "unhealthy")
        return autoheal.AutohealOutcome()

    monkeypatch.setattr(jobs, "gather_monitoring_sample", fake_sample)
    monkeypatch.setattr(jobs, "resolve_machine_credential", fake_credential)
    monkeypatch.setattr(autoheal, "apply", fake_apply)

    assert (await jobs._sample_machine_monitoring(str(machine.id)))["ok"] is True

    assert healed == ["web"]
    checks = await _rows(db_session_factory, EndpointCheck)
    assert [c.target for c in checks] == ["http://10.0.0.7:8080"]


# --- Docker host check ------------------------------------------------------------


def _host_raw(**over: Any) -> str:
    info = {
        "ServerVersion": "27.3.1",
        "Driver": "overlay2",
        "LoggingDriver": "json-file",
        "LiveRestoreEnabled": False,
        "CgroupVersion": "2",
        "DockerRootDir": "/var/lib/docker",
        "Warnings": ["WARNING: No swap limit support"],
        **over.get("info", {}),
    }
    containers = over.get(
        "containers",
        [
            {
                "id": "a" * 64,
                "name": "/web",
                "running": True,
                "memory": 0,
                "log": {"Type": "json-file", "Config": {}},
                "privileged": False,
                "network": "bridge",
                "pid": "",
                "socket": False,
            },
            {
                "id": "b" * 64,
                "name": "/traefik",
                "running": True,
                "memory": 268435456,
                "log": {"Type": "json-file", "Config": {"max-size": "10m"}},
                "privileged": True,
                "network": "host",
                "pid": "",
                "socket": True,
                "_": False,
            },
        ],
    )
    lines = ["@@INFO", json.dumps(info), "@@DAEMON", over.get("daemon", ""), "@@INSPECT"]
    lines += [json.dumps(c) for c in containers]
    lines += ["@@LOGS", *over.get("logs", [f"{300 * 1024 * 1024} {'a' * 64}-json.log"]), "@@END"]
    return "\n".join(lines)


def test_the_host_command_is_read_only_and_uses_the_docker_access_probe() -> None:
    command = docker_host.HOST_CHECK_COMMAND
    assert command.count("$D info") == 2 and "$D inspect" in command
    for verb in (" rm ", " stop ", " kill ", " restart ", " update ", "> /", ">/etc"):
        assert verb not in command
    assert "@@NOACCESS" in command


def test_the_host_check_finds_what_commonly_goes_wrong() -> None:
    host = docker_host.parse_host_output(_host_raw())
    machine = _machine(
        apt_upgradable_packages=[
            {"name": "curl", "new_version": "8"},
            {"name": "docker-ce", "new_version": "5:28.0.0"},
        ]
    )

    check = docker_host_check.evaluate(host, machine)
    findings = {f["code"]: f for f in check["findings"]}

    assert check["ok"] is True
    assert check["facts"]["version"] == "27.3.1" and check["facts"]["running"] == 2
    assert findings["log_rotation"]["items"] == ["web"] and findings["log_rotation"]["default"]
    assert findings["big_logs"]["items"] == ["web: 300 MB"]
    assert findings["engine_update"]["items"] == ["docker-ce 5:28.0.0"]
    assert findings["no_memory_limit"]["items"] == ["web"]
    assert findings["privileged"]["items"] == ["traefik"]
    assert findings["docker_socket"]["items"] == ["traefik"]
    assert findings["host_namespace"]["items"] == ["traefik"]
    assert findings["live_restore"]["level"] == "info"
    assert findings["docker_warnings"]["items"] == ["WARNING: No swap limit support"]
    assert "storage_driver" not in findings and "daemon_json_invalid" not in findings
    # Warnings first.
    levels = [f["level"] for f in check["findings"]]
    assert levels == sorted(levels, key=docker_host_check.LEVELS.index)
    assert docker_host_check.warn_count(check) == 4


def test_a_daemon_default_with_max_size_rotates_every_json_file_container() -> None:
    raw = _host_raw(
        daemon=json.dumps({"log-opts": {"max-size": "20m"}, "live-restore": True}),
        info={"LiveRestoreEnabled": True, "Driver": "devicemapper"},
        logs=["unreadable"],
    )
    host = docker_host.parse_host_output(raw)
    check = docker_host_check.evaluate(host, _machine())
    codes = {f["code"] for f in check["findings"]}

    assert "log_rotation" not in codes and "live_restore" not in codes
    assert "storage_driver" in codes and "big_logs" not in codes
    assert check["facts"]["log_max_size"] == "20m"
    assert check["facts"]["logs_readable"] is False


def test_a_broken_daemon_json_and_no_access_are_reported() -> None:
    broken = docker_host.parse_host_output(_host_raw(daemon='{"log-driver": '))
    assert {f["code"] for f in docker_host_check.evaluate(broken, _machine())["findings"]} >= {
        "daemon_json_invalid"
    }
    no_access = docker_host.parse_host_output("@@NOACCESS\n")
    assert docker_host_check.evaluate(no_access, _machine())["error"] == "no_access"
    assert docker_host_check.evaluate({"info": None}, _machine())["error"] == "no_info"


async def test_the_image_check_also_stores_the_host_check(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine = _machine()
    await _add(db_session_factory, machine)

    async def fake_check(*_args: Any, **_kwargs: Any) -> Any:
        return {"nginx:1.27": "current"}, {}, {}

    async def fake_describe(_images: Any) -> dict[str, Any]:
        return {}

    async def fake_host(*_args: Any) -> dict[str, Any]:
        return docker_host.parse_host_output(_host_raw())

    monkeypatch.setattr(jobs, "check_images", fake_check)
    monkeypatch.setattr(image_versions, "describe", fake_describe)
    monkeypatch.setattr(jobs, "read_docker_host", fake_host)

    await jobs._check_machine_image_updates(str(machine.id))

    stored = await _get(db_session_factory, Machine, machine.id)
    assert stored.docker_host_check["ok"] is True
    assert stored.docker_host_check["facts"]["version"] == "27.3.1"

    async def failing_host(*_args: Any) -> dict[str, Any]:
        raise OSError("connection reset")

    monkeypatch.setattr(jobs, "read_docker_host", failing_host)
    result = await jobs._check_machine_image_updates(str(machine.id))
    stored = await _get(db_session_factory, Machine, machine.id)
    # The image check itself still counts.
    assert result["ok"] is True
    assert stored.docker_host_check == {**stored.docker_host_check, "ok": False}
    assert "connection reset" in stored.docker_host_check["error"]


# --- Web and API ----------------------------------------------------------------------


async def _set_host_check(db_session_factory: Any, machine_id: uuid.UUID) -> None:
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        machine.docker_host_check = docker_host_check.evaluate(
            docker_host.parse_host_output(_host_raw()), machine
        )
        await db.commit()


async def test_the_host_page_lists_findings_and_the_containers_page_links_it(
    client: Any, db_session_factory: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    empty = await client.get(f"/machines/{machine_id}/docker/host")
    assert empty.status_code == 200 and "Not checked yet" in empty.text
    await _set_host_check(db_session_factory, machine_id)

    page = await client.get(f"/machines/{machine_id}/docker/host")
    containers = await client.get(f"/machines/{machine_id}/docker")

    assert page.status_code == 200
    assert "Container logs without a size limit" in page.text
    assert "27.3.1" in page.text and "web: 300 MB" in page.text
    assert 'name="back" value="host"' in page.text
    assert f'href="/machines/{machine_id}/docker/host"' in containers.text
    assert "Docker host check: 3 warning(s)" in containers.text


async def test_check_now_from_the_host_page_returns_there(
    client: Any, db_session_factory: Any, celery_calls: RecordedCeleryCalls
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    celery_calls.result_for["app.tasks.jobs.check_machine_image_updates"] = {"ok": True}

    response = await client.post(
        f"/machines/{machine_id}/docker/check-images", data={"csrf_token": csrf, "back": "host"}
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith(f"/machines/{machine_id}/docker/host?")


async def test_the_host_check_through_the_api(client: Any, db_session_factory: Any) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    headers = await _api_token(client)
    before = await client.get(f"/api/v1/machines/{machine_id}/docker/host", headers=headers)
    assert before.json()["host_check"] is None
    assert before.json()["daemon_settings"]["configured"] is False
    await _set_host_check(db_session_factory, machine_id)

    after = await client.get(f"/api/v1/machines/{machine_id}/docker/host", headers=headers)

    assert after.status_code == 200
    assert after.json()["host_check"]["facts"]["version"] == "27.3.1"


async def test_autoheal_is_set_on_the_container_page_with_action_power(
    client: Any, db_session_factory: Any, login_as: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    page = await client.get(f"/machines/{machine_id}/docker/containers/web")
    assert 'action="/machines/' in page.text and "/containers/web/autoheal" in page.text

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/autoheal",
        data={"csrf_token": csrf, "enabled": "1", "max_per_hour": "40"},
    )

    assert response.status_code == 303
    rows = await _rows(db_session_factory, DockerContainerSetting)
    assert [(r.name, r.autoheal, r.autoheal_max_per_hour) for r in rows] == [("web", True, 10)]
    entries = await audit_entries(db_session_factory, "machine.docker.container.autoheal_settings")
    assert entries[-1].details == {"container": "web", "autoheal": True, "max_per_hour": 10}

    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_UPDATES})
    csrf = await csrf_token(client, machine_id)
    denied = await client.post(
        f"/machines/{machine_id}/docker/containers/web/autoheal",
        data={"csrf_token": csrf, "enabled": ""},
    )
    assert denied.status_code == 403
    view = await client.get(f"/machines/{machine_id}/docker/containers/web")
    assert "/containers/web/autoheal" not in view.text
    assert "at most 10 times an hour" in view.text


async def test_autoheal_through_the_api(client: Any, db_session_factory: Any) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    headers = await _api_token(client)
    url = f"/api/v1/machines/{machine_id}/docker/containers/web/autoheal"

    too_many = await client.put(url, headers=headers, json={"enabled": True, "max_per_hour": 11})
    response = await client.put(url, headers=headers, json={"enabled": True, "max_per_hour": 2})
    off = await client.put(url, headers=headers, json={"enabled": False})

    assert too_many.status_code == 422
    assert response.status_code == 200
    assert response.json()["autoheal"]["enabled"] is True
    assert response.json()["autoheal"]["max_per_hour"] == 2
    assert off.json()["autoheal"] == {
        "enabled": False,
        "max_per_hour": 3,
        "restarts_last_hour": [],
        "gave_up_at": None,
    }


async def test_the_endpoint_check_switch_on_settings_and_the_api(
    client: Any, db_session_factory: Any
) -> None:
    page = await client.get("/settings?tab=checks")
    assert 'name="docker_endpoint_checks"' in page.text
    csrf = client.cookies.get("csrftoken")

    response = await client.post(
        "/settings/checks",
        data={
            "csrf_token": csrf,
            "docker_endpoint_checks_present": "1",
            "docker_endpoint_checks": "1",
        },
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        assert (await get_or_create_app_settings(db)).docker_endpoint_checks is True

    headers = await _api_token(client)
    bad = await client.patch(
        "/api/v1/settings", headers=headers, json={"docker_endpoint_checks": 1}
    )
    good = await client.patch(
        "/api/v1/settings", headers=headers, json={"docker_endpoint_checks": False}
    )
    read = await client.get("/api/v1/settings", headers=headers)

    assert bad.status_code == 422
    assert good.json()["changed"] == ["docker_endpoint_checks"]
    assert read.json()["docker_endpoint_checks"] is False


async def test_automatic_checks_are_marked_in_the_list_and_the_api(
    client: Any, db_session_factory: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    await _add(
        db_session_factory,
        EndpointCheck(
            name="web · :80",
            kind="http",
            target="http://10.20.0.5:80",
            source_machine_id=machine_id,
            auto_key="web|http://10.20.0.5:80",
        ),
    )
    headers = await _api_token(client)

    page = await client.get("/checks")
    api = await client.get("/api/v1/checks", headers=headers)

    assert "Made from a container" in page.text
    assert api.json()[0]["auto_key"] == "web|http://10.20.0.5:80"


async def test_the_schedule_form_offers_the_power_action(client: Any) -> None:
    page = await client.get("/scheduling/new")
    assert page.status_code == 200
    assert 'value="docker_power"' in page.text
    assert "param_docker_names" in page.text
