"""Docker upgrade #3: why an image check said "unknown" and how often it
runs (`app.ssh.image_updates`, `app.tasks.jobs`), container events as
notification rule events (`app.services.container_events`), the update
policy for scheduled updates (`app.services.update_policy` and the
container update job), and accepted vulnerabilities with the fleet-wide
view (`app.services.docker_acceptances`, Security → Container
vulnerabilities, its REST API).

As everywhere else, the underscore-prefixed coroutines are called
directly, never the Celery wrappers."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx2 import AsyncClient
from sqlalchemy import select

from app.core.app_settings import get_or_create_app_settings
from app.db.models.audit_log import AuditLogEntry
from app.db.models.docker import (
    DockerContainerSetting,
    DockerImageFinding,
    DockerImageScan,
    DockerJob,
    DockerJobKind,
    DockerJobStatus,
    DockerVulnerabilityAcceptance,
)
from app.db.models.machine import Machine
from app.db.models.notification_rule import NotificationEventType
from app.services import (
    container_events,
    docker_acceptances,
    docker_actions,
    docker_scans,
    image_versions,
)
from app.services import docker_jobs as docker_jobs_service
from app.services import update_policy as policy
from app.services.notifications import render_template
from app.ssh import monitoring
from app.ssh.docker_scan import ImageScanResult
from app.ssh.docker_update import build_pull_script, parse_pull_output
from app.ssh.image_updates import (
    ImageCheckError,
    is_docker_hub,
    parse_image_update_output,
    parse_unknown_reasons,
)
from app.tasks import docker_jobs as docker_tasks
from app.tasks import jobs
from tests.conftest import RecordedCeleryCalls
from tests.test_docker_tasks_jobs import (
    NEW_ID,
    OLD_ID,
    FakeMachine,
    _add,
    _get,
    _job,
    _machine,
    install_fake_machine,
)
from tests.test_update_history import _api_token

OTHER_ID = "sha256:" + "c" * 64
IMAGE_CHECK = "app.tasks.jobs.check_machine_image_updates"


@pytest.fixture
def machine_shell(monkeypatch: pytest.MonkeyPatch, db_session_factory: Any) -> FakeMachine:
    return install_fake_machine(monkeypatch, db_session_factory)


# --- Image checks: reasons, Docker Hub requests, interval ---------------------


def test_unknown_images_carry_the_reason() -> None:
    digest = "sha256:" + "d" * 64
    raw = "\n".join(
        [
            f"nginx:1.27\t{NEW_ID}\tnginx@{OLD_ID}\t1.27.0\t\t",
            "hub/limited:2\t\thub/limited@" + OLD_ID + "\t\t\t"
            "ERROR: toomanyrequests: You have reached your pull rate limit",
            "ghcr.io/me/private:1\t\tghcr.io/me/private@" + OLD_ID + "\t\t\t"
            "ERROR: unauthorized: authentication required",
            "myapp:dev\t\t\t\t\t",
            f"postgres@{digest}\t\tpostgres@{digest}\t\t\t",
            "quay.io/x/y:1\t\tquay.io/x/y@" + OLD_ID + "\t\t\t"
            "dial tcp: lookup quay.io: no such host",
            "odd:1\t\todd@" + OLD_ID + "\t\t\tsomething else went wrong",
        ]
    )

    assert parse_image_update_output(raw)["nginx:1.27"] == "update"
    assert parse_unknown_reasons(raw) == {
        "hub/limited:2": "rate_limited",
        "ghcr.io/me/private:1": "auth",
        "myapp:dev": "local",
        f"postgres@{digest}": "pinned",
        "quay.io/x/y:1": "network",
        "odd:1": "error",
    }


def test_older_five_field_output_still_parses() -> None:
    raw = f"nginx:1.27\t{NEW_ID}\tnginx@{OLD_ID}\t1.27.0\t1.27.1"
    assert parse_image_update_output(raw) == {"nginx:1.27": "update"}
    assert parse_unknown_reasons(raw) == {}


@pytest.mark.parametrize(
    ("image", "hub"),
    [
        ("nginx:1.27", True),
        ("library/nginx", True),
        ("linuxserver/sonarr:4", True),
        ("docker.io/library/redis:7", True),
        ("ghcr.io/me/app:1", False),
        ("registry.lan:5000/team/app:1", False),
        ("localhost/app:1", False),
    ],
)
def test_docker_hub_images_are_told_apart(image: str, hub: bool) -> None:
    assert is_docker_hub(image) is hub


async def test_the_check_records_reasons_rate_limits_and_hub_requests(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine = _machine()
    await _add(db_session_factory, machine)

    async def fake_check(*_args: Any, **_kwargs: Any) -> Any:
        return (
            {"nginx:1.27": "current", "hub/limited:2": "unknown", "myapp:dev": "unknown"},
            {},
            {"hub/limited:2": "rate_limited", "myapp:dev": "local"},
        )

    async def fake_describe(_images: Any) -> dict[str, Any]:
        return {}

    monkeypatch.setattr(jobs, "check_images", fake_check)
    monkeypatch.setattr(image_versions, "describe", fake_describe)

    result = await jobs._check_machine_image_updates(str(machine.id))

    stored = await _get(db_session_factory, Machine, machine.id)
    check = stored.docker_image_check
    assert result == {"ok": True, "updates": 0}
    assert check["ok"] is True and check["error"] is None
    assert check["reasons"] == {"hub/limited:2": "rate_limited", "myapp:dev": "local"}
    assert check["rate_limited"] == 1
    # The locally built image is never asked about.
    assert check["hub_requests"] == 2


async def test_a_failed_check_is_remembered(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine = _machine()
    await _add(db_session_factory, machine)

    async def failing(*_args: Any, **_kwargs: Any) -> Any:
        raise ImageCheckError("This account can't reach the Docker daemon.")

    monkeypatch.setattr(jobs, "check_images", failing)

    result = await jobs._check_machine_image_updates(str(machine.id))

    stored = await _get(db_session_factory, Machine, machine.id)
    assert result["ok"] is False
    assert stored.docker_image_check["ok"] is False
    assert "Docker daemon" in stored.docker_image_check["error"]
    assert stored.docker_images_checked_at is None


async def test_the_hourly_sweep_checks_only_machines_that_are_due(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch, celery_calls: RecordedCeleryCalls
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    now = datetime.now(UTC)
    never = _machine(name="never")
    recent = _machine(name="recent", docker_images_checked_at=now - timedelta(hours=2))
    old = _machine(name="old", docker_images_checked_at=now - timedelta(hours=30))
    failed_recently = _machine(
        name="failed",
        docker_image_check={"at": (now - timedelta(hours=1)).isoformat(), "ok": False},
    )
    await _add(db_session_factory, never, recent, old, failed_recently)

    await jobs._check_all_machine_image_updates()
    due = {args[0] for name, args, _ in celery_calls if name == IMAGE_CHECK}
    assert due == {str(never.id), str(old.id)}

    async with db_session_factory() as db:
        (await get_or_create_app_settings(db)).docker_image_check_interval_hours = 1
        await db.commit()
    celery_calls.clear()
    await jobs._check_all_machine_image_updates()
    due = {args[0] for name, args, _ in celery_calls if name == IMAGE_CHECK}
    assert due == {str(never.id), str(recent.id), str(old.id), str(failed_recently.id)}


async def test_the_check_interval_is_a_setting_on_the_web_and_in_the_api(
    client: AsyncClient, db_session_factory: Any
) -> None:
    await client.get("/settings?tab=checks")
    page = await client.get("/settings?tab=checks")
    assert 'name="docker_image_check_interval_hours"' in page.text
    response = await client.post(
        "/settings/checks",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "docker_image_check_interval_hours": "6",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    bad = await client.post(
        "/settings/checks",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "docker_image_check_interval_hours": "0",
        },
    )
    assert bad.status_code == 200

    headers = await _api_token(client)
    api = await client.patch(
        "/api/v1/settings", json={"docker_image_check_interval_hours": 12}, headers=headers
    )
    assert api.status_code == 200, api.text
    async with db_session_factory() as db:
        assert (await get_or_create_app_settings(db)).docker_image_check_interval_hours == 12
        actions = (await db.execute(select(AuditLogEntry.action))).scalars().all()
    assert "settings.background_checks.update" in actions


async def test_the_docker_tab_says_why_an_image_is_unknown(
    client: AsyncClient, db_session_factory: Any
) -> None:
    machine = _machine(
        docker_containers=[{"name": "web", "image": "hub/limited:2", "state": "running"}],
        docker_image_updates={"hub/limited:2": "unknown"},
        docker_image_check={
            "at": datetime.now(UTC).isoformat(),
            "ok": True,
            "error": None,
            "reasons": {"hub/limited:2": "rate_limited"},
            "rate_limited": 1,
            "hub_requests": 1,
        },
    )
    await _add(db_session_factory, machine)

    page = await client.get(f"/machines/{machine.id}/docker")
    headers = await _api_token(client)
    api = (await client.get(f"/api/v1/machines/{machine.id}/docker", headers=headers)).json()

    assert "Not checked: registry rate limit" in page.text
    assert "rate limit stopped the check of 1 image" in page.text
    assert "One check makes 1 Docker Hub request" in page.text
    assert api["image_check"]["rate_limited"] == 1
    assert api["containers"][0]["image_check_reason"] == "rate_limited"


# --- Container events ------------------------------------------------------------


def _event(action: str, name: str, exit_code: int | None = None) -> str:
    attributes: dict[str, Any] = {"name": name, "image": "nginx:1.27"}
    if exit_code is not None:
        attributes["exitCode"] = str(exit_code)
    return json.dumps(
        {"Type": "container", "Action": action, "Actor": {"ID": "x", "Attributes": attributes},
         "time": 1767225600}
    )


def test_events_are_read_after_the_machine_clock() -> None:
    raw = "\n".join(
        [
            "@@PS",
            "@@EVENTS",
            "1767225660",
            _event("die", "web", 1),
            _event("oom", "db"),
            _event("health_status: unhealthy", "api"),
            _event("start", "web"),
            "not json",
        ]
    )

    clock, events = monitoring._parse_docker_events(raw)

    assert clock == 1767225660
    assert [(e["action"], e["name"], e["exit_code"]) for e in events] == [
        ("die", "web", 1),
        ("oom", "db", None),
        ("unhealthy", "api", None),
    ]
    assert monitoring._parse_docker_events("@@NOACCESS") == (None, [])


def test_events_are_sorted_into_incidents() -> None:
    events: list[dict[str, Any]] = [
        {"action": "die", "name": "web", "exit_code": 1},
        {"action": "die", "name": "stopped", "exit_code": 143},
        {"action": "die", "name": "killed", "exit_code": 137},
        {"action": "oom", "name": "killed"},
        *[{"action": "die", "name": "loop", "exit_code": 2}] * 3,
        {"action": "unhealthy", "name": "api"},
        {"action": "unhealthy", "name": "flaky"},
        {"action": "healthy", "name": "flaky"},
    ]

    incidents = container_events.classify(events)

    assert incidents.crashed == {"web": [1]}
    assert incidents.restart_loop == {"loop": 3}
    assert incidents.oom == ["killed"]
    assert incidents.unhealthy == ["api"]
    assert not container_events.classify([{"action": "die", "name": "x", "exit_code": 0}])


def test_the_command_reads_events_only_from_a_marker() -> None:
    assert "DC_EVENTS_SINCE" in monitoring.MONITORING_COMMAND
    assert "--filter event=die --filter event=oom --filter event=health_status" in (
        monitoring.MONITORING_COMMAND
    )


async def test_a_sample_notifies_container_incidents_and_moves_the_marker(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine = _machine(docker_events_since=1767225600)
    await _add(db_session_factory, machine)
    seen_commands: list[int | None] = []
    sent: list[tuple[NotificationEventType, dict[str, Any]]] = []
    raw = "\n".join(
        [
            "===DOCKER===",
            "@@PS",
            "@@EVENTS",
            "1767225660",
            _event("die", "web", 1),
            _event("oom", "db"),
        ]
    )

    async def fake_sample(m: Machine, *_args: Any) -> Any:
        seen_commands.append(m.docker_events_since)
        return monitoring.parse_monitoring_output(raw, is_physical=False)

    async def fake_notify(_db: Any, event: NotificationEventType, **kwargs: Any) -> None:
        sent.append((event, kwargs["context"]))

    async def fake_credential(*_args: Any) -> None:
        return None

    monkeypatch.setattr(jobs, "gather_monitoring_sample", fake_sample)
    monkeypatch.setattr(jobs, "resolve_machine_credential", fake_credential)
    monkeypatch.setattr(container_events, "notify", fake_notify)

    result = await jobs._sample_machine_monitoring(str(machine.id))

    stored = await _get(db_session_factory, Machine, machine.id)
    assert result["ok"] is True
    assert seen_commands == [1767225600]
    assert stored.docker_events_since == 1767225660
    assert [(e, c["containers"]) for e, c in sent] == [
        (NotificationEventType.DOCKER_CONTAINER_CRASHED, "web"),
        (NotificationEventType.DOCKER_CONTAINER_OOM, "db"),
    ]
    assert "web: exit code 1" in sent[0][1]["details"]


@pytest.mark.parametrize("locale", ["en", "cs"])
@pytest.mark.parametrize(
    "event",
    [
        NotificationEventType.DOCKER_CONTAINER_CRASHED,
        NotificationEventType.DOCKER_CONTAINER_RESTART_LOOP,
        NotificationEventType.DOCKER_CONTAINER_OOM,
        NotificationEventType.DOCKER_CONTAINER_UNHEALTHY,
    ],
)
def test_container_event_templates_name_the_containers(
    event: NotificationEventType, locale: str
) -> None:
    context = {
        "containers": "web, db",
        "machine_name": "docker1",
        "machine_ip": "10.0.0.7",
        "timestamp": "2026-10-28T10:00:00Z",
        "details": "web: exit code 1",
    }
    subject, body = render_template(event, None, context, locale=locale)
    assert "web, db" in subject and "docker1" in subject
    assert "web: exit code 1" in body
    assert "{" not in subject + body


async def test_the_new_events_can_be_picked_in_a_rule(client: AsyncClient) -> None:
    page = await client.get("/notifications/rules/new")
    assert page.status_code == 200
    assert "docker.container.crashed" in page.text
    assert "Docker container keeps restarting" in page.text


# --- Update policy ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "version"),
    [
        ("1.27.3", (1, 27, 3)),
        ("v2.4", (2, 4)),
        ("2024.10.1-alpine", (2024, 10, 1)),
        ("16", (16,)),
        ("latest", None),
        ("", None),
        ("abc123", None),
    ],
)
def test_versions_are_read_from_labels_and_tags(text: str, version: Any) -> None:
    assert policy.parse_version(text) == version


@pytest.mark.parametrize(
    ("name", "old", "new", "allowed"),
    [
        ("any", None, None, True),
        ("minor", (1, 4, 2), (1, 9, 0), True),
        ("minor", (1, 4, 2), (2, 0, 0), False),
        ("patch", (1, 4, 2), (1, 4, 3), True),
        ("patch", (1, 4, 2), (1, 5, 0), False),
        ("patch", (16,), (16, 5), False),
        ("minor", (1, 4), None, False),
        ("minor", (1, 5, 0), (1, 4, 0), False),
    ],
)
def test_the_policy_guard(name: str, old: Any, new: Any, allowed: bool) -> None:
    assert policy.within(name, old, new) is allowed


def test_the_allowed_tag_keeps_the_shape_and_the_policy() -> None:
    tags = ["1.27.3", "1.27.4", "1.28.0", "2.0.0", "1.27.5-alpine", "latest", "v1.27.9"]
    assert policy.allowed_tag("patch", "1.27.3", tags) == "1.27.4"
    assert policy.allowed_tag("minor", "1.27.3", tags) == "1.28.0"
    assert policy.allowed_tag("any", "1.27.3", tags) is None
    assert policy.allowed_tag("minor", "latest", tags) is None
    assert policy.with_tag("registry.lan:5000/app:1.2.0", "1.3.0") == "registry.lan:5000/app:1.3.0"


def test_the_pull_script_reports_versions_when_asked() -> None:
    script = build_pull_script("nginx:1.27", current=OLD_ID, scan=False, versions=True)
    assert "@@DC_OLD_VERSION" in script and "org.opencontainers.image.version" in script
    assert "@@DC_NEW_VERSION" not in build_pull_script("nginx:1.27", current=OLD_ID, scan=False)
    parsed = parse_pull_output(
        f"@@DC_OLD_ID {OLD_ID}\n@@DC_NEW_ID {NEW_ID}\n@@DC_OLD_VERSION 1.4.2\n"
        "@@DC_NEW_VERSION <no value>\n"
    )
    assert (parsed.old_version, parsed.new_version) == ("1.4.2", "")


def _standalone_inspect(ref: str) -> str:
    container = {
        "Name": "/web",
        "Id": "c0ffee" * 10,
        "Image": OLD_ID,
        "Config": {"Image": ref, "Labels": {}, "Env": []},
        "HostConfig": {},
        "State": {"Running": True},
    }
    image = {"RepoDigests": ["nginx@sha256:" + "d" * 64], "Config": {}}
    return json.dumps([container]) + "\n@@DC_SPLIT\n" + json.dumps([image])


async def test_a_new_major_version_under_the_same_tag_is_not_installed(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    job = _job(
        machine,
        DockerJobKind.CONTAINER_UPDATE,
        "web",
        params={"gate": "off", "policy": "minor"},
    )
    await _add(db_session_factory, machine, job)
    machine_shell.answer("inspect --type container", _standalone_inspect("app:latest"))
    machine_shell.finishes(
        f"@@DC_OLD_ID {OLD_ID}\n@@DC_NEW_ID {NEW_ID}\n"
        "@@DC_OLD_VERSION 1.9.0\n@@DC_NEW_VERSION 2.0.0\n"
    )

    await docker_tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.SKIPPED
    assert stored.result["note"] == "policy"
    assert "2.0.0" in stored.error and "1.9.0" in stored.error
    assert len(machine_shell.started) == 1  # never recreated
    assert any("tag" in s and "app:latest" in s for s in machine_shell.short)
    assert machine_shell.notified == []


async def test_a_version_tag_moves_to_the_newest_allowed_tag(
    db_session_factory: Any, machine_shell: FakeMachine, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_tags(_ref: Any, transport: Any = None) -> list[str]:
        return ["1.27.3", "1.27.4", "1.28.0", "2.0.0"]

    monkeypatch.setattr(image_versions, "fetch_tags", fake_tags)
    machine = _machine(docker_containers=[{"name": "web", "image": "nginx:1.27.3"}])
    job = _job(
        machine,
        DockerJobKind.CONTAINER_UPDATE,
        "web",
        params={"gate": "off", "policy": "patch"},
    )
    await _add(db_session_factory, machine, job)
    machine_shell.answer("inspect --type container", _standalone_inspect("nginx:1.27.3"))
    machine_shell.finishes(f"@@DC_OLD_ID \n@@DC_NEW_ID {NEW_ID}\n@@DC_OLD_VERSION \n")
    machine_shell.finishes("@@DC_DONE\n")

    await docker_tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.SUCCEEDED, stored.error
    assert stored.result["ref"] == "nginx:1.27.4"
    assert stored.result["previous_ref"] == "nginx:1.27.3"
    pull_script, recreate_script = (script for _remote, script in machine_shell.started)
    assert "pull 'nginx:1.27.4'" in pull_script or "pull nginx:1.27.4" in pull_script
    assert '"Image":"nginx:1.27.4"' in recreate_script


async def test_scheduled_updates_carry_the_policy_and_manual_ones_do_not(
    db_session_factory: Any,
) -> None:
    machine = _machine(docker_containers=[{"name": "web", "image": "nginx:1.27"}])
    setting = DockerContainerSetting(
        machine_id=machine.id, name="web", auto_update=True, update_policy="patch"
    )
    await _add(db_session_factory, machine, setting)
    async with db_session_factory() as db:
        row = await db.get(Machine, machine.id)
        assert row is not None
        await docker_actions.trigger_container_updates(
            db, [row], scope="auto", gate=None, started_by="schedule"
        )
        await db.commit()
        [scheduled] = (await db.execute(select(DockerJob))).scalars().all()
        assert scheduled.params == {"gate": "off", "policy": "patch"}
        scheduled.status = DockerJobStatus.SUCCEEDED
        await db.commit()
        manual = await docker_actions.update_containers(db, row, ["web"], started_by="admin")
        assert manual.jobs[0].params == {"gate": "off"}


async def test_the_policy_is_a_container_setting_on_the_web_and_in_the_api(
    client: AsyncClient, db_session_factory: Any
) -> None:
    machine = _machine()
    await _add(db_session_factory, machine)
    await client.get(f"/machines/{machine.id}/docker/containers/web")
    response = await client.post(
        f"/machines/{machine.id}/docker/containers/web/settings",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "auto_update": "1",
            "gate": "off",
            "update_policy": "minor",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    bad = await client.post(
        f"/machines/{machine.id}/docker/containers/web/settings",
        data={"csrf_token": client.cookies.get("csrftoken"), "update_policy": "major"},
    )
    assert bad.status_code == 400

    headers = await _api_token(client)
    # Left out: unchanged.
    kept = await client.put(
        f"/api/v1/machines/{machine.id}/docker/containers/web/settings",
        json={"auto_update": True},
        headers=headers,
    )
    assert kept.status_code == 200
    async with db_session_factory() as db:
        [setting] = (await db.execute(select(DockerContainerSetting))).scalars().all()
        assert setting.update_policy == "minor"
    changed = await client.put(
        f"/api/v1/machines/{machine.id}/docker/containers/web/settings",
        json={"auto_update": True, "update_policy": "patch"},
        headers=headers,
    )
    assert changed.status_code == 200
    listing = (await client.get(f"/api/v1/machines/{machine.id}/docker", headers=headers)).json()
    assert listing["containers"][0]["update_policy"] == "patch"


# --- Accepted vulnerabilities and the fleet view ---------------------------------------


def _finding(vuln_id: str, severity: str, pkg: str = "openssl") -> dict[str, Any]:
    return {"id": vuln_id, "severity": severity, "pkg": pkg, "installed": "3.0.1", "fixed": "3.0.2"}


def _scan_result(image: str, findings: list[dict[str, Any]]) -> ImageScanResult:
    counts = dict.fromkeys(("critical", "high", "medium", "low", "unknown"), 0)
    for f in findings:
        counts[f["severity"]] += 1
    return ImageScanResult(
        image=image, scanners={"trivy": "0.58.1"}, counts=counts, vulnerabilities=findings
    )


async def _two_machines_with_scans(db_session_factory: Any) -> tuple[Machine, Machine]:
    one = _machine(name="one")
    two = _machine(name="two")
    await _add(db_session_factory, one, two)
    async with db_session_factory() as db:
        await docker_scans.store(
            db,
            one.id,
            [
                _scan_result(
                    "nginx:1.27", [_finding("CVE-1", "critical"), _finding("CVE-2", "high")]
                )
            ],
            {"nginx:1.27": NEW_ID},
        )
        await docker_scans.store(
            db,
            two.id,
            [
                _scan_result("nginx:1.26", [_finding("CVE-1", "critical")]),
                _scan_result("redis:7", [_finding("CVE-1", "critical", "libc")]),
            ],
            {"nginx:1.26": OLD_ID, "redis:7": OTHER_ID},
        )
        for machine_id, ids in ((one.id, {NEW_ID}), (two.id, {OLD_ID, OTHER_ID})):
            machine = await db.get(Machine, machine_id)
            assert machine is not None
            await docker_scans.summarize(db, machine, ids)
        await db.commit()
    return one, two


async def test_findings_are_kept_per_row_and_the_fleet_view_groups_them(
    db_session_factory: Any,
) -> None:
    await _two_machines_with_scans(db_session_factory)
    async with db_session_factory() as db:
        assert len((await db.execute(select(DockerImageFinding))).scalars().all()) == 4
        rows, truncated = await docker_acceptances.fleet_overview(db, select(Machine.id))
        found = await docker_acceptances.occurrences(db, "CVE-1", select(Machine.id))

    assert not truncated
    assert [(r.vuln_id, r.severity, r.machines, r.images) for r in rows] == [
        ("CVE-1", "critical", 2, 3),
        ("CVE-2", "high", 1, 1),
    ]
    assert sorted((o.machine.name, o.image_ref, o.pkg) for o in found) == [
        ("one", "nginx:1.27", "openssl"),
        ("two", "nginx:1.26", "openssl"),
        ("two", "redis:7", "libc"),
    ]


async def test_an_accepted_vulnerability_leaves_the_counts_until_it_expires(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    one, two = await _two_machines_with_scans(db_session_factory)
    async with db_session_factory() as db:
        # Only for nginx: the redis image keeps counting it.
        await docker_acceptances.accept(
            db, vuln_id="CVE-1", image="nginx:1.27", reason="not reachable", days=30, actor="a"
        )
        await db.commit()

    assert await docker_tasks._recompute_vulnerability_acceptances(["CVE-1"]) == 2

    async with db_session_factory() as db:
        scans = {s.image_ref: s for s in (await db.execute(select(DockerImageScan))).scalars()}
        machine_one = await db.get(Machine, one.id)
        machine_two = await db.get(Machine, two.id)
        assert scans["nginx:1.27"].counts["critical"] == 0
        assert scans["nginx:1.27"].raw_counts["critical"] == 1
        assert scans["nginx:1.26"].counts["critical"] == 0
        assert scans["redis:7"].counts["critical"] == 1
        assert machine_one is not None and machine_one.docker_vulnerabilities["critical"] == 0
        assert machine_two is not None and machine_two.docker_vulnerabilities["critical"] == 1
        # A new scan of the same image is counted the same way at once.
        counts = await docker_scans.store(
            db, one.id, [_scan_result("nginx:1.27", [_finding("CVE-1", "critical")])],
            {"nginx:1.27": NEW_ID},
        )
        assert (counts[NEW_ID] or {})["critical"] == 0
        [acceptance] = (await db.execute(select(DockerVulnerabilityAcceptance))).scalars().all()
        acceptance.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        await db.commit()

    assert await docker_tasks._expire_vulnerability_acceptances() == 1

    async with db_session_factory() as db:
        scans = {s.image_ref: s for s in (await db.execute(select(DockerImageScan))).scalars()}
        assert scans["nginx:1.27"].counts["critical"] == 1
        assert scans["nginx:1.27"].raw_counts is None
        assert (await db.execute(select(DockerVulnerabilityAcceptance))).first() is None


def test_repository_keys_are_the_same_for_every_tag() -> None:
    assert docker_acceptances.repository_key("nginx:1.27") == "docker.io/library/nginx"
    assert docker_acceptances.repository_key("docker.io/library/nginx:1.28") == (
        "docker.io/library/nginx"
    )
    assert docker_acceptances.repository_key("ghcr.io/me/app:1") == "ghcr.io/me/app"
    assert docker_acceptances.is_vuln_id_valid("GHSA-abcd-1234-efgh")
    assert not docker_acceptances.is_vuln_id_valid("CVE-1/../x")


async def test_the_security_pages_list_accept_and_revoke(
    client: AsyncClient, db_session_factory: Any, celery_calls: RecordedCeleryCalls
) -> None:
    await _two_machines_with_scans(db_session_factory)

    listing = await client.get("/security/containers")
    assert listing.status_code == 200
    assert "CVE-1" in listing.text and "Container vulnerabilities" in listing.text
    detail = await client.get("/security/containers/CVE-1")
    assert detail.status_code == 200
    assert "redis:7" in detail.text and "docker.io/library/nginx" in detail.text

    response = await client.post(
        "/security/containers/CVE-1/accept",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "image": "docker.io/library/nginx",
            "reason": "not reachable",
            "days": "30",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "app.tasks.docker_jobs.recompute_vulnerability_acceptances" in celery_calls.names
    too_long = await client.post(
        "/security/containers/CVE-1/accept",
        data={"csrf_token": client.cookies.get("csrftoken"), "days": "400"},
    )
    assert too_long.status_code == 400

    async with db_session_factory() as db:
        [acceptance] = (await db.execute(select(DockerVulnerabilityAcceptance))).scalars().all()
        actions = (await db.execute(select(AuditLogEntry.action))).scalars().all()
    assert acceptance.image == "docker.io/library/nginx"
    assert "docker.vulnerability.accept" in actions
    listing = await client.get("/security/containers")
    assert "not reachable" in listing.text

    revoked = await client.post(
        f"/security/containers/acceptances/{acceptance.id}/revoke",
        data={"csrf_token": client.cookies.get("csrftoken")},
        follow_redirects=False,
    )
    assert revoked.status_code == 303
    async with db_session_factory() as db:
        assert (await db.execute(select(DockerVulnerabilityAcceptance))).first() is None
        actions = (await db.execute(select(AuditLogEntry.action))).scalars().all()
    assert "docker.vulnerability.revoke" in actions


async def test_the_image_page_marks_accepted_findings(
    client: AsyncClient, db_session_factory: Any
) -> None:
    one, _two = await _two_machines_with_scans(db_session_factory)
    async with db_session_factory() as db:
        await docker_acceptances.accept(
            db, vuln_id="CVE-2", image="", reason="", days=10, actor="a"
        )
        await docker_acceptances.recompute(db, {"CVE-2"})
        await db.commit()

    page = await client.get(f"/machines/{one.id}/docker/images/{NEW_ID}/vulnerabilities")

    assert page.status_code == 200
    assert "accepted until" in page.text
    assert "The scanners found 1 critical and 1 high" in page.text


async def test_the_api_lists_accepts_and_revokes(
    client: AsyncClient, db_session_factory: Any
) -> None:
    await _two_machines_with_scans(db_session_factory)
    headers = await _api_token(client)

    listing = (await client.get("/api/v1/docker/vulnerabilities", headers=headers)).json()
    assert listing["vulnerabilities"][0]["vuln_id"] == "CVE-1"
    assert listing["vulnerabilities"][0]["machines"] == 2
    one = (await client.get("/api/v1/docker/vulnerabilities/CVE-1", headers=headers)).json()
    assert len(one["occurrences"]) == 3

    created = await client.post(
        "/api/v1/docker/vulnerability-acceptances",
        json={"vuln_id": "CVE-1", "reason": "later", "days": 7},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["image"] == "" and body["reason"] == "later"
    bad = await client.post(
        "/api/v1/docker/vulnerability-acceptances",
        json={"vuln_id": "CVE-1", "days": 366},
        headers=headers,
    )
    assert bad.status_code == 422
    acceptances = (
        await client.get("/api/v1/docker/vulnerability-acceptances", headers=headers)
    ).json()
    assert [a["vuln_id"] for a in acceptances] == ["CVE-1"]

    gone = await client.delete(
        f"/api/v1/docker/vulnerability-acceptances/{body['id']}", headers=headers
    )
    assert gone.status_code == 204
    missing = await client.delete(
        f"/api/v1/docker/vulnerability-acceptances/{uuid.uuid4()}", headers=headers
    )
    assert missing.status_code == 404


async def test_a_machine_without_findings_shows_nothing(client: AsyncClient) -> None:
    page = await client.get("/security/containers")
    assert "No critical or high vulnerabilities" in page.text
    missing = await client.get("/security/containers/CVE-404")
    assert missing.status_code == 200
    assert "No scanned image" in missing.text
    invalid = await client.get("/security/containers/bad id")
    assert invalid.status_code == 404



async def test_a_rollback_after_a_tag_bump_goes_back_to_the_old_tag(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    update = _job(
        machine,
        DockerJobKind.CONTAINER_UPDATE,
        "web",
        status=DockerJobStatus.SUCCEEDED,
        result={"previous_image_id": OLD_ID, "previous_ref": "nginx:1.27.3"},
    )
    await _add(db_session_factory, machine, update)
    assert docker_jobs_service.rollback_ref(update) == "nginx:1.27.3"
    async with db_session_factory() as db:
        row = await db.get(Machine, machine.id)
        assert row is not None
        job = await docker_actions.rollback_container(
            db, row, "web", OLD_ID, started_by="admin", ref="nginx:1.27.3"
        )
        await db.commit()
    assert job is not None and job.params == {"image_id": OLD_ID, "ref": "nginx:1.27.3"}
    machine_shell.answer("inspect --type container", _standalone_inspect("nginx:1.27.4"))
    machine_shell.finishes("@@DC_DONE\n")

    await docker_tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.SUCCEEDED, stored.error
    [(_remote, script)] = machine_shell.started
    assert '"Image":"nginx:1.27.3"' in script
    assert f"tag {OLD_ID} nginx:1.27.3" in script or f"tag '{OLD_ID}' 'nginx:1.27.3'" in script
