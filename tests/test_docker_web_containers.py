"""Changing containers and images from the Docker tab: per-container
settings, update and rollback, vulnerability scans and clean-up. Each
needs CSRF and `action.updates`, queues one `DockerJob` through
`run_docker_job`, and leaves an audit entry."""

from __future__ import annotations

import uuid

import pytest

from app.db.models.audit_log import AuditOutcome
from app.db.models.docker import DockerContainerSetting, DockerJobKind, DockerJobStatus
from app.db.models.role import Permission
from tests.test_docker_web_support import (
    IMAGE_ID,
    MACHINE_NAME,
    PREVIOUS_IMAGE_ID,
    RUN_JOB_TASK,
    VIEWER,
    add_job,
    audit_entries,
    csrf_token,
    follow,
    jobs_of,
    make_docker_machine,
)

NOT_UPDATES = frozenset(
    {Permission.MACHINE_VIEW, Permission.ACTION_POWER, Permission.ACTION_TERMINAL}
)


def _mutations(machine_id: uuid.UUID) -> list[tuple[str, dict[str, str]]]:
    base = f"/machines/{machine_id}/docker"
    return [
        (f"{base}/containers/web/settings", {"auto_update": "1", "gate": "high"}),
        (f"{base}/containers/web/update", {}),
        (f"{base}/update", {"scope": "with_update"}),
        (f"{base}/containers/web/rollback", {}),
        (f"{base}/images/scan", {"scope": "all"}),
        (f"{base}/prune", {"images": "1"}),
    ]


async def test_every_change_needs_a_csrf_token(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)

    for url, data in _mutations(machine_id):
        response = await client.post(url, data=data)
        assert response.status_code == 403, url

    assert celery_calls == []
    assert await jobs_of(db_session_factory, machine_id) == []


@pytest.mark.parametrize("permissions", [VIEWER, NOT_UPDATES])
async def test_every_change_needs_action_updates(
    client, login_as, db_session_factory, celery_calls, permissions
):
    machine_id = await make_docker_machine(db_session_factory)
    await add_job(db_session_factory, machine_id, result={"previous_image_id": PREVIOUS_IMAGE_ID})
    await login_as(client, permissions=permissions)
    csrf = await csrf_token(client, machine_id)

    for url, data in _mutations(machine_id):
        response = await client.post(url, data={**data, "csrf_token": csrf})
        assert response.status_code == 403, url

    assert celery_calls == []
    assert len(await jobs_of(db_session_factory, machine_id)) == 1  # only the seeded one


async def test_update_queues_a_job_and_audits_it(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/update",
        data={"csrf_token": csrf, "gate": "critical"},
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/jobs/{job.id}"
    assert job.kind == DockerJobKind.CONTAINER_UPDATE
    assert job.target == "web"
    assert job.params == {"gate": "critical"}
    assert job.started_by == "test-admin"
    assert celery_calls.names == [RUN_JOB_TASK]
    assert celery_calls[0][1] == (str(job.id),)
    [entry] = await audit_entries(db_session_factory, "machine.docker.container.update")
    assert entry.actor == "test-admin"
    assert entry.target_id == str(machine_id)
    assert entry.details == {"container": "web", "gate": "critical"}


async def test_update_is_not_queued_twice(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    await add_job(db_session_factory, machine_id, status=DockerJobStatus.PENDING, output=None)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/update", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith(
        f"/machines/{machine_id}/docker/containers/web?error="
    )
    assert celery_calls == []
    assert len(await jobs_of(db_session_factory, machine_id)) == 1


@pytest.mark.parametrize(
    ("name", "gate"), [("x;id", ""), ("web", "everything")], ids=["bad-name", "bad-gate"]
)
async def test_update_rejects_bad_input(client, db_session_factory, celery_calls, name, gate):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/{name}/update",
        data={"csrf_token": csrf, "gate": gate},
    )

    assert response.status_code == 400
    assert celery_calls == []


async def test_update_refuses_debcontrols_own_containers(
    client, db_session_factory, celery_calls, monkeypatch
):
    async def _own_project(db, machine):
        return "site"

    monkeypatch.setattr("app.services.docker_jobs.protected_project", _own_project)
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/update", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert celery_calls == []
    [entry] = await audit_entries(db_session_factory, "machine.docker.container.update")
    assert entry.outcome != AuditOutcome.SUCCESS
    assert entry.details == {"container": "web", "reason": "protected"}


async def test_update_all_with_a_newer_image_takes_only_those(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/update",
        # A hand-picked name is ignored: the scope decides.
        data={"csrf_token": csrf, "scope": "with_update", "container": "worker"},
    )

    jobs = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert response.headers["location"].startswith(f"/machines/{machine_id}/docker/jobs?notice=")
    assert [job.target for job in jobs] == ["web"]
    assert celery_calls.names == [RUN_JOB_TASK]


async def test_update_selected_queues_one_job_each_but_starts_one(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/update",
        data={"csrf_token": csrf, "container": ["web", "worker", "bad;name"]},
    )

    jobs = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert sorted(job.target for job in jobs) == ["web", "worker"]
    assert len({job.batch_id for job in jobs}) == 1
    # The jobs of a machine run one after another: only the first is queued.
    assert celery_calls.names == [RUN_JOB_TASK]
    assert len(await audit_entries(db_session_factory, "machine.docker.container.update")) == 2


async def test_update_with_nothing_selected_says_so(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(f"/machines/{machine_id}/docker/update", data={"csrf_token": csrf})

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert celery_calls == []


async def test_settings_are_saved_and_audited(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/settings",
        data={"csrf_token": csrf, "auto_update": "1", "gate": "worse"},
    )

    assert response.status_code == 303
    page = await follow(client, response.headers["location"])
    assert "worse" in page
    async with db_session_factory() as session:
        from sqlalchemy import select

        setting = (await session.execute(select(DockerContainerSetting))).scalar_one()
    assert (setting.name, setting.auto_update, setting.vulnerability_gate) == ("web", True, "worse")
    assert setting.updated_by == "test-admin"
    assert celery_calls == []
    [entry] = await audit_entries(db_session_factory, "machine.docker.container.settings")
    assert entry.details == {"container": "web", "auto_update": True, "gate": "worse"}


async def test_settings_reject_an_unknown_gate(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/settings",
        data={"csrf_token": csrf, "gate": "lenient"},
    )

    assert response.status_code == 400


async def test_rollback_goes_back_to_the_image_before_the_last_update(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    await add_job(
        db_session_factory,
        machine_id,
        result={"previous_image_id": PREVIOUS_IMAGE_ID, "new_image_id": IMAGE_ID},
    )
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/rollback", data={"csrf_token": csrf}
    )

    rollback = next(
        job
        for job in await jobs_of(db_session_factory, machine_id)
        if job.kind == DockerJobKind.CONTAINER_ROLLBACK
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/jobs/{rollback.id}"
    assert rollback.params == {"image_id": PREVIOUS_IMAGE_ID}
    assert celery_calls.names == [RUN_JOB_TASK]
    [entry] = await audit_entries(db_session_factory, "machine.docker.container.rollback")
    assert entry.details == {"container": "web", "image_id": PREVIOUS_IMAGE_ID}


async def test_rollback_without_a_previous_update_does_nothing(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/rollback", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert celery_calls == []


async def test_scan_one_image_and_come_back_to_the_job(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/images/scan",
        data={"csrf_token": csrf, "image": "nginx:1.27", "image_id": IMAGE_ID},
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/jobs/{job.id}"
    assert job.kind == DockerJobKind.IMAGE_SCAN
    assert job.params == {"images": {"nginx:1.27": IMAGE_ID}}
    assert celery_calls.names == [RUN_JOB_TASK]
    [entry] = await audit_entries(db_session_factory, "machine.docker.images.scan")
    assert entry.details == {"target": "nginx:1.27"}


@pytest.mark.parametrize(
    "data",
    [
        {"image": "nginx:1.27", "image_id": "sha256:short"},
        {"image": "$(id)", "image_id": IMAGE_ID},
        {"scope": "everything-everywhere"},
    ],
)
async def test_scan_rejects_bad_input(client, db_session_factory, celery_calls, data):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/images/scan", data={"csrf_token": csrf, **data}
    )

    assert response.status_code == 400
    assert celery_calls == []


async def test_scan_already_queued_returns_only_within_the_tab(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    await add_job(
        db_session_factory,
        machine_id,
        kind=DockerJobKind.IMAGE_SCAN,
        target="scope:all",
        status=DockerJobStatus.RUNNING,
    )
    csrf = await csrf_token(client, machine_id)

    elsewhere = await client.post(
        f"/machines/{machine_id}/docker/images/scan",
        data={"csrf_token": csrf, "scope": "all", "back": "https://evil.example/"},
    )
    within = await client.post(
        f"/machines/{machine_id}/docker/images/scan",
        data={"csrf_token": csrf, "scope": "all", "back": f"/machines/{machine_id}/docker/stacks"},
    )

    assert elsewhere.headers["location"].startswith(f"/machines/{machine_id}/docker/images?")
    assert within.headers["location"].startswith(f"/machines/{machine_id}/docker/stacks?")
    assert celery_calls == []


async def test_prune_queues_the_selected_clean_up(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/prune",
        data={"csrf_token": csrf, "images": "1", "build_cache": "1", "volumes": "1"},
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert job.kind == DockerJobKind.PRUNE
    assert job.params is not None
    assert job.params["images"] and job.params["build_cache"] and job.params["volumes"]
    assert not job.params["all_volumes"] and not job.params["containers"]
    assert celery_calls.names == [RUN_JOB_TASK]
    [entry] = await audit_entries(db_session_factory, "machine.docker.prune")
    assert entry.outcome == AuditOutcome.SUCCESS


async def test_prune_with_nothing_selected_does_nothing(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(f"/machines/{machine_id}/docker/prune", data={"csrf_token": csrf})

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert celery_calls == []


@pytest.mark.parametrize(
    "extra",
    [
        {"volumes": "1"},
        {"volumes": "1", "confirm_name": "wrong-machine"},
        {"volumes": "1", "confirm_name": MACHINE_NAME.upper()},
        # The machine's name alone is not enough: removing named volumes
        # also needs "unused volumes" itself ticked.
        {"images": "1", "confirm_name": MACHINE_NAME},
    ],
    ids=["no-name", "wrong-name", "wrong-case", "volumes-unticked"],
)
async def test_removing_all_volumes_needs_the_machine_name_typed(
    client, db_session_factory, celery_calls, extra
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/prune",
        data={"csrf_token": csrf, "all_volumes": "1", **extra},
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith(f"/machines/{machine_id}/docker/images?error=")
    assert celery_calls == []
    assert await jobs_of(db_session_factory, machine_id) == []
    [entry] = await audit_entries(db_session_factory, "machine.docker.prune")
    assert entry.outcome != AuditOutcome.SUCCESS
    assert "not confirmed" in entry.summary


async def test_removing_all_volumes_with_the_name_typed(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/prune",
        data={
            "csrf_token": csrf,
            "volumes": "1",
            "all_volumes": "1",
            "confirm_name": f"  {MACHINE_NAME} ",
        },
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/jobs/{job.id}"
    assert job.params is not None and job.params["all_volumes"] is True
    assert celery_calls.names == [RUN_JOB_TASK]
