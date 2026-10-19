"""The Docker tab's pages for someone who may only look (`machine.view`):
every page and htmx panel renders, the action forms are left out, the
pages behind `action.terminal` stay closed, and no stored secret ever
reaches the HTML."""

from __future__ import annotations

import uuid

import pytest

from app.db.models.docker import DockerJobKind, DockerJobStatus, StackSource
from app.db.models.role import Permission
from tests.conftest import RecordedCeleryCalls
from tests.test_docker_web_support import (
    BACKUP_ENV_SECRET,
    BACKUP_PASSWORD_SECRET,
    BACKUP_REPO_PASSWORD,
    GIT_TOKEN_SECRET,
    IMAGE_ID,
    INVENTORY_TASK,
    PREVIOUS_IMAGE_ID,
    SNAPSHOT_ID,
    SNAPSHOTS_TASK,
    STACK_ENV_SECRET,
    VIEWER,
    Factory,
    add_backup,
    add_job,
    add_scan,
    add_stack,
    inventory_answer,
    make_docker_machine,
)
from tests.test_monitoring_web import _add_monitoring_sample

ALL_SECRETS = (
    STACK_ENV_SECRET,
    "stack-env-secret-value",
    GIT_TOKEN_SECRET,
    BACKUP_PASSWORD_SECRET,
    BACKUP_ENV_SECRET,
    "backup-env-secret-value",
    BACKUP_REPO_PASSWORD,
)


async def _seed_everything(
    db_session_factory: Factory, celery_calls: RecordedCeleryCalls
) -> tuple[uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID]:
    machine_id = await make_docker_machine(db_session_factory)
    await _add_monitoring_sample(db_session_factory, machine_id)
    await add_scan(db_session_factory, machine_id)
    stack_id, _token = await add_stack(db_session_factory, machine_id, with_webhook=True)
    backup_id = await add_backup(db_session_factory, machine_id)
    job_id = await add_job(
        db_session_factory,
        machine_id,
        result={
            "previous_image_id": PREVIOUS_IMAGE_ID,
            "new_image_id": IMAGE_ID,
            "ref": "nginx:1.27",
        },
    )
    await add_job(
        db_session_factory,
        machine_id,
        kind=DockerJobKind.STACK_DEPLOY,
        target="site",
        status=DockerJobStatus.RUNNING,
        output=None,
        ref_id=stack_id,
    )
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    celery_calls.result_for[SNAPSHOTS_TASK] = {
        "ok": True,
        "snapshots": [
            {
                "id": SNAPSHOT_ID,
                "short_id": SNAPSHOT_ID[:8],
                "time": "2026-10-17T03:00:00.000Z",
                "size_bytes": 1_048_576,
                "paths": ["/volumes/site_data", "/srv/site/config"],
            }
        ],
    }
    return machine_id, stack_id, backup_id, job_id


def _viewer_pages(
    machine_id: uuid.UUID, stack_id: uuid.UUID, backup_id: uuid.UUID, job_id: uuid.UUID
) -> list[str]:
    base = f"/machines/{machine_id}/docker"
    return [
        base,
        f"{base}?range_key=24h",
        f"{base}/containers/web",
        f"{base}/containers/web/panel",
        f"{base}/images",
        f"{base}/images/panel",
        f"{base}/images/{IMAGE_ID}/vulnerabilities",
        f"{base}/images/{IMAGE_ID}/vulnerabilities?severity=critical&q=openssl",
        f"{base}/volumes",
        f"{base}/volumes/panel",
        f"{base}/volumes/panel?sizes=1",
        f"{base}/networks",
        f"{base}/networks/panel",
        f"{base}/networks/site_default",
        f"{base}/networks/site_default/panel",
        f"{base}/networks/gone",
        f"{base}/networks/gone/panel",
        f"{base}/stacks",
        f"{base}/stacks/panel",
        f"{base}/stacks/{stack_id}",
        f"{base}/backups",
        f"{base}/backups/{backup_id}",
        f"{base}/backups/{backup_id}/snapshots",
        f"{base}/jobs",
        f"{base}/jobs/panel",
        f"{base}/jobs/{job_id}",
        f"{base}/jobs/{job_id}/status",
    ]


async def test_a_viewer_can_open_every_page_and_panel(
    client, login_as, db_session_factory, celery_calls
):
    ids = await _seed_everything(db_session_factory, celery_calls)
    await login_as(client, permissions=VIEWER)

    for url in _viewer_pages(*ids):
        response = await client.get(url)
        assert response.status_code == 200, url
        for secret in ALL_SECRETS:
            assert secret not in response.text, (url, secret)


async def test_an_admin_never_sees_stored_secrets_except_the_stack_env_they_edit(
    client, db_session_factory, celery_calls
):
    """Even with every permission, the Git token, the restic password, the
    backup's extra environment and the repository's credentials are never
    rendered back. (The stack's `.env` is shown to `action.terminal` in its
    editor on purpose — see `test_stack_env_is_only_shown_to_terminal_users`.)"""
    machine_id, stack_id, backup_id, job_id = await _seed_everything(
        db_session_factory, celery_calls
    )
    base = f"/machines/{machine_id}/docker"
    pages = [*_viewer_pages(machine_id, stack_id, backup_id, job_id), f"{base}/backups/new"]

    for url in pages:
        response = await client.get(url)
        assert response.status_code == 200, url
        for secret in (
            GIT_TOKEN_SECRET,
            BACKUP_PASSWORD_SECRET,
            BACKUP_ENV_SECRET,
            "backup-env-secret-value",
            BACKUP_REPO_PASSWORD,
        ):
            assert secret not in response.text, (url, secret)


async def test_stack_env_is_only_shown_to_terminal_users(client, login_as, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id, source=StackSource.EDITOR)
    url = f"/machines/{machine_id}/docker/stacks/{stack_id}"

    as_admin = await client.get(url)
    await login_as(
        client,
        permissions={Permission.MACHINE_VIEW, Permission.ACTION_UPDATES, Permission.ACTION_POWER},
    )
    as_operator = await client.get(url)

    assert STACK_ENV_SECRET in as_admin.text
    assert as_operator.status_code == 200
    assert STACK_ENV_SECRET not in as_operator.text
    # Nor the compose file: it is for those who may edit it.
    assert "image: nginx:1.27" not in as_operator.text


async def test_containers_page_shows_containers_updates_and_scans(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    await add_scan(db_session_factory, machine_id)
    await add_job(db_session_factory, machine_id, status=DockerJobStatus.FAILED)

    response = await client.get(f"/machines/{machine_id}/docker")

    assert response.status_code == 200
    text = response.text
    assert f'href="/machines/{machine_id}/docker/containers/web"' in text
    assert f'href="/machines/{machine_id}/docker/containers/worker"' in text
    assert "nginx:1.27" in text
    # The newer image the image check found, and the scan of the running one.
    assert "1.27.1" in text
    assert f"/machines/{machine_id}/docker/images/{IMAGE_ID}/vulnerabilities" in text
    # Updating is offered, as a form, to someone allowed to update.
    assert f'action="/machines/{machine_id}/docker/update"' in text


async def test_containers_page_without_docker_says_so(client, db_session_factory):
    from app.db.models.machine import Machine

    machine_id = await make_docker_machine(db_session_factory)
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.docker_status = None
        machine.docker_containers = None
        await session.commit()

    response = await client.get(f"/machines/{machine_id}/docker")

    assert response.status_code == 200
    assert 'id="containers-table"' not in response.text


async def test_viewer_gets_no_action_forms(client, login_as, db_session_factory, celery_calls):
    machine_id, stack_id, backup_id, _job_id = await _seed_everything(
        db_session_factory, celery_calls
    )
    await login_as(client, permissions=VIEWER)
    base = f"/machines/{machine_id}/docker"

    containers = (await client.get(base)).text
    container = (await client.get(f"{base}/containers/web")).text
    container_panel = (await client.get(f"{base}/containers/web/panel")).text
    images_panel = (await client.get(f"{base}/images/panel")).text
    stacks = (await client.get(f"{base}/stacks")).text
    projects = (await client.get(f"{base}/stacks/panel")).text
    stack = (await client.get(f"{base}/stacks/{stack_id}")).text
    backups = (await client.get(f"{base}/backups")).text
    backup = (await client.get(f"{base}/backups/{backup_id}")).text
    snapshots = (await client.get(f"{base}/backups/{backup_id}/snapshots")).text

    assert f'action="{base}/update"' not in containers
    assert f"/machines/{machine_id}/containers/web/restart" not in containers
    assert f'action="{base}/containers/web/update"' not in container
    assert f'action="{base}/containers/web/settings"' not in container
    assert f"{base}/containers/web/shell" not in container
    assert f"{base}/containers/web/files" not in container
    assert "/restart?from=container" not in container_panel
    assert f'action="{base}/images/scan"' not in container_panel
    assert f"{base}/volumes/site_data/files" not in container_panel
    assert f'action="{base}/prune"' not in images_panel
    assert f'action="{base}/images/scan"' not in images_panel
    assert f"{base}/stacks/new" not in stacks
    assert f"{base}/projects/site/" not in projects
    assert f'action="{base}/stacks/{stack_id}' not in stack
    assert f'action="{base}/stacks"' not in stack
    assert f"{base}/backups/new" not in backups
    assert f'action="{base}/backups/{backup_id}' not in backup
    assert f'action="{base}/backups/{backup_id}/restore"' not in snapshots
    # What there is to see is still there.
    assert "site_default" in container_panel
    assert "nginx:1.27" in images_panel
    assert SNAPSHOT_ID[:8] in snapshots


async def test_each_permission_unlocks_its_own_forms(
    client, login_as, db_session_factory, celery_calls
):
    machine_id, _stack_id, backup_id, _job_id = await _seed_everything(
        db_session_factory, celery_calls
    )
    base = f"/machines/{machine_id}/docker"

    await login_as(
        client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_POWER}, username="power"
    )
    projects = (await client.get(f"{base}/stacks/panel")).text
    assert f'action="{base}/projects/site/down"' in projects
    assert f'action="{base}/projects/site/update"' not in projects
    assert f"{base}/projects/site/compose" not in projects

    await login_as(
        client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_UPDATES}, username="upd"
    )
    projects = (await client.get(f"{base}/stacks/panel")).text
    backup = (await client.get(f"{base}/backups/{backup_id}")).text
    assert f'action="{base}/projects/site/update"' in projects
    assert f'action="{base}/projects/site/down"' not in projects
    assert f'action="{base}/backups/{backup_id}/run"' in backup
    assert f'action="{base}/backups/{backup_id}/forget"' in backup
    # Backup settings and restores are action.terminal's.
    assert f'action="{base}/backups/{backup_id}"' not in backup
    snapshots = (await client.get(f"{base}/backups/{backup_id}/snapshots")).text
    assert f'action="{base}/backups/{backup_id}/restore"' not in snapshots

    await login_as(
        client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_TERMINAL}, username="term"
    )
    backup = (await client.get(f"{base}/backups/{backup_id}")).text
    snapshots = (await client.get(f"{base}/backups/{backup_id}/snapshots")).text
    container = (await client.get(f"{base}/containers/web")).text
    assert f'action="{base}/backups/{backup_id}"' in backup
    assert f'action="{base}/backups/{backup_id}/run"' not in backup
    assert f'action="{base}/backups/{backup_id}/restore"' in snapshots
    assert f"{base}/containers/web/shell" in container
    assert f'action="{base}/containers/web/update"' not in container


@pytest.mark.parametrize(
    "path",
    [
        "containers/web/shell",
        "containers/web/files",
        "containers/web/files/edit?path=/etc/hosts",
        "containers/web/files/download?path=/etc/hosts",
        "volumes/site_data/files",
        "stacks/new",
        "backups/new",
        "projects/site/compose",
    ],
)
async def test_terminal_pages_are_closed_to_a_viewer(
    client, login_as, db_session_factory, celery_calls, path
):
    machine_id = await make_docker_machine(db_session_factory)
    await login_as(
        client,
        permissions={Permission.MACHINE_VIEW, Permission.ACTION_UPDATES, Permission.ACTION_POWER},
    )

    response = await client.get(f"/machines/{machine_id}/docker/{path}")

    assert response.status_code == 403
    assert celery_calls == []


async def test_pages_need_machine_view(client, login_as, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    await login_as(client, permissions={Permission.ACTION_UPDATES})

    response = await client.get(f"/machines/{machine_id}/docker")

    assert response.status_code == 403


async def test_a_machine_outside_the_users_groups_is_not_found(
    client, login_as, db_session_factory
):
    from app.db.models.machine_group import MachineGroup

    machine_id = await make_docker_machine(db_session_factory)
    async with db_session_factory() as session:
        other = MachineGroup(name="elsewhere")
        session.add(other)
        await session.commit()
        other_id = other.id
    await login_as(client, permissions=VIEWER, group_ids={other_id})

    response = await client.get(f"/machines/{machine_id}/docker/stacks")

    assert response.status_code == 404


async def test_unknown_or_foreign_rows_are_not_found(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    other_id = await make_docker_machine(db_session_factory, name="other")
    stack_id, _ = await add_stack(db_session_factory, other_id)
    backup_id = await add_backup(db_session_factory, other_id)
    job_id = await add_job(db_session_factory, other_id)
    base = f"/machines/{machine_id}/docker"

    for url in (
        f"{base}/stacks/{stack_id}",
        f"{base}/backups/{backup_id}",
        f"{base}/jobs/{job_id}",
        f"{base}/jobs/{uuid.uuid4()}/status",
        f"{base}/images/{IMAGE_ID}/vulnerabilities",
        f"{base}/images/not-an-id/vulnerabilities",
        f"{base}/containers/bad;name",
        f"{base}/networks/bad;name",
        f"{base}/networks/bad;name/panel",
    ):
        assert (await client.get(url)).status_code == 404, url


async def test_panels_show_the_workers_error(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = {"ok": False, "error": "Docker daemon unreachable"}
    base = f"/machines/{machine_id}/docker"

    for url in (
        f"{base}/images/panel",
        f"{base}/volumes/panel",
        f"{base}/networks/panel",
        f"{base}/stacks/panel",
        f"{base}/containers/web/panel",
    ):
        response = await client.get(url)
        assert response.status_code == 200, url
        assert "Docker daemon unreachable" in response.text, url


async def test_panels_ask_the_worker_for_the_right_sections(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    base = f"/machines/{machine_id}/docker"

    await client.get(f"{base}/volumes/panel?sizes=1")
    await client.get(f"{base}/networks/panel")

    assert celery_calls.names == [INVENTORY_TASK, INVENTORY_TASK]
    assert celery_calls[0][1] == (str(machine_id), ["volumes", "inspect", "volume_sizes"])
    assert celery_calls[1][1] == (str(machine_id), ["networks", "inspect"])


async def test_network_page_shows_addressing_and_attached_containers(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    base = f"/machines/{machine_id}/docker"

    listing = await client.get(f"{base}/networks/panel")
    assert f'href="{base}/networks/site_default"' in listing.text
    container = await client.get(f"{base}/containers/web/panel")
    assert f'href="{base}/networks/site_default"' in container.text

    page = await client.get(f"{base}/networks/site_default")
    assert page.status_code == 200
    assert f"{base}/networks/site_default/panel" in page.text
    panel = await client.get(f"{base}/networks/site_default/panel")
    assert panel.status_code == 200
    for text in ("172.18.0.0/16", "172.18.0.1", "172.18.0.2/16", "02:42:ac:12:00:02", "br-site"):
        assert text in panel.text, text
    assert f'href="{base}/containers/web"' in panel.text
    assert celery_calls[-1][1] == (str(machine_id), ["network_inspect"])

    missing = await client.get(f"{base}/networks/gone/panel")
    assert missing.status_code == 200
    assert "172.18.0.0/16" not in missing.text


async def test_job_page_polls_while_running_and_stops_when_done(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    running = await add_job(
        db_session_factory, machine_id, status=DockerJobStatus.RUNNING, output=None
    )
    done = await add_job(db_session_factory, machine_id, target="worker")
    base = f"/machines/{machine_id}/docker"

    running_html = (await client.get(f"{base}/jobs/{running}/status")).text
    done_html = (await client.get(f"{base}/jobs/{done}")).text

    assert f'hx-get="{base}/jobs/{running}/status"' in running_html
    assert "hx-trigger" not in done_html.split('id="docker-job-status"')[1].split(">")[0]
    assert "Recreated web" in done_html


async def test_vulnerability_filter_narrows_the_findings(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    await add_scan(db_session_factory, machine_id)
    url = f"/machines/{machine_id}/docker/images/{IMAGE_ID}/vulnerabilities"

    everything = (await client.get(url)).text
    only_high = (await client.get(url, params={"severity": "high"})).text
    by_package = (await client.get(url, params={"q": "OPENSSL"})).text

    assert "CVE-2026-0001" in everything and "CVE-2026-0002" in everything
    assert "CVE-2026-0001" not in only_high and "CVE-2026-0002" in only_high
    assert "CVE-2026-0001" in by_package and "CVE-2026-0002" not in by_package


async def test_shell_page_points_at_the_container_terminal(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)

    response = await client.get(f"/machines/{machine_id}/docker/containers/web/shell")

    assert response.status_code == 200
    assert f'data-ws-path="/machines/{machine_id}/terminal/ws?container=web"' in response.text


async def test_shell_page_refuses_an_unpinned_machine_or_a_bad_name(client, db_session_factory):
    unpinned = await make_docker_machine(db_session_factory, pinned=False)
    pinned = await make_docker_machine(db_session_factory, name="pinned")

    assert (
        await client.get(f"/machines/{unpinned}/docker/containers/web/shell")
    ).status_code == 400
    assert (await client.get(f"/machines/{pinned}/docker/containers/-rm/shell")).status_code == 404
