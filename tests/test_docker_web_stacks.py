"""Compose stacks on the Docker tab: writing one (`action.terminal`, it
holds the compose file, `.env` and Git token), deploying and syncing it
(`action.updates`), taking projects down (`action.power`), its webhook
URL (shown once) and deleting it with or without its volumes."""

from __future__ import annotations

import re

import pytest

from app.core.security import decrypt_secret
from app.db.models.audit_log import AuditOutcome
from app.db.models.docker import DockerJobKind, DockerStack, StackSource
from app.db.models.role import Permission
from app.services import docker_stacks
from tests.test_docker_web_support import (
    COMPOSE_FILE_TASK,
    GIT_TOKEN_SECRET,
    INVENTORY_TASK,
    RUN_JOB_TASK,
    STACK_ENV_SECRET,
    SYNC_TASK,
    VIEWER,
    Factory,
    add_stack,
    audit_entries,
    csrf_token,
    follow,
    get_row,
    inventory_answer,
    jobs_of,
    make_docker_machine,
)

COMPOSE = "services:\n  app:\n    image: nginx:1.27\n"
UPDATES_AND_POWER = frozenset(
    {Permission.MACHINE_VIEW, Permission.ACTION_UPDATES, Permission.ACTION_POWER}
)
TERMINAL_ONLY = frozenset({Permission.MACHINE_VIEW, Permission.ACTION_TERMINAL})


async def _stack_by_name(db_session_factory: Factory, name: str) -> DockerStack:
    from sqlalchemy import select

    async with db_session_factory() as session:
        return (
            await session.execute(select(DockerStack).where(DockerStack.name == name))
        ).scalar_one()


# --- Creating and editing (action.terminal) ----------------------------------


async def test_create_an_editor_stack_and_deploy_it(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks",
        data={
            "csrf_token": csrf,
            "name": "Blog",
            "source": "editor",
            "compose": COMPOSE.replace("\n", "\r\n"),
            "env_action": "set",
            "env": "SECRET_KEY=hunter2",
            "deploy": "1",
        },
    )

    stack = await _stack_by_name(db_session_factory, "blog")
    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/jobs/{job.id}"
    assert stack.compose_content == COMPOSE
    assert stack.env_encrypted is not None
    assert decrypt_secret(stack.env_encrypted) == "SECRET_KEY=hunter2"
    assert (job.kind, job.target, job.ref_id) == (DockerJobKind.STACK_DEPLOY, "blog", stack.id)
    assert celery_calls.names == [RUN_JOB_TASK]
    [created] = await audit_entries(db_session_factory, "machine.docker.stack.create")
    assert "hunter2" not in str(created.details) and "hunter2" not in created.summary
    assert len(await audit_entries(db_session_factory, "machine.docker.stack.deploy")) == 1


async def test_a_terminal_user_without_updates_can_save_but_not_deploy(
    client, login_as, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    await login_as(client, permissions=TERMINAL_ONLY)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks",
        data={
            "csrf_token": csrf,
            "name": "blog",
            "source": "editor",
            "compose": COMPOSE,
            "deploy": "1",
        },
    )

    stack = await _stack_by_name(db_session_factory, "blog")
    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/stacks/{stack.id}"
    assert celery_calls == []


async def test_create_a_git_stack_stores_the_token_encrypted_and_never_shows_it(
    client, db_session_factory
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks",
        data={
            "csrf_token": csrf,
            "name": "app",
            "source": "git",
            "git_url": "https://git.example.test/ops/app.git",
            "git_branch": "release",
            "git_compose_path": "deploy/compose.yaml",
            "git_token_action": "set",
            "git_token": "glpat-createdToken",
            "auto_sync": "1",
        },
    )

    stack = await _stack_by_name(db_session_factory, "app")
    assert response.status_code == 303
    assert stack.git_token_encrypted is not None
    assert decrypt_secret(stack.git_token_encrypted) == "glpat-createdToken"
    assert (stack.git_branch, stack.git_compose_path, stack.auto_sync) == (
        "release",
        "deploy/compose.yaml",
        True,
    )
    page = await follow(client, response.headers["location"])
    assert "glpat-createdToken" not in page
    assert "https://git.example.test/ops/app.git" in page


@pytest.mark.parametrize(
    "data",
    [
        {"name": "Bad Name!", "source": "editor", "compose": COMPOSE},
        {"name": "blog", "source": "editor", "compose": "just: text\n"},
        {"name": "blog", "source": "git", "git_url": "ssh://git@host/repo.git"},
        {"name": "blog", "source": "git", "git_url": "https://user:pw@host/repo.git"},
    ],
    ids=["name", "compose", "git-ssh", "git-credentials-in-url"],
)
async def test_create_rejects_invalid_input_and_keeps_the_form(
    client, db_session_factory, celery_calls, data
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks", data={"csrf_token": csrf, **data}
    )

    assert response.status_code == 400
    assert 'class="alert alert-error"' in response.text
    async with db_session_factory() as session:
        assert await docker_stacks.list_stacks(session, machine_id) == []
    assert celery_calls == []


async def test_create_rejects_a_name_already_taken(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    await add_stack(db_session_factory, machine_id, name="site")
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks",
        data={"csrf_token": csrf, "name": "site", "source": "editor", "compose": COMPOSE},
    )

    assert response.status_code == 400


async def test_a_new_stack_can_go_into_a_directory_of_ones_choosing(
    client, db_session_factory
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    url = f"/machines/{machine_id}/docker/stacks"
    form = {"csrf_token": csrf, "source": "editor", "compose": COMPOSE}

    created = await client.post(url, data={**form, "name": "blog", "directory": "/opt/blog/"})
    assert created.status_code == 303
    stack = await _stack_by_name(db_session_factory, "blog")
    assert stack.directory == "/opt/blog"
    assert "dir=/opt/blog\n" in docker_stacks.deploy_script(stack)
    [audit] = await audit_entries(db_session_factory, "machine.docker.stack.create")
    assert audit.details is not None and audit.details["directory"] == "/opt/blog"
    page = await client.get(f"{url}/{stack.id}")
    assert "<code>/opt/blog</code>" in page.text
    assert 'name="directory"' not in page.text

    # Default when left empty; refused when invalid or another stack's.
    await client.post(url, data={**form, "name": "plain", "directory": ""})
    assert (await _stack_by_name(db_session_factory, "plain")).directory is None
    for name, directory in (("bad", "/etc/bad"), ("rel", "apps/x"), ("twin", "/opt/blog")):
        refused = await client.post(url, data={**form, "name": name, "directory": directory})
        assert refused.status_code == 400, directory

    # Editing keeps the directory, whatever the form sends.
    await client.post(
        f"{url}/{stack.id}",
        data={**form, "env_action": "keep", "directory": "/opt/elsewhere"},
    )
    assert (await _stack_by_name(db_session_factory, "blog")).directory == "/opt/blog"


async def test_a_rejected_form_does_not_echo_the_git_token(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks",
        data={
            "csrf_token": csrf,
            "name": "app",
            "source": "git",
            "git_url": "not a url",
            "git_token_action": "set",
            "git_token": "glpat-rejectedToken",
        },
    )

    assert response.status_code == 400
    assert "glpat-rejectedToken" not in response.text


async def test_saving_keeps_the_name_and_the_token_unless_asked(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}",
        data={
            "csrf_token": csrf,
            "name": "renamed",
            "source": "git",
            "git_url": "https://git.example.test/ops/site.git",
            "git_branch": "next",
            "git_token_action": "keep",
            "git_token": "ignored-when-keeping",
            "env_action": "set",
            "env": "",
        },
    )

    stack = await get_row(db_session_factory, DockerStack, stack_id)
    assert stack is not None
    assert response.status_code == 303
    assert stack.name == "site"
    assert stack.git_branch == "next"
    assert stack.git_token_encrypted is not None
    assert decrypt_secret(stack.git_token_encrypted) == GIT_TOKEN_SECRET
    assert stack.env_encrypted is None
    assert celery_calls == []
    assert len(await audit_entries(db_session_factory, "machine.docker.stack.edit")) == 1


async def test_saving_can_remove_the_token(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}",
        data={
            "csrf_token": csrf,
            "source": "git",
            "git_url": "https://git.example.test/ops/site.git",
            "git_token_action": "remove",
        },
    )

    stack = await get_row(db_session_factory, DockerStack, stack_id)
    assert stack is not None and stack.git_token_encrypted is None


@pytest.mark.parametrize("permissions", [VIEWER, UPDATES_AND_POWER])
async def test_writing_a_stack_needs_action_terminal(
    client, login_as, db_session_factory, celery_calls, permissions
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    await login_as(client, permissions=permissions)
    csrf = await csrf_token(client, machine_id)
    base = f"/machines/{machine_id}/docker/stacks"
    form = {"csrf_token": csrf, "name": "blog", "source": "editor", "compose": COMPOSE}

    for url, data in (
        (base, form),
        (f"{base}/{stack_id}", form),
        (f"{base}/{stack_id}/webhook", {"csrf_token": csrf}),
        (f"{base}/{stack_id}/delete", {"csrf_token": csrf}),
    ):
        assert (await client.post(url, data=data)).status_code == 403, url

    stack = await get_row(db_session_factory, DockerStack, stack_id)
    assert stack is not None and stack.webhook_token_hash is None
    assert await audit_entries(db_session_factory, "machine.docker.stack.create") == []
    assert celery_calls == []


async def test_stack_changes_need_a_csrf_token(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    base = f"/machines/{machine_id}/docker"

    for url in (
        f"{base}/stacks",
        f"{base}/stacks/{stack_id}",
        f"{base}/stacks/{stack_id}/deploy",
        f"{base}/stacks/{stack_id}/sync",
        f"{base}/stacks/{stack_id}/webhook",
        f"{base}/stacks/{stack_id}/delete",
        f"{base}/projects/site/down",
    ):
        assert (await client.post(url, data={"name": "x"})).status_code == 403, url

    assert celery_calls == []
    assert await get_row(db_session_factory, DockerStack, stack_id) is not None


# --- Deploy and sync (action.updates) ----------------------------------------


async def test_deploy_queues_a_job(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}/deploy",
        data={"csrf_token": csrf, "pull": "0"},
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert job.kind == DockerJobKind.STACK_DEPLOY
    assert job.params == {"pull": False}
    assert celery_calls.names == [RUN_JOB_TASK]
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.deploy")
    assert entry.details == {"stack": "site", "pull": False}


async def test_deploy_and_sync_need_action_updates(
    client, login_as, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    await login_as(
        client,
        permissions={Permission.MACHINE_VIEW, Permission.ACTION_POWER, Permission.ACTION_TERMINAL},
    )
    csrf = await csrf_token(client, machine_id)
    base = f"/machines/{machine_id}/docker"

    for url in (f"{base}/stacks/{stack_id}/deploy", f"{base}/stacks/{stack_id}/sync"):
        assert (await client.post(url, data={"csrf_token": csrf})).status_code == 403, url
    assert celery_calls == []


async def test_deploy_refuses_debcontrols_own_project(
    client, db_session_factory, celery_calls, monkeypatch
):
    async def _own_project(db, machine):
        return "site"

    monkeypatch.setattr("app.services.docker_jobs.protected_project", _own_project)
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}/deploy", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert celery_calls == []


@pytest.mark.parametrize(
    ("answer", "flash_key"),
    [
        ({"ok": True, "deployed": True}, "docker.stack.sync_deploying"),
        ({"ok": True, "deployed": False}, "docker.stack.sync_up_to_date"),
    ],
)
async def test_sync_asks_the_worker_and_reports_back(
    client, db_session_factory, celery_calls, answer, flash_key
):
    from app.i18n import get_locale, translate

    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    celery_calls.result_for[SYNC_TASK] = answer
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}/sync", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert celery_calls.names == [SYNC_TASK]
    assert celery_calls[0][1] == (str(stack_id), "test-admin")
    page = await follow(client, response.headers["location"])
    assert translate(get_locale("en"), flash_key) in page
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.sync")
    assert entry.outcome == AuditOutcome.SUCCESS


async def test_sync_failure_is_shown_and_audited(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    celery_calls.result_for[SYNC_TASK] = {"ok": False, "error": "Repository not found"}
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}/sync", data={"csrf_token": csrf}
    )

    assert "Repository not found" in await follow(client, response.headers["location"])
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.sync")
    assert entry.outcome == AuditOutcome.FAILURE


async def test_sync_of_an_editor_stack_does_nothing(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id, source=StackSource.EDITOR)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}/sync", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert celery_calls == []


# --- Webhook URL (shown once) ------------------------------------------------


async def test_webhook_url_is_shown_once_and_stored_only_as_its_hash(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)
    page_url = f"/machines/{machine_id}/docker/stacks/{stack_id}"

    response = await client.post(f"{page_url}/webhook", data={"csrf_token": csrf})

    # Shown on this response itself, never via a redirect URL.
    assert response.status_code == 200
    match = re.search(r"http://testserver/hooks/docker/([A-Za-z0-9_-]+)", response.text)
    assert match is not None
    token = match.group(1)
    stack = await get_row(db_session_factory, DockerStack, stack_id)
    assert stack is not None
    assert stack.webhook_token_hash == docker_stacks.hash_token(token)
    assert token not in (stack.webhook_token_hash or "")
    # Not shown again.
    again = await client.get(page_url)
    assert token not in again.text
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.webhook")
    assert token not in str(entry.details) and token not in entry.summary
    assert celery_calls == []


async def test_a_new_webhook_url_replaces_the_old_one_and_can_be_removed(
    client, db_session_factory
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, old_token = await add_stack(db_session_factory, machine_id, with_webhook=True)
    assert old_token is not None
    csrf = await csrf_token(client, machine_id)
    page_url = f"/machines/{machine_id}/docker/stacks/{stack_id}"

    await client.post(f"{page_url}/webhook", data={"csrf_token": csrf})
    stack = await get_row(db_session_factory, DockerStack, stack_id)
    assert stack is not None
    assert stack.webhook_token_hash not in (None, docker_stacks.hash_token(old_token))

    removed = await client.post(f"{page_url}/webhook", data={"csrf_token": csrf, "remove": "1"})
    stack = await get_row(db_session_factory, DockerStack, stack_id)
    assert removed.status_code == 200
    assert "/hooks/docker/" not in removed.text
    assert stack is not None and stack.webhook_token_hash is None


async def test_an_editor_stack_has_no_webhook(client, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id, source=StackSource.EDITOR)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}/webhook", data={"csrf_token": csrf}
    )

    assert response.status_code == 400


# --- Delete ------------------------------------------------------------------


async def test_deleting_a_never_deployed_stack_just_forgets_it(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id, deployed=False)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}/delete", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/stacks"
    assert await get_row(db_session_factory, DockerStack, stack_id) is None
    assert celery_calls == []
    assert len(await audit_entries(db_session_factory, "machine.docker.stack.delete")) == 1


async def test_deleting_a_deployed_stack_takes_it_down_first(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}/delete", data={"csrf_token": csrf}
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert job.kind == DockerJobKind.STACK_ACTION
    assert job.params == {"action": "remove", "volumes": False}
    assert celery_calls.names == [RUN_JOB_TASK]


@pytest.mark.parametrize("confirm", ["", "other", "SITE"])
async def test_deleting_with_volumes_needs_the_stack_name_typed(
    client, db_session_factory, celery_calls, confirm
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id, deployed=False)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}/delete",
        data={"csrf_token": csrf, "remove_volumes": "1", "confirm_name": confirm},
    )

    assert response.status_code == 303
    assert response.headers["location"].startswith(
        f"/machines/{machine_id}/docker/stacks/{stack_id}?error="
    )
    assert await get_row(db_session_factory, DockerStack, stack_id) is not None
    assert celery_calls == []
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.delete")
    assert entry.outcome != AuditOutcome.SUCCESS


async def test_deleting_with_volumes_and_the_name_typed(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}/delete",
        data={"csrf_token": csrf, "remove_volumes": "1", "confirm_name": "site"},
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert job.params == {"action": "remove", "volumes": True}
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.delete")
    assert entry.details == {"stack": "site", "volumes": True}


# --- Any Compose project on the machine ---------------------------------------


@pytest.mark.parametrize("action", ["start", "stop", "restart", "down"])
async def test_power_actions_on_a_project_need_action_power(
    client, login_as, db_session_factory, celery_calls, action
):
    machine_id = await make_docker_machine(db_session_factory)
    await login_as(
        client,
        permissions={
            Permission.MACHINE_VIEW,
            Permission.ACTION_UPDATES,
            Permission.ACTION_TERMINAL,
        },
    )
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/projects/site/{action}", data={"csrf_token": csrf}
    )

    assert response.status_code == 403
    assert celery_calls == []


@pytest.mark.parametrize("action", ["up", "update"])
async def test_recreating_a_project_needs_action_updates(
    client, login_as, db_session_factory, celery_calls, action
):
    machine_id = await make_docker_machine(db_session_factory)
    await login_as(
        client,
        permissions={Permission.MACHINE_VIEW, Permission.ACTION_POWER, Permission.ACTION_TERMINAL},
    )
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/projects/site/{action}", data={"csrf_token": csrf}
    )

    assert response.status_code == 403
    assert celery_calls == []


async def test_taking_a_project_down_queues_a_job(
    client, login_as, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_POWER})
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/projects/site/down", data={"csrf_token": csrf}
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert response.headers["location"] == f"/machines/{machine_id}/docker/jobs/{job.id}"
    assert (job.kind, job.target, job.params) == (
        DockerJobKind.STACK_ACTION,
        "site",
        {"action": "down"},
    )
    assert celery_calls.names == [RUN_JOB_TASK]
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.action")
    assert entry.details == {"project": "site", "action": "down"}


async def test_updating_an_unmanaged_project_uses_the_files_the_machine_reports(
    client, db_session_factory, celery_calls
):
    """The compose files of a project not deployed by debcontrol come from
    the machine itself, never from the request."""
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/projects/site/update",
        data={"csrf_token": csrf, "files": "/etc/evil.yaml", "working_dir": "/"},
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert response.status_code == 303
    assert job.params == {
        "action": "update",
        "working_dir": "/srv/site",
        "files": ["/srv/site/compose.yaml"],
    }
    assert celery_calls.names == [INVENTORY_TASK, RUN_JOB_TASK]


async def test_updating_a_project_whose_files_are_unknown_is_refused(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/projects/ghost/up", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert celery_calls.names == [INVENTORY_TASK]
    assert await jobs_of(db_session_factory, machine_id) == []


async def test_updating_a_managed_project_deploys_the_stack(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    csrf = await csrf_token(client, machine_id)

    await client.post(
        f"/machines/{machine_id}/docker/projects/site/update", data={"csrf_token": csrf}
    )

    [job] = await jobs_of(db_session_factory, machine_id)
    assert (job.kind, job.ref_id, job.params) == (
        DockerJobKind.STACK_DEPLOY,
        stack_id,
        {"pull": True},
    )
    assert celery_calls.names == [RUN_JOB_TASK]


@pytest.mark.parametrize(("project", "action"), [("site", "rm"), ("Site", "down"), ("-p", "down")])
async def test_project_action_rejects_bad_input(
    client, db_session_factory, celery_calls, project, action
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/projects/{project}/{action}", data={"csrf_token": csrf}
    )

    assert response.status_code == 400
    assert celery_calls == []


async def test_project_compose_page_reads_the_files_from_the_machine(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    celery_calls.result_for[COMPOSE_FILE_TASK] = {"ok": True, "content": "services:\n  web: {}\n"}

    response = await client.get(f"/machines/{machine_id}/docker/projects/site/compose")

    assert response.status_code == 200
    assert "/srv/site/compose.yaml" in response.text
    assert "web: {}" in response.text
    assert celery_calls.names == [INVENTORY_TASK, COMPOSE_FILE_TASK]
    assert celery_calls[1][1] == (str(machine_id), "/srv/site/compose.yaml")


WRITE_COMPOSE_TASK = "app.tasks.docker_jobs.docker_write_compose_file"
SITE_COMPOSE = "/srv/site/compose.yaml"


async def test_project_compose_page_offers_an_editor(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    celery_calls.result_for[COMPOSE_FILE_TASK] = {"ok": True, "content": "services:\n  web: {}\n"}

    response = await client.get(f"/machines/{machine_id}/docker/projects/site/compose")

    assert '<textarea id="compose-1" name="content"' in response.text
    assert f'name="path" value="{SITE_COMPOSE}"' in response.text
    assert 'name="up" value="1"' in response.text


async def test_saving_a_project_compose_file_writes_it_on_the_machine(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    celery_calls.result_for[WRITE_COMPOSE_TASK] = {"ok": True}
    csrf = await csrf_token(client, machine_id)
    url = f"/machines/{machine_id}/docker/projects/site/compose"

    saved = await client.post(
        url, data={"csrf_token": csrf, "path": SITE_COMPOSE, "content": "services: {}\r\n"}
    )

    assert saved.status_code == 303
    assert saved.headers["location"].startswith(url)
    assert celery_calls.names == [INVENTORY_TASK, WRITE_COMPOSE_TASK]
    assert celery_calls[1][1] == (
        str(machine_id), "site", SITE_COMPOSE, "services: {}\n", "/srv/site", [SITE_COMPOSE]
    )
    assert await jobs_of(db_session_factory, machine_id) == []
    [entry] = await audit_entries(db_session_factory, "machine.docker.project.compose_edit")
    assert entry.outcome == AuditOutcome.SUCCESS

    applied = await client.post(
        url, data={"csrf_token": csrf, "path": SITE_COMPOSE, "content": "services: {}\n",
                   "up": "1"},
    )
    [job] = await jobs_of(db_session_factory, machine_id)
    assert applied.headers["location"] == f"/machines/{machine_id}/docker/jobs/{job.id}"
    assert (job.kind, job.target) == (DockerJobKind.STACK_ACTION, "site")
    assert job.params == {"action": "up", "working_dir": "/srv/site", "files": [SITE_COMPOSE]}


async def test_a_compose_file_docker_rejects_is_reported_and_audited(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    celery_calls.result_for[WRITE_COMPOSE_TASK] = {
        "ok": False, "step": "config", "error": "services.web additional property foo"
    }
    csrf = await csrf_token(client, machine_id)

    posted = await client.post(
        f"/machines/{machine_id}/docker/projects/site/compose",
        data={"csrf_token": csrf, "path": SITE_COMPOSE, "content": "x", "up": "1"},
    )
    page = await follow(client, posted.headers["location"])

    assert "services.web additional property foo" in page
    assert await jobs_of(db_session_factory, machine_id) == []
    [entry] = await audit_entries(db_session_factory, "machine.docker.project.compose_edit")
    assert entry.outcome == AuditOutcome.FAILURE


async def test_saving_a_compose_file_is_refused_when_it_should_be(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    csrf = await csrf_token(client, machine_id)
    url = f"/machines/{machine_id}/docker/projects/site/compose"

    # Not one of the project's files (as the machine reports them).
    other = await client.post(url, data={"csrf_token": csrf, "path": "/etc/passwd", "content": "x"})
    assert other.status_code == 303
    assert WRITE_COMPOSE_TASK not in celery_calls.names
    # No CSRF token.
    assert (await client.post(url, data={"path": SITE_COMPOSE, "content": "x"})).status_code == 403
    # A stack debcontrol deploys is edited on its own page.
    await add_stack(db_session_factory, machine_id, name="site")
    managed = await client.post(url, data={"csrf_token": csrf, "path": SITE_COMPOSE,
                                           "content": "x"})
    assert managed.status_code == 303
    assert WRITE_COMPOSE_TASK not in celery_calls.names


@pytest.mark.parametrize(
    ("permissions", "up"), [(TERMINAL_ONLY, "1"), (UPDATES_AND_POWER, "0")]
)
async def test_saving_a_compose_file_needs_terminal_and_applying_it_updates(
    client, login_as, db_session_factory, celery_calls, permissions, up
):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    await login_as(client, permissions=permissions)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/projects/site/compose",
        data={"csrf_token": csrf, "path": SITE_COMPOSE, "content": "x", "up": up},
    )

    assert response.status_code == 403
    assert WRITE_COMPOSE_TASK not in celery_calls.names


async def test_new_stack_form_for_a_terminal_user(client, login_as, db_session_factory):
    machine_id = await make_docker_machine(db_session_factory)
    await login_as(client, permissions=TERMINAL_ONLY)

    response = await client.get(f"/machines/{machine_id}/docker/stacks/new")

    assert response.status_code == 200
    assert f'action="/machines/{machine_id}/docker/stacks"' in response.text
    # Without action.updates there is no "deploy now".
    assert 'name="deploy"' not in response.text


async def test_stack_page_for_a_terminal_user_shows_env_but_not_token(
    client, login_as, db_session_factory
):
    machine_id = await make_docker_machine(db_session_factory)
    stack_id, _ = await add_stack(db_session_factory, machine_id)
    await login_as(client, permissions=TERMINAL_ONLY)

    response = await client.get(f"/machines/{machine_id}/docker/stacks/{stack_id}")

    assert response.status_code == 200
    assert STACK_ENV_SECRET in response.text  # the .env editor
    assert GIT_TOKEN_SECRET not in response.text
    assert 'name="git_token" type="password"' in response.text
