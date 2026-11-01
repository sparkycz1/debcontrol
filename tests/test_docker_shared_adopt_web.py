"""Docker new features, part 2, through the web pages and the REST API:
Docker -> Registries and Docker -> Variables (scopes, permissions,
secrets never shown), shared variables picked by a stack, adopting a
Compose project, a `docker run` container turned into a stack, drift and
taking a stack's files over from the machine."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.docker import DockerRegistry, DockerStack, DockerVariable, StackSource
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from tests.test_docker_web_support import (
    INVENTORY_TASK,
    audit_entries,
    csrf_token,
    follow,
    get_row,
    inventory_answer,
    make_docker_machine,
)
from tests.test_update_history import _api_token

SYNC_LOGINS = "app.tasks.docker_extras.sync_registry_logins"
PROJECT_READ = "app.tasks.docker_extras.docker_project_read"
MARK_DIR = "app.tasks.docker_extras.docker_mark_stack_dir"
CONTAINER_COMPOSE = "app.tasks.docker_extras.docker_container_compose"
DRIFT = "app.tasks.docker_extras.check_stack_drift"
FILES_READ = "app.tasks.docker_extras.docker_stack_files_read"

PASSWORD = "registry-password-never-shown"
SECRET_VALUE = "shared-secret-never-shown"
COMPOSE = "services:\n  web:\n    image: nginx:1.27\n"


async def _csrf(client: Any) -> str:
    await client.get("/docker/registries")
    token = client.cookies.get("csrftoken")
    assert token
    return str(token)


async def _group_with(db_session_factory: Any, machine_id: uuid.UUID, name: str) -> uuid.UUID:
    async with db_session_factory() as session:
        group = MachineGroup(name=name)
        session.add(group)
        await session.flush()
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.group_id = group.id
        await session.commit()
        return group.id


async def _all(db_session_factory: Any, model: Any) -> list[Any]:
    async with db_session_factory() as session:
        return list((await session.execute(select(model))).scalars().all())


# --- Registries (web) --------------------------------------------------------------


async def test_adding_a_registry_stores_the_password_encrypted_and_logs_machines_in(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await _csrf(client)

    response = await client.post(
        "/docker/registries",
        data={
            "csrf_token": csrf,
            "server": "https://GHCR.io/",
            "username": "bot",
            "password": PASSWORD,
            "scope": "all",
        },
    )

    [registry] = await _all(db_session_factory, DockerRegistry)
    assert response.status_code == 303
    assert registry.server == "ghcr.io"
    assert decrypt_secret(registry.password_encrypted) == PASSWORD
    assert celery_calls.names == [SYNC_LOGINS]
    assert celery_calls[0][1] == (str(machine_id), False)
    [entry] = await audit_entries(db_session_factory, "docker.registry.create")
    assert PASSWORD not in str(entry.details) and PASSWORD not in entry.summary
    page = await follow(client, response.headers["location"])
    assert "<code>ghcr.io</code>" in page and PASSWORD not in page
    edit = await client.get(f"/docker/registries/{registry.id}")
    assert edit.status_code == 200 and PASSWORD not in edit.text


async def test_editing_a_registry_without_a_password_keeps_it(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    await make_docker_machine(db_session_factory)
    csrf = await _csrf(client)
    await client.post(
        "/docker/registries",
        data={"csrf_token": csrf, "server": "ghcr.io", "username": "bot", "password": PASSWORD},
    )
    [registry] = await _all(db_session_factory, DockerRegistry)

    saved = await client.post(
        f"/docker/registries/{registry.id}",
        data={"csrf_token": csrf, "server": "ghcr.io", "username": "bot2", "password": ""},
    )
    relogin = await client.post(
        f"/docker/registries/{registry.id}/login", data={"csrf_token": csrf}
    )
    deleted = await client.post(
        f"/docker/registries/{registry.id}/delete", data={"csrf_token": csrf}
    )

    assert saved.status_code == relogin.status_code == deleted.status_code == 303
    assert celery_calls[-1][1][1] is True  # "log in again" forces it
    assert await _all(db_session_factory, DockerRegistry) == []
    [edited] = await audit_entries(db_session_factory, "docker.registry.edit")
    assert (edited.details or {})["password_changed"] is False
    assert len(await audit_entries(db_session_factory, "docker.registry.delete")) == 1


async def test_a_bad_registry_form_is_shown_again_with_errors(
    client: Any, db_session_factory: Any
) -> None:
    csrf = await _csrf(client)

    response = await client.post(
        "/docker/registries",
        data={"csrf_token": csrf, "server": "not a host", "username": "bot", "password": ""},
    )

    assert response.status_code == 400
    assert await _all(db_session_factory, DockerRegistry) == []


async def test_a_group_limited_account_manages_only_its_groups_entries(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    mine = await make_docker_machine(db_session_factory)
    theirs = await make_docker_machine(db_session_factory, name="otherhost")
    my_group = await _group_with(db_session_factory, mine, "mine")
    their_group = await _group_with(db_session_factory, theirs, "theirs")
    async with db_session_factory() as session:
        fleet = DockerRegistry(
            server="ghcr.io", username="fleet", password_encrypted=encrypt_secret("x")
        )
        hidden = DockerRegistry(
            server="quay.io",
            username="hidden",
            password_encrypted=encrypt_secret("x"),
            group_id=their_group,
            scope_key=f"g:{their_group}",
        )
        session.add_all([fleet, hidden])
        await session.commit()
    await login_as(client, permissions={Permission.ACTION_TERMINAL}, group_ids={my_group})
    csrf = await _csrf(client)

    page = await client.get("/docker/registries")
    edit_fleet = await client.get(f"/docker/registries/{fleet.id}")
    edit_hidden = await client.get(f"/docker/registries/{hidden.id}")
    fleet_wide = await client.post(
        "/docker/registries",
        data={"csrf_token": csrf, "server": "a.example.com", "username": "u", "password": "p"},
    )
    other_group = await client.post(
        "/docker/registries",
        data={
            "csrf_token": csrf,
            "server": "a.example.com",
            "username": "u",
            "password": "p",
            "scope": f"group:{their_group}",
        },
    )
    own_group = await client.post(
        "/docker/registries",
        data={
            "csrf_token": csrf,
            "server": "a.example.com",
            "username": "u",
            "password": "p",
            "scope": f"machine:{mine}",
        },
    )

    assert page.status_code == 200
    assert "<code>ghcr.io</code>" in page.text and "<code>quay.io</code>" not in page.text
    assert f"/docker/registries/{fleet.id}" not in page.text  # read-only for this account
    assert edit_fleet.status_code == 403
    assert edit_hidden.status_code == 404
    assert fleet_wide.status_code == 400 and other_group.status_code == 400
    assert own_group.status_code == 303


async def test_registries_and_variables_need_the_terminal_permission(
    client: Any, login_as: Any
) -> None:
    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_UPDATES})

    assert (await client.get("/docker/registries")).status_code == 403
    assert (await client.get("/docker/variables")).status_code == 403
    containers = await client.get("/docker/containers")
    assert containers.status_code == 200
    assert 'href="/docker/registries"' not in containers.text


# --- Variables (web) ---------------------------------------------------------------


async def test_a_secret_variable_is_never_sent_back(
    client: Any, db_session_factory: Any
) -> None:
    csrf = await _csrf(client)

    created = await client.post(
        "/docker/variables",
        data={"csrf_token": csrf, "name": "SMTP_PASSWORD", "value": SECRET_VALUE, "secret": "1"},
    )
    [variable] = await _all(db_session_factory, DockerVariable)
    listing = await client.get("/docker/variables")
    edit = await client.get(f"/docker/variables/{variable.id}")
    kept = await client.post(
        f"/docker/variables/{variable.id}",
        data={
            "csrf_token": csrf,
            "name": "SMTP_PASSWORD",
            "value_action": "keep",
            "value": "",
            "secret": "1",
        },
    )
    bad = await client.post(
        "/docker/variables",
        data={"csrf_token": csrf, "name": "1BAD", "value": SECRET_VALUE, "secret": "1"},
    )

    assert created.status_code == kept.status_code == 303
    assert SECRET_VALUE not in listing.text and SECRET_VALUE not in edit.text
    assert bad.status_code == 400 and SECRET_VALUE not in bad.text
    stored = await get_row(db_session_factory, DockerVariable, variable.id)
    assert stored is not None and decrypt_secret(stored.value_encrypted) == SECRET_VALUE
    for action in ("docker.variable.create", "docker.variable.edit"):
        [entry] = await audit_entries(db_session_factory, action)
        assert SECRET_VALUE not in str(entry.details)


async def test_a_stack_picks_shared_variables_and_shows_missing_ones(
    client: Any, db_session_factory: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    await client.post(
        "/docker/variables", data={"csrf_token": csrf, "name": "TZ", "value": "Europe/Prague"}
    )

    form = await client.get(f"/machines/{machine_id}/docker/stacks/new")
    created = await client.post(
        f"/machines/{machine_id}/docker/stacks",
        data={
            "csrf_token": csrf,
            "name": "blog",
            "source": "editor",
            "compose": COMPOSE,
            "env_action": "set",
            "env": "",
            "shared_variables_shown": "1",
            "shared_variables": ["TZ"],
            "drift_check_shown": "1",
            "drift_check": "1",
        },
    )
    stack = (await _all(db_session_factory, DockerStack))[0]
    variables = await client.get("/docker/variables")
    async with db_session_factory() as session:
        row = await session.get(DockerStack, stack.id)
        assert row is not None
        row.shared_variables = ["TZ", "MISSING_ONE"]
        await session.commit()
    page = await client.get(f"/machines/{machine_id}/docker/stacks/{stack.id}")

    assert 'value="TZ"' in form.text
    assert created.status_code == 303
    assert stack.shared_variables == ["TZ"] and stack.drift_check is True
    assert "MISSING_ONE" in page.text
    assert "Europe/Prague" in variables.text


# --- Adopting a project, a container to a stack (web) -------------------------------


async def test_adopting_a_compose_project_makes_a_stack_in_its_directory(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    celery_calls.result_for[PROJECT_READ] = {
        "ok": True,
        "read": {"compose": COMPOSE, "env": "A=1\n", "writable": True, "marked": False},
    }
    celery_calls.result_for[MARK_DIR] = {"ok": True}
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/projects/site/adopt", data={"csrf_token": csrf}
    )

    [stack] = await _all(db_session_factory, DockerStack)
    assert response.status_code == 303
    assert response.headers["location"].startswith(
        f"/machines/{machine_id}/docker/stacks/{stack.id}?"
    )
    assert (stack.name, stack.directory, stack.compose_content) == ("site", "/srv/site", COMPOSE)
    assert stack.deployed_hash is None
    assert celery_calls.names == [INVENTORY_TASK, PROJECT_READ, MARK_DIR]
    assert celery_calls[1][1] == (str(machine_id), "site", "/srv/site", ["/srv/site/compose.yaml"])
    [entry] = await audit_entries(db_session_factory, "machine.docker.project.adopt")
    assert (entry.details or {})["directory"] == "/srv/site"


async def test_a_project_that_cannot_be_adopted_changes_nothing(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    celery_calls.result_for[PROJECT_READ] = {
        "ok": True,
        "read": {"compose": COMPOSE, "writable": False},
    }
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/projects/site/adopt", data={"csrf_token": csrf}
    )

    assert response.status_code == 303
    assert await _all(db_session_factory, DockerStack) == []
    assert MARK_DIR not in celery_calls.names
    [entry] = await audit_entries(db_session_factory, "machine.docker.project.adopt")
    assert (entry.details or {})["reason"] == "docker.adopt.error.not_writable"


async def test_a_container_becomes_a_filled_in_stack_form_and_then_a_stack(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[CONTAINER_COMPOSE] = {
        "ok": True,
        "service": "worker",
        "compose": "services:\n  worker:\n    image: redis:7\n    container_name: worker\n",
        "env": "TOKEN='x'\n",
        "warnings": ["Links (--link) were left out; use a shared network instead."],
    }
    csrf = await csrf_token(client, machine_id)

    form = await client.get(f"/machines/{machine_id}/docker/containers/worker/to-stack")
    created = await client.post(
        f"/machines/{machine_id}/docker/stacks",
        data={
            "csrf_token": csrf,
            "name": "worker",
            "source": "editor",
            "compose": "services:\n  worker:\n    image: redis:7\n",
            "env_action": "set",
            "env": "TOKEN='x'",
            "replace_container": "worker",
        },
    )
    bad = await client.post(
        f"/machines/{machine_id}/docker/stacks",
        data={
            "csrf_token": csrf,
            "name": "other",
            "source": "editor",
            "compose": COMPOSE,
            "env_action": "set",
            "env": "",
            "replace_container": "x;id",
        },
    )

    assert form.status_code == 200
    assert 'name="replace_container" value="worker"' in form.text
    assert "container_name: worker" in form.text
    assert "--link" in form.text
    assert created.status_code == 303 and bad.status_code == 400
    [stack] = await _all(db_session_factory, DockerStack)
    assert stack.replace_container == "worker"
    [entry] = await audit_entries(db_session_factory, "machine.docker.stack.create")
    assert (entry.details or {})["replace_container"] == "worker"


# --- Drift and taking files over (web) ---------------------------------------------


async def _editor_stack(db_session_factory: Any, machine_id: uuid.UUID, **values: Any) -> Any:
    async with db_session_factory() as session:
        stack = DockerStack(
            machine_id=machine_id,
            name=values.pop("name", "blog"),
            source=StackSource.EDITOR,
            compose_content=COMPOSE,
            env_encrypted=encrypt_secret("A=1\n"),
            **values,
        )
        session.add(stack)
        await session.commit()
        return stack.id


async def test_checking_drift_needs_a_deploy_and_reports_the_result(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    fresh = await _editor_stack(db_session_factory, machine_id)
    deployed = await _editor_stack(
        db_session_factory,
        machine_id,
        name="shop",
        deployed_hash="h",
        drift_status="drift",
        drift_details={"files": [{"name": ".env", "state": "changed"}], "services": []},
    )
    celery_calls.result_for[DRIFT] = {"ok": True, "status": "drift", "details": {}}
    csrf = await csrf_token(client, machine_id)

    refused = await client.post(
        f"/machines/{machine_id}/docker/stacks/{fresh}/drift", data={"csrf_token": csrf}
    )
    checked = await client.post(
        f"/machines/{machine_id}/docker/stacks/{deployed}/drift", data={"csrf_token": csrf}
    )
    page = await client.get(f"/machines/{machine_id}/docker/stacks/{deployed}")

    assert refused.status_code == checked.status_code == 303
    assert celery_calls.names == [DRIFT]
    assert celery_calls[0][1] == (str(deployed),)
    assert ".env" in page.text
    assert f"/machines/{machine_id}/docker/stacks/{deployed}/import" in page.text


async def test_taking_files_over_from_the_machine_keeps_shared_values_shared(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    stack_id = await _editor_stack(db_session_factory, machine_id, deployed_hash="h")
    celery_calls.result_for[FILES_READ] = {
        "ok": True,
        "read": {
            "compose": "services:\r\n  web:\r\n    image: nginx:1.28\r\n",
            "env": "A=2\n# Shared variables (debcontrol)\nTZ='UTC'\n",
        },
    }
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/stacks/{stack_id}/import", data={"csrf_token": csrf}
    )

    stack = await get_row(db_session_factory, DockerStack, stack_id)
    assert response.status_code == 303
    assert stack is not None
    assert stack.compose_content == "services:\n  web:\n    image: nginx:1.28\n"
    assert decrypt_secret(stack.env_encrypted or b"") == "A=2\n"
    assert len(await audit_entries(db_session_factory, "machine.docker.stack.import")) == 1


async def test_drift_and_adopt_routes_need_their_permissions(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    stack_id = await _editor_stack(db_session_factory, machine_id, deployed_hash="h")
    csrf = await csrf_token(client, machine_id)
    await login_as(client, permissions={Permission.MACHINE_VIEW})
    client.cookies.set("csrftoken", csrf)

    base = f"/machines/{machine_id}/docker"
    for path in (
        f"{base}/projects/site/adopt",
        f"{base}/stacks/{stack_id}/drift",
        f"{base}/stacks/{stack_id}/import",
    ):
        assert (await client.post(path, data={"csrf_token": csrf})).status_code == 403, path
    assert (await client.get(f"{base}/containers/worker/to-stack")).status_code == 403


# --- REST API ----------------------------------------------------------------------


async def test_registries_api_round_trip_never_returns_the_password(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    await make_docker_machine(db_session_factory)
    headers = await _api_token(client)

    created = await client.post(
        "/api/v1/docker/registries",
        json={"server": "ghcr.io", "username": "bot", "password": PASSWORD},
        headers=headers,
    )
    registry_id = created.json()["registry"]["id"]
    listed = await client.get("/api/v1/docker/registries", headers=headers)
    changed = await client.put(
        f"/api/v1/docker/registries/{registry_id}",
        json={"server": "ghcr.io", "username": "bot2"},
        headers=headers,
    )
    relogin = await client.post(f"/api/v1/docker/registries/{registry_id}/login", headers=headers)
    missing_password = await client.post(
        "/api/v1/docker/registries",
        json={"server": "quay.io", "username": "bot"},
        headers=headers,
    )
    deleted = await client.delete(f"/api/v1/docker/registries/{registry_id}", headers=headers)

    assert created.status_code == 201 and created.json()["machines_queued"] == 1
    assert PASSWORD not in created.text and PASSWORD not in listed.text
    assert listed.json()[0]["scope"] == "all"
    assert changed.json()["registry"]["username"] == "bot2"
    assert relogin.json() == {"machines_queued": 1}
    assert missing_password.status_code == 422
    assert missing_password.json()["detail"] == ["docker.registry.error.password"]
    assert deleted.status_code == 204
    assert celery_calls.names.count(SYNC_LOGINS) == 3


async def test_variables_api_hides_secret_values(client: Any, db_session_factory: Any) -> None:
    headers = await _api_token(client)

    secret = await client.post(
        "/api/v1/docker/variables",
        json={"name": "TOKEN", "value": SECRET_VALUE, "secret": True},
        headers=headers,
    )
    plain = await client.post(
        "/api/v1/docker/variables", json={"name": "TZ", "value": "UTC"}, headers=headers
    )
    duplicate = await client.post(
        "/api/v1/docker/variables", json={"name": "TZ", "value": "x"}, headers=headers
    )
    kept = await client.put(
        f"/api/v1/docker/variables/{secret.json()['id']}",
        json={"name": "TOKEN", "secret": True, "description": "api"},
        headers=headers,
    )
    listed = await client.get("/api/v1/docker/variables", headers=headers)
    deleted = await client.delete(f"/api/v1/docker/variables/{plain.json()['id']}", headers=headers)

    assert secret.status_code == plain.status_code == 201
    assert secret.json()["value"] is None and plain.json()["value"] == "UTC"
    assert duplicate.status_code == 422
    assert kept.json()["description"] == "api"
    assert SECRET_VALUE not in listed.text
    assert deleted.status_code == 204
    [variable] = await _all(db_session_factory, DockerVariable)
    assert decrypt_secret(variable.value_encrypted) == SECRET_VALUE


async def test_a_group_limited_token_cannot_add_fleet_wide_entries(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    group_id = await _group_with(db_session_factory, machine_id, "mine")
    await login_as(
        client,
        permissions={Permission.ACTION_TERMINAL, Permission.MACHINE_VIEW},
        group_ids={group_id},
        api_access_enabled=True,
    )
    headers = await _api_token(client)

    fleet = await client.post(
        "/api/v1/docker/variables", json={"name": "TZ", "value": "UTC"}, headers=headers
    )
    own = await client.post(
        "/api/v1/docker/variables",
        json={"name": "TZ", "value": "UTC", "scope": f"group:{group_id}"},
        headers=headers,
    )

    assert fleet.status_code == 422 and fleet.json()["detail"] == ["docker.scope.error"]
    assert own.status_code == 201 and own.json()["scope_label"] == "group mine"


async def test_api_adopt_compose_drift_and_import(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    headers = await _api_token(client)
    base = f"/api/v1/machines/{machine_id}/docker"
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()
    celery_calls.result_for[PROJECT_READ] = {
        "ok": True,
        "read": {"compose": COMPOSE, "env": "", "writable": True},
    }
    celery_calls.result_for[MARK_DIR] = {"ok": True}
    celery_calls.result_for[CONTAINER_COMPOSE] = {
        "ok": True, "service": "worker", "compose": COMPOSE, "env": "", "warnings": []
    }
    celery_calls.result_for[DRIFT] = {"ok": True, "status": "ok", "details": {"files": []}}
    celery_calls.result_for[FILES_READ] = {"ok": True, "read": {"compose": COMPOSE, "env": None}}

    adopted = await client.post(f"{base}/projects/site/adopt", headers=headers)
    again = await client.post(f"{base}/projects/site/adopt", headers=headers)
    compose = await client.get(f"{base}/containers/worker/compose", headers=headers)
    stack_id = adopted.json()["stack"]["id"]
    not_deployed = await client.post(f"{base}/stacks/{stack_id}/drift", headers=headers)
    async with db_session_factory() as session:
        row = await session.get(DockerStack, uuid.UUID(stack_id))
        assert row is not None
        row.deployed_hash = "h"
        await session.commit()
    drift = await client.post(f"{base}/stacks/{stack_id}/drift", headers=headers)
    imported = await client.post(f"{base}/stacks/{stack_id}/import", headers=headers)

    assert adopted.status_code == 201
    assert adopted.json()["stack"]["directory"] == "/srv/site"
    assert again.status_code == 422 and again.json()["detail"] == ["docker.adopt.error.managed"]
    assert compose.json()["replace_container"] == "worker"
    assert not_deployed.status_code == 400
    assert drift.json() == {"status": "ok", "details": {"files": []}, "summary": ""}
    assert imported.status_code == 200


async def test_api_stack_takes_shared_variables_and_replace_container(
    client: Any, db_session_factory: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    headers = await _api_token(client)
    base = f"/api/v1/machines/{machine_id}/docker"
    await client.post(
        "/api/v1/docker/variables", json={"name": "TZ", "value": "UTC"}, headers=headers
    )

    created = await client.post(
        f"{base}/stacks",
        json={
            "name": "worker",
            "compose": COMPOSE,
            "shared_variables": ["TZ", "NOPE"],
            "drift_check": True,
            "replace_container": "worker",
        },
        headers=headers,
    )
    bad_names = await client.post(
        f"{base}/stacks",
        json={"name": "x", "compose": COMPOSE, "shared_variables": ["1bad"]},
        headers=headers,
    )

    stack = created.json()["stack"]
    assert created.status_code == 201, created.text
    assert stack["shared_variables"] == ["TZ", "NOPE"]
    assert stack["shared_variables_missing"] == ["NOPE"]
    assert stack["replace_container"] == "worker"
    assert stack["drift_check"] is True and stack["drift_status"] is None
    assert bad_names.status_code == 422


async def test_a_group_limited_account_sees_logins_of_its_machines_only(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    from datetime import UTC, datetime

    from app.db.models.docker import DockerRegistryLogin

    mine = await make_docker_machine(db_session_factory)
    theirs = await make_docker_machine(db_session_factory, name="hiddenhost")
    my_group = await _group_with(db_session_factory, mine, "mine")
    await _group_with(db_session_factory, theirs, "theirs")
    async with db_session_factory() as session:
        fleet = DockerRegistry(
            server="ghcr.io", username="fleet", password_encrypted=encrypt_secret("x")
        )
        session.add(fleet)
        await session.flush()
        for machine_id in (mine, theirs):
            session.add(
                DockerRegistryLogin(
                    machine_id=machine_id,
                    server="ghcr.io",
                    registry_id=fleet.id,
                    status="failed",
                    message="denied",
                    checked_at=datetime.now(UTC),
                )
            )
        session.add(
            DockerStack(
                machine_id=theirs,
                name="hidden",
                source=StackSource.EDITOR,
                compose_content=COMPOSE,
                shared_variables=["TZ"],
            )
        )
        session.add(DockerVariable(name="TZ", value_encrypted=encrypt_secret("UTC")))
        await session.commit()
    await login_as(
        client,
        permissions={Permission.ACTION_TERMINAL},
        group_ids={my_group},
        api_access_enabled=True,
    )
    headers = await _api_token(client)

    page = await client.get("/docker/registries")
    api = await client.get("/api/v1/docker/registries", headers=headers)
    variables = await client.get("/api/v1/docker/variables", headers=headers)

    assert "hiddenhost" not in page.text and "dockerhost" in page.text
    assert [login["machine_id"] for login in api.json()[0]["logins"]] == [str(mine)]
    assert variables.json()[0]["used_by_stacks"] == 0


async def test_a_secret_stays_secret_and_a_moved_registry_needs_its_password(
    client: Any, db_session_factory: Any
) -> None:
    headers = await _api_token(client)
    secret = await client.post(
        "/api/v1/docker/variables",
        json={"name": "TOKEN", "value": SECRET_VALUE, "secret": True},
        headers=headers,
    )
    registry = await client.post(
        "/api/v1/docker/registries",
        json={"server": "ghcr.io", "username": "bot", "password": PASSWORD},
        headers=headers,
    )

    unticked = await client.put(
        f"/api/v1/docker/variables/{secret.json()['id']}",
        json={"name": "TOKEN"},
        headers=headers,
    )
    moved = await client.put(
        f"/api/v1/docker/registries/{registry.json()['registry']['id']}",
        json={"server": "evil.example.com", "username": "bot"},
        headers=headers,
    )

    assert unticked.status_code == 200
    assert unticked.json()["secret"] is True and unticked.json()["value"] is None
    assert moved.status_code == 422
    assert moved.json()["detail"] == ["docker.registry.error.password"]
