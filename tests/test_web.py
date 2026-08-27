from __future__ import annotations

import uuid

from app.db.models.machine import Machine


async def test_healthz(client):
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_root_redirects_to_machines(client):
    response = await client.get("/")
    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/machines"


async def test_create_machine_requires_csrf_token(client):
    # Without a valid CSRF token the POST must fail, even if an attacker
    # guessed/observed the URL.
    response = await client.post(
        "/machines",
        data={
            "name": "db1",
            "ip_address": "10.0.0.10",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": "something-else-entirely",
        },
    )
    assert response.status_code == 403


async def test_create_and_list_machine(client):
    new_form = await client.get("/machines/new")
    assert new_form.status_code == 200
    csrf_token = client.cookies.get("csrftoken")
    assert csrf_token

    create = await client.post(
        "/machines",
        data={
            "name": "db1",
            "ip_address": "10.0.0.10",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "s3cret",
            "description": "test machine",
            "csrf_token": csrf_token,
        },
    )
    assert create.status_code == 303

    listing = await client.get("/machines")
    assert listing.status_code == 200
    assert "db1" in listing.text
    assert "10.0.0.10" in listing.text
    # The password must never show up in HTML output.
    assert "s3cret" not in listing.text

    machine_url = create.headers["location"]
    detail = await client.get(machine_url)
    assert detail.status_code == 200
    assert "Not gathered yet" in detail.text
    assert "s3cret" not in detail.text


async def test_edit_machine_updates_fields_and_resets_pinning_on_ip_change(
    client, db_session_factory
):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    create = await client.post(
        "/machines",
        data={
            "name": "edit-me",
            "ip_address": "10.0.0.40",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "original-secret",
            "csrf_token": csrf_token,
        },
    )
    machine_id = uuid.UUID(create.headers["location"].rsplit("/", 1)[-1])

    # Simulate a previously confirmed host key / gathered facts directly in
    # the DB — there's no live machine in tests to actually discover one from.
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        machine.host_key_fingerprint = "SHA256:abcdefg"
        machine.os_version = "Debian GNU/Linux 12 (bookworm)"
        original_secret_encrypted = bytes(machine.secret_encrypted)
        await session.commit()

    edit_form = await client.get(f"/machines/{machine_id}/edit")
    assert edit_form.status_code == 200
    assert "edit-me" in edit_form.text
    assert "10.0.0.40" in edit_form.text

    # Change the IP and leave the password blank; also uncheck "active"
    # (HTML omits unchecked checkboxes from the submitted form entirely).
    update = await client.post(
        f"/machines/{machine_id}/edit",
        data={
            "name": "edited-name",
            "ip_address": "10.0.0.41",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    assert update.status_code == 303

    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine.name == "edited-name"
        assert machine.ip_address == "10.0.0.41"
        assert machine.is_active is False
        # Changing the IP must reset trust/facts established for the old target.
        assert machine.host_key_fingerprint is None
        assert machine.os_version is None
        # Blank password on edit means "keep the existing one".
        assert bytes(machine.secret_encrypted) == original_secret_encrypted


async def test_create_machine_rejects_invalid_ip_address(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/machines",
        data={
            "name": "db1",
            "ip_address": "not-an-ip-address",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 422


async def test_new_machine_form_rejects_invalid_port(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/machines",
        data={
            "name": "db1",
            "ip_address": "10.0.0.10",
            "port": "70000",  # outside the valid 1-65535 range
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 422


async def test_new_machine_form_prefills_from_query_params(client):
    response = await client.get("/machines/new?ip_address=10.0.0.20&name=fromform")
    assert response.status_code == 200
    assert "10.0.0.20" in response.text
    assert "fromform" in response.text


async def test_machine_group_lifecycle(client):
    await client.get("/machine-groups/new")
    csrf_token = client.cookies.get("csrftoken")

    create_group = await client.post(
        "/machine-groups",
        data={"name": "production", "description": "prod boxes", "csrf_token": csrf_token},
    )
    assert create_group.status_code == 303
    group_url = create_group.headers["location"]

    create_machine = await client.post(
        "/machines",
        data={
            "name": "prod1",
            "ip_address": "10.0.0.11",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    assert create_machine.status_code == 303
    machine_url = create_machine.headers["location"]
    machine_id = machine_url.rsplit("/", 1)[-1]

    group_detail = await client.get(group_url)
    assert "No machines in this group yet" in group_detail.text

    add = await client.post(
        f"{group_url}/machines",
        data={"machine_id": machine_id, "csrf_token": csrf_token},
    )
    assert add.status_code == 303

    group_detail = await client.get(group_url)
    assert "prod1" in group_detail.text

    remove = await client.post(
        f"{group_url}/machines/{machine_id}/remove",
        data={"csrf_token": csrf_token},
    )
    assert remove.status_code == 303

    group_detail = await client.get(group_url)
    assert "No machines in this group yet" in group_detail.text


async def test_all_machines_group_always_shows_every_machine(client):
    listing = await client.get("/machine-groups")
    assert listing.status_code == 200
    assert "All machines" in listing.text

    all_page = await client.get("/machine-groups/all")
    assert all_page.status_code == 200
    assert "No managed machines yet" in all_page.text

    await client.get("/machine-groups/new")
    csrf_token = client.cookies.get("csrftoken")
    create_group = await client.post(
        "/machine-groups",
        data={"name": "custom", "description": "", "csrf_token": csrf_token},
    )
    group_url = create_group.headers["location"]

    create_machine = await client.post(
        "/machines",
        data={
            "name": "any1",
            "ip_address": "10.0.0.50",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    machine_id = create_machine.headers["location"].rsplit("/", 1)[-1]

    # Assign the machine to a real group — it must still show up under "All".
    await client.post(
        f"{group_url}/machines",
        data={"machine_id": machine_id, "csrf_token": csrf_token},
    )

    all_page = await client.get("/machine-groups/all")
    assert "any1" in all_page.text

    listing = await client.get("/machine-groups")
    assert "custom" in listing.text
    assert "All machines" in listing.text


async def test_group_name_all_is_reserved(client):
    await client.get("/machine-groups/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/machine-groups",
        data={"name": "All", "description": "", "csrf_token": csrf_token},
    )
    assert response.status_code == 422


async def test_users_is_a_placeholder(client):
    users = await client.get("/users")
    assert users.status_code == 200
    assert "Coming soon" in users.text


async def test_settings_shows_ssh_identity(client):
    response = await client.get("/settings")
    assert response.status_code == 200
    assert "ssh-ed25519" in response.text
    assert "SHA256:" in response.text
