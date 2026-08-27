from __future__ import annotations


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
            "hostname": "db1.example.com",
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
            "hostname": "db1.example.com",
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
    assert "db1.example.com" in listing.text
    # The password must never show up in HTML output.
    assert "s3cret" not in listing.text


async def test_new_machine_form_rejects_invalid_port(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/machines",
        data={
            "hostname": "db1.example.com",
            "port": "70000",  # outside the valid 1-65535 range
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 422


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
            "hostname": "prod1.example.com",
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
    assert "prod1.example.com" in group_detail.text

    remove = await client.post(
        f"{group_url}/machines/{machine_id}/remove",
        data={"csrf_token": csrf_token},
    )
    assert remove.status_code == 303

    group_detail = await client.get(group_url)
    assert "No machines in this group yet" in group_detail.text


async def test_users_and_settings_are_placeholders(client):
    users = await client.get("/users")
    assert users.status_code == 200
    assert "Coming soon" in users.text

    settings_page = await client.get("/settings")
    assert settings_page.status_code == 200
    assert "Coming soon" in settings_page.text
