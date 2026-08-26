from __future__ import annotations


async def test_healthz(client):
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_dashboard_empty_state(client):
    response = await client.get("/")
    assert response.status_code == 200
    assert "žádné spravované stroje" in response.text.lower() or "0" in response.text


async def test_create_machine_requires_csrf_token(client):
    # Bez platného CSRF tokenu musí POST selhat, i kdyby útočník uhodl/odposlechl URL.
    response = await client.post(
        "/machines",
        data={
            "hostname": "db1.example.com",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": "neco-uplne-jineho",
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
            "description": "testovací stroj",
            "csrf_token": csrf_token,
        },
    )
    assert create.status_code == 303

    listing = await client.get("/machines")
    assert listing.status_code == 200
    assert "db1.example.com" in listing.text
    # Heslo se nikdy nesmí objevit v HTML výstupu.
    assert "s3cret" not in listing.text


async def test_new_machine_form_rejects_invalid_port(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/machines",
        data={
            "hostname": "db1.example.com",
            "port": "70000",  # mimo platný rozsah 1-65535
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 422
