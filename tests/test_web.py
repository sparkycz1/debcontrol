from __future__ import annotations

import re
import uuid

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models.machine import Machine
from app.main import app


async def test_healthz(client):
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_root_redirects_to_dashboard(client):
    response = await client.get("/")
    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/dashboard"


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
    # Discovery runs automatically as soon as the page loads (no manual
    # click needed right after adding a machine) — still requires an
    # explicit confirm click once a fingerprint comes back, though; this
    # is a trigger attribute, not an auto-trust of whatever key shows up.
    assert 'hx-trigger="click, load"' in detail.text


async def test_failed_discovery_offers_a_retry_button(client, monkeypatch):
    """A failed auto-triggered discovery (e.g. the machine isn't reachable
    yet right after being added) must not strand the user without any way
    to try again short of reloading the whole page."""
    import app.web.routes.machines as machines_routes
    from app.ssh.exceptions import SSHConnectionError

    async def _always_fails(*args, **kwargs):
        raise SSHConnectionError("connection refused")

    monkeypatch.setattr(machines_routes, "discover_host_key_fingerprint", _always_fails)

    await client.get("/machines/new")  # provisions the csrftoken cookie
    create = await client.post(
        "/machines",
        data={
            "name": "unreachable1",
            "ip_address": "10.0.0.11",
            "port": "22",
            "username": "admin",
            "auth_method": "ssh_key",
            "csrf_token": client.cookies.get("csrftoken"),
        },
    )
    assert create.status_code == 303
    machine_url = create.headers["location"]

    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"{machine_url}/discover-host-key", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 200
    assert "Could not determine the key fingerprint" in response.text
    assert "Retry discovery" in response.text


async def test_installed_packages_load_lazily_in_a_modal(client, db_session_factory):
    """The full package listing must not be embedded in the detail page's
    initial render (hundreds of rows on a real machine made that page slow
    and cluttered) — only the summary counts and a button that fetches the
    listing on demand into #packages-panel."""
    from datetime import UTC, datetime

    from app.db.models.machine_package import MachinePackage
    from app.ssh.packages import PackageSource

    await client.get("/machines/new")
    create = await client.post(
        "/machines",
        data={
            "name": "pkgs1",
            "ip_address": "10.0.0.20",
            "port": "22",
            "username": "admin",
            "auth_method": "ssh_key",
            "csrf_token": client.cookies.get("csrftoken"),
        },
    )
    assert create.status_code == 303
    machine_url = create.headers["location"]
    machine_id = machine_url.rsplit("/", 1)[-1]

    async with db_session_factory() as db:
        machine = await db.get(Machine, uuid.UUID(machine_id))
        machine.packages_updated_at = datetime.now(UTC)
        db.add(
            MachinePackage(
                machine_id=machine.id,
                name="openssh-server",
                version="1:9.6p1-3",
                source=PackageSource.APT,
                held=False,
            )
        )
        await db.commit()

    detail = await client.get(machine_url)
    assert detail.status_code == 200
    assert "1 package installed" in detail.text
    assert "Show installed packages" in detail.text
    # The row itself must not be pre-rendered on the page load.
    assert "openssh-server" not in detail.text

    panel = await client.get(f"{machine_url}/packages")
    assert panel.status_code == 200
    assert "openssh-server" in panel.text
    assert 'hx-swap-oob="true"' in panel.text  # keeps the summary in sync


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


async def test_users_page_lists_the_logged_in_admin(client):
    from tests.conftest import ADMIN_USERNAME

    users = await client.get("/users")
    assert users.status_code == 200
    assert ADMIN_USERNAME in users.text


async def test_settings_shows_ssh_identity(client):
    response = await client.get("/settings")
    assert response.status_code == 200
    assert "ssh-ed25519" in response.text
    assert "SHA256:" in response.text


async def test_settings_audit_retention_defaults_to_forever(client):
    response = await client.get("/settings")
    assert response.status_code == 200
    assert "forever" in response.text


async def test_update_audit_retention_persists_value(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/settings/audit-retention", data={"retention_days": "90", "csrf_token": csrf_token}
    )
    assert response.status_code == 303

    page = await client.get("/settings")
    assert 'value="90"' in page.text

    log = await client.get("/audit")
    assert "settings.audit_retention.update" in log.text
    assert "90 day" in log.text


async def test_update_audit_retention_empty_means_forever(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")

    await client.post(
        "/settings/audit-retention", data={"retention_days": "30", "csrf_token": csrf_token}
    )
    response = await client.post(
        "/settings/audit-retention", data={"retention_days": "", "csrf_token": csrf_token}
    )
    assert response.status_code == 303

    page = await client.get("/settings")
    assert "keep forever" in page.text.lower() or "forever" in page.text


async def test_update_audit_retention_rejects_non_integer(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/settings/audit-retention", data={"retention_days": "banana", "csrf_token": csrf_token}
    )
    assert response.status_code == 200
    assert "isn&#39;t a whole number" in response.text or "whole number" in response.text


async def test_update_audit_retention_rejects_negative(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/settings/audit-retention", data={"retention_days": "-5", "csrf_token": csrf_token}
    )
    assert response.status_code == 200
    assert "whole number" in response.text


async def test_verify_audit_chain_endpoint_reports_intact_chain(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    # Generate at least one chained entry first.
    await client.post(
        "/machines",
        data={
            "name": "chain-check",
            "ip_address": "10.9.9.5",
            "port": "22",
            "username": "admin",
            "auth_method": "password",
            "secret": "",
            "csrf_token": csrf_token,
        },
    )

    response = await client.post("/settings/audit-verify", data={"csrf_token": csrf_token})
    assert response.status_code == 200
    assert "verified intact" in response.text

    log = await client.get("/audit")
    assert "audit_log.verify" in log.text


async def _create_machine(
    client: httpx.AsyncClient, csrf_token: str, **overrides: str
) -> uuid.UUID:
    data = {
        "name": "m",
        "ip_address": "10.0.1.1",
        "port": "22",
        "username": "admin",
        "auth_method": "password",
        "secret": "",
        "csrf_token": csrf_token,
    }
    data.update(overrides)
    response = await client.post("/machines", data=data)
    assert response.status_code == 303
    return uuid.UUID(response.headers["location"].rsplit("/", 1)[-1])


async def _pin_host_key(
    db_session_factory: async_sessionmaker[AsyncSession], machine_id: uuid.UUID
) -> None:
    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        machine.host_key_fingerprint = "SHA256:fakefingerprint"
        await session.commit()


def _extract_scheduled_task_id(listing_html: str) -> str:
    # The page header's "New scheduled task" link (/scheduling/new) also
    # starts with "/scheduling/", so a plain string split isn't safe here —
    # match the actual per-row edit link instead.
    match = re.search(r"/scheduling/([0-9a-f-]{36})/edit", listing_html)
    assert match is not None
    return match.group(1)


async def test_machine_search_filters_by_multiple_fields(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    await _create_machine(client, csrf_token, name="web-alpha", ip_address="10.1.1.1")
    await _create_machine(client, csrf_token, name="db-beta", ip_address="10.2.2.2")

    by_name = await client.get("/machines?q=alpha")
    assert "web-alpha" in by_name.text
    assert "db-beta" not in by_name.text

    by_ip = await client.get("/machines?q=10.2.2.2")
    assert "db-beta" in by_ip.text
    assert "web-alpha" not in by_ip.text

    no_match = await client.get("/machines?q=nonexistent")
    assert 'No machines match "nonexistent"' in no_match.text


async def test_group_and_all_pages_support_search(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    create_group = await client.post(
        "/machine-groups", data={"name": "searchgroup", "description": "", "csrf_token": csrf_token}
    )
    group_url = create_group.headers["location"]

    machine_id = await _create_machine(client, csrf_token, name="findme", ip_address="10.3.3.3")
    await client.post(
        f"{group_url}/machines", data={"machine_id": str(machine_id), "csrf_token": csrf_token}
    )
    await _create_machine(client, csrf_token, name="ignoreme", ip_address="10.4.4.4")

    group_search = await client.get(f"{group_url}?q=findme")
    assert "findme" in group_search.text

    all_search = await client.get("/machine-groups/all?q=findme")
    assert "findme" in all_search.text
    assert "ignoreme" not in all_search.text


async def test_trigger_machine_update_requires_pinned_host_key(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token)

    response = await client.post(
        f"/machines/{machine_id}/updates",
        data={"strategy": "dist_upgrade", "csrf_token": csrf_token},
    )
    assert response.status_code == 400


async def test_trigger_machine_update_creates_run_and_redirects(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token)
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/updates",
        data={"strategy": "full_upgrade", "csrf_token": csrf_token},
    )
    assert response.status_code == 303
    run_url = response.headers["location"]
    assert run_url.startswith(f"/machines/{machine_id}/updates/")

    run_page = await client.get(run_url)
    assert run_page.status_code == 200
    assert "full-upgrade" in run_page.text

    assert "run_machine_update" in [call[0] for call in app.state.arq_redis.enqueued]


async def test_trigger_group_update_batches_and_skips_unpinned(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    create_group = await client.post(
        "/machine-groups", data={"name": "batchgroup", "description": "", "csrf_token": csrf_token}
    )
    group_url = create_group.headers["location"]

    pinned_id = await _create_machine(client, csrf_token, name="pinned", ip_address="10.5.5.1")
    await _pin_host_key(db_session_factory, pinned_id)
    unpinned_id = await _create_machine(client, csrf_token, name="unpinned", ip_address="10.5.5.2")

    for machine_id in (pinned_id, unpinned_id):
        await client.post(
            f"{group_url}/machines",
            data={"machine_id": str(machine_id), "csrf_token": csrf_token},
        )

    response = await client.post(
        f"{group_url}/updates", data={"strategy": "dist_upgrade", "csrf_token": csrf_token}
    )
    assert response.status_code == 303
    batch_url = response.headers["location"]
    assert "skipped=1" in batch_url

    batch_page = await client.get(batch_url)
    assert batch_page.status_code == 200
    assert f"/machines/{pinned_id}" in batch_page.text
    assert f"/machines/{unpinned_id}" not in batch_page.text
    assert "1 machine(s) were skipped" in batch_page.text


async def test_check_updates_requires_pinned_host_key(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token)

    response = await client.get(f"/machines/{machine_id}")
    assert "Check for updates now" in response.text
    # The button itself is disabled (rendered with the `disabled` attribute)
    # rather than the endpoint refusing outright — confirm that's the case.
    assert "disabled" in response.text


async def test_check_updates_endpoint_updates_machine_record(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token)
    await _pin_host_key(db_session_factory, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/check-updates", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 200
    assert "check_machine_updates" in [call[0] for call in app.state.arq_redis.enqueued]


async def test_power_action_requires_matching_confirmation(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="power-me")
    await _pin_host_key(db_session_factory, machine_id)

    confirm_page = await client.get(f"/machines/{machine_id}/power/reboot")
    assert confirm_page.status_code == 200
    assert "power-me" in confirm_page.text

    wrong = await client.post(
        f"/machines/{machine_id}/power",
        data={"action": "reboot", "confirm_name": "not-the-name", "csrf_token": csrf_token},
    )
    assert wrong.status_code == 422
    assert "exactly to confirm" in wrong.text
    assert "send_machine_power_command" not in [call[0] for call in app.state.arq_redis.enqueued]

    right = await client.post(
        f"/machines/{machine_id}/power",
        data={"action": "reboot", "confirm_name": "power-me", "csrf_token": csrf_token},
    )
    assert right.status_code == 303
    assert right.headers["location"] == f"/machines/{machine_id}?power_sent=reboot"
    assert "send_machine_power_command" in [call[0] for call in app.state.arq_redis.enqueued]


async def test_power_action_requires_pinned_host_key(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="unpinned-power")

    response = await client.post(
        f"/machines/{machine_id}/power",
        data={"action": "reboot", "confirm_name": "unpinned-power", "csrf_token": csrf_token},
    )
    assert response.status_code == 400


async def test_group_check_updates_and_power_endpoints(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")

    create_group = await client.post(
        "/machine-groups", data={"name": "powergroup", "description": "", "csrf_token": csrf_token}
    )
    group_url = create_group.headers["location"]

    machine_id = await _create_machine(client, csrf_token, name="grouped", ip_address="10.6.6.1")
    await _pin_host_key(db_session_factory, machine_id)
    await client.post(
        f"{group_url}/machines", data={"machine_id": str(machine_id), "csrf_token": csrf_token}
    )

    check = await client.post(f"{group_url}/check-updates", data={"csrf_token": csrf_token})
    assert check.status_code == 303

    confirm_page = await client.get(f"{group_url}/power/shutdown")
    assert confirm_page.status_code == 200
    assert "powergroup" in confirm_page.text

    power = await client.post(
        f"{group_url}/power",
        data={"action": "shutdown", "confirm_name": "powergroup", "csrf_token": csrf_token},
    )
    assert power.status_code == 303
    assert power.headers["location"] == group_url

    enqueued_functions = [call[0] for call in app.state.arq_redis.enqueued]
    assert "check_machine_updates" in enqueued_functions
    assert "send_machine_power_command" in enqueued_functions


async def test_all_machines_check_updates_and_power_endpoints(client, db_session_factory):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="anymachine", ip_address="10.6.6.2")
    await _pin_host_key(db_session_factory, machine_id)

    check = await client.post("/machine-groups/all/check-updates", data={"csrf_token": csrf_token})
    assert check.status_code == 303

    confirm_page = await client.get("/machine-groups/all/power/reboot")
    assert confirm_page.status_code == 200
    assert "ALL MACHINES" in confirm_page.text

    wrong = await client.post(
        "/machine-groups/all/power",
        data={"action": "reboot", "confirm_name": "nope", "csrf_token": csrf_token},
    )
    assert wrong.status_code == 422

    right = await client.post(
        "/machine-groups/all/power",
        data={"action": "reboot", "confirm_name": "ALL MACHINES", "csrf_token": csrf_token},
    )
    assert right.status_code == 303
    assert right.headers["location"] == "/machine-groups/all"


async def test_scheduling_nav_link_present(client):
    response = await client.get("/machines")
    assert 'href="/scheduling"' in response.text


async def test_scheduling_empty_state(client):
    response = await client.get("/scheduling")
    assert response.status_code == 200
    assert "No scheduled tasks yet" in response.text


async def test_new_scheduled_task_form_lists_registered_actions(client):
    response = await client.get("/scheduling/new")
    assert response.status_code == 200
    for label in ("System update", "Check for updates", "Reboot", "Shut down"):
        assert label in response.text


async def test_create_scheduled_task_requires_csrf_token(client):
    response = await client.post(
        "/scheduling",
        data={
            "name": "nightly",
            "target": "all",
            "action": "check_updates",
            "cron_expression": "0 3 * * *",
            "csrf_token": "wrong",
        },
    )
    assert response.status_code == 403


async def test_create_scheduled_task_rejects_invalid_cron(client):
    await client.get("/scheduling/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/scheduling",
        data={
            "name": "nightly",
            "target": "all",
            "action": "check_updates",
            "cron_expression": "not a cron",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 422
    assert "not a valid cron expression" in response.text


async def test_create_and_list_scheduled_task_for_all_machines(client):
    await client.get("/scheduling/new")
    csrf_token = client.cookies.get("csrftoken")

    create = await client.post(
        "/scheduling",
        data={
            "name": "nightly check",
            "target": "all",
            "action": "check_updates",
            "cron_expression": "0 3 * * *",
            "is_enabled": "on",
            "csrf_token": csrf_token,
        },
    )
    assert create.status_code == 303
    assert create.headers["location"] == "/scheduling"

    listing = await client.get("/scheduling")
    assert "nightly check" in listing.text
    assert "All machines" in listing.text
    assert "check_updates" in listing.text
    assert "0 3 * * *" in listing.text
    assert "badge-ok" in listing.text  # enabled


async def test_create_scheduled_task_for_one_machine_with_strategy_param(client):
    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    machine_id = await _create_machine(client, csrf_token, name="target-me")

    create = await client.post(
        "/scheduling",
        data={
            "name": "weekly full upgrade",
            "target": f"machine:{machine_id}",
            "action": "system_update",
            "param_strategy": "full_upgrade",
            "cron_expression": "0 4 * * 0",
            "is_enabled": "on",
            "csrf_token": csrf_token,
        },
    )
    assert create.status_code == 303

    listing = await client.get("/scheduling")
    assert "weekly full upgrade" in listing.text
    assert "target-me" in listing.text

    task_id = _extract_scheduled_task_id(listing.text)
    edit_page = await client.get(f"/scheduling/{task_id}/edit")
    assert edit_page.status_code == 200
    assert "full-upgrade" in edit_page.text


async def test_new_scheduled_task_form_defaults_to_enabled(client):
    response = await client.get("/scheduling/new")
    assert 'name="is_enabled" checked' in response.text


async def test_failed_scheduled_task_submission_preserves_unchecked_enabled_box(client):
    # Regression check: a failed-validation re-render must reflect exactly
    # what was submitted, not silently reapply the "new form" default of
    # enabled — otherwise unchecking "Enabled" then hitting another error
    # would look like it was ignored.
    await client.get("/scheduling/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/scheduling",
        data={
            "name": "disabled-on-create",
            "target": "all",
            "action": "check_updates",
            "cron_expression": "not a cron",
            # "is_enabled" deliberately omitted — an unchecked checkbox.
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 422
    assert 'name="is_enabled" checked' not in response.text


async def test_scheduled_task_target_must_be_a_known_machine_or_group(client):
    await client.get("/scheduling/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/scheduling",
        data={
            "name": "bogus target",
            "target": "bogus",
            "action": "check_updates",
            "cron_expression": "0 3 * * *",
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 422
    assert "Invalid target" in response.text


async def test_toggle_and_run_now_and_delete_scheduled_task(client):
    await client.get("/scheduling/new")
    csrf_token = client.cookies.get("csrftoken")

    create = await client.post(
        "/scheduling",
        data={
            "name": "toggle-me",
            "target": "all",
            "action": "reboot",
            "cron_expression": "0 3 * * *",
            "is_enabled": "on",
            "csrf_token": csrf_token,
        },
    )
    assert create.status_code == 303

    listing = await client.get("/scheduling")
    task_id = _extract_scheduled_task_id(listing.text)

    # Disable — next_run_at is cleared, badge flips to "disabled".
    toggled = await client.post(f"/scheduling/{task_id}/toggle", data={"csrf_token": csrf_token})
    assert toggled.status_code == 303
    disabled_listing = await client.get("/scheduling")
    assert "badge-warn" in disabled_listing.text

    # Re-enable.
    await client.post(f"/scheduling/{task_id}/toggle", data={"csrf_token": csrf_token})

    # Run now — enqueues the same job the per-minute tick would.
    run_now = await client.post(f"/scheduling/{task_id}/run-now", data={"csrf_token": csrf_token})
    assert run_now.status_code == 303
    assert "run_scheduled_task" in [call[0] for call in app.state.arq_redis.enqueued]
    assert (task_id,) == [call[1] for call in app.state.arq_redis.enqueued][-1]

    ran_listing = await client.get(run_now.headers["location"])
    assert "Run enqueued" in ran_listing.text

    # Delete.
    deleted = await client.post(f"/scheduling/{task_id}/delete", data={"csrf_token": csrf_token})
    assert deleted.status_code == 303
    final_listing = await client.get("/scheduling")
    assert "toggle-me" not in final_listing.text
