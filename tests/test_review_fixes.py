"""Fixes from the 2026-09 live-instance review (0.76.0): Fleet attention
counting, the Security updates page's pre-0.75.0 gap notice, real interval
values on the Monitoring tab, HTML error pages, the Settings -> Security
sign-in policy (`app.auth.session_policy`), plural forms and localized
audit descriptions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import i18n
from app.auth import session_policy
from app.auth.sessions import create_session
from app.core.app_settings import get_or_create_app_settings
from app.db.models.machine import AuthMethod, Machine
from app.db.models.role import Role
from app.db.models.user import AuthProvider, User
from app.services.fleet_overview import build_fleet_row
from app.services.security_updates import machines_without_package_details
from tests.test_api_v1_extended import _api_token
from tests.test_onboarding import _make_machine


def _machine(**fields: object) -> Machine:
    machine = Machine(
        id=uuid.uuid4(), name="box", ip_address="10.0.0.1", port=22, username="u",
        auth_method=AuthMethod.PASSWORD,
    )
    for key, value in fields.items():
        setattr(machine, key, value)
    return machine


async def _set_settings(
    db_session_factory: async_sessionmaker[AsyncSession], **values: object
) -> None:
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        for key, value in values.items():
            setattr(app_settings, key, value)
        await db.commit()
    session_policy.invalidate()


# --- Fleet ---------------------------------------------------------------


def test_pending_security_updates_or_reboot_need_attention_even_when_gauges_are_green():
    healthy = build_fleet_row(_machine(is_reachable=True), None)
    security = build_fleet_row(
        _machine(is_reachable=True, upgradable_count=40, security_upgradable_count=10), None
    )
    reboot = build_fleet_row(_machine(is_reachable=True, reboot_required=True), None)

    assert not healthy.needs_attention
    assert security.needs_attention and security.level == "warn"
    assert reboot.needs_attention and reboot.level == "warn"
    assert security.as_dict()["security_upgradable_count"] == 10


async def test_fleet_page_counts_and_shows_pending_updates(client, db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        machine.is_reachable = True
        machine.upgradable_count = 3
        machine.security_upgradable_count = 1
        await db.commit()

    response = await client.get("/dashboard")

    assert response.status_code == 200
    assert "Updates</span> 3 (1 sec)" in response.text
    # The security tile links to the Security section.
    assert 'href="/security/updates"' in response.text


# --- Security updates page -------------------------------------------------


def test_machines_whose_stored_list_predates_security_flags_are_reported():
    old = _machine(
        name="old",
        security_upgradable_count=2,
        apt_upgradable_packages=[{"name": "openssl", "new_version": "3"}],
    )
    fresh = _machine(
        name="fresh",
        security_upgradable_count=1,
        apt_upgradable_packages=[{"name": "openssl", "new_version": "3", "security": True}],
    )

    assert machines_without_package_details([fresh, old]) == [old]


async def test_security_page_lists_machines_without_package_details(client, db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        machine.upgradable_count = 3
        machine.security_upgradable_count = 2
        machine.apt_upgradable_packages = [{"name": "libc6", "new_version": "2"}]
        await db.commit()

    response = await client.get("/security/updates")

    assert response.status_code == 200
    assert f'href="/machines/{machine_id}/updates"' in response.text
    assert "2 pending security updates" in response.text
    assert "No security updates are pending" not in response.text


# --- Monitoring tab --------------------------------------------------------


async def test_monitoring_hint_names_the_actual_instance_default(client, db_session_factory):
    machine_id = await _make_machine(db_session_factory)

    response = await client.get(f"/machines/{machine_id}/monitoring")

    assert response.status_code == 200
    assert "every 120 s, the instance default" in response.text


# --- Error pages / OpenAPI -------------------------------------------------


async def test_unknown_page_renders_an_html_404_for_a_browser(client):
    response = await client.get("/no/such/page", headers={"accept": "text/html"})

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/html")
    assert "Page not found" in response.text
    assert 'href="/dashboard"' in response.text


async def test_api_404_stays_json(client):
    headers = await _api_token(client)
    response = await client.get(
        f"/api/v1/machines/{uuid.uuid4()}", headers={**headers, "accept": "text/html"}
    )

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")


# --- Sign-in policy --------------------------------------------------------


def test_parse_networks_and_ip_allowed():
    networks, invalid = session_policy.parse_networks("192.168.1.10/24, 10.0.0.5\nnonsense")

    assert [str(n) for n in networks] == ["192.168.1.0/24", "10.0.0.5/32"]
    assert invalid == ["nonsense"]
    assert session_policy.ip_allowed("192.168.1.77", networks)
    assert session_policy.ip_allowed("::ffff:10.0.0.5", networks)
    assert not session_policy.ip_allowed("172.16.0.1", networks)
    assert not session_policy.ip_allowed(None, networks)
    assert session_policy.ip_allowed("172.16.0.1", ())


async def test_session_lifetime_comes_from_settings(db_session_factory):
    await _set_settings(db_session_factory, session_idle_timeout_minutes=30)
    async with db_session_factory() as db:
        role = Role(name="lifetime-role")
        db.add(role)
        await db.flush()
        user = User(
            username="lifetime", is_active=True, auth_provider=AuthProvider.LOCAL, role=role
        )
        db.add(user)
        await db.flush()
        session, _token = await create_session(db, user, ip_address=None, user_agent=None)

    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    remaining = expires_at - datetime.now(UTC)
    assert timedelta(minutes=25) < remaining <= timedelta(minutes=30)


async def test_saving_the_sign_in_policy(client, db_session_factory):
    await client.get("/settings?tab=security")
    response = await client.post(
        "/settings/sign-in-policy",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "session_idle_timeout_minutes": "60",
            "session_absolute_max_hours": "48",
            "login_max_failed_attempts": "3",
            "login_lockout_minutes": "30",
            "login_allowed_networks": "127.0.0.0/8\n10.0.0.0/8",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.session_idle_timeout_minutes == 60
        assert app_settings.login_max_failed_attempts == 3
        assert app_settings.login_allowed_networks == "127.0.0.0/8\n10.0.0.0/8"


async def test_sign_in_policy_refuses_networks_that_exclude_the_saver(client, db_session_factory):
    await client.get("/settings?tab=security")
    response = await client.post(
        "/settings/sign-in-policy",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "session_idle_timeout_minutes": "720",
            "session_absolute_max_hours": "720",
            "login_max_failed_attempts": "5",
            "login_lockout_minutes": "15",
            "login_allowed_networks": "203.0.113.0/24",
        },
    )

    assert response.status_code == 200
    assert "lock you out" in response.text
    async with db_session_factory() as db:
        assert (await get_or_create_app_settings(db)).login_allowed_networks is None


async def test_requests_from_outside_the_allowed_networks_are_blocked(client, db_session_factory):
    await _set_settings(db_session_factory, login_allowed_networks="203.0.113.0/24")

    page = await client.get("/dashboard")
    health = await client.get("/healthz")

    assert page.status_code == 403
    assert "not allowed" in page.text
    assert health.status_code == 200


async def test_lockout_threshold_comes_from_settings(anonymous_client, db_session_factory):
    from tests.conftest import create_local_user

    await _set_settings(db_session_factory, login_max_failed_attempts=2)
    await create_local_user(db_session_factory, username="locky", password="correct-horse-1")

    for _ in range(2):
        await anonymous_client.get("/login")
        await anonymous_client.post(
            "/login",
            data={
                "username": "locky",
                "password": "wrong",
                "csrf_token": anonymous_client.cookies.get("csrftoken"),
            },
        )

    async with db_session_factory() as db:
        user = (await db.execute(select(User).where(User.username == "locky"))).scalar_one()
        assert user.locked_until is not None


async def test_security_tab_lists_accounts_without_a_second_factor(client):
    response = await client.get("/settings?tab=security")

    assert response.status_code == 200
    # The fixture's admin account has neither TOTP nor a passkey.
    assert "sign in with a password alone" in response.text


async def test_sign_in_policy_numbers_are_writable_over_the_api(client, db_session_factory):
    headers = await _api_token(client)

    response = await client.patch(
        "/api/v1/settings", json={"session_idle_timeout_minutes": 90}, headers=headers
    )
    refused = await client.patch(
        "/api/v1/settings", json={"login_allowed_networks": "10.0.0.0/8"}, headers=headers
    )

    assert response.status_code == 200
    assert response.json()["changed"] == ["session_idle_timeout_minutes"]
    assert refused.status_code == 422
    # The save invalidated the cached policy, so the very next request
    # already runs on the new value (not the 720-minute one cached before).
    policy = session_policy.fresh_cached_policy()
    assert policy is not None and policy.idle_timeout == timedelta(minutes=90)


# --- i18n --------------------------------------------------------------------


def test_czech_plural_categories():
    assert [i18n.plural_category("cs", n) for n in (0, 1, 2, 4, 5, 22)] == [
        "other", "one", "few", "few", "other", "other",
    ]
    assert [i18n.plural_category("en", n) for n in (0, 1, 2)] == ["other", "one", "other"]


def test_translate_picks_the_plural_form():
    cs = i18n.get_locale("cs")
    en = i18n.get_locale("en")

    assert i18n.translate(cs, "dashboard.group_count", count=1) == "1 skupina"
    assert i18n.translate(cs, "dashboard.group_count", count=3) == "3 skupiny"
    assert i18n.translate(cs, "dashboard.group_count", count=0) == "0 skupin"
    assert i18n.translate(en, "dashboard.group_count", count=1) == "1 group"
    assert i18n.translate(en, "dashboard.group_count", count=2) == "2 groups"


async def test_audit_descriptions_are_localized_for_czech(client, db_session_factory):
    from app.audit import log_event

    async with db_session_factory() as db:
        await log_event(db, action="machine.logs.view", summary='Viewed journal on "prx"')
    await client.get("/settings")
    await client.post(
        "/account/locale",
        data={"locale": "cs", "csrf_token": client.cookies.get("csrftoken")},
    )

    response = await client.get("/audit")

    assert "Zobrazení logů" in response.text
    # The exact English summary stays available on hover.
    assert 'title="Viewed journal on &#34;prx&#34;"' in response.text
