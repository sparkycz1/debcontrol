"""The 0.77.0 navigation/UX round: the Security section, Backup & restore,
maintenance windows under Scheduling (and pausing scheduled tasks), the
one-save Checks tab, live Beat intervals, the integration "Test" buttons,
the AI nav entry, permission descriptions and S.M.A.R.T. labels."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.core.app_settings import get_or_create_app_settings
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType
from app.db.models.scheduled_task_run import ScheduledTaskRun
from app.scheduling.jobs import _run_scheduled_task
from app.tasks import celery_app as celery_app_module
from tests.test_onboarding import _make_machine

# --- Security section --------------------------------------------------------


async def test_security_pages_live_under_their_own_nav_entry(client):
    updates = await client.get("/security/updates")
    packages = await client.get("/security/packages?q=openssl")

    assert updates.status_code == 200
    assert packages.status_code == 200
    assert 'href="/security/updates"' in updates.text  # nav + tab
    assert 'href="/security/packages"' in updates.text


async def test_old_security_urls_redirect(client):
    updates = await client.get("/machines/security-updates", follow_redirects=False)
    search = await client.get("/machines/package-search?q=libc", follow_redirects=False)

    assert (updates.status_code, updates.headers["location"]) == (308, "/security/updates")
    assert search.headers["location"] == "/security/packages?q=libc"


async def test_dashboard_tiles_link_to_filtered_lists(client):
    response = await client.get("/dashboard")

    assert 'href="/machines?status=offline"' in response.text
    assert 'href="/machines?status=updates"' in response.text
    assert 'href="/machines?status=online"' in response.text


async def test_online_status_filter(client, db_session_factory):
    machine_id = await _make_machine(db_session_factory)
    async with db_session_factory() as db:
        from app.db.models.machine import Machine

        machine = await db.get(Machine, machine_id)
        assert machine is not None
        machine.is_reachable = False
        await db.commit()

    online = await client.get("/machines?status=online")
    offline = await client.get("/machines?status=offline")

    assert f"/machines/{machine_id}" not in online.text
    assert f"/machines/{machine_id}" in offline.text


# --- Backup & restore ----------------------------------------------------------


async def test_backup_page_lists_every_export(client):
    response = await client.get("/backup")

    assert response.status_code == 200
    for href in (
        "/machines/config/export?format=json",
        "/scheduling/config/export",
        "/roles/config/export",
        "/notifications/rules/export",
        "/machines/config/import",
    ):
        assert f'href="{href}"' in response.text


async def test_backup_page_shows_only_what_the_role_allows(client, login_as):
    await login_as(client, permissions={Permission.SCHEDULING_VIEW})

    response = await client.get("/backup")

    assert 'href="/scheduling/config/export"' in response.text
    assert 'href="/roles/config/export"' not in response.text
    assert 'href="/scheduling/config/import"' not in response.text  # view only


# --- Maintenance windows -------------------------------------------------------


async def test_maintenance_windows_moved_under_scheduling(client):
    page = await client.get("/scheduling/maintenance")
    old = await client.get("/notifications/maintenance/new", follow_redirects=False)

    assert page.status_code == 200
    assert (old.status_code, old.headers["location"]) == (308, "/scheduling/maintenance/new")


async def _make_task(db_session_factory: Any) -> Any:
    async with db_session_factory() as session:
        task = ScheduledTask(
            name="Nightly check",
            action="check_updates",
            target_type=ScheduleTargetType.ALL_MACHINES,
            cron_expression="0 3 * * *",
            is_enabled=True,
        )
        session.add(task)
        await session.commit()
        return task.id


async def test_a_pausing_window_skips_machines_in_scheduled_runs(
    db_session_factory, celery_calls, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    await _make_machine(db_session_factory)
    task_id = await _make_task(db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        db.add(
            MaintenanceWindow(
                name="Disk swap",
                starts_at=now - timedelta(minutes=5),
                ends_at=now + timedelta(hours=1),
                all_machines=True,
                pause_scheduled_tasks=True,
            )
        )
        await db.commit()

    result = await _run_scheduled_task(str(task_id))

    assert result["attempted"] == 0
    async with db_session_factory() as db:
        run = (await db.execute(select(ScheduledTaskRun))).scalar_one()
        assert "paused by a maintenance window" in run.summary


async def test_a_window_that_only_mutes_notifications_does_not_pause(
    db_session_factory, celery_calls, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    await _make_machine(db_session_factory)
    task_id = await _make_task(db_session_factory)
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        db.add(
            MaintenanceWindow(
                name="Quiet",
                starts_at=now - timedelta(minutes=5),
                ends_at=now + timedelta(hours=1),
                all_machines=True,
            )
        )
        await db.commit()

    result = await _run_scheduled_task(str(task_id))

    assert result["attempted"] == 1


# --- Settings --------------------------------------------------------------------


async def test_checks_tab_saves_everything_at_once(client, db_session_factory):
    await client.get("/settings?tab=checks")
    response = await client.post(
        "/settings/checks",
        data={
            "csrf_token": client.cookies.get("csrftoken"),
            "ssh_connect_timeout": "15",
            "monitoring_interval_seconds": "300",
            "monitoring_history_retention_days": "",
            "dashboard_trends_retention_days": "30",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.ssh_connect_timeout == 15
        assert app_settings.monitoring_interval_seconds == 300
        assert app_settings.monitoring_history_retention_days is None
        assert app_settings.dashboard_trends_retention_days == 30
        # Not sent: unchanged.
        assert app_settings.update_timeout_seconds == 1800


async def test_checks_tab_rejects_out_of_range_values_without_saving(client, db_session_factory):
    await client.get("/settings?tab=checks")
    response = await client.post(
        "/settings/checks",
        data={"csrf_token": client.cookies.get("csrftoken"), "ssh_connect_timeout": "9999"},
    )

    assert response.status_code == 200
    async with db_session_factory() as db:
        assert (await get_or_create_app_settings(db)).ssh_connect_timeout == 10


def test_beat_intervals_follow_the_database(monkeypatch):
    values = {
        "reachability_check_interval_seconds": 60,
        "facts_refresh_interval_seconds": 3600,
        "monitoring_interval_seconds": 120,
        "notification_condition_check_interval_seconds": 60,
    }
    monkeypatch.setattr(celery_app_module, "_bootstrap_interval_settings", lambda: dict(values))
    monkeypatch.setattr(celery_app_module, "_INTERVAL_REFRESH_SECONDS", 0.0)
    celery_app_module._interval_cache.update(values=None, read_at=0.0)
    interval = celery_app_module.SettingInterval("monitoring_interval_seconds")
    assert interval.run_every == timedelta(seconds=120)

    values["monitoring_interval_seconds"] = 300
    interval.is_due(datetime.now(UTC))

    assert interval.run_every == timedelta(seconds=300)
    rebuilt_class, args = interval.__reduce__()
    assert rebuilt_class is celery_app_module.SettingInterval
    assert args == ("monitoring_interval_seconds",)
    celery_app_module._interval_cache.update(values=None, read_at=0.0)


async def test_ldap_test_button_reports_a_missing_configuration(client):
    await client.get("/settings?tab=integrations")
    response = await client.post(
        "/settings/ldap/test", data={"csrf_token": client.cookies.get("csrftoken")}
    )

    assert response.status_code == 200
    assert "LDAP is not fully configured" in response.text


async def test_smtp_test_button_needs_an_email_on_the_account(client):
    await client.get("/settings?tab=integrations")
    response = await client.post(
        "/settings/smtp/test", data={"csrf_token": client.cookies.get("csrftoken")}
    )

    assert response.status_code == 200
    assert "no e-mail address" in response.text


async def test_oidc_test_button_reads_the_discovery_document(client, monkeypatch):
    async def fake_discovery(app_settings: Any) -> str:
        return "https://id.example.com"

    monkeypatch.setattr("app.web.routes.settings.oidc_check_discovery", fake_discovery)
    await client.get("/settings?tab=integrations")
    response = await client.post(
        "/settings/oidc/test", data={"csrf_token": client.cookies.get("csrftoken")}
    )

    assert "https://id.example.com" in response.text


# --- Navigation, roles, S.M.A.R.T. ---------------------------------------------------


async def test_ai_nav_entry_hidden_until_a_model_is_enabled(client):
    response = await client.get("/dashboard")

    assert 'href="/ai"' not in response.text


async def test_role_form_describes_each_permission(client):
    response = await client.get("/roles/new")

    assert "Run updates" in response.text
    assert "<code class=\"permission-code\">action.updates</code>" in response.text


def test_smart_attribute_labels_are_translated():
    from starlette.datastructures import State

    from app import i18n
    from app.web.templating import smart_attr_label

    class _Request:
        state = State()

    request = _Request()
    request.state.locale = i18n.get_locale("cs")

    assert smart_attr_label(request, "Reallocated_Sector_Ct") == "Přemapované sektory"  # type: ignore[arg-type]
    assert smart_attr_label(request, "CriticalWarning") == "Kritické varování"  # type: ignore[arg-type]
    assert smart_attr_label(request, "Vendor_Specific_X") == "Vendor_Specific_X"  # type: ignore[arg-type]


async def test_bulk_bar_starts_with_a_hint_and_power_actions_apart(client, db_session_factory):
    await _make_machine(db_session_factory)

    response = await client.get("/machines?view=table")

    assert 'class="bulk-bar"' in response.text
    assert "bulk-when-empty" in response.text
    assert "bulk-danger-zone" in response.text
