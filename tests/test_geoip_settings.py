"""Settings -> Security -> GeoIP: enable/configure/save, and the "Download
now" button — see app/web/routes/settings.py's update_geoip_settings/
download_geoip_database_now and app/services/geoip.py.
"""

from __future__ import annotations


async def test_geoip_panel_appears_on_security_tab(client):
    response = await client.get("/settings?tab=security")
    assert response.status_code == 200
    assert "GeoIP" in response.text
    assert 'name="geoip_primary_url"' in response.text
    assert "No database downloaded yet." in response.text


async def test_saving_geoip_settings_redirects_back_to_security_tab(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/geoip",
        data={
            "csrf_token": csrf_token,
            "geoip_enabled": "on",
            "geoip_primary_url": "https://example.com/GeoLite2-City.mmdb",
            "geoip_backup_url": "",
            "geoip_refresh_interval_hours": "24",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/settings?tab=security"

    page = await client.get("/settings?tab=security")
    assert 'checked' in page.text  # the enabled checkbox
    assert 'value="24"' in page.text


async def test_enabling_geoip_without_a_url_is_rejected(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/geoip",
        data={
            "csrf_token": csrf_token,
            "geoip_enabled": "on",
            "geoip_primary_url": "",
            "geoip_backup_url": "",
            "geoip_refresh_interval_hours": "24",
        },
    )
    assert response.status_code == 200
    assert "Enabling GeoIP needs at least a primary database URL." in response.text


async def test_geoip_refresh_interval_out_of_range_is_rejected(client):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/geoip",
        data={
            "csrf_token": csrf_token,
            "geoip_enabled": "",
            "geoip_primary_url": "https://example.com/GeoLite2-City.mmdb",
            "geoip_backup_url": "",
            "geoip_refresh_interval_hours": "0",
        },
    )
    assert response.status_code == 200
    assert "Refresh interval must be a whole number of hours" in response.text


async def test_download_now_without_a_configured_url_shows_an_error(client):
    response = await client.get("/settings?tab=security")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/geoip/download",
        data={"csrf_token": csrf_token},
    )
    assert response.status_code == 200
    assert "No GeoIP database URL is configured yet." in response.text


async def test_download_now_dispatches_the_celery_task_with_force(client, celery_calls):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        "/settings/geoip",
        data={
            "csrf_token": csrf_token,
            "geoip_enabled": "",
            "geoip_primary_url": "https://example.com/GeoLite2-City.mmdb",
            "geoip_backup_url": "",
            "geoip_refresh_interval_hours": "24",
        },
    )

    response = await client.post(
        "/settings/geoip/download",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "app.tasks.jobs.refresh_geoip_database" in celery_calls.names
    _name, _args, kwargs = next(
        c for c in celery_calls if c[0] == "app.tasks.jobs.refresh_geoip_database"
    )
    assert kwargs == {"force": True}
