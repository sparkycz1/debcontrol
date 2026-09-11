"""`AppSettings.audit_log_retention_days` now defaults to 90 days rather
than `None` ("keep forever") — see that column's docstring in
`app/db/models/app_settings.py`."""

from __future__ import annotations

from app.core.app_settings import get_or_create_app_settings


async def test_new_app_settings_row_defaults_audit_retention_to_90_days(db_session_factory):
    async with db_session_factory() as db:
        app_settings = await get_or_create_app_settings(db)
        assert app_settings.audit_log_retention_days == 90
