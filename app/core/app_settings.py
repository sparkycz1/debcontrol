"""Accessor for the singleton `AppSettings` row — see
`app.db.models.app_settings` for what it holds and why it's separate from
`app.core.config.Settings`."""

from __future__ import annotations

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.app_settings import SINGLETON_ID, AppSettings


async def get_or_create_app_settings(db: AsyncSession) -> AppSettings:
    """Return the app settings row, creating it (with all-default values)
    on first use. Same create-or-fetch-on-conflict pattern as
    `app.ssh.identity.get_or_create_identity` — a race between two requests
    both creating it is handled by re-reading after a unique violation,
    not by locking."""
    settings_row = await db.get(AppSettings, SINGLETON_ID)
    if settings_row is not None:
        return settings_row

    settings_row = AppSettings(id=SINGLETON_ID)
    db.add(settings_row)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        settings_row = await db.get(AppSettings, SINGLETON_ID)
        assert settings_row is not None
    return settings_row
