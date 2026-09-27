"""Accessors for the five `AiProviderConfig` rows and the models fetched
for them."""

from __future__ import annotations

import time
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.base import ModelInfo
from app.db.models.ai_model import AiModel
from app.db.models.ai_provider import AiProviderConfig, AiProviderKind


async def get_or_create_ai_provider_configs(
    db: AsyncSession,
) -> dict[AiProviderKind, AiProviderConfig]:
    """Every provider kind's config row, creating any that don't exist yet.

    Same create-or-fetch-on-conflict shape as
    `app.core.app_settings.get_or_create_app_settings`: a race between two
    requests both creating a row is resolved by re-reading after the unique
    violation, not by locking. Returns them keyed by kind, in the fixed
    enum order, so the Settings page always renders the same five blocks.
    """
    result = await db.execute(select(AiProviderConfig))
    existing = {config.kind: config for config in result.scalars().all()}

    missing = [kind for kind in AiProviderKind if kind not in existing]
    if missing:
        db.add_all(AiProviderConfig(kind=kind) for kind in missing)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
        result = await db.execute(select(AiProviderConfig))
        existing = {config.kind: config for config in result.scalars().all()}

    return {kind: existing[kind] for kind in AiProviderKind if kind in existing}


async def replace_fetched_models(
    db: AsyncSession, config: AiProviderConfig, models: list[ModelInfo]
) -> tuple[int, int]:
    """Upsert a freshly fetched catalog onto `config`, preserving each
    surviving model's `enabled` flag and deleting ids the provider no longer
    lists. Returns (kept_or_added, removed).

    Preserving `enabled` is the point: re-fetching must never silently
    re-disable a model an admin explicitly approved for chat, nor enable one
    they didn't.
    """
    result = await db.execute(select(AiModel).where(AiModel.provider_id == config.id))
    current = {row.model_id: row for row in result.scalars().all()}

    fetched_ids = {model.id for model in models}
    removed = 0
    for model_id, row in current.items():
        if model_id not in fetched_ids:
            await db.delete(row)
            removed += 1

    for model in models:
        if model.id not in current:
            db.add(AiModel(provider_id=config.id, model_id=model.id, enabled=False))

    config.models_fetched_at = datetime.now(UTC)
    await db.commit()
    return len(fetched_ids), removed


async def get_selectable_models(db: AsyncSession) -> list[tuple[AiProviderConfig, AiModel]]:
    """Every (provider, model) pair a user may start a conversation with:
    the model is enabled *and* its provider is enabled. Both flags are
    required — enabling a provider isn't the same as approving its whole
    catalog, and an approved model on a disabled provider shouldn't be
    offered either."""
    result = await db.execute(
        select(AiProviderConfig, AiModel)
        .join(AiModel, AiModel.provider_id == AiProviderConfig.id)
        .where(AiProviderConfig.enabled, AiModel.enabled)
        .order_by(AiProviderConfig.kind, AiModel.model_id)
    )
    return [(config, model) for config, model in result.all()]


# The header shows the AI nav entry only when a conversation could actually
# be started — checked on every page render for accounts with `ai.access`,
# so cached in process for a few seconds; the Settings AI routes invalidate
# it on save.
_AVAILABILITY_TTL_SECONDS = 30.0
_availability_cache: tuple[float, bool] | None = None


async def ai_chat_available(db: AsyncSession) -> bool:
    global _availability_cache
    now = time.monotonic()
    if _availability_cache is not None and now - _availability_cache[0] < _AVAILABILITY_TTL_SECONDS:
        return _availability_cache[1]
    available = bool(await get_selectable_models(db))
    _availability_cache = (now, available)
    return available


def invalidate_ai_availability() -> None:
    global _availability_cache
    _availability_cache = None
