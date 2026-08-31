"""Async DB engine and session factory."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings

settings = get_settings()

# pool_pre_ping checks the connection before use (Postgres/the network can
# silently drop idle connections). pool_size/max_overflow are configurable
# (DB_POOL_SIZE/DB_MAX_OVERFLOW) — see the settings' own docstring for why
# the defaults are larger than SQLAlchemy's own (5/10).
engine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    echo=False,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession]:
    """FastAPI dependency providing a DB session for the lifetime of one request."""
    async with AsyncSessionLocal() as session:
        yield session
