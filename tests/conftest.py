from __future__ import annotations

import os

# Set these BEFORE importing `app.main` — configuration (`Settings`) is
# validated right at import time, and tests don't run against real
# infrastructure (the DB dependency is swapped for SQLite below; Redis is
# never touched in tests via ASGITransport, since that doesn't trigger
# FastAPI's lifespan).
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-not-for-real-use-000000")
os.environ.setdefault("ENCRYPTION_KEY", "IYH8EiMlmjkDacPXmvWQgDjTojLMD6GDwD8STyL1x0Y=")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app


@pytest_asyncio.fixture
async def db_session_factory():
    """Isolated in-memory SQLite DB for each test (no real Postgres)."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def client(db_session_factory):
    async def _override_get_db():
        async with db_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()
