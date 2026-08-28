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
os.environ.setdefault("INFORM_TOKEN", "test-only-inform-token-not-for-real-use-000000")

from typing import Any

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app


class FakeArqJob:
    """Stand-in for `arq.jobs.Job` — enough for code that calls `.result()`."""

    def __init__(self, result: Any = None) -> None:
        self._result = result

    async def result(self, timeout: float | None = None) -> Any:  # noqa: ASYNC109
        # `timeout` has to be named exactly this — it mirrors arq's real
        # `Job.result(timeout=...)`, which call sites pass as a keyword.
        return self._result


class FakeArqRedis:
    """Stand-in for the real Redis-backed arq pool.

    Tests run via ASGITransport, which never triggers FastAPI's lifespan —
    so `app.state.arq_redis` (normally a real connection made at startup)
    doesn't exist at all. Routes that enqueue background jobs (SSH checks,
    system updates, ...) would crash with an AttributeError without this.
    It doesn't run anything — it just records what was enqueued and hands
    back a canned "ok" result, which is enough to exercise the HTTP layer
    (a run gets created, a redirect happens, ...) without a real worker or
    SSH connectivity, neither of which is available in this environment.
    """

    def __init__(self) -> None:
        self.enqueued: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    async def enqueue_job(self, function: str, *args: Any, **kwargs: Any) -> FakeArqJob:
        self.enqueued.append((function, args, kwargs))
        return FakeArqJob(result={"ok": True, "output": "fake"})


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
    app.state.arq_redis = FakeArqRedis()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()
