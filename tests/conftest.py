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

from collections.abc import Awaitable, Callable
from collections.abc import Set as AbstractSet
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.auth.security import hash_password
from app.auth.sessions import SESSION_COOKIE_NAME, create_session
from app.db.base import Base
from app.db.models.role import Permission, Role, RolePermission
from app.db.models.user import AuthProvider, User
from app.db.session import get_db
from app.main import app

ADMIN_USERNAME = "test-admin"


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
        self._counters: dict[str, int] = {}

    async def enqueue_job(self, function: str, *args: Any, **kwargs: Any) -> FakeArqJob:
        self.enqueued.append((function, args, kwargs))
        return FakeArqJob(result={"ok": True, "output": "fake"})

    # Minimal INCR/EXPIRE stand-in for app.auth.rate_limit — no real TTL
    # behaviour (counters never expire within a test), which is fine since
    # each test gets its own fresh instance anyway.
    async def incr(self, key: str) -> int:
        self._counters[key] = self._counters.get(key, 0) + 1
        return self._counters[key]

    async def expire(self, key: str, seconds: int) -> bool:
        return True


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


async def _create_user_with_permissions(
    db_session_factory: Any,
    *,
    username: str,
    permissions: set[Permission],
    auth_provider: AuthProvider = AuthProvider.LOCAL,
    **user_kwargs: Any,
) -> tuple[User, str]:
    """Creates a fresh role (granting exactly `permissions`) and a user with
    it, plus a real login session — returns (user, raw session token) so a
    test can put the token on whichever `AsyncClient` needs to act as them.
    """
    async with db_session_factory() as db:
        role = Role(name=f"role-for-{username}")
        role.permission_grants = [RolePermission(permission=p) for p in permissions]
        db.add(role)
        await db.flush()

        user = User(
            username=username,
            auth_provider=auth_provider,
            is_active=True,
            role=role,
            **user_kwargs,
        )
        db.add(user)
        await db.flush()

        _session, raw_token = await create_session(
            db, user, ip_address="testclient", user_agent="pytest"
        )
        await db.commit()
        await db.refresh(user)
    return user, raw_token


async def create_local_user(
    db_session_factory: Any,
    *,
    username: str,
    password: str,
    permissions: AbstractSet[Permission] = frozenset(),
    **user_kwargs: Any,
) -> User:
    """For tests that exercise the actual `/login` form (as opposed to
    `client`/`login_as`, which skip it and inject a session directly) — a
    real local account with a real, known password."""
    async with db_session_factory() as db:
        role = Role(name=f"role-for-{username}")
        role.permission_grants = [RolePermission(permission=p) for p in permissions]
        db.add(role)
        await db.flush()

        user = User(
            username=username,
            auth_provider=AuthProvider.LOCAL,
            password_hash=hash_password(password),
            is_active=True,
            role=role,
            **user_kwargs,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    return user


def _configure_app_for_tests(db_session_factory: Any) -> None:
    async def _override_get_db():
        async with db_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    app.state.arq_redis = FakeArqRedis()
    # The auth middleware (app.auth.middleware) opens its own DB session
    # from `request.app.state.db_session_factory` rather than through
    # FastAPI's dependency injection — point it at the same SQLite engine
    # `get_db` was just overridden to use, or every request would otherwise
    # try (and fail) to reach the real Postgres `AsyncSessionLocal` is bound
    # to. See app.main's `lifespan` for the production equivalent.
    app.state.db_session_factory = db_session_factory


@pytest_asyncio.fixture
async def client(db_session_factory):
    """An `AsyncClient` already logged in as a user with *every* permission
    — this is what most tests want, since they're exercising a feature, not
    RBAC itself. Use `anonymous_client` for login/logout/access-denied
    tests, or `login_as` to act as a more restricted user."""
    _configure_app_for_tests(db_session_factory)
    _, raw_token = await _create_user_with_permissions(
        db_session_factory,
        username=ADMIN_USERNAME,
        permissions=set(Permission),
        api_access_enabled=True,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        ac.cookies.set(SESSION_COOKIE_NAME, raw_token)
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def anonymous_client(db_session_factory):
    """An `AsyncClient` with no session cookie at all."""
    _configure_app_for_tests(db_session_factory)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def login_as(db_session_factory: Any) -> Callable[..., Awaitable[User]]:
    """`await login_as(some_client, permissions={Permission.MACHINE_VIEW})`
    — creates a role+user with exactly those permissions and points
    `some_client`'s session cookie at them, replacing whatever it had."""

    async def _login_as(
        ac: AsyncClient,
        *,
        permissions: AbstractSet[Permission] = frozenset(),
        username: str = "restricted-user",
        **user_kwargs: Any,
    ) -> User:
        user, raw_token = await _create_user_with_permissions(
            db_session_factory, username=username, permissions=set(permissions), **user_kwargs
        )
        ac.cookies.set(SESSION_COOKIE_NAME, raw_token)
        return user

    return _login_as
