"""The app for the browser smoke test (`e2e/test_pages.py`): the real
FastAPI application on an in-memory SQLite database with a small, fixed
set of data — wired the same way `tests/conftest.py` wires it, so it needs
no Postgres, Redis or Celery.

    python -m e2e.serve [port]

Prints `SESSION_TOKEN=<token>` (a signed-in all-permissions session for
the `session` cookie) once the data is in, then serves on 127.0.0.1.
Also handy for looking at a change by hand.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import AsyncGenerator
from datetime import UTC, date, datetime, timedelta

os.environ.setdefault("SECRET_KEY", "e2e-only-secret-key-not-for-real-use-0000000000")
os.environ.setdefault("ENCRYPTION_KEY", "IYH8EiMlmjkDacPXmvWQgDjTojLMD6GDwD8STyL1x0Y=")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://e2e:e2e@localhost/e2e")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("POSTGRES_PASSWORD", "e2e")
os.environ.setdefault("REDIS_PASSWORD", "e2e")
os.environ.setdefault("INFORM_TOKEN", "e2e-only-inform-token-not-for-real-use-0000000000")

import uvicorn
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.auth.sessions import create_session
from app.db.base import Base
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.endpoint_check_result import EndpointCheckResult
from app.db.models.fleet_snapshot import FleetSnapshot
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_reachability_sample import (
    MachineReachabilitySample,
)
from app.db.models.notification_rule import (
    NotificationEventType,
    NotificationRule,
)
from app.db.models.role import Permission, Role, RolePermission
from app.db.models.scheduled_task import ScheduledTask, ScheduleTargetType
from app.db.models.user import AuthProvider, User
from app.db.session import get_db
from app.main import app
from tests.conftest import FakeRedis

DEFAULT_PORT = 8765

engine = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
factory = async_sessionmaker(engine, expire_on_commit=False)


async def seed() -> str:
    """Create the schema and the sample data; returns a session token."""
    now = datetime.now(UTC).replace(microsecond=0)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with factory() as db:
        role = Role(name="Administrator", description="Full access.")
        role.permission_grants = [RolePermission(permission=p) for p in Permission]
        user = User(
            username="admin",
            auth_provider=AuthProvider.LOCAL,
            is_active=True,
            role=role,
            api_access_enabled=True,
        )
        group = MachineGroup(name="Web")
        db.add_all([role, user, group])
        await db.flush()

        web = Machine(
            name="web1",
            ip_address="192.0.2.10",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            host_key_fingerprint="SHA256:e2e",
            group_id=group.id,
            is_reachable=True,
            os_id="debian",
            upgradable_count=4,
            security_upgradable_count=1,
            monitoring_updated_at=now,
        )
        db_host = Machine(
            name="db1",
            ip_address="192.0.2.11",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            is_reachable=False,
            os_id="ubuntu",
        )
        check = EndpointCheck(name="shop", kind="http", target="https://shop.example.com")
        db.add_all([web, db_host, check])
        await db.flush()

        for k in range(60):
            at = now - timedelta(minutes=2 * (59 - k))
            db.add(
                MachineMonitoringSample(
                    machine_id=web.id,
                    sampled_at=at,
                    cpu_percent=5.0 + (k % 7) * 3,
                    load1=0.2,
                    load5=0.2,
                    load15=0.1,
                )
            )
            db.add(
                MachineReachabilitySample(
                    machine_id=web.id, checked_at=at, reachable=True, latency_ms=4.0 + k % 3
                )
            )
            db.add(
                EndpointCheckResult(
                    check_id=check.id,
                    checked_at=at,
                    ok=k % 11 != 0,
                    status_code=200,
                    latency_ms=80.0 + k % 9,
                )
            )
        for days_ago, online in ((2, 1), (1, 2), (0, 1)):
            db.add(
                FleetSnapshot(
                    snapshot_date=date.today() - timedelta(days=days_ago),
                    total_machines=2,
                    online_machines=online,
                    offline_machines=2 - online,
                    needs_updates=1,
                    needs_security_updates=1,
                    needs_reboot=0,
                )
            )
        db.add(
            ScheduledTask(
                name="Nightly updates",
                action="system_update",
                target_type=ScheduleTargetType.ALL_MACHINES,
                cron_expression="0 3 * * *",
            )
        )
        db.add(
            NotificationRule(
                name="Outages",
                enabled=True,
                event_types=[NotificationEventType.MACHINE_UNREACHABLE.value],
            )
        )
        await db.flush()
        _session, token = await create_session(db, user, ip_address=None, user_agent=None)
        await db.commit()
    return token


async def _get_db() -> AsyncGenerator[AsyncSession]:
    async with factory() as session:
        yield session


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    token = asyncio.run(seed())
    app.dependency_overrides[get_db] = _get_db
    app.state.redis = FakeRedis()
    app.state.db_session_factory = factory
    print("SESSION_TOKEN=" + token, flush=True)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off")


if __name__ == "__main__":
    main()
