"""`app.services.dashboard_cache.cached_fleet_stats` — a short-TTL Redis
cache in front of `app.services.fleet_stats.compute_fleet_stats` (see that
module's own docstring for why: burst damping across concurrently loaded
Dashboards, not a substitute for freshness). Scoped independently by exact
`group_ids`, so a restricted account's cached count never leaks into an
unrestricted one's, or vice versa.
"""

from __future__ import annotations

from app.db.models.machine import AuthMethod, Machine
from app.services.dashboard_cache import cached_fleet_stats


class _FakeRedis:
    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self._values.get(key)

    async def set(self, key: str, value: str, ex: int) -> bool:
        self._values[key] = value
        return True


async def test_cached_fleet_stats_serves_a_stale_count_within_ttl(db_session_factory):
    async with db_session_factory() as db:
        db.add(
            Machine(
                name="m1", ip_address="10.1.1.1", username="admin", auth_method=AuthMethod.SSH_KEY
            )
        )
        await db.commit()

    redis = _FakeRedis()
    async with db_session_factory() as db:
        first = await cached_fleet_stats(db, redis)
    assert first["total"] == 1

    async with db_session_factory() as db:
        db.add(
            Machine(
                name="m2", ip_address="10.1.1.2", username="admin", auth_method=AuthMethod.SSH_KEY
            )
        )
        await db.commit()

    # Same (unscoped) key — still cached, so the second machine isn't
    # reflected yet. This is the intended trade-off (see module docstring).
    async with db_session_factory() as db:
        second = await cached_fleet_stats(db, redis)
    assert second["total"] == 1


async def test_cached_fleet_stats_keeps_scopes_separate(db_session_factory):
    async with db_session_factory() as db:
        db.add(
            Machine(
                name="m1", ip_address="10.1.1.1", username="admin", auth_method=AuthMethod.SSH_KEY
            )
        )
        await db.commit()

    redis = _FakeRedis()
    async with db_session_factory() as db:
        unscoped = await cached_fleet_stats(db, redis, None)
        scoped = await cached_fleet_stats(db, redis, set())
    assert unscoped["total"] == 1
    # An empty (but not None) group_ids scope means "no groups visible" —
    # a different cache key from the unscoped ("None" = whole fleet) one,
    # and a different count.
    assert scoped["total"] == 0


async def test_cached_fleet_stats_works_without_redis(db_session_factory):
    async with db_session_factory() as db:
        db.add(
            Machine(
                name="m1", ip_address="10.1.1.1", username="admin", auth_method=AuthMethod.SSH_KEY
            )
        )
        await db.commit()

    async with db_session_factory() as db:
        stats = await cached_fleet_stats(db, None)
    assert stats["total"] == 1
