"""A short-TTL Redis cache for the Dashboard's per-request fleet stat
counts (`app.services.fleet_stats.compute_fleet_stats`) — six `COUNT`
queries against `Machine`, cheap individually but re-run in full on every
single dashboard load. `compute_fleet_stats` itself stays pure/uncached —
the daily snapshot job (`app.tasks.jobs.record_fleet_snapshot`) calls it
directly with no Redis instance to reuse and no reason to want a stale
count for a once-a-day permanent record.

Cached for a few seconds only, keyed by the exact scope (`group_ids`) it
was computed for — this is burst damping (several admins reloading the
dashboard within the same few seconds see the same numbers, one query
instead of several redundant round-trips to Postgres), not a substitute
for freshness on an operational tool where "is this machine online right
now" matters. A machine's reachability/update state changing mid-window is
invisible for at most the TTL, an acceptable trade at this length.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Set as AbstractSet
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.fleet_stats import FleetStats, compute_fleet_stats

_CACHE_TTL_SECONDS = 5


class _RedisLike(Protocol):
    async def get(self, key: str) -> bytes | str | None: ...
    async def set(self, key: str, value: str, ex: int) -> object: ...


def _cache_key(group_ids: AbstractSet[uuid.UUID] | None) -> str:
    if group_ids is None:
        return "dashboard:fleet_stats:all"
    return "dashboard:fleet_stats:" + ",".join(sorted(str(group_id) for group_id in group_ids))


async def cached_fleet_stats(
    db: AsyncSession,
    redis: _RedisLike | None,
    group_ids: AbstractSet[uuid.UUID] | None = None,
) -> FleetStats:
    """Same result as `compute_fleet_stats(db, group_ids)`, served from a
    short-lived Redis cache when one's available. Falls back to computing
    directly (no caching, same as before this existed) if `redis` is
    `None` — never a hard dependency, and any Redis error propagates
    exactly as any other query dependency's would rather than being
    swallowed into a silently-uncached path."""
    if redis is None:
        return await compute_fleet_stats(db, group_ids)

    key = _cache_key(group_ids)
    cached = await redis.get(key)
    if cached is not None:
        result: FleetStats = json.loads(cached)
        return result

    stats = await compute_fleet_stats(db, group_ids)
    await redis.set(key, json.dumps(stats), ex=_CACHE_TTL_SECONDS)
    return stats
