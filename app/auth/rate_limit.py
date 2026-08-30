"""Per-IP rate limiting for the login endpoints, backed by Redis.

This is deliberately separate from the existing per-*account* lockout in
`app.auth.login` (`User.failed_login_attempts`/`locked_until`): that one
protects a single account from being guessed, but has no limit on how many
*different* usernames one source can try. This closes that gap with a
coarse, high-limit-by-design per-IP cap — meant to blunt obviously abusive
volume (credential stuffing, username enumeration at scale), not to
inconvenience a legitimate user who mistypes a password a few times or a
shared office/VPN egress IP with several people logging in.

Uses `app.state.redis` — a plain `redis.asyncio.Redis` pool opened once in
`app.main`'s lifespan, so a burst of login attempts doesn't open a fresh
connection per request. It hits the same Redis *server* the Celery queue
uses, but shares nothing else with it: this is straight `INCR`/`EXPIRE`, no
queue involvement whatsoever.
"""

from __future__ import annotations

from typing import Protocol


class _RedisLike(Protocol):
    async def incr(self, key: str) -> int: ...
    async def expire(self, key: str, seconds: int) -> object: ...


async def check_rate_limit(
    redis: _RedisLike, key: str, *, limit: int, window_seconds: int
) -> bool:
    """Increment `key`'s counter and return whether it's still within `limit`.

    A fixed-window counter, not a true sliding window — good enough for
    "stop obviously abusive volume" and much cheaper than a sorted-set
    sliding window. The window's TTL is set on the first increment; if a
    crash happened between `INCR` and `EXPIRE` the key could rarely be left
    without one, which only makes that one window run a little long — it
    can never make the limit looser, so it isn't a security concern.
    """
    current = await redis.incr(key)
    if current == 1:
        await redis.expire(key, window_seconds)
    return current <= limit
