"""`/push/<token>`: the heartbeat of a push check (see
`app.services.endpoint_checks`), called by a backup script, a cron job or
anything else that should run regularly:

    curl -fsS https://debcontrol.example/push/<token>
    curl -fsS "https://debcontrol.example/push/<token>?status=down&msg=disk+full"

Served without a session and outside the network allowlist (see
`app.auth.middleware`), like the status page: the token in the address is
what authorizes the call, and all it can do is report that one check up
or down. An unknown token, a disabled check and a check that is no longer
a push check all answer the same 404. The answer never says anything about
the check beyond "recorded".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.endpoint_check import EndpointCheck
from app.db.session import get_db
from app.tasks import jobs as tasks

router = APIRouter(prefix="/push")

# Heartbeats closer together than this are accepted but not recorded
# again: a loop calling the address cannot fill the history table.
MIN_SECONDS_BETWEEN_RECORDS = 10
_HEADERS = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"}


async def _push(db: AsyncSession, token: str, state: str, msg: str) -> Response:
    if not token or len(token) > 64:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    check = (
        await db.execute(select(EndpointCheck).where(EndpointCheck.push_token == token))
    ).scalar_one_or_none()
    if check is None or check.kind != "push" or not check.enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    ok = state.strip().lower() not in ("down", "fail", "error", "0")
    now = datetime.now(UTC)
    last = check.last_push_at
    if (
        last is not None
        and check.last_ok is ok
        and now - (last if last.tzinfo else last.replace(tzinfo=UTC))
        < timedelta(seconds=MIN_SECONDS_BETWEEN_RECORDS)
    ):
        return PlainTextResponse("OK\n", headers=_HEADERS)
    tasks.receive_endpoint_push.delay(str(check.id), ok, msg[:200] or None, now.isoformat())
    return PlainTextResponse("OK\n", headers=_HEADERS)


@router.get("/{token}", include_in_schema=False)
async def push_get(
    token: str, status: str = "up", msg: str = "", db: AsyncSession = Depends(get_db)
) -> Response:
    return await _push(db, token, status, msg)


@router.post("/{token}", include_in_schema=False)
async def push_post(
    token: str, status: str = "up", msg: str = "", db: AsyncSession = Depends(get_db)
) -> Response:
    return await _push(db, token, status, msg)
