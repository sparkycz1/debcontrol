"""`/hooks/docker/<token>`: the webhook of a Git stack (see
`app.services.docker_stacks`). A Git host (GitHub, GitLab, Gitea, ...)
calls it on a push:

    curl -fsS -X POST https://debcontrol.example/hooks/docker/<token>

Served without a session and outside the network allowlist (see
`app.auth.middleware`), like push checks: the token is the credential,
and all it can do is have that one stack pulled from its own configured
repository and branch and deployed. The request body is ignored — what
is deployed never comes from the caller. An unknown token answers 404; a
call while a deployment is already waiting or running is accepted
without queuing another.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.db.models.docker import StackSource
from app.db.models.machine import Machine
from app.db.session import get_db
from app.services import docker_jobs, docker_stacks
from app.tasks.docker_jobs import queue_stack_deploy

router = APIRouter(prefix="/hooks/docker")

# Calls closer together than this are accepted but do nothing.
MIN_SECONDS_BETWEEN_DEPLOYS = 10
WEBHOOK_ACTOR = "Git webhook (automatic)"
_HEADERS = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"}


@router.post("/{token}", include_in_schema=False)
async def docker_webhook(
    request: Request, token: str, db: AsyncSession = Depends(get_db)
) -> Response:
    stack = await docker_stacks.find_by_webhook(db, token)
    if stack is None or stack.source != StackSource.GIT:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    machine = await db.get(Machine, stack.machine_id)
    if machine is None or not machine.is_active or not machine.host_key_fingerprint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    now = datetime.now(UTC)
    last = stack.webhook_last_at
    if last is not None and now - (last if last.tzinfo else last.replace(tzinfo=UTC)) < timedelta(
        seconds=MIN_SECONDS_BETWEEN_DEPLOYS
    ):
        return PlainTextResponse("OK\n", status_code=202, headers=_HEADERS)
    stack.webhook_last_at = now
    await db.commit()
    if await docker_jobs.protected_project(db, machine) == stack.name:
        return PlainTextResponse("OK\n", status_code=202, headers=_HEADERS)
    job = await queue_stack_deploy(db, stack, started_by=WEBHOOK_ACTOR)
    if job is not None:
        await log_event(
            db,
            request=request,
            actor=WEBHOOK_ACTOR,
            action="machine.docker.stack.webhook_deploy",
            summary=(
                f'Git webhook started deploying Docker stack "{stack.name}" on "{machine.name}"'
            ),
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
            details={"stack": stack.name, "job": str(job.id)},
        )
    return PlainTextResponse("OK\n", status_code=202, headers=_HEADERS)
