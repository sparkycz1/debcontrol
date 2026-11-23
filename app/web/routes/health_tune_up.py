"""Health → **Tune-up** ("Komplet"): every maintenance step debcontrol can
run, on one machine, a group or every machine at once — see
`app.services.tune_up` for the steps.

- `GET /health/tune-up` — the form (`?machine=<id>` picks one machine,
  the Overview's button) and the recent tune-ups.
- `POST /health/tune-up` — start one (`action.updates`; the reboot step
  also `action.power`), audited as `machine.tune_up.start`.
- `GET /health/tune-up/{batch_id}` — every machine of one tune-up, step by
  step; `?partial=1` is the table alone, which the page reloads while the
  tune-up runs.
- `POST /health/tune-up/{batch_id}/cancel` — stop it: waiting machines
  don't start, a running one stops after its current step. Audited as
  `machine.tune_up.cancel`.

Every list is limited to the machines the account can see.
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import self_host, tune_up
from app.services.access_scope import groups_visible_to, machines_visible_to
from app.web.flash import read_flash, sign_flash
from app.web.templating import t, templates

router = APIRouter(dependencies=[Depends(require_permission(Permission.MACHINE_VIEW))])

_need_updates = Depends(require_permission(Permission.ACTION_UPDATES))


def health_tabs(request: Request) -> list[tuple[str, str, str]]:
    return [
        ("health", t(request, "health.title"), "/health"),
        ("tune_up", t(request, "tune_up.title"), "/health/tune-up"),
    ]


async def visible_machines(db: AsyncSession, user: User) -> list[Machine]:
    query = await machines_visible_to(db, user)
    result = await db.execute(query.where(Machine.is_active.is_(True)).order_by(Machine.name))
    return list(result.scalars().all())


async def visible_ids(db: AsyncSession, user: User) -> set[uuid.UUID]:
    return {m.id for m in await visible_machines(db, user)}


async def chosen_machines(
    db: AsyncSession,
    user: User,
    target: str,
    machine_id: str | None,
    group_id: str | None,
) -> list[Machine]:
    """The machines a request names — always within what `user` sees."""
    machines = await visible_machines(db, user)
    if target == "all":
        return machines
    try:
        if target == "machine" and machine_id:
            wanted = uuid.UUID(machine_id)
            return [m for m in machines if m.id == wanted]
        if target == "group" and group_id:
            group = uuid.UUID(group_id)
            return [m for m in machines if m.group_id == group]
    except ValueError:
        return []
    return []


def options_for(user: User, options: tune_up.Options) -> tune_up.Options:
    """The reboot step only for an account that may reboot."""
    if options.reboot and not user.has_permission(Permission.ACTION_POWER):
        data = options.as_dict()
        data["reboot"] = False
        return tune_up.Options.from_dict(data)
    return options


async def start_for(
    request: Request,
    db: AsyncSession,
    user: User,
    machines: list[Machine],
    options: tune_up.Options,
) -> tuple[uuid.UUID | None, int]:
    """Start and audit a tune-up — the one path for the page and the API."""
    options = options_for(user, options)
    batch_id, skipped = await tune_up.start(db, machines, options, started_by=user.username)
    started = len(machines) - skipped
    if batch_id is not None:
        only = machines[0] if len(machines) == 1 else None
        await log_event(
            db,
            request=request,
            action="machine.tune_up.start",
            summary=(
                f'Started a tune-up of "{only.name}"'
                if only
                else f"Started a tune-up of {started} machines"
            ),
            outcome=AuditOutcome.SUCCESS,
            target_type="machine" if only else None,
            target_id=only.id if only else None,
            target_label=only.name if only else None,
            details={
                "batch_id": str(batch_id),
                "started": started,
                "skipped": skipped,
                "options": options.as_dict(),
            },
        )
    return batch_id, skipped


async def cancel_for(
    request: Request, db: AsyncSession, user: User, batch_id: uuid.UUID
) -> int:
    count = await tune_up.cancel_batch(
        db, batch_id, await visible_ids(db, user), actor=user.username
    )
    if count:
        await log_event(
            db,
            request=request,
            action="machine.tune_up.cancel",
            summary=f"Stopped a tune-up ({count} machines)",
            outcome=AuditOutcome.SUCCESS,
            details={"batch_id": str(batch_id), "runs": count},
        )
    return count


@router.get("/health/tune-up")
async def tune_up_page(
    request: Request,
    machine: str = "",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machines = await visible_machines(db, current_user)
    groups_query = await groups_visible_to(db, current_user)
    groups = list((await db.execute(groups_query.order_by(MachineGroup.name))).scalars().all())
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "health/tune_up.html",
        {
            "tabs": health_tabs(request),
            "active_tab": "tune_up",
            "machines": machines,
            "groups": groups,
            "preselected": machine,
            "defaults": tune_up.Options(),
            "steps": tune_up.STEPS,
            "batches": await tune_up.recent_batches(db, {m.id for m in machines}),
            "can_run": current_user.has_permission(Permission.ACTION_UPDATES),
            "can_reboot": current_user.has_permission(Permission.ACTION_POWER),
            "self_host_role": None,
            "self_host_names": await self_host.visible_names(db, current_user),
            "csrf_token": csrf_token,
            "notice": read_flash(request, "notice"),
            "error": read_flash(request, "error"),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/health/tune-up", dependencies=[_need_updates, Depends(verify_csrf)])
async def start_tune_up(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    form = await request.form()
    target = str(form.get("target") or "")
    machines = await chosen_machines(
        db,
        current_user,
        target,
        str(form.get("machine_id") or "") or None,
        str(form.get("group_id") or "") or None,
    )
    if not machines:
        return _back_with_error(request, "tune_up.error.no_machines")
    batch_id, skipped = await start_for(
        request, db, current_user, machines, tune_up.Options.from_form(form)
    )
    if batch_id is None:
        return _back_with_error(request, "tune_up.error.none_started")
    notice = sign_flash(
        t(request, "tune_up.started", count=len(machines) - skipped, skipped=skipped)
    )
    return _to_batch(batch_id, notice)


async def _batch_or_404(
    db: AsyncSession, user: User, batch_id: uuid.UUID
) -> tune_up.BatchView:
    view = await tune_up.batch(db, batch_id, await visible_ids(db, user))
    if view is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such tune-up.")
    return view


@router.get("/health/tune-up/{batch_id}")
async def tune_up_batch_page(
    request: Request,
    batch_id: uuid.UUID,
    partial: int = 0,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    view = await _batch_or_404(db, current_user, batch_id)
    context: dict[str, Any] = {
        "tabs": health_tabs(request),
        "active_tab": "tune_up",
        "view": view,
        "steps": tune_up.STEPS,
        "can_run": current_user.has_permission(Permission.ACTION_UPDATES),
        "notice": read_flash(request, "notice"),
    }
    if partial:
        return templates.TemplateResponse(request, "health/_tune_up_runs.html", context)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    context["csrf_token"] = csrf_token
    response = templates.TemplateResponse(request, "health/tune_up_batch.html", context)
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post(
    "/health/tune-up/{batch_id}/cancel", dependencies=[_need_updates, Depends(verify_csrf)]
)
async def cancel_tune_up(
    request: Request,
    batch_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    await _batch_or_404(db, current_user, batch_id)
    count = await cancel_for(request, db, current_user, batch_id)
    return _to_batch(batch_id, sign_flash(t(request, "tune_up.cancelled", count=count)))


def _back_with_error(request: Request, key: str) -> Response:
    query = urlencode({"error": sign_flash(t(request, key))})
    return RedirectResponse(url=f"/health/tune-up?{query}", status_code=status.HTTP_303_SEE_OTHER)


def _to_batch(batch_id: uuid.UUID, notice: str) -> Response:
    """The batch's own page — its id is one debcontrol made, never request text."""
    query = urlencode({"notice": notice})
    return RedirectResponse(
        url=f"/health/tune-up/{uuid.UUID(str(batch_id))}?{query}",
        status_code=status.HTTP_303_SEE_OTHER,
    )

