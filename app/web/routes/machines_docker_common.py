"""What the Docker tab's route modules share: the sub-navigation, page
rendering, waiting for a worker's answer, and redirects with an outcome.

The Docker tab (`/machines/{id}/docker/...`) is split over
`machines_docker` (containers, images, volumes, networks, jobs),
`machines_docker_stacks`, `machines_docker_backups` and
`machines_docker_files`. Permissions (see wiki/Docker):

- `machine.view` — every page;
- `action.power` — start/stop/restart a container or a stack, take a
  stack down;
- `action.updates` — update and roll back containers, scan images, clean
  up, run/check/prune backups, deploy and sync stacks, auto-update and
  vulnerability-gate settings;
- `action.terminal` — the container shell, the file browser, a stack's
  compose file and `.env`, Git sources, backup settings and restores.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlencode

from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Request, Response, status
from fastapi.responses import RedirectResponse

from app.auth.dependencies import require_permission
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.web.flash import sign_flash
from app.web.messages import LocalizedText
from app.web.routes.machines_common import _machine_tabs
from app.web.templating import t, templates

need_terminal = Depends(require_permission(Permission.ACTION_TERMINAL))

SUB_PAGES = ("containers", "stacks", "images", "volumes", "networks", "backups", "jobs")


def docker_base(machine: Machine) -> str:
    return f"/machines/{machine.id}/docker"


def docker_subnav(request: Request, machine: Machine) -> list[tuple[str, str, str]]:
    base = docker_base(machine)
    return [
        ("containers", t(request, "docker.nav.containers"), base),
        ("stacks", t(request, "docker.nav.stacks"), f"{base}/stacks"),
        ("images", t(request, "docker.nav.images"), f"{base}/images"),
        ("volumes", t(request, "docker.nav.volumes"), f"{base}/volumes"),
        ("networks", t(request, "docker.nav.networks"), f"{base}/networks"),
        ("backups", t(request, "docker.nav.backups"), f"{base}/backups"),
        ("jobs", t(request, "docker.nav.jobs"), f"{base}/jobs"),
    ]


def actor(user: User) -> str:
    return user.username


def render(
    request: Request,
    template: str,
    machine: Machine,
    user: User,
    sub: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
) -> Response:
    """A Docker tab page: the machine's tabs with Docker active, the Docker
    sub-navigation with `sub` active, and a CSRF token."""
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        template,
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, user),
            "active_tab": "docker",
            "subnav": docker_subnav(request, machine),
            "active_sub": sub,
            "csrf_token": csrf_token,
            "docker_base": docker_base(machine),
            "can_power": user.has_permission(Permission.ACTION_POWER),
            "can_updates": user.has_permission(Permission.ACTION_UPDATES),
            "can_terminal": user.has_permission(Permission.ACTION_TERMINAL),
            "can_manage": user.has_permission(Permission.MACHINE_MANAGE),
            **(context or {}),
        },
        status_code=status_code,
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


def render_partial(request: Request, template: str, context: dict[str, Any]) -> Response:
    return templates.TemplateResponse(request, template, context)


async def wait_task(
    request: Request,
    async_result: Any,
    timeout: float,  # noqa: ASYNC109 - Celery's result timeout, not a deadline here
) -> tuple[dict[str, Any] | None, str | None]:
    """(the task's answer, None) or (None, an error to show)."""
    try:
        result = await asyncio.to_thread(async_result.get, timeout=timeout)
    except CeleryTimeoutError:
        return None, LocalizedText(request, "common.error.job_timeout")
    except Exception as exc:
        return None, str(exc) or type(exc).__name__
    if not isinstance(result, dict):
        return None, "Unexpected answer from the worker."
    if not result.get("ok"):
        error = str(result.get("error") or "Unknown error.")
        if result.get("no_access"):
            error = LocalizedText(request, "docker.no_access")
        elif error == "too_large":
            error = LocalizedText(request, "docker.files.too_large")
        return result, error
    return result, None


def redirect(url: str, **flash: str | None) -> RedirectResponse:
    """303 to `url`, carrying each given message signed (`app.web.flash`)."""
    query = {key: sign_flash(value) for key, value in flash.items() if value}
    if query:
        url += ("&" if "?" in url else "?") + urlencode(query)
    return RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)
