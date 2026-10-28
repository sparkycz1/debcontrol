"""A machine's Logs tab (journal, log files, Docker), saved log views, the
log-file browser, and the Terminal page."""

from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass

# NOT the builtin `TimeoutError` — `celery.exceptions.TimeoutError` does not
# subclass it, so catching the builtin around `AsyncResult.get(timeout=...)`
# would silently never match and the timeout branches below would be dead code.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.config import get_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services.saved_log_views import (
    ALLOWED_LOG_VIEW_PARAMS,
    build_log_query_string,
    create_saved_log_view,
    delete_saved_log_view,
    list_saved_log_views,
)
from app.services.saved_views import (
    DuplicateViewNameError,
)
from app.ssh import logs as ssh_logs
from app.tasks import jobs as tasks
from app.web.log_lines import journal_log_lines, parse_log_lines
from app.web.messages import LocalizedText
from app.web.routes.machines_common import (
    _get_machine_or_404,
    _machine_tabs,
    machines_router,
)
from app.web.templating import templates

router = machines_router()


need_terminal = Depends(require_permission(Permission.ACTION_TERMINAL))


@router.get("/{machine_id}/terminal", dependencies=[need_terminal])
async def terminal_page(
    request: Request, machine_id: uuid.UUID, db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """The interactive web terminal's page shell — the actual byte relay
    happens over the WebSocket in `app/web/routes/terminal_ws.py`, which
    (since `app.auth.middleware` never runs for WebSocket requests) does its
    own independent session/permission check rather than relying on this
    page having already been reached. Gated behind `ACTION_TERMINAL` — see
    that permission's comment in `app/db/models/role.py` for why it's its
    own dedicated permission rather than folded into an existing one."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    if not machine.host_key_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirm the host key fingerprint before opening a terminal.",
        )
    return templates.TemplateResponse(
        request,
        "machines/terminal.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "terminal",
            "recording": (await get_or_create_app_settings(db)).terminal_recording_enabled,
        },
    )


@dataclass
class _LogQuery:
    source: str
    path: str
    container: str
    lines: int
    search: str
    since: str
    until: str
    priority: str
    unit: str
    boot: str
    hide_own: bool
    level: str


@dataclass
class _LogResult:
    output: str | None = None
    journal_entries: list[dict[str, object]] | None = None
    hidden_count: int = 0
    error: str | LocalizedText | None = None


def _log_query(
    machine: Machine,
    *,
    path: str,
    lines: int,
    search: str,
    since: str,
    until: str,
    source: str,
    container: str,
    priority: str,
    unit: str,
    boot: str,
    hide_own: str,
    level: str,
) -> _LogQuery:
    if source not in ("journal", "file", "docker"):
        source = "file" if path.strip() else "journal"
    journal = source == "journal"
    docker_containers = machine.docker_containers or []
    if source == "docker" and not container and docker_containers:
        running = [c for c in docker_containers if c.get("state") == "running"]
        container = str((running or docker_containers)[0].get("name") or "")
    return _LogQuery(
        source=source,
        path=path,
        container=container,
        lines=lines,
        search=search,
        since=since,
        until=until,
        priority=ssh_logs.normalize_priority(priority) if journal else "",
        unit=ssh_logs.normalize_unit(unit) if journal else "",
        boot=ssh_logs.normalize_boot(boot) if journal else "",
        hide_own=journal and hide_own in ("1", "true", "on"),
        level="" if journal else ssh_logs.normalize_level(level),
    )


def _fetches(query: _LogQuery) -> bool:
    return not (query.source == "file" and not query.path.strip()) and not (
        query.source == "docker" and not query.container
    )


async def _fetch_logs(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    query: _LogQuery,
    *,
    max_lines: int,
    download: bool = False,
) -> _LogResult:
    """Read the logs `query` asks for through the worker, and audit it
    (which machine, which source, the search term — never the content)."""
    app_settings = await get_or_create_app_settings(db)
    found = _LogResult()
    clamped_lines = max(1, min(query.lines, max_lines))
    # Options only when set, so a worker still running the previous
    # version (mid-upgrade) accepts the call.
    level_option = {"level": query.level} if query.level else {}
    try:
        if query.source == "docker":
            async_result = tasks.view_machine_docker_logs.delay(
                str(machine.id),
                container=query.container,
                lines=clamped_lines,
                search=query.search,
                since=query.since,
                until=query.until,
                **level_option,
            )
        elif query.source == "file":
            async_result = tasks.view_machine_log_file.delay(
                str(machine.id),
                path=query.path.strip(),
                lines=clamped_lines,
                search=query.search,
                **level_option,
            )
        else:
            journal_options: dict[str, object] = {
                key: value
                for key, value in (
                    ("priority", query.priority),
                    ("unit", query.unit),
                    ("boot", query.boot),
                    ("hide_own", query.hide_own),
                )
                if value
            }
            async_result = tasks.view_machine_journal.delay(
                str(machine.id),
                lines=clamped_lines,
                search=query.search,
                since=query.since,
                until=query.until,
                **journal_options,
            )
        result = await asyncio.to_thread(
            async_result.get, timeout=app_settings.ssh_connect_timeout + 15
        )
        if isinstance(result, dict):
            if result.get("ok"):
                found.output = str(result.get("output") or "")
                if isinstance(result.get("entries"), list):
                    found.journal_entries = list(result["entries"])
                found.hidden_count = int(result.get("hidden") or 0)
            else:
                found.error = str(result.get("error") or "Unknown error.")
    except CeleryTimeoutError:
        found.error = LocalizedText(request, "common.error.command_timeout")
    except Exception as exc:
        found.error = str(exc)

    stack = (
        query.container[len(ssh_logs.STACK_PREFIX) :]
        if query.container.startswith(ssh_logs.STACK_PREFIX)
        else ""
    )
    verb = "Downloaded" if download else "Viewed"
    details: dict[str, object] = {}
    if query.search.strip():
        details["search"] = query.search
    if query.level:
        details["level"] = query.level
    if download:
        details["download"] = True
    await log_event(
        db,
        request=request,
        action="machine.logs.view",
        summary=(
            f'{verb} Docker logs of stack "{stack}" on "{machine.name}"'
            if stack
            else f'{verb} Docker logs of "{query.container}" on "{machine.name}"'
            if query.source == "docker"
            else f'{verb} log file "{query.path.strip()}" on "{machine.name}"'
            if query.source == "file"
            else f'{verb} journal on "{machine.name}"'
        ),
        outcome=AuditOutcome.SUCCESS if found.error is None else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details=details or None,
    )
    return found


def _stacks_of(machine: Machine) -> list[str]:
    """The Compose projects whose merged logs the Docker source offers."""
    projects = {
        str(c.get("compose_project") or "")
        for c in machine.docker_containers or []
        if isinstance(c, dict)
    }
    return sorted(p for p in projects if p)


@router.get("/{machine_id}/logs", dependencies=[need_terminal])
async def machine_logs(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    path: str = "",
    lines: int = ssh_logs.DEFAULT_LINE_LIMIT,
    search: str = "",
    since: str = "",
    until: str = "",
    source: str = "",
    container: str = "",
    priority: str = "",
    unit: str = "",
    boot: str = "",
    hide_own: str = "",
    level: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The Logs tab — journal by default, one allowed file when `path` is
    given, or one Docker container's `docker logs` when `source=docker`
    (the container picked from the latest monitoring sample's list,
    `Machine.docker_containers`; "@<project>" merges a Compose project's
    containers). A live SSH round trip on every load/filter change, same
    "gated behind `action.terminal`, not `machine.view`" reasoning
    `app.ssh.logs`'s module docstring lays out; see that module for the
    command-building and path-restriction logic itself. Audited (which
    machine, journal-vs-file, search term) the same way "Refresh packages
    now"/"Test connection" are — not the returned log content itself,
    which is never stored anywhere in this app."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    query = _log_query(
        machine,
        path=path,
        lines=lines,
        search=search,
        since=since,
        until=until,
        source=source,
        container=container,
        priority=priority,
        unit=unit,
        boot=boot,
        hide_own=hide_own,
        level=level,
    )
    source, container = query.source, query.container
    priority, unit, boot, hide_own_sessions = query.priority, query.unit, query.boot, query.hide_own
    docker_containers = machine.docker_containers or []

    found = _LogResult()
    if not machine.host_key_fingerprint:
        found.error = LocalizedText(request, "machine.confirm_key_first_overview")
    elif _fetches(query):
        found = await _fetch_logs(request, db, machine, query, max_lines=ssh_logs.MAX_LINE_LIMIT)
    output, journal_entries, hidden_count, error = (
        found.output,
        found.journal_entries,
        found.hidden_count,
        found.error,
    )

    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "machines/logs.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "logs",
            "csrf_token": csrf_token,
            "output": output,
            "log_lines": (
                journal_log_lines(journal_entries, search)
                if journal_entries is not None
                else parse_log_lines(output, search)
            ),
            "unit": unit,
            "boot": boot,
            "hide_own": hide_own_sessions,
            "hidden_count": hidden_count,
            "max_boot_offset": ssh_logs.MAX_BOOT_OFFSET,
            "error": error,
            "source": source,
            "container": container,
            "docker_containers": docker_containers,
            "docker_stacks": _stacks_of(machine),
            "stack_prefix": ssh_logs.STACK_PREFIX,
            "level": query.level,
            "levels": ssh_logs.LOG_LEVELS,
            "can_download": _fetches(query) and bool(machine.host_key_fingerprint),
            "download_lines": ssh_logs.MAX_DOWNLOAD_LINES,
            "path": path,
            "lines": lines,
            "search": search,
            "since": since,
            "until": until,
            "priority": priority,
            "priorities": ssh_logs.JOURNAL_PRIORITIES,
            "saved_log_views": await list_saved_log_views(db, current_user.id),
            "log_view_qs": build_log_query_string(
                {"source": source, "path": path, "container": container, "priority": priority,
                 "unit": unit, "boot": boot, "hide_own": "1" if hide_own_sessions else "",
                 "level": query.level,
                 "search": search, "since": since, "until": until,
                 "lines": str(lines) if lines != ssh_logs.DEFAULT_LINE_LIMIT else ""}
            ),
            "view_error": request.query_params.get("view_error"),
            "default_lines": ssh_logs.DEFAULT_LINE_LIMIT,
            "allowed_paths": get_settings().log_file_allowed_path_list,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


@router.get("/{machine_id}/logs/download", dependencies=[need_terminal])
async def machine_logs_download(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    path: str = "",
    search: str = "",
    since: str = "",
    until: str = "",
    source: str = "",
    container: str = "",
    priority: str = "",
    unit: str = "",
    boot: str = "",
    hide_own: str = "",
    level: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The Logs tab's current view as a plain-text file — the same filters,
    the last `MAX_DOWNLOAD_LINES` lines whatever the page shows. Audited
    like viewing them."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    query = _log_query(
        machine,
        path=path,
        lines=ssh_logs.MAX_DOWNLOAD_LINES,
        search=search,
        since=since,
        until=until,
        source=source,
        container=container,
        priority=priority,
        unit=unit,
        boot=boot,
        hide_own=hide_own,
        level=level,
    )
    if not machine.host_key_fingerprint or not _fetches(query):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nothing to download.")
    found = await _fetch_logs(
        request, db, machine, query, max_lines=ssh_logs.MAX_DOWNLOAD_LINES, download=True
    )
    if found.error is not None:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(found.error))
    if found.journal_entries is not None:
        text = "\n".join(str(e.get("text") or "") for e in found.journal_entries)
    else:
        text = found.output or ""
    what = (
        query.container.lstrip(ssh_logs.STACK_PREFIX)
        if query.source == "docker"
        else query.path.rsplit("/", 1)[-1]
        if query.source == "file"
        else "journal"
    )
    filename = _FILENAME_RE.sub("-", f"{machine.name}-{what}").strip("-")[:120] or "logs"
    return Response(
        content=text if text.endswith("\n") or not text else text + "\n",
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}.log"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.post("/{machine_id}/logs/views", dependencies=[need_terminal, Depends(verify_csrf)])
async def save_log_view(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    name: str = Form(""),
) -> Response:
    """"Save this view" on the Logs tab — only the Logs filters are kept
    (`app.services.saved_log_views`), not the machine, so the view can be
    replayed on any machine's Logs tab."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    form = await request.form()
    query_string = build_log_query_string(
        {key: str(form.get(key, "")) for key in ALLOWED_LOG_VIEW_PARAMS}
    )
    base = f"/machines/{machine.id}/logs?{query_string}"
    if not name.strip():
        return RedirectResponse(url=base, status_code=status.HTTP_303_SEE_OTHER)
    try:
        await create_saved_log_view(db, current_user.id, name, query_string)
    except DuplicateViewNameError:
        return RedirectResponse(
            url=f"{base}&view_error=duplicate_name", status_code=status.HTTP_303_SEE_OTHER
        )
    return RedirectResponse(url=base, status_code=status.HTTP_303_SEE_OTHER)


@router.post(
    "/{machine_id}/logs/views/{view_id}/delete",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def delete_log_view(
    machine_id: uuid.UUID,
    view_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    machine = await _get_machine_or_404(machine_id, db, current_user)
    await delete_saved_log_view(db, current_user.id, view_id)
    return RedirectResponse(
        url=f"/machines/{machine.id}/logs", status_code=status.HTTP_303_SEE_OTHER
    )


def _join_log_path(directory: str, name: str) -> str:
    return name if directory in ("", "/") else f"{directory.rstrip('/')}/{name}"


@router.get("/{machine_id}/logs/browse", dependencies=[need_terminal])
async def machine_logs_browse(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    path: str = "",
    current_user: User = Depends(get_current_user),
) -> Response:
    """The Logs tab's "browse" picker — lists what's directly inside an
    allowed directory so an operator can navigate to a file rather than
    already knowing its exact path. Starts at the first configured
    `LOG_FILE_ALLOWED_PATHS` prefix when no `path` is given. Same live SSH
    round trip / `action.terminal` gate as the rest of the Logs tab; see
    `app.ssh.logs`'s module docstring."""
    machine = await _get_machine_or_404(machine_id, db, current_user)
    app_settings = await get_or_create_app_settings(db)
    allowed_paths = get_settings().log_file_allowed_path_list
    current_path = path.strip() or (allowed_paths[0] if allowed_paths else "")

    entries: list[dict[str, object]] = []
    error: str | None = None
    if not machine.host_key_fingerprint:
        error = LocalizedText(request, "machine.confirm_key_first_overview")
    elif not current_path:
        error = LocalizedText(request, "machine.error.no_log_paths")
    else:
        try:
            async_result = tasks.browse_machine_log_directory.delay(
                str(machine.id), path=current_path
            )
            result = await asyncio.to_thread(
                async_result.get, timeout=app_settings.ssh_connect_timeout + 15
            )
            if isinstance(result, dict):
                if result.get("ok"):
                    raw_entries = result.get("entries") or []
                    entries = sorted(
                        (
                            {
                                "name": e["name"],
                                "is_dir": e["is_dir"],
                                "path": _join_log_path(current_path, e["name"]),
                            }
                            for e in raw_entries
                        ),
                        key=lambda e: (not e["is_dir"], str(e["name"]).lower()),
                    )
                else:
                    error = str(result.get("error") or "Unknown error.")
        except CeleryTimeoutError:
            error = LocalizedText(request, "common.error.command_timeout")
        except Exception as exc:
            error = str(exc)

    # Never offer a parent link above whichever allowed root contains
    # `current_path` — that would just error out server-side anyway (see
    # `app.ssh.logs.is_path_allowed`), but there's no reason to dangle a
    # link that can only fail.
    parent_path: str | None = None
    matched_root = next(
        (
            root
            for root in allowed_paths
            if current_path == root or current_path.startswith(f"{root}/")
        ),
        None,
    )
    if matched_root and current_path != matched_root:
        candidate = current_path.rstrip("/").rsplit("/", 1)[0] or "/"
        parent_path = candidate if len(candidate) >= len(matched_root) else matched_root

    if current_path:
        await log_event(
            db,
            request=request,
            action="machine.logs.browse",
            summary=f'Browsed "{current_path}" on "{machine.name}"',
            outcome=AuditOutcome.SUCCESS if error is None else AuditOutcome.FAILURE,
            target_type="machine",
            target_id=machine.id,
            target_label=machine.name,
        )

    return templates.TemplateResponse(
        request,
        "machines/logs_browse.html",
        {
            "machine": machine,
            "tabs": _machine_tabs(request, machine, current_user),
            "active_tab": "logs",
            "current_path": current_path,
            "parent_path": parent_path,
            "entries": entries,
            "error": error,
            "allowed_paths": allowed_paths,
        },
    )
