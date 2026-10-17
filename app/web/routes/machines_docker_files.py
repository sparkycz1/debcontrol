"""The file browser of a container or a volume (`app.ssh.docker_files`):
browse, view and edit text files, download, upload, create folders and
delete. All of it needs `action.terminal` — it reads and writes inside
the container as root, which is what the container shell can do too —
and every change and download is in the audit log.

Text is edited up to `docker_files.MAX_EDIT_BYTES`; anything else is
downloaded (up to `MAX_DOWNLOAD_BYTES`). Uploads are capped at
`MAX_UPLOAD_BYTES`. A file keeps its owner and mode when it is saved.
"""

from __future__ import annotations

import base64
import posixpath
import uuid
from typing import Any
from urllib.parse import quote

from fastapi import Depends, File, Form, HTTPException, Request, Response, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_current_user
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import verify_csrf
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import Machine
from app.db.models.user import User
from app.db.session import get_db
from app.ssh import docker_files
from app.ssh.docker_cli import (
    DockerCommandError,
    is_container_name_valid,
    is_volume_name_valid,
)
from app.tasks import docker_jobs as docker_tasks
from app.web.messages import LocalizedText
from app.web.routes.machines_common import _get_machine_or_404, machines_router
from app.web.routes.machines_docker_common import (
    docker_base,
    need_terminal,
    redirect,
    render,
    wait_task,
)

router = machines_router()

_KINDS = {"containers": "container", "volumes": "volume"}
_FILE_WAIT_EXTRA = 330


def _target(kind: str, name: str) -> tuple[str, docker_files.Target]:
    target_kind = _KINDS.get(kind)
    valid = (
        is_container_name_valid(name) if target_kind == "container" else is_volume_name_valid(name)
    )
    if target_kind is None or not valid:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")
    return target_kind, docker_files.Target(target_kind, name)  # type: ignore[arg-type]


def _path(path: str) -> str:
    try:
        return docker_files.normalize_path(path or "/")
    except DockerCommandError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid path."
        ) from exc


def _files_url(machine: Machine, kind: str, name: str, path: str = "/", page: str = "") -> str:
    url = f"{docker_base(machine)}/{kind}/{quote(name, safe='')}/files"
    if page:
        url += f"/{page}"
    return f"{url}?path={quote(path, safe='/')}"


def _crumbs(path: str) -> list[tuple[str, str]]:
    crumbs = [("/", "/")]
    current = ""
    for part in [p for p in path.split("/") if p]:
        current += "/" + part
        crumbs.append((part, current))
    return crumbs


async def _run(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    op: str,
    target: docker_files.Target,
    path: str,
    **extra: str,
) -> tuple[dict[str, Any] | None, str | None]:
    app_settings = await get_or_create_app_settings(db)
    return await wait_task(
        request,
        docker_tasks.docker_files_task.delay(
            str(machine.id), op, target.kind, target.name, path, **extra
        ),
        app_settings.ssh_connect_timeout + _FILE_WAIT_EXTRA,
    )


async def _audit(
    db: AsyncSession,
    request: Request,
    machine: Machine,
    action: str,
    summary: str,
    details: dict[str, Any],
    *,
    ok: bool = True,
) -> None:
    await log_event(
        db,
        request=request,
        action=action,
        summary=summary,
        outcome=AuditOutcome.SUCCESS if ok else AuditOutcome.FAILURE,
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details=details,
    )


@router.get("/{machine_id}/docker/{kind}/{name}/files", dependencies=[need_terminal])
async def docker_files_page(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str = "/",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    _kind, target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, current_user)
    path = _path(path)
    result, error = await _run(request, db, machine, "list", target, path)
    return render(
        request,
        "machines/docker/files.html",
        machine,
        current_user,
        kind,
        {
            "kind": kind,
            "target": target,
            "path": path,
            "parent": posixpath.dirname(path) if path != "/" else None,
            "crumbs": _crumbs(path),
            "entries": (result or {}).get("entries") or [] if error is None else [],
            "error": error,
            "files_url": lambda p, page="": _files_url(machine, kind, name, p, page),
            "join": posixpath.join,
            "max_upload": docker_files.MAX_UPLOAD_BYTES,
        },
    )


@router.get("/{machine_id}/docker/{kind}/{name}/files/edit", dependencies=[need_terminal])
async def docker_file_edit(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    _kind, target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, current_user)
    path = _path(path)
    result, error = await _run(request, db, machine, "read", target, path)
    text: str | None = None
    binary = False
    if error is None and result is not None:
        content = base64.b64decode(str(result.get("data_b64") or ""))
        try:
            text = content.decode("utf-8")
            binary = "\0" in text
        except UnicodeDecodeError:
            binary = True
        if binary:
            text = None
    return render(
        request,
        "machines/docker/file_edit.html",
        machine,
        current_user,
        kind,
        {
            "kind": kind,
            "target": target,
            "path": path,
            "directory": posixpath.dirname(path),
            "crumbs": _crumbs(path),
            "text": text,
            "binary": binary,
            "info": result if error is None else None,
            "error": error,
            "files_url": lambda p, page="": _files_url(machine, kind, name, p, page),
        },
    )


@router.get("/{machine_id}/docker/{kind}/{name}/files/download", dependencies=[need_terminal])
async def docker_file_download(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    _kind, target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, current_user)
    path = _path(path)
    result, error = await _run(request, db, machine, "download", target, path)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.download",
        f'Downloaded {path} from {target.kind} "{name}" on "{machine.name}"',
        {"kind": target.kind, "name": name, "path": path, **({"error": error} if error else {})},
        ok=error is None,
    )
    if error is not None or result is None:
        return redirect(
            _files_url(machine, kind, name, posixpath.dirname(path)), error=error or "?"
        )
    content = base64.b64decode(str(result.get("data_b64") or ""))
    filename = posixpath.basename(path) or "download"
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename, safe='')}",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.post(
    "/{machine_id}/docker/{kind}/{name}/files/save",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def docker_file_save(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str = Form(...),
    content: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    _kind, target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, current_user)
    path = _path(path)
    data = content.replace("\r\n", "\n").encode()
    if len(data) > docker_files.MAX_EDIT_BYTES:
        return redirect(
            _files_url(machine, kind, name, path, "edit"),
            error=LocalizedText(request, "docker.files.too_large"),
        )
    _result, error = await _run(
        request,
        db,
        machine,
        "write",
        target,
        path,
        data_b64=base64.b64encode(data).decode(),
    )
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.write",
        f'Saved {path} in {target.kind} "{name}" on "{machine.name}"',
        {"kind": target.kind, "name": name, "path": path, "bytes": len(data)},
        ok=error is None,
    )
    return redirect(
        _files_url(machine, kind, name, path, "edit"),
        error=error,
        notice=None if error else LocalizedText(request, "docker.files.saved"),
    )


@router.post(
    "/{machine_id}/docker/{kind}/{name}/files/upload",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def docker_file_upload(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str = Form(...),
    upload: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    _kind, target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, current_user)
    directory = _path(path)
    back = _files_url(machine, kind, name, directory)
    filename = posixpath.basename((upload.filename or "").replace("\\", "/"))
    if not filename or filename in (".", "..") or any(c in filename for c in "\0\n\r"):
        return redirect(back, error=LocalizedText(request, "docker.files.bad_name"))
    data = await upload.read(docker_files.MAX_UPLOAD_BYTES + 1)
    if len(data) > docker_files.MAX_UPLOAD_BYTES:
        return redirect(back, error=LocalizedText(request, "docker.files.too_large"))
    target_path = posixpath.join(directory, filename)
    _result, error = await _run(
        request,
        db,
        machine,
        "write",
        target,
        target_path,
        data_b64=base64.b64encode(data).decode(),
    )
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.write",
        f'Uploaded {target_path} to {target.kind} "{name}" on "{machine.name}"',
        {"kind": target.kind, "name": name, "path": target_path, "bytes": len(data)},
        ok=error is None,
    )
    return redirect(
        back, error=error, notice=None if error else LocalizedText(request, "docker.files.uploaded")
    )


@router.post(
    "/{machine_id}/docker/{kind}/{name}/files/mkdir",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def docker_file_mkdir(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str = Form(...),
    folder: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    _kind, target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, current_user)
    directory = _path(path)
    back = _files_url(machine, kind, name, directory)
    folder = folder.strip()
    if not folder or "/" in folder or folder in (".", "..") or any(c in folder for c in "\0\n\r"):
        return redirect(back, error=LocalizedText(request, "docker.files.bad_name"))
    new_path = posixpath.join(directory, folder)
    _result, error = await _run(request, db, machine, "mkdir", target, new_path)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.mkdir",
        f'Created folder {new_path} in {target.kind} "{name}" on "{machine.name}"',
        {"kind": target.kind, "name": name, "path": new_path},
        ok=error is None,
    )
    return redirect(back, error=error)


@router.post(
    "/{machine_id}/docker/{kind}/{name}/files/delete",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def docker_file_delete(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    _kind, target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, current_user)
    path = _path(path)
    back = _files_url(machine, kind, name, posixpath.dirname(path))
    if path == "/":
        return redirect(back, error=LocalizedText(request, "docker.files.bad_name"))
    _result, error = await _run(request, db, machine, "delete", target, path)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.delete",
        f'Deleted {path} in {target.kind} "{name}" on "{machine.name}"',
        {"kind": target.kind, "name": name, "path": path},
        ok=error is None,
    )
    return redirect(back, error=error)
