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
            "max_upload_files": docker_files.MAX_UPLOAD_FILES,
            "max_download": docker_files.MAX_DOWNLOAD_BYTES,
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
    return _render_edit(request, machine, current_user, kind, target, path, result, error)


def _as_text(result: dict[str, Any] | None) -> str | None:
    """The file `_run(..., "read")` returned, as text; None for a binary
    file (not UTF-8, or with a NUL in it)."""
    content = base64.b64decode(str((result or {}).get("data_b64") or ""))
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None if "\0" in text else text


def _render_edit(
    request: Request,
    machine: Machine,
    current_user: User,
    kind: str,
    target: docker_files.Target,
    path: str,
    result: dict[str, Any] | None,
    error: str | None,
    *,
    edited: str | None = None,
    opened_sha256: str | None = None,
    diff: docker_files.TextDiff | None = None,
    conflict: bool = False,
) -> Response:
    """The editor. `edited` is text the user is still working on (shown
    instead of the file); `opened_sha256` the version they opened, which
    a save is checked against; `diff` the changes against the file on the
    machine now; `conflict` that the file changed there since it was
    opened."""
    text: str | None = None
    binary = False
    if error is None and result is not None:
        text = _as_text(result)
        binary = text is None
    if edited is not None and not binary:
        text = edited
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
            "sha256": opened_sha256 or (result or {}).get("sha256") or "",
            "diff": diff,
            "conflict": conflict,
            # Text the user is still editing stays on the page even when
            # the file can't be read back now.
            "kept": edited is not None and not binary,
            "files_url": lambda p, page="": _files_url(machine, kind, target.name, p, page),
        },
    )


async def _compare(
    request: Request,
    db: AsyncSession,
    machine: Machine,
    target: docker_files.Target,
    path: str,
    edited: str,
    opened_sha256: str,
) -> tuple[dict[str, Any] | None, str | None, docker_files.TextDiff | None, bool]:
    """Read the file as it is on the machine now and compare it with the
    edited text: (read result, error, diff, changed since opened)."""
    result, error = await _run(request, db, machine, "read", target, path)
    if error is not None or result is None:
        return result, error, None, False
    current = _as_text(result)
    if current is None:
        return result, None, None, False
    diff = docker_files.text_diff(current, edited, path)
    conflict = bool(opened_sha256) and result.get("sha256") != opened_sha256
    return result, None, diff, conflict


@router.post(
    "/{machine_id}/docker/{kind}/{name}/files/diff",
    dependencies=[need_terminal, Depends(verify_csrf)],
)
async def docker_file_diff(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str = Form(...),
    content: str = Form(""),
    sha256: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Show changes": what saving the edited text would change in the
    file as it is on the machine now. Changes nothing."""
    _kind, target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, current_user)
    path = _path(path)
    edited = content.replace("\r\n", "\n")
    if len(edited.encode()) > docker_files.MAX_EDIT_BYTES:
        return redirect(
            _files_url(machine, kind, name, path, "edit"),
            error=LocalizedText(request, "docker.files.too_large"),
        )
    result, error, diff, conflict = await _compare(
        request, db, machine, target, path, edited, _sha(sha256)
    )
    return _render_edit(
        request, machine, current_user, kind, target, path, result, error,
        edited=edited, opened_sha256=_sha(sha256), diff=diff, conflict=conflict,
    )


def _sha(value: str) -> str:
    """A SHA-256 hex digest from a form, or "" (none given, or not one)."""
    value = value.strip().lower()
    return value if len(value) == 64 and all(c in "0123456789abcdef" for c in value) else ""


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
    sha256: str = Form(""),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Save from the editor. With `sha256` (the version the editor opened)
    nothing is written when the file changed on the machine meanwhile: the
    editor comes back with the text kept and the changes shown."""
    _kind, target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, current_user)
    path = _path(path)
    edited = content.replace("\r\n", "\n")
    data = edited.encode()
    if len(data) > docker_files.MAX_EDIT_BYTES:
        return redirect(
            _files_url(machine, kind, name, path, "edit"),
            error=LocalizedText(request, "docker.files.too_large"),
        )
    opened = _sha(sha256)
    _result, error = await _run(
        request,
        db,
        machine,
        "write",
        target,
        path,
        data_b64=base64.b64encode(data).decode(),
        **({"expect_sha256": opened} if opened else {}),
    )
    conflict = error == "changed"
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.write",
        f'Saved {path} in {target.kind} "{name}" on "{machine.name}"'
        if not conflict
        else f'Did not save {path} in {target.kind} "{name}" on "{machine.name}": '
        "it changed on the machine since it was opened",
        {
            "kind": target.kind,
            "name": name,
            "path": path,
            "bytes": len(data),
            **({"conflict": True} if conflict else {}),
        },
        ok=error is None,
    )
    if conflict:
        result, read_error, diff, _changed = await _compare(
            request, db, machine, target, path, edited, opened
        )
        return _render_edit(
            request, machine, current_user, kind, target, path, result, read_error,
            edited=edited, opened_sha256=(result or {}).get("sha256") or "", diff=diff,
            conflict=True,
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
    upload: list[UploadFile] = File(default_factory=list),
    folder_upload: list[UploadFile] = File(default_factory=list),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Upload one file, several (`upload`: each under its own name), or a
    folder (`folder_upload`: the browser sends each file of it with its
    path inside the folder). One file replacing an existing one keeps its
    owner and mode; several go in one tar stream, new ones owned by
    root."""
    _kind, target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, current_user)
    directory = _path(path)
    back = _files_url(machine, kind, name, directory)
    uploads = [(u, False) for u in upload if u.filename] + [
        (u, True) for u in folder_upload if u.filename
    ]
    if not uploads:
        return redirect(back, error=LocalizedText(request, "docker.files.nothing_chosen"))
    if len(uploads) > docker_files.MAX_UPLOAD_FILES:
        return redirect(
            back,
            error=LocalizedText(
                request, "docker.files.too_many", count=docker_files.MAX_UPLOAD_FILES
            ),
        )
    files: list[tuple[str, bytes]] = []
    total = 0
    for item, in_folder in uploads:
        raw_name = (item.filename or "").replace("\\", "/")
        if not in_folder:
            # A single file goes under its own name, wherever the browser
            # says it came from.
            raw_name = posixpath.basename(raw_name)
        try:
            relative = docker_files.relative_upload_path(raw_name)
        except DockerCommandError:
            return redirect(back, error=LocalizedText(request, "docker.files.bad_name"))
        data = await item.read(docker_files.MAX_UPLOAD_BYTES - total + 1)
        total += len(data)
        if total > docker_files.MAX_UPLOAD_BYTES:
            return redirect(back, error=LocalizedText(request, "docker.files.too_large"))
        files.append((relative, data))
    if len(files) == 1 and "/" not in files[0][0]:
        target_path = posixpath.join(directory, files[0][0])
        _result, error = await _run(
            request,
            db,
            machine,
            "write",
            target,
            target_path,
            data_b64=base64.b64encode(files[0][1]).decode(),
        )
        summary = f'Uploaded {target_path} to {target.kind} "{name}" on "{machine.name}"'
        details: dict[str, Any] = {"path": target_path}
    else:
        try:
            tar = docker_files.build_upload_tar(files)
        except DockerCommandError:
            return redirect(back, error=LocalizedText(request, "docker.files.bad_name"))
        _result, error = await _run(
            request, db, machine, "unpack", target, directory,
            data_b64=base64.b64encode(tar).decode(),
        )
        summary = (
            f'Uploaded {len(files)} files to {directory} in {target.kind} "{name}" '
            f'on "{machine.name}"'
        )
        details = {
            "path": directory,
            "files": len(files),
            "names": [relative for relative, _data in files[:50]],
        }
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.write",
        summary,
        {"kind": target.kind, "name": name, **details, "bytes": total},
        ok=error is None,
    )
    return redirect(
        back,
        error=error,
        notice=None
        if error
        else LocalizedText(request, "docker.files.uploaded_many", count=len(files))
        if len(files) > 1
        else LocalizedText(request, "docker.files.uploaded"),
    )


@router.get("/{machine_id}/docker/{kind}/{name}/files/archive", dependencies=[need_terminal])
async def docker_folder_download(
    request: Request,
    machine_id: uuid.UUID,
    kind: str,
    name: str,
    path: str = "/",
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """A folder with everything in it, as a .tar.gz (owners and modes
    kept), up to `MAX_DOWNLOAD_BYTES` before compression."""
    _kind, target = _target(kind, name)
    machine = await _get_machine_or_404(machine_id, db, current_user)
    path = _path(path)
    result, error = await _run(request, db, machine, "archive", target, path)
    await _audit(
        db,
        request,
        machine,
        "machine.docker.file.download",
        f'Downloaded folder {path} from {target.kind} "{name}" on "{machine.name}"',
        {
            "kind": target.kind,
            "name": name,
            "path": path,
            "archive": True,
            **({"error": error} if error else {}),
        },
        ok=error is None,
    )
    if error is not None or result is None:
        message: str | LocalizedText = error or "?"
        if error == "too_large":
            message = LocalizedText(
                request,
                "docker.files.folder_too_large",
                size=f"{docker_files.MAX_DOWNLOAD_BYTES // (1024 * 1024)} MiB",
            )
        return redirect(_files_url(machine, kind, name, path), error=message)
    filename = docker_files.archive_filename(target, path)
    return Response(
        content=base64.b64decode(str(result.get("data_b64") or "")),
        media_type="application/gzip",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename, safe='')}",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
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
