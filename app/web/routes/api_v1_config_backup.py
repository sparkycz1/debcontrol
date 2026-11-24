"""REST API for configuration backups of machines
(`app.services.config_backup`) — the same settings, runs, snapshots and
restores as Backup & restore -> *Machine configuration* and each
machine's *Backup* tab, under the same permissions and audit action codes.

- `GET /api/v1/config-backups/settings` (`settings.view`) — the
  repository (redacted), retention and the last maintenance. Never the
  password or environment.
- `PUT /api/v1/config-backups/settings` (`settings.manage`) — change them:
  `{"repository", "password", "environment", "keep_daily", "keep_weekly",
  "keep_monthly"}`, each optional; `"repository": ""` = the default local
  repository, `"environment": ""` = remove it. The first change must set a
  password. The repository is opened (and created when empty) before the
  change is kept.
- `POST /api/v1/config-backups/maintenance` (`settings.manage`) — run the
  retention (`forget --prune`) and check now.
- `GET /api/v1/config-backups` — every visible machine with its newest run.
- `POST /api/v1/config-backups/run` (`machine.manage`) — back up
  `{"machine_ids": [...]}` or `{"all": true}`.
- `GET /api/v1/machines/{id}/config-backups` — the machine's runs.
- `POST /api/v1/machines/{id}/config-backups` (`machine.manage`) — back it
  up now (409 when one is already waiting or running).
- `GET /api/v1/machines/{id}/config-backups/snapshots` — its snapshots.
- `GET .../snapshots/{snapshot}` — the files and the changes since the
  previous snapshot.
- `GET .../snapshots/{snapshot}/file?path=` (`action.terminal`) — one file.
- `GET .../snapshots/{snapshot}/archive` (`action.terminal`) — all of it
  as a tar archive.
- `POST .../snapshots/{snapshot}/restore` (`action.terminal`) —
  `{"path"}`: put the file in `~/debcontrol-restore/<snapshot>/` of the
  SSH account on the machine; returns where.
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.core.app_settings import get_or_create_app_settings
from app.db.models.config_backup import ConfigBackupRun
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services import config_backup
from app.services.access_scope import machines_visible_to
from app.web.routes.api_v1 import _get_machine_or_404

router = APIRouter(prefix="/api/v1")

_view = Depends(require_api_permission(Permission.MACHINE_VIEW))
_manage = Depends(require_api_permission(Permission.MACHINE_MANAGE))
_terminal = Depends(require_api_permission(Permission.ACTION_TERMINAL))
_settings_view = Depends(require_api_permission(Permission.SETTINGS_VIEW))
_settings_manage = Depends(require_api_permission(Permission.SETTINGS_MANAGE))

_NOT_FOUND_KEYS = ("config_backup.error.snapshot", "config_backup.error.path")


class SettingsBody(BaseModel):
    repository: str | None = Field(default=None, max_length=1024)
    password: str | None = Field(default=None, max_length=1024)
    environment: str | None = Field(default=None, max_length=8192)
    keep_daily: int | None = None
    keep_weekly: int | None = None
    keep_monthly: int | None = None


class RunBody(BaseModel):
    machine_ids: list[uuid.UUID] = Field(default_factory=list, max_length=5000)
    all: bool = False


class RestoreBody(BaseModel):
    path: str = Field(min_length=1, max_length=4096)


def _http(exc: config_backup.ConfigBackupError) -> HTTPException:
    code = (
        status.HTTP_404_NOT_FOUND
        if exc.key in _NOT_FOUND_KEYS
        else status.HTTP_409_CONFLICT
        if exc.key == "config_backup.error.not_configured"
        else status.HTTP_400_BAD_REQUEST
    )
    detail = exc.key.rsplit(".", 1)[-1]
    message = f"{detail}: {exc.detail}" if exc.detail else detail
    return HTTPException(status_code=code, detail=message)


def run_dict(run: ConfigBackupRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "machine_id": str(run.machine_id),
        "status": run.status,
        "snapshot_id": run.snapshot_id,
        "size_bytes": run.size_bytes,
        "file_count": run.file_count,
        "unreadable_count": run.unreadable_count,
        "added_bytes": run.added_bytes,
        "error": run.error,
        "started_by": run.started_by,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }


@router.get("/config-backups/settings", dependencies=[_settings_view])
async def get_config_backup_settings_api(db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    return config_backup.settings_view(await get_or_create_app_settings(db)).as_dict()


@router.put("/config-backups/settings", dependencies=[_settings_manage])
async def put_config_backup_settings_api(
    request: Request,
    body: SettingsBody,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    settings = await get_or_create_app_settings(db)
    if settings.config_backup_password_encrypted is None and not body.password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="password_required")
    change = config_backup.SettingsChange(**body.model_dump())
    try:
        changed = config_backup.apply_settings(settings, change)
        repo = config_backup.repository_of(settings)
        if repo is not None and ({"repository", "password", "environment"} & set(changed)):
            await config_backup.ensure_repository(repo)
    except config_backup.ConfigBackupError as exc:
        await db.rollback()
        raise _http(exc) from exc
    await db.commit()
    if changed:
        await log_event(
            db,
            request=request,
            action="config_backup.settings.update",
            summary="Changed the configuration backup repository settings",
            target_type="settings",
            target_label="config_backup",
            details={
                "changed": changed,
                "repository": settings.config_backup_repository_display
                or config_backup.default_location(),
            },
        )
    return config_backup.settings_view(settings).as_dict()


@router.post(
    "/config-backups/maintenance",
    dependencies=[_settings_manage],
    status_code=status.HTTP_202_ACCEPTED,
)
async def run_config_backup_maintenance_api(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    from app.tasks import config_backup as tasks

    tasks.config_backup_maintenance.delay()
    await log_event(
        db,
        request=request,
        action="config_backup.maintenance.run",
        summary="Started the configuration backup retention and check",
        target_type="settings",
        target_label="config_backup",
    )
    return {"queued": True}


async def _visible(db: AsyncSession, user: User) -> list[Machine]:
    query = await machines_visible_to(db, user)
    result = await db.execute(query.order_by(Machine.name))
    return list(result.scalars().all())


@router.get("/config-backups", dependencies=[_view])
async def list_config_backups_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    rows = await config_backup.fleet_rows(db, await _visible(db, user))
    return [
        {
            "machine_id": str(row.machine.id),
            "machine": row.machine.name,
            "status": row.machine.config_backup_status,
            "last_success_at": row.machine.config_backup_last_success_at.isoformat()
            if row.machine.config_backup_last_success_at
            else None,
            "last_run": run_dict(row.last_run) if row.last_run else None,
        }
        for row in rows
    ]


async def _queue(
    request: Request, db: AsyncSession, user: User, machines: list[Machine]
) -> dict[str, Any]:
    try:
        runs, skipped = await config_backup.queue_backups(db, machines, started_by=user.username)
    except config_backup.ConfigBackupError as exc:
        raise _http(exc) from exc
    if runs:
        single = machines[0] if len(machines) == 1 else None
        await log_event(
            db,
            request=request,
            action="config_backup.run",
            summary=(
                f'Started a configuration backup of "{single.name}"'
                if single
                else f"Started configuration backups of {len(runs)} machine(s)"
            ),
            target_type="machine",
            target_id=single.id if single else None,
            target_label=single.name if single else None,
            details={"machines": len(runs), "skipped": skipped},
        )
    return {"queued": [run_dict(run) for run in runs], "skipped": skipped}


@router.post(
    "/config-backups/run", dependencies=[_manage], status_code=status.HTTP_202_ACCEPTED
)
async def run_config_backups_api(
    request: Request,
    body: RunBody,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machines = await _visible(db, user)
    if not body.all:
        wanted = set(body.machine_ids)
        machines = [m for m in machines if m.id in wanted]
    if not machines:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="no_machines")
    return await _queue(request, db, user, machines)


@router.get("/machines/{machine_id}/config-backups", dependencies=[_view])
async def machine_config_backup_runs_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    machine = await _get_machine_or_404(machine_id, db, user)
    return [run_dict(run) for run in await config_backup.list_runs(db, machine.id)]


@router.post(
    "/machines/{machine_id}/config-backups",
    dependencies=[_manage],
    status_code=status.HTTP_202_ACCEPTED,
)
async def machine_config_backup_run_api(
    request: Request,
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine = await _get_machine_or_404(machine_id, db, user)
    result = await _queue(request, db, user, [machine])
    if not result["queued"]:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="not_queued")
    return dict(result["queued"][0])


@router.get("/machines/{machine_id}/config-backups/snapshots", dependencies=[_view])
async def machine_config_backup_snapshots_api(
    machine_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> list[dict[str, Any]]:
    machine = await _get_machine_or_404(machine_id, db, user)
    try:
        repo = await config_backup.current_repository(db)
        snaps = await config_backup.snapshots(repo, machine.id)
    except config_backup.ConfigBackupError as exc:
        raise _http(exc) from exc
    return [snap.as_dict() for snap in snaps]


async def _snapshot(
    db: AsyncSession, user: User, machine_id: uuid.UUID, snapshot_id: str
) -> tuple[Machine, config_backup.Repository, config_backup.Snapshot,
           config_backup.Snapshot | None]:
    machine = await _get_machine_or_404(machine_id, db, user)
    try:
        repo = await config_backup.current_repository(db)
        snapshot, previous = await config_backup.find_snapshot(repo, machine.id, snapshot_id)
    except config_backup.ConfigBackupError as exc:
        raise _http(exc) from exc
    return machine, repo, snapshot, previous


@router.get(
    "/machines/{machine_id}/config-backups/snapshots/{snapshot_id}", dependencies=[_view]
)
async def machine_config_backup_snapshot_api(
    machine_id: uuid.UUID,
    snapshot_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    _machine, repo, snapshot, previous = await _snapshot(db, user, machine_id, snapshot_id)
    try:
        entries = await config_backup.list_entries(repo, snapshot)
        changes = await config_backup.changes_since(repo, previous, snapshot) if previous else None
    except config_backup.ConfigBackupError as exc:
        raise _http(exc) from exc
    return {
        **snapshot.as_dict(),
        "previous_id": previous.id if previous else None,
        "changes": changes.as_dict() if changes else None,
        "entries": [entry.as_dict() for entry in entries],
    }


@router.get(
    "/machines/{machine_id}/config-backups/snapshots/{snapshot_id}/file",
    dependencies=[_terminal],
)
async def machine_config_backup_file_api(
    request: Request,
    machine_id: uuid.UUID,
    snapshot_id: str,
    path: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    machine, repo, snapshot, _previous = await _snapshot(db, user, machine_id, snapshot_id)
    try:
        content = await config_backup.read_file(repo, snapshot, path)
    except config_backup.ConfigBackupError as exc:
        raise _http(exc) from exc
    await log_event(
        db,
        request=request,
        action="config_backup.file.download",
        summary=f'Downloaded {path} from a configuration backup of "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"snapshot": snapshot.short_id, "path": path},
    )
    name = config_backup.safe_filename(path.rstrip("/").rsplit("/", 1)[-1])
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
            "Cache-Control": "no-store",
        },
    )


@router.get(
    "/machines/{machine_id}/config-backups/snapshots/{snapshot_id}/archive",
    dependencies=[_terminal],
)
async def machine_config_backup_archive_api(
    request: Request,
    machine_id: uuid.UUID,
    snapshot_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> Response:
    machine, repo, snapshot, _previous = await _snapshot(db, user, machine_id, snapshot_id)
    await log_event(
        db,
        request=request,
        action="config_backup.archive.download",
        summary=f'Downloaded a configuration backup of "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"snapshot": snapshot.short_id},
    )
    name = config_backup.archive_name(machine, snapshot)
    return StreamingResponse(
        config_backup.archive_stream(repo, snapshot),
        media_type="application/x-tar",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
            "Cache-Control": "no-store",
        },
    )


@router.post(
    "/machines/{machine_id}/config-backups/snapshots/{snapshot_id}/restore",
    dependencies=[_terminal],
)
async def machine_config_backup_restore_api(
    request: Request,
    machine_id: uuid.UUID,
    snapshot_id: str,
    body: RestoreBody,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    machine, repo, snapshot, _previous = await _snapshot(db, user, machine_id, snapshot_id)
    if not machine.host_key_fingerprint:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="host_key")
    try:
        written = await config_backup.restore_to_machine(db, machine, repo, snapshot, body.path)
    except config_backup.ConfigBackupError as exc:
        raise _http(exc) from exc
    await log_event(
        db,
        request=request,
        action="config_backup.file.restore",
        summary=f'Restored {body.path} from a configuration backup onto "{machine.name}"',
        target_type="machine",
        target_id=machine.id,
        target_label=machine.name,
        details={"snapshot": snapshot.short_id, "path": body.path, "written_to": written},
    )
    return {"path": body.path, "written_to": written}
