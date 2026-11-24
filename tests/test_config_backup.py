"""Configuration backups of machines (`app.services.config_backup`,
`app.ssh.config_backup`): what the machine runs, unpacking an untrusted
archive, the settings, a whole run with restic stubbed out (and with the
real binary when it is installed), retention, health, the scheduled
action, the pages and the REST API."""

from __future__ import annotations

import io
import json
import os
import shutil
import tarfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from httpx2 import AsyncClient
from sqlalchemy import select

from app.core.app_settings import get_or_create_app_settings
from app.db.models import config_backup as model
from app.db.models.config_backup import ConfigBackupRun
from app.db.models.machine import AuthMethod, Machine
from app.db.models.notification_rule import NotificationEventType
from app.db.models.role import Permission
from app.scheduling.actions import get_action
from app.scheduling.builtin_actions import register_builtin_actions
from app.services import config_backup, machine_health
from app.ssh import config_backup as remote
from app.ssh.onboarding import SUDO_COMMANDS
from tests.test_update_history import _api_token

# --- What the machine runs ---------------------------------------------------


def test_tar_runs_only_the_granted_command_line() -> None:
    for grant in remote.TAR_GRANTS:
        assert grant in SUDO_COMMANDS
        # sudoers would need these escaped; none may appear.
        assert not set(grant) & set("=,:\\")
    assert remote.TAR_ARGS.endswith("-C / etc var/spool/cron")
    assert f'sudo -n "$t" {remote.TAR_ARGS}' in remote.TAR_COMMAND
    playbook = Path(__file__).resolve().parent.parent / "ansible" / "debcontrol-onboard.yml"
    text = playbook.read_text(encoding="utf-8")
    assert all(grant in text for grant in remote.TAR_GRANTS)


def test_package_sections_and_unreadable_paths() -> None:
    raw = (
        "===DPKG_SELECTIONS===\nbash\t\t\t\tinstall\nvim\t\t\t\tinstall\n"
        "===APT_MANUAL===\nvim\n===CRONTAB===\n0 3 * * * /usr/local/bin/x\n"
        "===WHOAMI===\ndebcontrol\n"
    )
    sections = remote.split_sections(raw)
    assert sections["APT_MANUAL"] == "vim"
    assert sections["WHOAMI"] == "debcontrol"
    stderr = (
        "tar: etc/shadow: Cannot open: Permission denied\n"
        "tar: etc/ssl/private: Warning: Cannot open: Permission denied\n"
        "tar: var/spool/cron: Cannot stat: No such file or directory\n"
        "tar: Exiting with failure status due to previous errors\n"
        "tar: etc/shadow: Cannot open: Permission denied\n"
    )
    assert remote.unreadable_paths(stderr) == ["etc/shadow", "etc/ssl/private"]


def _tar(entries: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for info, data in entries:
            if data is not None:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            else:
                tar.addfile(info)
    return buffer.getvalue()


def _info(name: str, **values: Any) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    for key, value in values.items():
        setattr(info, key, value)
    return info


def test_unpack_refuses_what_could_escape(tmp_path: Path) -> None:
    archive = tmp_path / "a.tar"
    archive.write_bytes(
        _tar(
            [
                (_info("etc", type=tarfile.DIRTYPE, mode=0o755), None),
                (_info("etc/hostname", mode=0o644, uname="root", gname="root"), b"nas\n"),
                (_info("etc/shadow", mode=0o000, uname="root", gname="shadow"), b"root:x:1\n"),
                (_info("etc/sudo", mode=0o4755), b"suid"),
                (_info("/abs/evil", mode=0o644), b"x"),
                (_info("../evil", mode=0o644), b"x"),
                (_info("etc/out", type=tarfile.SYMTYPE, linkname="/etc/passwd"), None),
                (_info("etc/local", type=tarfile.SYMTYPE, linkname="hostname"), None),
                (_info("etc/dev", type=tarfile.CHRTYPE, devmajor=1, devminor=3), None),
                (_info("_debcontrol/planted", mode=0o644), b"x"),
            ]
        )
    )
    dest = tmp_path / "root"
    dest.mkdir()
    result = remote.unpack(archive, dest)
    assert (dest / "etc/hostname").read_text() == "nas\n"
    # Mode 000 on the machine, still readable for debcontrol's account.
    assert (dest / "etc/shadow").read_bytes() == b"root:x:1\n"
    assert not (dest / "etc/sudo").stat().st_mode & 0o4000
    assert not (tmp_path / "abs").exists() and not (tmp_path / "evil").exists()
    # A leading "/" is dropped: it lands inside the staging folder.
    assert (dest / "abs" / "evil").exists()
    assert not (dest / "etc/out").exists()
    assert (dest / "etc/local").is_symlink()
    assert not (dest / "etc/dev").exists()
    assert not (dest / "_debcontrol").exists()
    assert result.file_count == 4
    assert "-0644\t0\t0\t/abs/evil" in result.permissions
    assert "-0000\troot\tshadow\t/etc/shadow" in result.permissions

    remote.write_meta(
        dest,
        packages={"APT_MANUAL": "vim", "CRONTAB": "@daily x", "WHOAMI": "debcontrol"},
        unpacked=result,
        unreadable=["etc/ssl/private"],
    )
    meta = dest / "_debcontrol"
    assert (meta / "packages-apt-manual.txt").read_text() == "vim\n"
    assert (meta / "crontab-debcontrol.txt").exists()
    assert "/etc/shadow" in (meta / "permissions.tsv").read_text()
    assert (meta / "unreadable.txt").read_text() == "etc/ssl/private\n"
    assert (meta / "README.txt").exists()


def test_unpack_rejects_garbage_and_huge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = tmp_path / "a.tar"
    archive.write_bytes(b"not a tar at all" * 100)
    with pytest.raises(remote.ArchiveError):
        remote.unpack(archive, tmp_path)
    archive.write_bytes(_tar([(_info("etc/a"), b"12345")]))
    monkeypatch.setattr(remote, "MAX_ARCHIVE_BYTES", 10)
    with pytest.raises(remote.ArchiveError):
        remote.unpack(archive, tmp_path)


def test_member_paths_and_restore_command() -> None:
    assert remote.is_safe_member_path("/etc/ssh/sshd_config")
    for bad in ("etc/x", "/etc/../root", "/etc//x", "/etc/x\n", "/etc/./x"):
        assert not remote.is_safe_member_path(bad)
    command = remote.restore_command("debcontrol-restore/abcd1234/etc/it's")
    assert "'debcontrol-restore/abcd1234/etc/it'\"'\"'s'" in command
    assert "umask 077" in command


# --- Settings ----------------------------------------------------------------


async def test_settings_are_validated_and_encrypted(db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        settings = await get_or_create_app_settings(db)
        assert config_backup.repository_of(settings) is None
        with pytest.raises(config_backup.ConfigBackupError):
            config_backup.apply_settings(
                settings, config_backup.SettingsChange(repository="sftp:host:/x")
            )
        with pytest.raises(config_backup.ConfigBackupError):
            config_backup.apply_settings(
                settings,
                config_backup.SettingsChange(repository=str(config_backup._APP_ROOT / "app")),
            )
        with pytest.raises(config_backup.ConfigBackupError):
            config_backup.apply_settings(settings, config_backup.SettingsChange(password="short"))
        with pytest.raises(config_backup.ConfigBackupError):
            config_backup.apply_settings(
                settings,
                config_backup.SettingsChange(keep_daily=0, keep_weekly=0, keep_monthly=0),
            )
        with pytest.raises(config_backup.ConfigBackupError):
            config_backup.apply_settings(
                settings, config_backup.SettingsChange(environment="RESTIC_PASSWORD=x")
            )
        changed = config_backup.apply_settings(
            settings,
            config_backup.SettingsChange(
                repository="rest:https://user:secret@backup.example:8000/cfg",
                password="correct horse",
                environment="AWS_ACCESS_KEY_ID=abc",
                keep_daily=3,
            ),
        )
        assert changed == ["repository", "password", "environment", "keep_daily"]
        assert b"secret" not in (settings.config_backup_repository_encrypted or b"")
        assert settings.config_backup_repository_display == "rest:https://***@backup.example:8000/cfg"
        view = config_backup.settings_view(settings).as_dict()
        assert "secret" not in json.dumps(view) and view["has_environment"]
        repo = config_backup.repository_of(settings)
        assert repo is not None and repo.password == "correct horse"
        env = repo.environ()
        assert env["AWS_ACCESS_KEY_ID"] == "abc" and env["RESTIC_PASSWORD"] == "correct horse"
        # Back to the default local repository; environment removed.
        config_backup.apply_settings(
            settings, config_backup.SettingsChange(repository="", environment="")
        )
        repo = config_backup.repository_of(settings)
        assert repo is not None and repo.location == config_backup.default_location()
        assert repo.env == ()


# --- restic output -----------------------------------------------------------

SNAPSHOTS = json.dumps(
    [
        {"id": "a" * 64, "short_id": "aaaaaaaa", "time": "2026-11-23T03:00:00.1Z",
         "summary": {"total_files_processed": 900, "total_bytes_processed": 4096}},
        {"id": "b" * 64, "short_id": "bbbbbbbb", "time": "2026-11-24T03:00:00Z"},
        {"id": "not hex", "time": "2026-11-24T03:00:00Z"},
    ]
).encode()


def test_parse_restic_output() -> None:
    snaps = config_backup.parse_snapshots(SNAPSHOTS)
    assert [s.short_id for s in snaps] == ["bbbbbbbb", "aaaaaaaa"]
    assert snaps[1].files == 900
    ls = config_backup.ResticResult(
        0,
        b'{"time":"x","tree":"t","struct_type":"snapshot"}\n'
        b'{"name":"hosts","type":"file","path":"/etc/hosts","size":20,"permissions":"-rw-r--r--",'
        b'"mtime":"2026-11-24T03:00:00Z","struct_type":"node"}\n'
        b'{"name":"x","type":"file","path":"/etc/../x","struct_type":"node"}\n',
        "",
    )
    entries = config_backup.parse_ls(ls)
    assert [e.path for e in entries] == ["/etc/hosts"] and entries[0].size == 20
    diff = config_backup.ResticResult(
        0,
        b'{"message_type":"change","path":"/etc/new","modifier":"+"}\n'
        b'{"message_type":"change","path":"/etc/old","modifier":"-"}\n'
        b'{"message_type":"change","path":"/etc/hosts","modifier":"M"}\n'
        b'{"message_type":"change","path":"/etc/meta","modifier":"U"}\n'
        b'{"message_type":"change","path":"/_debcontrol/permissions.tsv","modifier":"M"}\n'
        b'{"message_type":"statistics"}\n',
        "",
    )
    changes = config_backup.parse_diff(diff)
    assert changes.added == ["/etc/new"] and changes.removed == ["/etc/old"]
    assert changes.modified == ["/etc/hosts"] and changes.total == 3


# --- A whole run -------------------------------------------------------------


async def _machine(db_session_factory: Any, name: str = "nas", **extra: Any) -> uuid.UUID:
    async with db_session_factory() as db:
        machine = Machine(
            name=name, ip_address=f"10.41.0.{uuid.uuid4().int % 250 + 1}", port=22,
            username="admin", auth_method=AuthMethod.SSH_KEY,
            **{"host_key_fingerprint": "SHA256:test", **extra},
        )
        db.add(machine)
        await db.commit()
        return machine.id


async def _configure(db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        settings = await get_or_create_app_settings(db)
        config_backup.apply_settings(
            settings, config_backup.SettingsChange(password="correct horse")
        )
        await db.commit()


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(config_backup, "data_dir", lambda: tmp_path)
    return tmp_path


async def test_queue_needs_a_repository_and_skips_busy_machines(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.tasks import config_backup as tasks

    queued: list[str] = []
    monkeypatch.setattr(tasks.run_config_backup, "delay", queued.append)
    machine_id = await _machine(db_session_factory)
    no_key = await _machine(db_session_factory, name="new", host_key_fingerprint=None)
    async with db_session_factory() as db:
        machines = list((await db.execute(select(Machine))).scalars().all())
        with pytest.raises(config_backup.ConfigBackupError):
            await config_backup.queue_backups(db, machines, started_by="admin")
    await _configure(db_session_factory)
    async with db_session_factory() as db:
        machines = list((await db.execute(select(Machine))).scalars().all())
        runs, skipped = await config_backup.queue_backups(db, machines, started_by="admin")
        assert [r.machine_id for r in runs] == [machine_id] and skipped == 1
        runs, skipped = await config_backup.queue_backups(db, machines, started_by="admin")
        assert runs == [] and skipped == 2
    assert len(queued) == 1 and no_key


async def _pending_run(db_session_factory: Any, machine_id: uuid.UUID) -> uuid.UUID:
    async with db_session_factory() as db:
        run = ConfigBackupRun(machine_id=machine_id, status=model.PENDING, started_by="admin")
        db.add(run)
        await db.commit()
        return run.id


def _fake_collect(unreadable: list[str]) -> Any:
    async def collect(
        machine: Any, secret: Any, connect_timeout: int, dest: Path, archive: Path
    ) -> config_backup.Collected:
        (dest / "etc").mkdir()
        (dest / "etc" / "hostname").write_text("nas\n")
        unpacked = remote.Unpacked(file_count=1, size_bytes=4, permissions=[])
        remote.write_meta(dest, packages={}, unpacked=unpacked, unreadable=unreadable)
        return config_backup.Collected(unpacked, unreadable)

    return collect


async def test_run_backup_stores_the_outcome(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch, data_dir: Path
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _machine(db_session_factory)
    await _configure(db_session_factory)
    run_id = await _pending_run(db_session_factory, machine_id)
    calls: list[tuple[str, ...]] = []

    async def fake_restic(repo: Any, *args: str, cwd: Path | None = None, **_: Any) -> Any:
        calls.append(args)
        if args[0] == "backup":
            assert cwd is not None and (cwd / "etc" / "hostname").exists()
            summary = {"message_type": "summary", "snapshot_id": "c" * 64, "data_added": 512}
            return config_backup.ResticResult(0, json.dumps(summary).encode(), "")
        return config_backup.ResticResult(0, b"", "")

    monkeypatch.setattr(config_backup, "_collect", _fake_collect(["etc/shadow"]))
    monkeypatch.setattr(config_backup, "run_restic", fake_restic)
    status = await config_backup.run_backup(run_id)
    assert status == model.PARTIAL
    assert list(calls[0][:2]) == ["cat", "config"]
    assert "--host" in calls[1] and str(machine_id) in calls[1] and config_backup.TAG in calls[1]
    async with db_session_factory() as db:
        run = await db.get(ConfigBackupRun, run_id)
        machine = await db.get(Machine, machine_id)
        assert run is not None and machine is not None
        assert run.snapshot_id == "c" * 64 and run.unreadable_count == 1
        assert run.added_bytes == 512 and run.finished_at is not None
        assert machine.config_backup_status == model.PARTIAL
        assert machine.config_backup_last_success_at is not None
    # The staging folder is gone.
    assert not any((data_dir / config_backup.STAGING_DIR).iterdir())


async def test_failed_backup_notifies(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch, data_dir: Path
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _machine(db_session_factory)
    await _configure(db_session_factory)
    run_id = await _pending_run(db_session_factory, machine_id)

    async def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise remote.ArchiveError("tar: not found")

    sent: list[tuple[NotificationEventType, dict[str, Any]]] = []

    async def fake_notify(_db: Any, event: NotificationEventType, **kwargs: Any) -> None:
        sent.append((event, kwargs["context"]))

    monkeypatch.setattr(config_backup, "_collect", broken)
    monkeypatch.setattr("app.services.notifications.notify", fake_notify)
    assert await config_backup.run_backup(run_id) == model.FAILED
    assert sent == [(NotificationEventType.CONFIG_BACKUP_FAILED, {"details": "tar: not found"})]
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None and machine.config_backup_status == model.FAILED
        assert machine.config_backup_last_success_at is None
        findings = machine_health.evaluate(machine, [], machine_health.Thresholds())
        assert any(f.key == "backups.config_failed" and f.tab == "backup" for f in findings)


def test_health_flags_an_old_backup() -> None:
    now = datetime.now(UTC)
    machine = Machine(
        id=uuid.uuid4(), name="nas", ip_address="10.0.0.9", port=22, username="admin",
        auth_method=AuthMethod.SSH_KEY, config_backup_status="succeeded",
        config_backup_last_success_at=now - timedelta(days=10),
    )
    findings = machine_health.evaluate(machine, [], machine_health.Thresholds(), now=now)
    stale = next(f for f in findings if f.key == "backups.config_stale")
    assert stale.params == {"days": 10}
    assert "{" not in machine_health.finding_text(stale, "cs")
    machine.config_backup_last_success_at = now
    machine.config_backup_status = None
    assert not [
        f for f in machine_health.evaluate(machine, [], machine_health.Thresholds(), now=now)
        if f.key.startswith("backups.config")
    ]


async def test_maintenance_forgets_by_host_and_fails_stale_runs(
    db_session_factory: Any, monkeypatch: pytest.MonkeyPatch, data_dir: Path
) -> None:
    machine_id = await _machine(db_session_factory)
    await _configure(db_session_factory)
    async with db_session_factory() as db:
        db.add(ConfigBackupRun(
            machine_id=machine_id, status=model.RUNNING,
            created_at=datetime.now(UTC) - timedelta(hours=5),
        ))
        await db.commit()
    calls: list[tuple[str, ...]] = []

    async def fake_restic(repo: Any, *args: str, **_: Any) -> Any:
        calls.append(args)
        return config_backup.ResticResult(0, SNAPSHOTS if args[0] == "snapshots" else b"", "")

    monkeypatch.setattr(config_backup, "run_restic", fake_restic)
    async with db_session_factory() as db:
        assert await config_backup.run_maintenance(db) is None
        settings = await get_or_create_app_settings(db)
        assert settings.config_backup_maintenance_at is not None
        run = (await db.execute(select(ConfigBackupRun))).scalar_one()
        assert run.status == model.FAILED
    forget = next(c for c in calls if c[0] == "forget")
    assert list(forget[3:5]) == ["--group-by", "host"]
    assert "--keep-daily" in forget and "--prune" in forget
    assert any(c[0] == "check" for c in calls)


def test_scheduled_action_is_registered() -> None:
    register_builtin_actions()
    spec = get_action("config_backup")
    assert spec is not None and not spec.destructive


# --- With the real restic (skipped where it isn't installed) ----------------


@pytest.mark.skipif(shutil.which("restic") is None, reason="restic is not installed")
async def test_real_restic_round_trip(data_dir: Path) -> None:
    repo = config_backup.Repository(str(data_dir / "repo"), "correct horse")
    await config_backup.ensure_repository(repo)
    await config_backup.ensure_repository(repo)  # already there: fine
    machine_id = uuid.uuid4()
    tree = data_dir / "tree"
    for content in ("one\n", "two\n"):
        (tree / "etc").mkdir(parents=True, exist_ok=True)
        (tree / "etc" / "hosts").write_text(content)
        result = await config_backup.run_restic(
            repo, "backup", ".", "--host", str(machine_id), "--tag", config_backup.TAG,
            "--json", cwd=tree,
        )
        assert result.ok, result.stderr
    snaps = await config_backup.snapshots(repo, machine_id)
    assert len(snaps) == 2
    newest, previous = await config_backup.find_snapshot(repo, machine_id, snaps[0].short_id)
    assert previous is not None
    assert "/etc/hosts" in [e.path for e in await config_backup.list_entries(repo, newest)]
    assert (await config_backup.changes_since(repo, previous, newest)).modified == ["/etc/hosts"]
    assert await config_backup.read_file(repo, newest, "/etc/hosts") == b"two\n"
    with pytest.raises(config_backup.ConfigBackupError):
        await config_backup.find_snapshot(repo, uuid.uuid4(), snaps[0].short_id)
    chunks = [c async for c in config_backup.archive_stream(repo, newest)]
    with tarfile.open(fileobj=io.BytesIO(b"".join(chunks))) as tar:
        assert any(m.name.endswith("etc/hosts") for m in tar.getmembers())


# --- Pages and the REST API ---------------------------------------------------


def _fake_repo(monkeypatch: pytest.MonkeyPatch) -> None:
    snaps = config_backup.parse_snapshots(SNAPSHOTS)

    async def snapshots(repo: Any, machine_id: Any) -> list[config_backup.Snapshot]:
        return snaps

    async def entries(repo: Any, snapshot: Any) -> list[config_backup.Entry]:
        return [config_backup.Entry("/etc/hosts", "file", 20, "-rw-r--r--", None),
                config_backup.Entry("/etc", "dir", None, "drwxr-xr-x", None)]

    async def changes(repo: Any, previous: Any, snapshot: Any) -> config_backup.Changes:
        return config_backup.Changes(modified=["/etc/hosts"])

    async def read(repo: Any, snapshot: Any, path: str) -> bytes:
        if path != "/etc/hosts":
            raise config_backup.ConfigBackupError("config_backup.error.path")
        return b"127.0.0.1 localhost\n"

    async def restore(db: Any, machine: Any, repo: Any, snapshot: Any, path: str) -> str:
        return f"/home/debcontrol/debcontrol-restore/{snapshot.short_id}{path}"

    monkeypatch.setattr(config_backup, "snapshots", snapshots)
    monkeypatch.setattr(config_backup, "list_entries", entries)
    monkeypatch.setattr(config_backup, "changes_since", changes)
    monkeypatch.setattr(config_backup, "read_file", read)
    monkeypatch.setattr(config_backup, "restore_to_machine", restore)


async def test_machine_tab_and_snapshot_pages(
    client: AsyncClient, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine_id = await _machine(db_session_factory)
    response = await client.get(f"/machines/{machine_id}/backup")
    assert response.status_code == 200
    assert "/backup/machines" in response.text and 'href="/machines/' in response.text
    await _configure(db_session_factory)
    _fake_repo(monkeypatch)
    response = await client.get(f"/machines/{machine_id}/backup/snapshots")
    assert "bbbbbbbb" in response.text
    response = await client.get(f"/machines/{machine_id}/backup/bbbbbbbb")
    assert response.status_code == 200
    assert 'id="config-backup-files"' in response.text and "/etc/hosts" in response.text
    assert 'id="config-backup-changes"' in response.text
    assert (await client.get(f"/machines/{machine_id}/backup/cccccccc")).status_code == 404
    response = await client.get(
        f"/machines/{machine_id}/backup/bbbbbbbb/file", params={"path": "/etc/hosts"}
    )
    assert response.status_code == 200 and response.content == b"127.0.0.1 localhost\n"
    assert "attachment" in response.headers["content-disposition"]
    response = await client.post(
        f"/machines/{machine_id}/backup/bbbbbbbb/restore",
        data={"path": "/etc/hosts", "csrf_token": client.cookies.get("csrftoken")},
    )
    assert response.status_code == 303 and "backup_notice" in response.headers["location"]


async def test_viewer_sees_but_cannot_take_files(
    client: AsyncClient, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch,
    login_as: Any,
) -> None:
    machine_id = await _machine(db_session_factory)
    await _configure(db_session_factory)
    _fake_repo(monkeypatch)
    await login_as(client, permissions={Permission.MACHINE_VIEW})
    response = await client.get(f"/machines/{machine_id}/backup/bbbbbbbb")
    assert response.status_code == 200 and "/file?path=" not in response.text
    response = await client.get(
        f"/machines/{machine_id}/backup/bbbbbbbb/file", params={"path": "/etc/hosts"}
    )
    assert response.status_code == 403
    await client.get(f"/machines/{machine_id}/backup")
    response = await client.post(
        f"/machines/{machine_id}/backup",
        data={"csrf_token": client.cookies.get("csrftoken")},
    )
    assert response.status_code == 403
    response = await client.get("/backup/machines")
    assert response.status_code == 200 and 'action="/backup/machines/settings"' not in response.text


async def test_fleet_page_settings_and_run(
    client: AsyncClient, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.tasks import config_backup as tasks

    machine_id = await _machine(db_session_factory)
    queued: list[str] = []
    monkeypatch.setattr(tasks.run_config_backup, "delay", queued.append)
    opened: list[str] = []

    async def ensure(repo: config_backup.Repository) -> None:
        opened.append(repo.location)

    monkeypatch.setattr(config_backup, "ensure_repository", ensure)
    response = await client.get("/backup/machines")
    assert response.status_code == 200 and 'id="config-backup-machines"' in response.text
    assert "/backup/machines" in (await client.get("/backup")).text
    csrf = client.cookies.get("csrftoken")
    response = await client.post(
        "/backup/machines/settings", data={"csrf_token": csrf, "repository": "/srv/x"}
    )
    assert "cb_error" in response.headers["location"]  # a password is needed first
    response = await client.post(
        "/backup/machines/settings",
        data={"csrf_token": csrf, "repository": "", "password": "correct horse",
              "keep_daily": "5", "keep_weekly": "", "keep_monthly": "6"},
    )
    assert "cb_notice" in response.headers["location"]
    assert opened == [config_backup.default_location()]
    response = await client.post(
        "/backup/machines/run", data={"csrf_token": csrf, "scope": "all"}
    )
    assert "cb_notice" in response.headers["location"] and len(queued) == 1
    async with db_session_factory() as db:
        settings = await get_or_create_app_settings(db)
        assert settings.config_backup_keep_daily == 5 and settings.config_backup_keep_monthly == 6
        assert settings.config_backup_keep_weekly == 4
        runs = list((await db.execute(select(ConfigBackupRun))).scalars().all())
        assert [r.machine_id for r in runs] == [machine_id]
        actions = [
            row[0] for row in (await db.execute(
                select(__import__("app.db.models.audit_log", fromlist=["AuditLogEntry"])
                       .AuditLogEntry.action)
            )).all()
        ]
        assert "config_backup.settings.update" in actions and "config_backup.run" in actions


async def test_api(
    client: AsyncClient, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.tasks import config_backup as tasks

    machine_id = await _machine(db_session_factory)
    headers = await _api_token(client)
    monkeypatch.setattr(tasks.run_config_backup, "delay", lambda _id: None)

    async def ensure(repo: config_backup.Repository) -> None:
        return None

    monkeypatch.setattr(config_backup, "ensure_repository", ensure)
    body = (await client.get("/api/v1/config-backups/settings", headers=headers)).json()
    assert body["configured"] is False
    response = await client.post(
        f"/api/v1/machines/{machine_id}/config-backups", headers=headers
    )
    assert response.status_code == 409
    response = await client.put(
        "/api/v1/config-backups/settings", headers=headers,
        json={"password": "correct horse", "environment": "B2_ACCOUNT_KEY=k"},
    )
    assert response.status_code == 200 and response.json()["has_environment"]
    assert "correct horse" not in response.text and "B2_ACCOUNT_KEY" not in response.text
    response = await client.post(
        f"/api/v1/machines/{machine_id}/config-backups", headers=headers
    )
    assert response.status_code == 202 and response.json()["status"] == "pending"
    response = await client.post(
        "/api/v1/config-backups/run", headers=headers, json={"all": True}
    )
    assert response.json() == {"queued": [], "skipped": 1}
    fleet = (await client.get("/api/v1/config-backups", headers=headers)).json()
    assert fleet[0]["last_run"]["status"] == "pending"
    runs = (await client.get(f"/api/v1/machines/{machine_id}/config-backups", headers=headers))
    assert len(runs.json()) == 1

    _fake_repo(monkeypatch)
    base = f"/api/v1/machines/{machine_id}/config-backups/snapshots"
    assert (await client.get(base, headers=headers)).json()[0]["short_id"] == "bbbbbbbb"
    snap = (await client.get(f"{base}/bbbbbbbb", headers=headers)).json()
    assert snap["changes"]["modified"] == ["/etc/hosts"] and snap["previous_id"] == "a" * 64
    assert (await client.get(f"{base}/dddddddd", headers=headers)).status_code == 404
    file = await client.get(f"{base}/bbbbbbbb/file", params={"path": "/etc/x"}, headers=headers)
    assert file.status_code == 404
    file = await client.get(
        f"{base}/bbbbbbbb/file", params={"path": "/etc/hosts"}, headers=headers
    )
    assert file.content == b"127.0.0.1 localhost\n"
    restored = await client.post(
        f"{base}/bbbbbbbb/restore", json={"path": "/etc/hosts"}, headers=headers
    )
    assert restored.json()["written_to"].endswith("/bbbbbbbb/etc/hosts")
    maintenance_calls: list[int] = []
    monkeypatch.setattr(
        tasks.config_backup_maintenance, "delay", lambda: maintenance_calls.append(1)
    )
    response = await client.post("/api/v1/config-backups/maintenance", headers=headers)
    assert response.status_code == 202 and maintenance_calls == [1]


def test_restic_env_keeps_only_what_restic_needs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy:3128")
    env = config_backup.Repository("/srv/r", "pw", ("X_TOKEN=1",)).environ()
    assert "DATABASE_URL" not in env and env["HTTPS_PROXY"] == "http://proxy:3128"
    assert env["X_TOKEN"] == "1" and env["RESTIC_REPOSITORY"] == "/srv/r"
    assert os.environ["DATABASE_URL"]  # untouched


# --- Over a real SSH connection (in-process server) -------------------------


class _Server:
    """Answers the package listing, the tar and the restore command the way
    a machine would; remembers what a restore wrote."""

    def __init__(self) -> None:
        self.written: dict[str, bytes] = {}
        self.archive = _tar([
            (_info("etc", type=tarfile.DIRTYPE, mode=0o755), None),
            (_info("etc/hostname", mode=0o644, uname="root", gname="root"), b"nas\n"),
            (_info("var/spool/cron/crontabs/root", mode=0o600), b"@daily /bin/true\n"),
        ])

    async def handle(self, process: Any) -> None:
        command = process.command or ""
        if "===DPKG_SELECTIONS===" in command:
            process.stdout.write(b"===APT_MANUAL===\nvim\n===WHOAMI===\ndebcontrol\n")
        elif "--ignore-failed-read" in command:
            for start in range(0, len(self.archive), 1000):
                process.stdout.write(self.archive[start:start + 1000])
            process.stderr.write(b"tar: etc/shadow: Warning: Cannot open: Permission denied\n")
        elif "debcontrol-restore" in command:
            self.written[command] = await process.stdin.read()
            process.stdout.write(b"/home/debcontrol\n")
        process.exit(0)


@pytest.fixture
async def fake_machine_ssh() -> Any:
    import asyncssh

    from app.ssh.client import FINGERPRINT_HASH

    class _Open(asyncssh.SSHServer):
        def begin_auth(self, username: str) -> bool:
            return False

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    handler = _Server()
    server = await asyncssh.create_server(
        _Open, host="127.0.0.1", port=0, server_host_keys=[host_key],
        process_factory=handler.handle, encoding=None,
    )
    machine = Machine(
        id=uuid.uuid4(), name="nas", ip_address="127.0.0.1",
        port=server.sockets[0].getsockname()[1], username="debcontrol",
        auth_method=AuthMethod.PASSWORD,
        host_key_fingerprint=host_key.get_fingerprint(FINGERPRINT_HASH),
    )
    try:
        yield machine, handler
    finally:
        server.close()
        await server.wait_closed()


async def test_collect_over_ssh(fake_machine_ssh: Any, tmp_path: Path) -> None:
    machine, _handler = fake_machine_ssh
    tree = tmp_path / "root"
    tree.mkdir()
    collected = await config_backup._collect(machine, "pw", 5, tree, tmp_path / "a.tar")
    assert (tree / "etc" / "hostname").read_text() == "nas\n"
    assert (tree / "var/spool/cron/crontabs/root").exists()
    assert collected.unreadable == ["etc/shadow"] and collected.unpacked.file_count == 2
    assert (tree / "_debcontrol" / "packages-apt-manual.txt").read_text() == "vim\n"


async def test_restore_over_ssh(
    fake_machine_ssh: Any, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    machine, handler = fake_machine_ssh
    snap = config_backup.parse_snapshots(SNAPSHOTS)[0]

    async def read(repo: Any, snapshot: Any, path: str) -> bytes:
        return b"secret file\n"

    async def credential(machine: Any, db: Any) -> str:
        return "pw"

    monkeypatch.setattr(config_backup, "read_file", read)
    monkeypatch.setattr(config_backup, "resolve_machine_credential", credential)
    repo = config_backup.Repository("/srv/r", "pw")
    async with db_session_factory() as db:
        written = await config_backup.restore_to_machine(db, machine, repo, snap, "/etc/hosts")
    assert written == "/home/debcontrol/debcontrol-restore/bbbbbbbb/etc/hosts"
    assert list(handler.written.values()) == [b"secret file\n"]
