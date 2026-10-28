"""Docker upgrade #4: cancelling a Docker job (`docker_jobs.request_cancel`,
`detached_jobs.build_stop_command` / `follow`), backup commands before and
after a backup and the test restore (`app.ssh.restic`), the Logs tab's
level filter, download and merged stack logs (`app.ssh.logs`), and the
file editor's changes view, conflict check, folder upload and folder
download (`app.ssh.docker_files`).

As everywhere else, the underscore-prefixed coroutines are called
directly, never the Celery wrappers."""

from __future__ import annotations

import base64
import gzip
import io
import json
import tarfile
from datetime import UTC, datetime
from typing import Any

import pytest

from app.db.models.docker import DockerBackup, DockerJob, DockerJobKind, DockerJobStatus
from app.db.models.role import Permission
from app.ssh import detached_jobs, docker_files, restic
from app.ssh import logs as ssh_logs
from app.ssh.detached_updates import FollowResult
from app.ssh.docker_cli import DockerCommandError
from app.tasks import docker_jobs as tasks
from tests.test_docker_tasks_jobs import (
    FakeMachine,
    _add,
    _backup,
    _get,
    _job,
    _machine,
    install_fake_machine,
)
from tests.test_docker_web_support import (
    FILES_TASK,
    RUN_JOB_TASK,
    add_job,
    audit_entries,
    csrf_token,
    get_row,
    make_docker_machine,
)
from tests.test_update_history import _api_token

JOB_ID = "0b0e9d6a-3f51-4c55-9a51-3d5a8f0e2c11"


@pytest.fixture
def machine_shell(monkeypatch: pytest.MonkeyPatch, db_session_factory: Any) -> FakeMachine:
    return install_fake_machine(monkeypatch, db_session_factory)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# --- Cancelling a job: the machine side ---------------------------------------------


def test_a_job_runs_in_its_own_process_group_and_stop_signals_that_group() -> None:
    start = detached_jobs.build_start_command("docker", JOB_ID)
    stop = detached_jobs.build_stop_command("docker", JOB_ID)

    assert 'echo $! > "$1.cpid"' in start
    assert "dc_detach=setsid" in start
    assert 'kill -TERM "-$p"' in stop
    # Never a pid that isn't a number.
    assert 'case "$p" in ""|*[!0-9]*) exit 0;; esac' in stop
    assert '"$f.cpid"' in detached_jobs.build_cleanup_command("docker", JOB_ID)


def test_stop_refuses_a_bad_job_id() -> None:
    with pytest.raises(ValueError):
        detached_jobs.build_stop_command("docker", "x; rm -rf /")


class _FakeConn:
    def __init__(self, states: list[str]) -> None:
        self.states = states
        self.commands: list[str] = []

    async def __aenter__(self) -> _FakeConn:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        return None

    async def run(self, command: str, **_kwargs: Any) -> Any:
        self.commands.append(command)

        class _Result:
            stdout: bytes = b""

        result = _Result()
        if "DC_JOB_STATE" in command:
            state = self.states.pop(0) if self.states else "finished 143"
            result.stdout = f"DC_JOB_STATE {state}\nline\n".encode()
        return result


async def test_follow_signals_the_job_once_when_asked_and_reads_it_to_the_end(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _FakeConn(["running", "running", "finished 143"])

    async def fake_open(*_args: Any) -> _FakeConn:
        return conn

    asked: list[int] = []

    async def stop_requested() -> bool:
        asked.append(1)
        return True

    monkeypatch.setattr(detached_jobs, "open_connection", fake_open)

    result = await detached_jobs.follow(
        object(),  # type: ignore[arg-type]
        None,
        "docker",
        JOB_ID,
        5,
        60,
        stop_requested=stop_requested,
        poll_seconds=0,
    )

    stops = [c for c in conn.commands if "kill -TERM" in c]
    assert (result.state, result.exit_status, result.stopped) == ("finished", 143, True)
    assert len(stops) == 1
    assert len(asked) == 1


# --- Cancelling a job: the service, the worker, the routes -------------------------


async def test_a_waiting_job_is_cancelled_at_once(db_session_factory: Any) -> None:
    from app.services import docker_jobs

    machine = _machine()
    job = _job(machine, DockerJobKind.CONTAINER_UPDATE, "web")
    await _add(db_session_factory, machine, job)

    async with db_session_factory() as db:
        row = await db.get(DockerJob, job.id)
        outcome = await docker_jobs.request_cancel(db, row, "alice")

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert outcome == "cancelled"
    assert stored.status == DockerJobStatus.CANCELLED
    assert stored.cancel_requested_by == "alice"
    assert stored.finished_at is not None


async def test_a_running_deploy_cant_be_stopped_but_a_running_scan_can(
    db_session_factory: Any,
) -> None:
    from app.services import docker_jobs

    machine = _machine()
    deploy = _job(machine, DockerJobKind.STACK_DEPLOY, "shop", status=DockerJobStatus.RUNNING)
    scan = _job(machine, DockerJobKind.IMAGE_SCAN, "nginx", status=DockerJobStatus.RUNNING)
    update = _job(
        machine,
        DockerJobKind.CONTAINER_UPDATE,
        "web",
        status=DockerJobStatus.RUNNING,
        result={"phase": "recreate"},
    )
    await _add(db_session_factory, machine, deploy, scan, update)

    async with db_session_factory() as db:
        outcomes = [
            await docker_jobs.request_cancel(db, await db.get(DockerJob, j.id), "alice")
            for j in (deploy, scan, update)
        ]
        again = await docker_jobs.request_cancel(db, await db.get(DockerJob, scan.id), "bob")

    stored_scan = await _get(db_session_factory, DockerJob, scan.id)
    assert outcomes == [None, "requested", None]
    assert again is None  # asked once
    assert stored_scan.status == DockerJobStatus.RUNNING
    assert stored_scan.cancel_requested_by == "alice"


def test_cancelling_needs_the_permission_that_starts_the_job() -> None:
    from app.services import docker_jobs

    assert docker_jobs.cancel_permission(DockerJobKind.STACK_ACTION) == Permission.ACTION_POWER
    assert docker_jobs.cancel_permission(DockerJobKind.STACK_DEPLOY) == Permission.ACTION_TERMINAL
    assert docker_jobs.cancel_permission(DockerJobKind.PRUNE) == Permission.ACTION_UPDATES
    # Starting a restore needs action.terminal, so does stopping one.
    assert (
        docker_jobs.cancel_permission(DockerJobKind.BACKUP_RESTORE) == Permission.ACTION_TERMINAL
    )


async def test_a_job_asked_to_stop_before_its_phase_starts_runs_nothing(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    backup = _backup(machine)
    job = _job(
        machine,
        DockerJobKind.BACKUP_RUN,
        "nightly",
        ref_id=backup.id,
        cancel_requested_by="alice",
        cancel_requested_at=datetime.now(UTC),
    )
    await _add(db_session_factory, machine, backup, job)

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.CANCELLED
    assert "alice" in (stored.error or "")
    assert machine_shell.started == []


async def test_a_stopped_job_is_recorded_as_cancelled(
    monkeypatch: pytest.MonkeyPatch, db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    backup = _backup(machine)
    job = _job(machine, DockerJobKind.BACKUP_RUN, "nightly", ref_id=backup.id)
    await _add(db_session_factory, machine, backup, job)
    seen: dict[str, Any] = {}

    async def fake_follow(*_args: Any, **kwargs: Any) -> FollowResult:
        seen.update(kwargs)
        return FollowResult("finished", 143, "@@DC_STEP backup\n", stopped=True)

    monkeypatch.setattr(detached_jobs, "follow", fake_follow)

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerJob, job.id)
    assert stored.status == DockerJobStatus.CANCELLED
    assert seen["stop_requested"] is not None
    # Every job script turns SIGTERM into a plain exit, so its cleanup runs.
    assert machine_shell.started[0][1].startswith("trap 'exit 143' TERM HUP")


async def test_cancel_route_cancels_a_waiting_job_and_audits_it(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    job_id = await add_job(db_session_factory, machine_id, status=DockerJobStatus.PENDING)
    waiting = await add_job(db_session_factory, machine_id, status=DockerJobStatus.PENDING)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/jobs/{job_id}/cancel", data={"csrf_token": csrf}
    )

    stored = await get_row(db_session_factory, DockerJob, job_id)
    assert response.status_code == 303
    assert stored is not None and stored.status == DockerJobStatus.CANCELLED
    # The next waiting job gets its turn.
    assert (RUN_JOB_TASK, (str(waiting),), {}) in list(celery_calls)
    [entry] = await audit_entries(db_session_factory, "machine.docker.job.cancel")
    assert (entry.details or {})["was"] == "cancelled"


async def test_cancel_route_needs_csrf_and_the_right_permission(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    job_id = await add_job(db_session_factory, machine_id, status=DockerJobStatus.PENDING)
    url = f"/machines/{machine_id}/docker/jobs/{job_id}/cancel"

    no_csrf = await client.post(url, data={})
    csrf = await csrf_token(client, machine_id)
    await login_as(client, permissions={Permission.MACHINE_VIEW, Permission.ACTION_POWER})
    wrong = await client.post(url, data={"csrf_token": csrf})

    stored = await get_row(db_session_factory, DockerJob, job_id)
    assert no_csrf.status_code == 403
    assert wrong.status_code == 403
    assert stored is not None and stored.status == DockerJobStatus.PENDING


async def test_api_cancel_answers_409_for_a_finished_job(
    client: Any, db_session_factory: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    done = await add_job(db_session_factory, machine_id)
    waiting = await add_job(db_session_factory, machine_id, status=DockerJobStatus.PENDING)
    headers = await _api_token(client)
    base = f"/api/v1/machines/{machine_id}/docker/jobs"

    finished = await client.post(f"{base}/{done}/cancel", headers=headers)
    cancelled = await client.post(f"{base}/{waiting}/cancel", headers=headers)

    assert finished.status_code == 409
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["outcome"] == "cancelled"
    assert cancelled.json()["job"]["status"] == "cancelled"


# --- Backups: commands before and after, test restore ------------------------------


def _config(**overrides: Any) -> restic.ResticConfig:
    values: dict[str, Any] = {
        "backup_id": "1234abcd-0000-0000-0000-000000000000",
        "host": "docker1",
        "repository": "/srv/backup",
        "password": "pw",
        "volumes": ["shop_data"],
        "paths": [],
        "excludes": [],
    }
    values.update(overrides)
    return restic.ResticConfig(**values)


def test_backup_hooks_run_in_the_container_around_the_backup() -> None:
    hooks = restic.BackupHooks("shop-db-1", "pg_dump -f /dump.sql app", "rm -f /dump.sql")

    script = restic.build_backup_script(
        _config(), stop_containers=False, keep={}, hooks=hooks
    )

    pre = script.index("pg_dump")
    assert script.index("@@DC_STEP init") < pre < script.index("R backup /backup")
    assert "$D exec shop-db-1 sh -c 'pg_dump -f /dump.sql app'" in script
    assert "@@DC_FAILED pre" in script
    # The post command also runs from the cleanup when the backup fails.
    assert "@@DC_HOOK_FAILED post" in script


@pytest.mark.parametrize(
    "hooks",
    [
        restic.BackupHooks("", "true", ""),
        restic.BackupHooks("bad name;", "true", ""),
        restic.BackupHooks("db", "x" * (restic.MAX_HOOK_CHARS + 1), ""),
    ],
)
def test_backup_hooks_are_validated(hooks: restic.BackupHooks) -> None:
    with pytest.raises(DockerCommandError):
        restic.build_backup_script(_config(), stop_containers=False, keep={}, hooks=hooks)


def test_the_test_restore_uses_a_temporary_volume_it_always_removes() -> None:
    script = restic.build_verify_script(_config())
    volume = restic.verify_volume(_config())

    assert volume == "debcontrol-verify-1234abcd"
    assert "restore latest" in script
    assert "--verify" in script
    assert script.count(f"volume rm -f {volume}") >= 2  # before, and in the cleanup
    with pytest.raises(DockerCommandError):
        restic.build_verify_script(_config(), "latest; rm -rf /")


def test_parse_verify_output() -> None:
    ok = json.dumps(
        {
            "message_type": "summary",
            "total_files": 10,
            "files_restored": 10,
            "total_bytes": 100,
            "bytes_restored": 100,
        }
    )
    short = json.dumps({"message_type": "summary", "total_files": 10, "files_restored": 9})
    error = json.dumps({"message_type": "error", "error": {"message": "bad"}})

    assert restic.parse_verify_output("noise\n" + ok).complete
    assert not restic.parse_verify_output(short).complete
    assert not restic.parse_verify_output(ok + "\n" + error).complete
    assert not restic.parse_verify_output("{not json").complete


async def test_a_test_restore_records_its_result(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    backup = _backup(machine)
    job = _job(
        machine, DockerJobKind.BACKUP_VERIFY, "nightly", ref_id=backup.id,
        params={"snapshot": "latest"},
    )
    await _add(db_session_factory, machine, backup, job)
    summary = {"message_type": "summary", "total_files": 3, "files_restored": 3}
    machine_shell.finishes(json.dumps(summary) + "\n@@DC_DONE\n")

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerBackup, backup.id)
    stored_job = await _get(db_session_factory, DockerJob, job.id)
    assert stored_job.status == DockerJobStatus.SUCCEEDED
    assert stored.last_verify_status == "ok"
    assert stored.last_verify_details["restored_files"] == 3


async def test_a_failed_test_restore_is_notified(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    backup = _backup(machine)
    job = _job(
        machine, DockerJobKind.BACKUP_VERIFY, "nightly", ref_id=backup.id,
        params={"snapshot": "latest"},
    )
    await _add(db_session_factory, machine, backup, job)
    summary = {"message_type": "summary", "total_files": 3, "files_restored": 1}
    machine_shell.finishes(json.dumps(summary) + "\n@@DC_DONE\n")

    await tasks._run_docker_job(str(job.id))

    stored = await _get(db_session_factory, DockerBackup, backup.id)
    stored_job = await _get(db_session_factory, DockerJob, job.id)
    assert stored_job.status == DockerJobStatus.FAILED
    assert "1 of 3" in (stored_job.error or "")
    assert stored.last_verify_status == "failed"
    assert [event for event, _ctx in machine_shell.notified]


# --- Logs: level filter, merged stack logs, download -------------------------------


def test_level_filter_is_a_fixed_word_list() -> None:
    command = ssh_logs.build_file_command(
        path="/var/log/syslog", lines=100, search="", level="error"
    )

    assert "grep -iwE" in command
    assert "fatal" in command
    assert ssh_logs.normalize_level("WARN") == "warn"
    assert ssh_logs.normalize_level("x; rm") == ""
    assert "grep" not in ssh_logs.build_file_command(
        path="/var/log/syslog", lines=100, search="", level="debug; rm -rf /"
    )


def test_stack_logs_merge_the_projects_containers() -> None:
    command = ssh_logs.build_docker_logs_command(
        container="@shop", lines=100, search="", since="", until=""
    )

    assert ssh_logs.stack_of("@shop") == "shop"
    assert ssh_logs.stack_of("web") is None
    assert "com.docker.compose.project=shop" in command
    assert "sort -s -k1,1" in command
    with pytest.raises(ssh_logs.LogAccessError):
        ssh_logs.stack_of("@bad;name")


async def test_logs_download_is_a_text_file_and_is_audited(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for["app.tasks.jobs.view_machine_docker_logs"] = {
        "ok": True,
        "output": "2026-10-28T10:00:00Z web | started\n",
    }

    response = await client.get(
        f"/machines/{machine_id}/logs/download",
        params={"source": "docker", "container": "@site", "level": "error"},
    )

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/plain")
    assert 'filename="dockerhost-site.log"' in response.headers["content-disposition"]
    assert "web | started" in response.text
    kwargs = celery_calls[0][2]
    assert (kwargs["container"], kwargs["lines"], kwargs["level"]) == (
        "@site",
        ssh_logs.MAX_DOWNLOAD_LINES,
        "error",
    )
    [entry] = await audit_entries(db_session_factory, "machine.logs.view")
    assert (entry.details or {})["download"] is True


async def test_projects_panel_links_to_stack_logs(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    from tests.test_docker_web_support import INVENTORY_TASK, inventory_answer

    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[INVENTORY_TASK] = inventory_answer()

    response = await client.get(f"/machines/{machine_id}/docker/stacks/panel")

    assert response.status_code == 200
    assert f"/machines/{machine_id}/logs?source=docker&amp;container=%40site" in response.text


# --- Files: changes before saving, conflicts, folder upload and download -----------


def test_text_diff_counts_lines() -> None:
    diff = docker_files.text_diff("a\nb\nc\n", "a\nB\nc\nd\n", "/etc/x")

    assert diff.changed
    assert (diff.added, diff.removed) == (2, 1)
    assert diff.lines[0].startswith("--- /etc/x")
    assert not docker_files.text_diff("same", "same", "/x").changed


@pytest.mark.parametrize(
    "name", ["../x", "a/../../x", "", "a/\x01b", "./", "a/" * 40 + "b"]
)
def test_relative_upload_paths_stay_inside(name: str) -> None:
    with pytest.raises(DockerCommandError):
        docker_files.relative_upload_path(name)


def test_upload_tar_holds_the_folders_and_files() -> None:
    tar = docker_files.build_upload_tar([("site/index.html", b"<h1>"), ("site/css/a.css", b"x")])

    with tarfile.open(fileobj=io.BytesIO(tar)) as archive:
        members = {m.name: m for m in archive.getmembers()}
    assert set(members) == {"./site", "./site/index.html", "./site/css", "./site/css/a.css"}
    assert members["./site/css"].isdir()
    assert docker_files.check_upload_tar(tar) == 2
    with pytest.raises(DockerCommandError):
        docker_files.build_upload_tar([("a", b"1"), ("a", b"2")])


def test_check_upload_tar_refuses_links_and_escapes() -> None:
    for member in (
        tarfile.TarInfo("../evil"),
        tarfile.TarInfo("/etc/evil"),
    ):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            archive.addfile(member, io.BytesIO(b""))
        with pytest.raises(DockerCommandError):
            docker_files.check_upload_tar(buffer.getvalue())
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/shadow"
        archive.addfile(link)
    with pytest.raises(DockerCommandError):
        docker_files.check_upload_tar(buffer.getvalue())


async def test_show_changes_compares_with_the_file_on_the_machine(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    current = b"listen 80;\n"
    celery_calls.result_for[FILES_TASK] = {
        "ok": True, "size": len(current), "mode": 0o644, "uid": 0, "gid": 0,
        "sha256": docker_files.content_sha256(current), "data_b64": _b64(current),
    }

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/files/diff",
        data={
            "csrf_token": csrf,
            "path": "/etc/nginx/nginx.conf",
            "content": "listen 8080;\r\n",
            "sha256": docker_files.content_sha256(current),
        },
    )

    assert response.status_code == 200
    assert "+listen 8080;" in response.text
    assert "-listen 80;" in response.text
    # The edited text stays in the editor, and nothing was written.
    assert "listen 8080;\n</textarea>" in response.text
    assert [args[1] for _name, args, _kw in celery_calls if _name == FILES_TASK] == ["read"]


async def test_save_refuses_a_file_that_changed_meanwhile(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    opened = docker_files.content_sha256(b"old\n")
    celery_calls.result_for[FILES_TASK] = {"ok": False, "error": "changed"}

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/files/save",
        data={"csrf_token": csrf, "path": "/etc/motd", "content": "mine\n", "sha256": opened},
    )

    writes = [kw for name, args, kw in celery_calls if name == FILES_TASK and args[1] == "write"]
    assert response.status_code == 200
    assert writes[0]["expect_sha256"] == opened
    assert "mine\n</textarea>" in response.text
    [entry] = await audit_entries(db_session_factory, "machine.docker.file.write")
    assert (entry.details or {})["conflict"] is True


async def test_folder_upload_sends_one_tar_with_the_folder(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/volumes/site_data/files/upload",
        data={"csrf_token": csrf, "path": "/html"},
        files=[
            ("folder_upload", ("site/index.html", b"<h1>hi</h1>", "text/html")),
            ("folder_upload", ("site/img/a.png", b"\x89PNG", "image/png")),
        ],
    )

    [(_name, args, kwargs)] = [c for c in celery_calls if c[0] == FILES_TASK]
    assert response.status_code == 303
    assert args == (str(machine_id), "unpack", "volume", "site_data", "/html")
    tar = base64.b64decode(kwargs["data_b64"])
    assert docker_files.check_upload_tar(tar) == 2
    [entry] = await audit_entries(db_session_factory, "machine.docker.file.write")
    assert (entry.details or {})["files"] == 2


async def test_folder_upload_refuses_an_escaping_path(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/volumes/site_data/files/upload",
        data={"csrf_token": csrf, "path": "/html"},
        files=[("folder_upload", ("../../etc/cron.d/x", b"* * * * * root id", "text/plain"))],
    )

    assert response.status_code == 303
    assert [c for c in celery_calls if c[0] == FILES_TASK] == []


async def test_folder_download_is_a_gzip_archive(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    packed = gzip.compress(docker_files.build_tar("a.txt", b"a"))
    celery_calls.result_for[FILES_TASK] = {
        "ok": True,
        "size": len(packed),
        "data_b64": _b64(packed),
    }

    response = await client.get(
        f"/machines/{machine_id}/docker/containers/web/files/archive", params={"path": "/srv/app"}
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/gzip"
    assert "app.tar.gz" in response.headers["content-disposition"]
    assert response.content == packed
    assert celery_calls[-1][1][1:] == ("archive", "container", "web", "/srv/app")
    [entry] = await audit_entries(db_session_factory, "machine.docker.file.download")
    assert (entry.details or {})["archive"] is True


async def test_api_upload_conflict_and_archive(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    machine_id = await make_docker_machine(db_session_factory)
    headers = await _api_token(client)
    base = f"/api/v1/machines/{machine_id}/docker/containers/web/files"

    celery_calls.result_for[FILES_TASK] = {"ok": True}
    uploaded = await client.post(
        f"{base}/upload",
        headers=headers,
        json={"path": "/srv", "files": [{"path": "a/b.txt", "content_b64": _b64(b"b")}]},
    )
    bad = await client.post(
        f"{base}/upload",
        headers=headers,
        json={"path": "/srv", "files": [{"path": "../b.txt", "content_b64": _b64(b"b")}]},
    )
    celery_calls.result_for[FILES_TASK] = {"ok": False, "error": "changed"}
    conflict = await client.put(
        f"{base}/content",
        headers=headers,
        json={"path": "/etc/motd", "content_b64": _b64(b"x"), "expect_sha256": "a" * 64},
    )
    packed = gzip.compress(b"tar")
    celery_calls.result_for[FILES_TASK] = {"ok": True, "data_b64": _b64(packed)}
    archive = await client.get(f"{base}/archive", headers=headers, params={"path": "/srv"})

    assert uploaded.status_code == 200, uploaded.text
    assert uploaded.json()["files"] == 1
    assert bad.status_code == 400
    assert conflict.status_code == 409
    assert archive.status_code == 200
    assert archive.content == packed


def test_archive_filename() -> None:
    container = docker_files.Target("container", "web")
    volume = docker_files.Target("volume", "site_data")

    assert docker_files.archive_filename(container, "/srv/app") == "app.tar.gz"
    assert docker_files.archive_filename(volume, "/") == "site_data.tar.gz"


def test_is_tar_stream() -> None:
    tar = docker_files.build_tar("a.txt", b"a" * 2000)

    assert docker_files.is_tar_stream(tar)
    assert not docker_files.is_tar_stream(tar[:700])
    assert not docker_files.is_tar_stream(b"")




async def test_api_shows_backup_commands_only_to_terminal_users(
    client: Any, login_as: Any, db_session_factory: Any
) -> None:
    from tests.test_docker_web_support import add_backup

    machine_id = await make_docker_machine(db_session_factory)
    backup_id = await add_backup(db_session_factory, machine_id)
    async with db_session_factory() as db:
        row = await db.get(DockerBackup, backup_id)
        row.hook_container, row.pre_command = "db", "PGPASSWORD=s3cret pg_dump app"
        await db.commit()
    headers = await _api_token(client)
    url = f"/api/v1/machines/{machine_id}/docker/backups/{backup_id}"

    full = await client.get(url, headers=headers)
    await login_as(client, permissions={Permission.MACHINE_VIEW}, api_access_enabled=True)
    viewer_headers = await _api_token(client)
    viewer = await client.get(url, headers=viewer_headers)

    assert full.json()["pre_command"] == "PGPASSWORD=s3cret pg_dump app"
    assert viewer.status_code == 200, viewer.text
    assert viewer.json()["pre_command"] is None
    assert viewer.json()["hooks_set"] is True
    assert "s3cret" not in viewer.text
