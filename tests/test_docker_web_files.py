"""The file browser of a container or a volume: all of it needs
`action.terminal` (it reads and writes as root inside the container),
every change and download is audited, and names and paths are checked
before anything is sent to a worker."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlsplit

import pytest

from app.db.models.audit_log import AuditOutcome
from app.db.models.role import Permission
from app.ssh import docker_files
from tests.test_docker_web_support import (
    FILES_TASK,
    VIEWER,
    audit_entries,
    csrf_token,
    make_docker_machine,
)

UPDATES_AND_POWER = frozenset(
    {Permission.MACHINE_VIEW, Permission.ACTION_UPDATES, Permission.ACTION_POWER}
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


async def test_listing_a_folder(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[FILES_TASK] = {
        "ok": True,
        "entries": [
            {
                "name": "conf.d",
                "kind": "dir",
                "size": 4096,
                "mtime": 1_760_000_000,
                "mode": "drwxr-xr-x",
                "owner": "root",
            },
            {
                "name": "nginx.conf",
                "kind": "file",
                "size": 1200,
                "mtime": 1_760_000_000,
                "mode": "-rw-r--r--",
                "owner": "root",
            },
        ],
    }

    response = await client.get(
        f"/machines/{machine_id}/docker/containers/web/files",
        params={"path": "/etc/nginx/../nginx"},
    )

    base = f"/machines/{machine_id}/docker/containers/web/files"
    assert response.status_code == 200
    assert celery_calls.names == [FILES_TASK]
    assert celery_calls[0][1] == (str(machine_id), "list", "container", "web", "/etc/nginx")
    assert f'href="{base}?path=/etc/nginx/conf.d"' in response.text
    assert f'href="{base}/edit?path=/etc/nginx/nginx.conf"' in response.text
    assert f'action="{base}/upload?path=/etc/nginx"' in response.text


async def test_listing_a_volume(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)

    response = await client.get(f"/machines/{machine_id}/docker/volumes/site_data/files")

    assert response.status_code == 200
    assert celery_calls[0][1] == (str(machine_id), "list", "volume", "site_data", "/")


@pytest.mark.parametrize(
    "path",
    [
        "networks/site_default/files",
        "containers/bad;name/files",
        "volumes/-x/files",
    ],
)
async def test_only_containers_and_volumes_with_valid_names(
    client, db_session_factory, celery_calls, path
):
    machine_id = await make_docker_machine(db_session_factory)

    response = await client.get(f"/machines/{machine_id}/docker/{path}")

    assert response.status_code == 404
    assert celery_calls == []


async def test_a_bad_path_is_rejected(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)

    response = await client.get(
        f"/machines/{machine_id}/docker/containers/web/files", params={"path": "/etc\nrm -rf /"}
    )

    assert response.status_code == 400
    assert celery_calls == []


async def test_editing_a_text_file_and_refusing_a_binary_one(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    url = f"/machines/{machine_id}/docker/containers/web/files/edit"
    info = {"ok": True, "size": 20, "mode": 0o100644, "uid": 0, "gid": 0}

    celery_calls.result_for[FILES_TASK] = {**info, "data_b64": _b64(b"worker_processes 4;\n")}
    text = await client.get(url, params={"path": "/etc/nginx/nginx.conf"})
    celery_calls.result_for[FILES_TASK] = {**info, "data_b64": _b64(b"\x7fELF\x00\x01")}
    binary = await client.get(url, params={"path": "/usr/sbin/nginx"})

    assert text.status_code == 200
    assert "worker_processes 4;" in text.text
    assert 'name="content"' in text.text
    assert binary.status_code == 200
    assert 'name="content"' not in binary.text


async def test_download_sends_the_file_and_audits_it(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[FILES_TASK] = {"ok": True, "data_b64": _b64(b"secret config")}

    response = await client.get(
        f"/machines/{machine_id}/docker/containers/web/files/download",
        params={"path": "/etc/app/config file.ini"},
    )

    assert response.status_code == 200
    assert response.content == b"secret config"
    assert response.headers["content-type"] == "application/octet-stream"
    assert (
        response.headers["content-disposition"] == "attachment; filename*=UTF-8''config%20file.ini"
    )
    assert response.headers["x-content-type-options"] == "nosniff"
    [entry] = await audit_entries(db_session_factory, "machine.docker.file.download")
    assert entry.outcome == AuditOutcome.SUCCESS
    assert entry.details == {"kind": "container", "name": "web", "path": "/etc/app/config file.ini"}


async def test_a_failed_download_goes_back_to_the_folder(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[FILES_TASK] = {"ok": False, "error": "too_large"}

    response = await client.get(
        f"/machines/{machine_id}/docker/containers/web/files/download",
        params={"path": "/var/log/huge.log"},
    )

    assert response.status_code == 303
    location = urlsplit(response.headers["location"])
    assert location.path == f"/machines/{machine_id}/docker/containers/web/files"
    assert parse_qs(location.query)["path"] == ["/var/log"]
    [entry] = await audit_entries(db_session_factory, "machine.docker.file.download")
    assert entry.outcome == AuditOutcome.FAILURE


async def test_saving_writes_the_content_with_unix_line_endings(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/files/save",
        data={"csrf_token": csrf, "path": "/etc/nginx/nginx.conf", "content": "a\r\nb\r\n"},
    )

    assert response.status_code == 303
    assert "notice=" in response.headers["location"]
    [(name, args, kwargs)] = celery_calls
    assert name == FILES_TASK
    assert args == (str(machine_id), "write", "container", "web", "/etc/nginx/nginx.conf")
    assert kwargs == {"data_b64": _b64(b"a\nb\n")}
    [entry] = await audit_entries(db_session_factory, "machine.docker.file.write")
    assert entry.details == {
        "kind": "container",
        "name": "web",
        "path": "/etc/nginx/nginx.conf",
        "bytes": 4,
    }


async def test_saving_too_much_text_is_refused(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/files/save",
        data={
            "csrf_token": csrf,
            "path": "/big.txt",
            "content": "x" * (docker_files.MAX_EDIT_BYTES + 1),
        },
    )

    assert response.status_code == 303
    assert celery_calls == []
    assert await audit_entries(db_session_factory, "machine.docker.file.write") == []


async def test_upload_writes_into_the_folder_under_the_files_own_name(
    client, db_session_factory, celery_calls
):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/volumes/site_data/files/upload",
        data={"csrf_token": csrf, "path": "/html"},
        files={"upload": ("..\\..\\index.html", b"<h1>hi</h1>", "text/html")},
    )

    assert response.status_code == 303
    [(_name, args, kwargs)] = celery_calls
    assert args == (str(machine_id), "write", "volume", "site_data", "/html/index.html")
    assert kwargs == {"data_b64": _b64(b"<h1>hi</h1>")}
    assert len(await audit_entries(db_session_factory, "machine.docker.file.write")) == 1


@pytest.mark.parametrize("folder", ["", "a/b", "..", "."])
async def test_mkdir_rejects_bad_names(client, db_session_factory, celery_calls, folder):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/files/mkdir",
        data={"csrf_token": csrf, "path": "/srv", "folder": folder},
    )

    assert response.status_code in (303, 422)
    assert celery_calls == []


async def test_mkdir_and_delete_are_audited(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)
    base = f"/machines/{machine_id}/docker/containers/web/files"

    made = await client.post(
        f"{base}/mkdir", data={"csrf_token": csrf, "path": "/srv", "folder": "new"}
    )
    deleted = await client.post(f"{base}/delete", data={"csrf_token": csrf, "path": "/srv/old.txt"})

    assert made.status_code == deleted.status_code == 303
    assert [args[1:] for _name, args, _kwargs in celery_calls] == [
        ("mkdir", "container", "web", "/srv/new"),
        ("delete", "container", "web", "/srv/old.txt"),
    ]
    [mkdir] = await audit_entries(db_session_factory, "machine.docker.file.mkdir")
    [delete] = await audit_entries(db_session_factory, "machine.docker.file.delete")
    assert mkdir.details is not None and mkdir.details["path"] == "/srv/new"
    assert delete.details is not None and delete.details["path"] == "/srv/old.txt"


async def test_the_root_folder_cannot_be_deleted(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/files/delete",
        data={"csrf_token": csrf, "path": "/srv/.."},
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert celery_calls == []


async def test_a_worker_error_is_audited_as_a_failure(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    celery_calls.result_for[FILES_TASK] = {"ok": False, "error": "Permission denied"}
    csrf = await csrf_token(client, machine_id)

    response = await client.post(
        f"/machines/{machine_id}/docker/containers/web/files/delete",
        data={"csrf_token": csrf, "path": "/proc/1"},
    )

    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    [entry] = await audit_entries(db_session_factory, "machine.docker.file.delete")
    assert entry.outcome == AuditOutcome.FAILURE


@pytest.mark.parametrize("permissions", [VIEWER, UPDATES_AND_POWER])
async def test_changing_files_needs_action_terminal(
    client, login_as, db_session_factory, celery_calls, permissions
):
    machine_id = await make_docker_machine(db_session_factory)
    await login_as(client, permissions=permissions)
    csrf = await csrf_token(client, machine_id)
    base = f"/machines/{machine_id}/docker/containers/web/files"

    for page, data in (
        ("save", {"path": "/a", "content": "x"}),
        ("mkdir", {"path": "/", "folder": "x"}),
        ("delete", {"path": "/a"}),
    ):
        response = await client.post(f"{base}/{page}", data={"csrf_token": csrf, **data})
        assert response.status_code == 403, page
    upload = await client.post(
        f"{base}/upload", data={"csrf_token": csrf, "path": "/"}, files={"upload": ("a", b"x")}
    )
    assert upload.status_code == 403
    assert celery_calls == []
    assert await audit_entries(db_session_factory, "machine.docker.file.write") == []


async def test_changing_files_needs_a_csrf_token(client, db_session_factory, celery_calls):
    machine_id = await make_docker_machine(db_session_factory)
    base = f"/machines/{machine_id}/docker/containers/web/files"

    for page, data in (
        ("save", {"path": "/a", "content": "x"}),
        ("mkdir", {"path": "/", "folder": "x"}),
        ("delete", {"path": "/a"}),
    ):
        assert (await client.post(f"{base}/{page}", data=data)).status_code == 403, page
    upload = await client.post(f"{base}/upload", data={"path": "/"}, files={"upload": ("a", b"x")})
    assert upload.status_code == 403
    assert celery_calls == []
