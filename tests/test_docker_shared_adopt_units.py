"""Docker new features, part 2, below the web layer: private registry
logins (`app.ssh.docker_registry`, `app.services.docker_registries`,
`docker_extras.reconcile_logins`), shared variables merged into a stack's
`.env` (`app.services.docker_variables`, `docker_stacks.effective_env`),
adopting a project and turning a `docker run` container into a compose
file (`app.ssh.docker_adopt`, `app.ssh.docker_convert`) and drift
(`app.ssh.docker_drift`, `app.services.docker_drift`).

The shell scripts run in a local `sh` with a fake `$D`; the tasks run
their underscore-prefixed coroutines against a scripted fake machine."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from sqlalchemy import select

from app.core.security import decrypt_secret, encrypt_secret
from app.db.models.docker import (
    DockerRegistry,
    DockerRegistryLogin,
    DockerStack,
    DockerVariable,
    scope_key,
)
from app.db.models.machine_group import MachineGroup
from app.db.models.notification_rule import NotificationEventType
from app.services import (
    docker_adopt,
    docker_drift,
    docker_registries,
    docker_stacks,
    docker_variables,
)
from app.services.docker_scopes import Scope
from app.ssh import docker_adopt as ssh_adopt
from app.ssh import docker_convert, docker_registry
from app.ssh.docker_cli import CommandOutput, DockerCommandError
from app.ssh.docker_compose import StackFiles, build_stack_script, env_line
from app.ssh.docker_drift import build_drift_script, parse_drift_output
from app.tasks import docker_extras
from tests.test_docker_tasks_jobs import FakeMachine, _add, _get, _machine, install_fake_machine

# --- Registry logins: the commands -------------------------------------------------


@pytest.mark.parametrize(
    ("entered", "server"),
    [
        ("ghcr.io", "ghcr.io"),
        ("https://Registry.Example.com:5000/", "registry.example.com:5000"),
        ("http://docker.io", "docker.io"),
        ("registry.example.com:0", None),
        ("registry.example.com:70000", None),
        ("bad host", None),
        ("a..b", None),
        ("-x.example.com", None),
        ("ghcr.io/owner", None),
    ],
)
def test_registry_server_is_reduced_to_host_and_port(entered: str, server: str | None) -> None:
    assert docker_registry.normalize_server(entered) == server


def test_login_takes_the_password_on_stdin_only() -> None:
    command = docker_registry.build_login_command("ghcr.io", "bot")

    assert command == "$D login --username bot --password-stdin ghcr.io"
    with pytest.raises(DockerCommandError):
        docker_registry.build_login_command("ghcr.io;id", "bot")
    with pytest.raises(DockerCommandError):
        docker_registry.build_login_command("ghcr.io", "-bot")
    assert docker_registry.build_logout_command("ghcr.io") == "$D logout ghcr.io"


def test_password_rules_and_login_message() -> None:
    assert docker_registry.is_password_valid("s3cret")
    assert not docker_registry.is_password_valid("")
    assert not docker_registry.is_password_valid("a\nb")
    assert not docker_registry.is_password_valid("x" * 4097)
    answer = (
        "WARNING! Your password will be stored unencrypted in /root/.docker/config.json.\n"
        "Configure a credential helper to remove this warning. See\n"
        "https://docs.docker.com/engine/reference/commandline/login/#credential-stores\n"
        "\nLogin Succeeded\n"
    )
    assert docker_registry.login_message(answer) == "Login Succeeded"


# --- Scopes --------------------------------------------------------------------------


def test_scope_parse_and_precedence() -> None:
    group_id, machine_id = uuid.uuid4(), uuid.uuid4()

    assert Scope.parse("") == Scope("all")
    assert Scope.parse(f"group:{group_id}") == Scope("group", group_id=group_id)
    assert Scope.parse(f"machine:{machine_id}") == Scope("machine", machine_id=machine_id)
    assert Scope.parse("group:nope") is None
    assert Scope.parse("site:1") is None
    assert Scope("machine", machine_id=machine_id).rank > Scope("group", group_id=group_id).rank
    assert scope_key(group_id, None) == f"g:{group_id}"
    assert scope_key(None, machine_id) == f"m:{machine_id}"
    assert scope_key(None, None) == ""


# --- Shared variables ------------------------------------------------------------------


def _variable(name: str, value: str, **scope: Any) -> DockerVariable:
    group_id, machine_id = scope.get("group_id"), scope.get("machine_id")
    return DockerVariable(
        name=name,
        value_encrypted=encrypt_secret(value),
        secret=scope.get("secret", False),
        group_id=group_id,
        machine_id=machine_id,
        scope_key=scope_key(group_id, machine_id),
    )


def test_picked_names_are_checked_and_deduplicated() -> None:
    assert docker_variables.parse_names(["SMTP_HOST", " SMTP_HOST", "", "TZ"]) == [
        "SMTP_HOST",
        "TZ",
    ]
    assert docker_variables.parse_names(["1BAD"]) is None
    assert docker_variables.parse_names([f"V{i}" for i in range(101)]) is None
    assert not docker_variables.is_value_valid("a\nb")


async def test_the_most_specific_definition_wins(db_session_factory: Any) -> None:
    group = MachineGroup(name="prod")
    await _add(db_session_factory, group)
    machine = _machine(group_id=group.id)
    other = _machine(name="other")
    stack = DockerStack(
        machine_id=machine.id,
        name="shop",
        source="editor",
        compose_content="services: {}\n",
        shared_variables=["TZ", "SMTP_PASSWORD", "UNDEFINED"],
    )
    await _add(
        db_session_factory,
        machine,
        other,
        stack,
        _variable("TZ", "UTC"),
        _variable("TZ", "Europe/Prague", group_id=group.id),
        _variable("SMTP_PASSWORD", "fleet"),
        _variable("SMTP_PASSWORD", "machine-only", machine_id=machine.id, secret=True),
        _variable("SMTP_PASSWORD", "elsewhere", machine_id=other.id),
        _variable("NOT_PICKED", "x"),
    )

    async with db_session_factory() as db:
        stored = await db.get(DockerStack, stack.id)
        resolved = await docker_variables.resolve(db, stored)

    assert resolved == {"TZ": "Europe/Prague", "SMTP_PASSWORD": "machine-only"}
    assert docker_variables.missing(stack, resolved) == ["UNDEFINED"]


def test_effective_env_appends_shared_values_the_stack_does_not_set() -> None:
    stack = DockerStack(
        name="shop",
        source="editor",
        compose_content="services: {}\n",
        env_encrypted=encrypt_secret("TZ=UTC\nAPP=1"),
    )

    env = docker_stacks.effective_env(stack, {"TZ": "Europe/Prague", "TOKEN": "a'b$c"})

    assert env == (
        "TZ=UTC\nAPP=1\n"
        f"{docker_stacks.SHARED_ENV_MARKER}\n"
        'TOKEN="a\'b\\$c"\n'
    )
    assert docker_stacks.effective_env(stack, {}) == docker_stacks.env_text(stack)
    assert docker_stacks.effective_env(stack, {"TZ": "x"}) == docker_stacks.env_text(stack)
    assert docker_adopt.strip_shared(env) == "TZ=UTC\nAPP=1\n"


def test_env_line_quotes_values_literally() -> None:
    assert env_line("A", "plain $HOME") == "A='plain $HOME'"
    assert env_line("A", 'it\'s "x" \\ $y') == 'A="it\'s \\"x\\" \\\\ \\$y"'


def test_content_hash_moves_with_shared_values_but_not_without_them() -> None:
    stack = DockerStack(
        name="shop", source="editor", compose_content="services: {}\n", env_encrypted=None
    )
    plain = docker_stacks.content_hash(stack, {})

    stack.deployed_hash = docker_stacks.content_hash(stack, {"TOKEN": "one"})

    assert docker_stacks.content_hash(stack, {"TOKEN": "one"}) != plain
    assert docker_stacks.is_changed(stack, {"TOKEN": "two"})
    assert not docker_stacks.is_changed(stack, {"TOKEN": "one"})


def test_deploy_writes_shared_values_into_the_env_file() -> None:
    stack = DockerStack(
        name="shop",
        source="editor",
        compose_content="services: {}\n",
        env_encrypted=encrypt_secret("A=1\n"),
        shared_variables=["TOKEN"],
    )

    script = docker_stacks.deploy_script(stack, shared={"TOKEN": "s3cret"})

    assert "A=1\n# Shared variables (debcontrol)\nTOKEN='s3cret'\n" in script


# --- Registry logins: reconciling a machine -------------------------------------------


@pytest.fixture
def logins(monkeypatch: pytest.MonkeyPatch, db_session_factory: Any) -> list[tuple[str, Any]]:
    """Every script `reconcile_logins` runs, with what it sent on stdin."""
    install_fake_machine(monkeypatch, db_session_factory)
    calls: list[tuple[str, Any]] = []

    async def fake_run_script(
        _machine: Any, _secret: Any, _timeout: int, script: str, **kwargs: Any
    ) -> CommandOutput:
        calls.append((script, kwargs.get("stdin")))
        if script.endswith(" bad.example.com"):
            return CommandOutput(1, "Error response from daemon: unauthorized")
        return CommandOutput(0, "WARNING! Password stored unencrypted\nLogin Succeeded")

    monkeypatch.setattr(docker_extras, "run_script", fake_run_script)
    return calls


def _registry(server: str, password: str = "pw", **scope: Any) -> DockerRegistry:  # noqa: S107
    group_id, machine_id = scope.get("group_id"), scope.get("machine_id")
    return DockerRegistry(
        server=server,
        username="bot",
        password_encrypted=encrypt_secret(password),
        group_id=group_id,
        machine_id=machine_id,
        scope_key=scope_key(group_id, machine_id),
    )


async def _logins_of(db_session_factory: Any, machine_id: uuid.UUID) -> dict[str, Any]:
    async with db_session_factory() as db:
        rows = await db.execute(
            select(DockerRegistryLogin).where(DockerRegistryLogin.machine_id == machine_id)
        )
        return {row.server: row for row in rows.scalars()}


async def test_reconcile_logs_in_with_the_most_specific_entry_and_records_failures(
    db_session_factory: Any, logins: list[tuple[str, Any]]
) -> None:
    machine = _machine()
    await _add(
        db_session_factory,
        machine,
        _registry("ghcr.io", "fleet-pw"),
        _registry("ghcr.io", "machine-pw", machine_id=machine.id),
        _registry("bad.example.com"),
    )

    result = await docker_extras._sync_registry_logins(str(machine.id))

    assert result == {"ok": True, "logged_in": 1, "failed": 1, "logged_out": 0}
    assert ("$D login --username bot --password-stdin ghcr.io", "machine-pw") in logins
    assert all("pw" not in script for script, _stdin in logins)
    rows = await _logins_of(db_session_factory, machine.id)
    assert rows["ghcr.io"].status == "ok"
    assert rows["ghcr.io"].message == "Login Succeeded"
    assert rows["bad.example.com"].status == "failed"
    assert "unauthorized" in rows["bad.example.com"].message


async def test_reconcile_skips_good_logins_and_logs_out_of_removed_ones(
    db_session_factory: Any, logins: list[tuple[str, Any]]
) -> None:
    machine = _machine()
    registry = _registry("ghcr.io")
    await _add(db_session_factory, machine, registry)
    later = datetime.now(UTC) + timedelta(minutes=5)
    await _add(
        db_session_factory,
        DockerRegistryLogin(
            machine_id=machine.id,
            server="ghcr.io",
            registry_id=registry.id,
            status="ok",
            checked_at=later,
        ),
        DockerRegistryLogin(
            machine_id=machine.id, server="old.example.com", status="ok", checked_at=later
        ),
    )

    first = await docker_extras._sync_registry_logins(str(machine.id))
    forced = await docker_extras._sync_registry_logins(str(machine.id), True)

    assert first["logged_out"] == 1
    assert [script for script, _ in logins][:1] == ["$D logout old.example.com"]
    assert forced["logged_out"] == 0
    assert logins[-1][0].startswith("$D login")  # only the forced run logged in again
    assert len([s for s, _ in logins if s.startswith("$D login")]) == 1
    assert set(await _logins_of(db_session_factory, machine.id)) == {"ghcr.io"}


def test_queueing_registry_logins_sends_one_task_per_machine(celery_calls: Any) -> None:
    first, second = uuid.uuid4(), uuid.uuid4()

    assert docker_extras.queue_registry_sync([first, second, first], force=True) == 2
    assert celery_calls.names == [
        "app.tasks.docker_extras.sync_registry_logins",
        "app.tasks.docker_extras.sync_registry_logins",
    ]
    assert celery_calls[0][1] == (str(first), True)


async def test_registry_form_checks_scope_and_duplicates(
    db_session_factory: Any, login_as: Any, client: Any
) -> None:
    group = MachineGroup(name="prod")
    await _add(db_session_factory, group, _registry("ghcr.io"))
    from app.db.models.user import User

    async with db_session_factory() as db:
        admin = (await db.execute(select(User).limit(1))).scalar_one()
        duplicate = docker_registries.RegistryForm("GHCR.io", "bot", "pw")
        bad = docker_registries.RegistryForm("ghcr.io", "", None, scope="group:nope")
        group_scoped = docker_registries.RegistryForm(
            "ghcr.io", "bot", "pw", scope=f"group:{group.id}"
        )

        assert await duplicate.validate(db, admin) == ["docker.registry.error.taken"]
        assert set(await bad.validate(db, admin)) == {
            "docker.registry.error.username",
            "docker.registry.error.password",
            "docker.scope.error",
        }
        assert await group_scoped.validate(db, admin) == []


# --- Adopting ------------------------------------------------------------------------


def _run(script: str, home: Path, docker: str = "") -> str:
    prelude = (
        "dc_d() { " + (docker or "return 0") + "; }; D=dc_d\n"
    )
    done = subprocess.run(  # noqa: S603 - the script under test, run locally
        ["sh", "-c", prelude + script],  # noqa: S607
        capture_output=True,
        text=True,
        env={**os.environ, "HOME": str(home), "TMPDIR": str(home)},
        timeout=30,
        check=False,
    )
    return done.stdout


def test_reading_a_project_returns_its_files_and_whether_it_is_writable(tmp_path: Path) -> None:
    project = tmp_path / "site"
    project.mkdir()
    (project / "docker-compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (project / ".env").write_text("TOKEN=@@DC_ENV fake\n")

    out = _run(
        ssh_adopt.build_project_read_script(
            "site", str(project), [str(project / "docker-compose.yml")]
        ),
        tmp_path,
    )
    read = ssh_adopt.parse_read_output(out)

    assert read["compose"] == "services:\n  web:\n    image: nginx\n"
    assert read["env"] == "TOKEN=@@DC_ENV fake\n"
    assert read["writable"] is True
    assert read["marked"] is False
    assert docker_adopt.read_errors(read) == []


def test_reading_several_compose_files_merges_them_without_interpolation(
    tmp_path: Path,
) -> None:
    files = [str(tmp_path / "a.yml"), str(tmp_path / "b.yml")]
    docker = (
        'case "$*" in *"config --no-interpolate"*) '
        "printf 'services:\\n  web:\\n    image: ${IMAGE}\\n';; esac"
    )

    script = ssh_adopt.build_project_read_script("site", str(tmp_path), files)
    read = ssh_adopt.parse_read_output(_run(script, tmp_path, docker))

    assert "config --no-interpolate" in script
    assert read["compose"] == "services:\n  web:\n    image: ${IMAGE}\n"


def test_a_project_that_cannot_be_adopted_says_why(tmp_path: Path) -> None:
    gone = ssh_adopt.parse_read_output(
        _run(ssh_adopt.build_project_read_script("site", "/nonexistent-dc", ["/x.yml"]), tmp_path)
    )

    assert docker_adopt.read_errors(gone) == ["docker.adopt.error.no_directory"]
    assert docker_adopt.precheck_errors("site", "/srv/site", managed=True, protected=False) == [
        "docker.adopt.error.managed"
    ]
    assert docker_adopt.precheck_errors("site", "/srv/site", managed=False, protected=True) == [
        "docker.protected"
    ]
    assert docker_adopt.precheck_errors("site", "", managed=False, protected=False) == [
        "docker.adopt.error.directory"
    ]
    compose = "services: {}\n"
    assert docker_adopt.read_errors({"compose": compose, "writable": False}) == [
        "docker.adopt.error.not_writable"
    ]
    assert docker_adopt.read_errors({"compose": compose, "writable": True, "marked": True}) == [
        "docker.adopt.error.marked"
    ]
    assert docker_adopt.read_errors({"config_error": "bad"}) == ["docker.adopt.error.config"]
    with pytest.raises(DockerCommandError):
        ssh_adopt.build_project_read_script("site", "relative", ["/x.yml"])
    with pytest.raises(DockerCommandError):
        ssh_adopt.build_project_read_script("site", "/srv/site", ["/a:b"])


def test_marking_writes_the_stack_marker_once(tmp_path: Path) -> None:
    (tmp_path / "site").mkdir()

    first = _run(ssh_adopt.build_mark_script("site", "~/site"), tmp_path)
    again = _run(ssh_adopt.build_mark_script("site", "~/site"), tmp_path)
    other = _run(ssh_adopt.build_mark_script("other", "~/site"), tmp_path)

    assert "@@DC_DONE" in first and "@@DC_DONE" in again
    assert "@@DC_FAILED marked" in other
    assert (tmp_path / "site" / ".debcontrol-stack").read_text() == "site\n"


def test_an_adopted_stack_keeps_name_directory_and_files() -> None:
    machine_id = uuid.uuid4()
    read = {"compose": "services:\r\n  web:\r\n    image: nginx\r\n", "env": "A=1\n"}

    stack = docker_adopt.new_stack(machine_id, "site", "/srv/site/", read, "admin")

    assert (stack.name, stack.directory, stack.source) == ("site", "/srv/site", "editor")
    assert stack.compose_content == "services:\n  web:\n    image: nginx\n"
    assert decrypt_secret(stack.env_encrypted or b"") == "A=1\n"
    assert stack.deployed_hash is None


def test_reading_a_stacks_files_back(tmp_path: Path) -> None:
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "compose.yaml").write_text("services: {}\n")

    read = ssh_adopt.parse_read_output(
        _run(ssh_adopt.build_stack_files_read_script("web", "~/web"), tmp_path)
    )

    assert read["compose"] == "services: {}\n"
    assert read["env"] is None


# --- docker run -> compose -------------------------------------------------------------


def _inspected() -> tuple[dict[str, Any], dict[str, Any]]:
    container = {
        "Id": "abc123def456",
        "Name": "/My_App",
        "Config": {
            "Image": "ghcr.io/acme/app:1.2",
            "Hostname": "abc123def456",
            "Env": ["PATH=/usr/bin", "DB_PASSWORD=pa$$'word", "TZ=UTC"],
            "Cmd": ["serve"],
            "Labels": {
                "org.opencontainers.image.version": "1.2",
                "traefik.http.middlewares.auth.basicauth.users": "me:$apr1$x$y",
            },
            "Healthcheck": {"Test": ["CMD", "true"], "Interval": 30_000_000_000, "Retries": 3},
        },
        "HostConfig": {
            "RestartPolicy": {"Name": "unless-stopped"},
            "PortBindings": {
                "80/tcp": [{"HostIp": "", "HostPort": "8080"}],
                "53/udp": [{"HostIp": "127.0.0.1", "HostPort": "53"}],
            },
            "NetworkMode": "proxy",
            "Memory": 268435456,
            "CapAdd": ["NET_ADMIN"],
            "Links": ["/db:/My_App/db"],
            "LogConfig": {"Type": "json-file", "Config": {}},
            "ShmSize": 67108864,
        },
        "Mounts": [
            {"Type": "volume", "Name": "app_data", "Destination": "/data", "RW": True},
            {"Type": "bind", "Source": "/etc/app", "Destination": "/config", "RW": False},
        ],
        "NetworkSettings": {"Networks": {"proxy": {}}},
    }
    image = {
        "Id": "sha256:" + "f" * 64,
        "Config": {
            "Env": ["PATH=/usr/bin"],
            "Cmd": ["serve"],
            "Labels": {"org.opencontainers.image.version": "1.2"},
        },
    }
    return container, image


def test_a_container_becomes_a_compose_file_without_its_secrets() -> None:
    converted = docker_convert.to_compose(*_inspected())
    document = yaml.safe_load(converted.compose)
    service = document["services"]["my_app"]

    assert converted.service == "my_app"
    assert service["image"] == "ghcr.io/acme/app:1.2"
    assert service["container_name"] == "My_App"
    assert service["restart"] == "unless-stopped"
    assert service["env_file"] == [".env"]
    assert "command" not in service  # the image's own
    assert "hostname" not in service  # docker's default
    assert service["ports"] == ["127.0.0.1:53:53/udp", "8080:80"]
    assert service["volumes"] == ["app_data:/data", "/etc/app:/config:ro"]
    assert service["networks"] == ["proxy"]
    assert service["mem_limit"] == 268435456
    assert service["cap_add"] == ["NET_ADMIN"]
    assert "shm_size" not in service and "logging" not in service
    assert service["healthcheck"] == {"test": ["CMD", "true"], "interval": "30s", "retries": 3}
    # `$` is doubled so Compose doesn't interpolate it; image labels stay out.
    assert service["labels"] == {"traefik.http.middlewares.auth.basicauth.users": "me:$$apr1$$x$$y"}
    assert document["volumes"] == {"app_data": {"external": True, "name": "app_data"}}
    assert document["networks"] == {"proxy": {"external": True, "name": "proxy"}}
    assert "DB_PASSWORD" not in converted.compose
    assert converted.env == "DB_PASSWORD=\"pa\\$\\$'word\"\nTZ='UTC'\n"
    assert converted.warnings == ["Links (--link) were left out; use a shared network instead."]


def test_inspect_output_is_parsed_and_names_checked() -> None:
    raw = '@@DC_CTR {"Name": "/x"}\n@@DC_IMG not json\n'

    assert docker_convert.parse_inspect_output(raw) == ({"Name": "/x"}, {})
    assert docker_convert.project_name("--Odd.Name!") == "odd-name"
    with pytest.raises(DockerCommandError):
        docker_convert.build_inspect_script("bad name")


def test_the_first_deploy_sets_the_old_container_aside_and_removes_it_after(
    tmp_path: Path,
) -> None:
    files = StackFiles("web", compose="services: {}\n", replace_container="old-web")

    script = _stack_script(files)

    assert "$D stop old-web >/dev/null && $D rename old-web old-web-pre-debcontrol" in script
    assert "$D rm old-web-pre-debcontrol" in script
    assert "$D rename old-web-pre-debcontrol old-web && $D start old-web" in script
    assert script.index("@@DC_STEP replace") < script.index("@@DC_STEP up")


def _stack_script(files: StackFiles) -> str:
    return build_stack_script(files, pull=False)


def test_a_bad_container_name_to_replace_is_refused() -> None:
    with pytest.raises(DockerCommandError):
        _stack_script(
            StackFiles("web", compose="services: {}\n", replace_container="x;id")
        )


# --- Drift ---------------------------------------------------------------------------


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _deployed_stack(**overrides: Any) -> DockerStack:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "machine_id": uuid.uuid4(),
        "name": "web",
        "source": "editor",
        "compose_content": "services:\n  web:\n    image: nginx\n",
        "deployed_compose": "services:\n  web:\n    image: nginx\n",
        "deployed_env_encrypted": encrypt_secret("A=1\n"),
        "deployed_hash": "h",
    }
    values.update(overrides)
    return DockerStack(**values)


def _reading(**parts: str) -> str:
    compose = parts.get("compose", _sha("services:\n  web:\n    image: nginx\n"))
    env = parts.get("env", _sha("A=1\n"))
    return "\n".join(
        [
            f"@@DC_FILE compose.yaml {compose}",
            f"@@DC_FILE .env {env}",
            *parts.get("rest", "@@DC_SVC web abc\n@@DC_CTR web|abc|web-web-1|running").split("\n"),
        ]
    )


def test_a_stack_as_deployed_has_no_drift() -> None:
    status, details = docker_drift.evaluate(_deployed_stack(), parse_drift_output(_reading()))

    assert status == "ok"
    assert docker_drift.summary(details) == ""


@pytest.mark.parametrize(
    ("reading", "expected"),
    [
        (_reading(compose="0" * 64), ["compose.yaml: changed on the machine"]),
        (_reading(env="-"), [".env: missing on the machine"]),
        (
            _reading(rest="@@DC_SVC web abc\n@@DC_CTR web|zzz|web-web-1|running"),
            ["container web-web-1: runs other settings than the compose file"],
        ),
        (_reading(rest="@@DC_SVC web abc"), ["service web: no container"]),
        (
            _reading(rest="@@DC_SVC web abc\n@@DC_CTR web|abc|a|running\n@@DC_CTR db|q|b|running"),
            ["container b: service db is not in the compose file"],
        ),
    ],
)
def test_drift_is_found_and_described(reading: str, expected: list[str]) -> None:
    status, details = docker_drift.evaluate(_deployed_stack(), parse_drift_output(reading))

    assert status == "drift"
    assert docker_drift.summary(details).splitlines() == expected


def test_a_git_stack_on_another_commit_and_a_failed_config() -> None:
    stack = _deployed_stack(
        source="git", deployed_compose=None, deployed_commit="1" * 40, git_compose_path="c.yaml"
    )

    moved = docker_drift.evaluate(
        stack,
        parse_drift_output(f"@@DC_FILE .env {_sha('A=1\n')}\n@@DC_HEAD {'2' * 40}\n"),
    )
    failed = docker_drift.evaluate(
        stack,
        parse_drift_output(
            f"@@DC_FILE .env {_sha('A=1\n')}\n@@DC_HEAD {'1' * 40}\n@@DC_CONFIG_FAILED\nyaml: bad"
        ),
    )
    gone = docker_drift.evaluate(stack, parse_drift_output("@@DC_NODIR\n"))

    assert moved[0] == "drift" and moved[1]["commit"]["found"] == "2" * 40
    assert failed[0] == "error" and "yaml: bad" in failed[1]["message"]
    assert gone[0] == "drift"
    assert docker_drift.compose_paths(stack) == ["repo/c.yaml"]


def test_storing_drift_reports_only_the_turn() -> None:
    stack = _deployed_stack()

    assert docker_drift.store(stack, "drift", {}) is True
    assert docker_drift.store(stack, "drift", {}) is False
    assert docker_drift.store(stack, "ok", {}) is False
    assert stack.drift_checked_at is not None


def test_the_drift_script_reads_files_and_hashes(tmp_path: Path) -> None:
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "compose.yaml").write_text("services: {}\n")
    docker = (
        'case "$*" in *"config --hash"*) echo "web abc";; '
        "ps*) echo '@@DC_CTR web|abc|web-web-1|running';; esac"
    )

    reading = parse_drift_output(
        _run(build_drift_script("web", "~/web", ["compose.yaml"], git=False), tmp_path, docker)
    )

    assert reading.files == {"compose.yaml": _sha("services: {}\n"), ".env": "-"}
    assert reading.services == {"web": "abc"}
    assert reading.containers == [("web", "abc", "web-web-1", "running")]
    with pytest.raises(DockerCommandError):
        build_drift_script("web", "", ["../etc/passwd"], git=False)


# --- Drift and adopt tasks -----------------------------------------------------------


@pytest.fixture
def machine_shell(monkeypatch: pytest.MonkeyPatch, db_session_factory: Any) -> FakeMachine:
    fake = install_fake_machine(monkeypatch, db_session_factory)

    async def fake_run_script(
        _machine: Any, _secret: Any, _timeout: int, script: str, **_kwargs: Any
    ) -> CommandOutput:
        fake.short.append(script)
        for needle, output in fake.answers:
            if needle in script:
                return output
        return CommandOutput(0, "")

    async def fake_notify(_session: Any, event: NotificationEventType, **kwargs: Any) -> None:
        fake.notified.append((event, dict(kwargs.get("context") or {})))

    monkeypatch.setattr(docker_extras, "run_script", fake_run_script)
    monkeypatch.setattr(docker_extras, "notify", fake_notify)
    return fake


async def test_a_drift_check_stores_the_result_and_notifies_once(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    stack = _deployed_stack(machine_id=machine.id)
    await _add(db_session_factory, machine, stack)
    machine_shell.answer("config --hash", _reading(env="0" * 64))

    first = await docker_extras._check_stack_drift(str(stack.id))
    second = await docker_extras._check_stack_drift(str(stack.id))

    stored = await _get(db_session_factory, DockerStack, stack.id)
    assert first["status"] == second["status"] == "drift"
    assert stored.drift_status == "drift"
    assert stored.drift_details["files"] == [{"name": ".env", "state": "changed"}]
    assert machine_shell.notified == [
        (
            NotificationEventType.DOCKER_STACK_DRIFT,
            {"stack": "web", "details": ".env: changed on the machine"},
        )
    ]


async def test_an_undeployed_stack_is_not_checked_and_the_sweep_picks_switched_on_stacks(
    db_session_factory: Any, machine_shell: FakeMachine, celery_calls: Any
) -> None:
    machine = _machine()
    fresh = _deployed_stack(machine_id=machine.id, name="fresh", deployed_hash=None)
    on = _deployed_stack(machine_id=machine.id, name="on", drift_check=True)
    off = _deployed_stack(machine_id=machine.id, name="off")
    await _add(db_session_factory, machine, fresh, on, off)

    result = await docker_extras._check_stack_drift(str(fresh.id))
    queued = await docker_extras._check_all_stack_drift()

    assert result["ok"] is False and machine_shell.short == []
    assert queued == 1
    assert celery_calls[0] == ("app.tasks.docker_extras.check_stack_drift", (str(on.id),), {})


async def test_turning_a_container_into_compose_refuses_compose_containers(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    await _add(db_session_factory, machine)
    container, image = _inspected()

    machine_shell.answer(
        "container inspect",
        f"@@DC_CTR {json.dumps(container)}\n@@DC_IMG {json.dumps(image)}\n",
    )

    converted = await docker_extras._docker_container_compose(str(machine.id), "My_App")
    container["Config"]["Labels"]["com.docker.compose.project"] = "x"
    machine_shell.answers.clear()
    machine_shell.answer("container inspect", f"@@DC_CTR {json.dumps(container)}\n")
    refused = await docker_extras._docker_container_compose(str(machine.id), "My_App")

    assert converted["ok"] and converted["service"] == "my_app"
    assert refused == {"ok": False, "error": "This container belongs to a Compose project."}


async def test_reading_a_project_through_the_task(
    db_session_factory: Any, machine_shell: FakeMachine
) -> None:
    machine = _machine()
    await _add(db_session_factory, machine)
    encoded = base64.b64encode(b"services: {}\n").decode()
    machine_shell.answer("@@DC_COMPOSE", f"@@DC_COMPOSE {encoded}\n@@DC_WRITABLE\n")

    result = await docker_extras._docker_project_read(
        str(machine.id), "site", "/srv/site", ["/srv/site/compose.yaml"]
    )

    assert result["ok"] and result["read"]["compose"] == "services: {}\n"
    assert result["read"]["writable"] is True
