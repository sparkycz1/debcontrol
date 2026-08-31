"""Onboarding a fresh machine (Settings tab's "Initial setup", for a
PASSWORD-auth machine) — see app/ssh/onboarding.py for what the generated
script does and app/tasks/jobs.py's _run_machine_onboarding for how it's
run and what happens on success/failure.
"""

from __future__ import annotations

import shlex
import uuid

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models.machine import AuthMethod, Machine
from app.ssh.onboarding import ONBOARD_SUCCESS_MARKER, ONBOARD_USERNAME, build_onboarding_command
from app.tasks.jobs import _run_machine_onboarding

# --- build_onboarding_command: pure, no I/O -----------------------------


def test_build_onboarding_command_creates_the_dedicated_user():
    command = build_onboarding_command("ssh-ed25519 AAAAfake user@host")

    assert f"id -u {ONBOARD_USERNAME}" in command
    assert f"useradd -m -s /bin/bash {ONBOARD_USERNAME}" in command


def test_build_onboarding_command_installs_the_public_key_idempotently():
    command = build_onboarding_command("ssh-ed25519 AAAAfake user@host")

    assert "'ssh-ed25519 AAAAfake user@host'" in command
    # Checked before appended — running this again must not duplicate the line.
    assert "grep -qxF" in command
    assert command.index("grep -qxF") < command.index(">> ")


def test_build_onboarding_command_grants_exactly_the_documented_sudoers_lines():
    command = build_onboarding_command("key")

    assert (
        f"{ONBOARD_USERNAME} ALL=(root) NOPASSWD: /usr/bin/apt-get, /usr/sbin/shutdown" in command
    )
    assert f"{ONBOARD_USERNAME} ALL=(root) NOPASSWD: /usr/bin/flatpak, /usr/bin/snap" in command
    # The flatpak/snap grant only applies inside the "if either is installed" guard.
    assert "if command -v flatpak" in command
    assert "visudo -cf" in command


def test_build_onboarding_command_installs_ncurses_term_best_effort():
    command = build_onboarding_command("key")

    # `|| true` right after: a failed apt step (no network, stale cache)
    # must never fail the whole script.
    assert "apt-get install -y ncurses-term >/dev/null 2>&1) || true;" in command


def test_build_onboarding_command_ends_with_the_success_marker():
    command = build_onboarding_command("key")

    assert command.strip().endswith(ONBOARD_SUCCESS_MARKER)


def test_build_onboarding_command_quotes_a_hostile_public_key():
    hostile_key = "key'; rm -rf / #"
    command = build_onboarding_command(hostile_key)

    # The whole hostile string must appear only as shlex's properly-escaped
    # single token (each place the key is used) — never as a bare,
    # unescaped `'; rm -rf / #` that a shell would parse as a second
    # command spliced into the script.
    quoted = shlex.quote(hostile_key)
    assert command.count(quoted) == 2  # the grep check, and the echo append
    assert "'; rm -rf / #" not in command.replace(quoted, "")


# --- _run_machine_onboarding: mocked SSH, no network --------------------


class _FakeResult:
    def __init__(self, stdout: str, exit_status: int) -> None:
        self.stdout = stdout
        self.exit_status = exit_status


class _FakeConnection:
    def __init__(self, result: _FakeResult) -> None:
        self._result = result

    async def run(self, command: str, **kwargs: object) -> _FakeResult:
        return self._result

    async def __aenter__(self) -> _FakeConnection:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


async def _make_machine(db_session_factory: async_sessionmaker[AsyncSession]) -> uuid.UUID:
    async with db_session_factory() as session:
        machine = Machine(
            name="fresh1",
            ip_address="10.9.9.9",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            secret_encrypted=None,
            host_key_fingerprint="SHA256:fakefingerprint",
        )
        session.add(machine)
        await session.commit()
        return machine.id


async def test_onboarding_switches_machine_to_the_apps_ssh_key_on_success(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _make_machine(db_session_factory)

    fake_result = _FakeResult(f"...\n{ONBOARD_SUCCESS_MARKER}\n", 0)

    async def fake_open_connection(machine: object, secret: object, timeout_seconds: int) -> object:
        return _FakeConnection(fake_result)

    monkeypatch.setattr(
        "app.ssh.exec.open_connection", fake_open_connection
    )

    result = await _run_machine_onboarding(str(machine_id))

    assert result["ok"] is True

    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        assert machine.username == ONBOARD_USERNAME
        assert machine.auth_method == AuthMethod.SSH_KEY
        assert machine.secret_encrypted is None


async def test_onboarding_requires_a_pinned_host_key(db_session_factory, monkeypatch):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    async with db_session_factory() as session:
        machine = Machine(
            name="unpinned",
            ip_address="10.9.9.10",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            host_key_fingerprint=None,
        )
        session.add(machine)
        await session.commit()
        machine_id = machine.id

    result = await _run_machine_onboarding(str(machine_id))

    assert result["ok"] is False
    assert "host key" in str(result["error"]).lower()


async def test_onboarding_script_failure_does_not_switch_auth_method(
    db_session_factory, monkeypatch
):
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await _make_machine(db_session_factory)

    # Exit 0 but no success marker — e.g. the connection dropped partway
    # through and `set -e` never actually reached the last line.
    fake_result = _FakeResult("useradd: ...\n", 0)

    async def fake_open_connection(machine: object, secret: object, timeout_seconds: int) -> object:
        return _FakeConnection(fake_result)

    monkeypatch.setattr("app.ssh.exec.open_connection", fake_open_connection)

    result = await _run_machine_onboarding(str(machine_id))

    assert result["ok"] is False

    async with db_session_factory() as session:
        machine = await session.get(Machine, machine_id)
        assert machine is not None
        assert machine.auth_method == AuthMethod.PASSWORD


# --- The web endpoint: dispatch only, real SSH stays mocked out ---------


async def test_run_onboarding_endpoint_dispatches_the_task(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/machines/{machine_id}/run-onboarding", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 200
    assert celery_calls.names == ["app.tasks.jobs.run_machine_onboarding"]
    assert celery_calls[0][1] == (str(machine_id),)
    # celery_calls' default stub result is {"ok": True, "output": "fake"} —
    # the endpoint should render that as a success, without needing the
    # real task (which never ran) to have actually flipped anything.
    assert "Setup completed" in response.text


async def test_run_onboarding_endpoint_shows_the_reported_error(
    client, db_session_factory, celery_calls
):
    machine_id = await _make_machine(db_session_factory)
    celery_calls.result_for["app.tasks.jobs.run_machine_onboarding"] = {
        "ok": False,
        "error": "Permission denied (publickey,password).",
    }

    await client.get("/machines/new")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/machines/{machine_id}/run-onboarding", data={"csrf_token": csrf_token}
    )
    assert response.status_code == 200
    assert "Permission denied" in response.text
