"""Compose stacks (`app.services.docker_stacks`) and restic backups
(`app.services.docker_backups`): what their forms accept, and that every
secret they carry — Git token, `.env`, restic repository, password and
environment — is stored encrypted, never as plain text."""

from __future__ import annotations

import uuid
from typing import Any

from app.core.security import decrypt_secret
from app.db.models.docker import DockerBackup, DockerStack, StackSource
from app.db.models.machine import AuthMethod, Machine
from app.services import docker_backups, docker_stacks
from app.services.docker_backups import BackupForm
from app.services.docker_stacks import StackForm

COMPOSE = "services:\n  web:\n    image: nginx:1.27\n"
TOKEN = "ghp_supersecrettoken123"
ENV = "DB_PASSWORD=hunter2-very-secret\n"


def _git_form(**overrides: Any) -> StackForm:
    values: dict[str, Any] = {
        "name": "  My-App ",
        "source": StackSource.GIT.value,
        "git_url": "https://git.example.com/me/app.git",
        "git_branch": "main",
        "git_compose_path": "/deploy/compose.yaml",
        "git_token": TOKEN,
        "env": ENV,
        "auto_sync": True,
    }
    values.update(overrides)
    return StackForm(**values)


def _new_stack() -> DockerStack:
    return DockerStack(machine_id=uuid.uuid4(), name="", source="")


# --- Stacks: validation ----------------------------------------------------------


def test_a_valid_git_stack_is_normalized() -> None:
    form = _git_form()
    assert form.validate() == []
    assert form.name == "my-app"
    assert form.git_compose_path == "deploy/compose.yaml"


def test_stack_form_rejects_bad_input() -> None:
    form = _git_form(
        name="bad name!",
        git_url="ssh://git@example.com/app.git",
        git_branch="main..evil",
        git_compose_path="../../etc/passwd",
        git_token="token\ninjected",
    )
    assert set(form.validate()) == {
        "docker.stack.error.name",
        "docker.stack.error.git_url",
        "docker.stack.error.git_branch",
        "docker.stack.error.git_path",
        "docker.stack.error.git_token",
    }


def test_git_url_with_credentials_in_it_is_refused() -> None:
    # The token has its own (encrypted) field; one in the URL would be stored plain.
    form = _git_form(git_url=f"https://user:{TOKEN}@git.example.com/app.git")
    assert "docker.stack.error.git_url" in form.validate()


def test_editor_stack_needs_a_compose_file_with_services() -> None:
    for compose in ("", "just: a mapping\n", "services: [unclosed\n", "- a list\n"):
        form = StackForm(name="web", source=StackSource.EDITOR.value, compose=compose)
        assert form.validate() == ["docker.stack.error.compose"], compose
    ok = StackForm(name="web", source=StackSource.EDITOR.value, compose=COMPOSE)
    assert ok.validate() == []


def test_unknown_source_is_refused() -> None:
    assert "docker.stack.error.source" in StackForm(name="web", source="ftp").validate()


# --- Stacks: secrets ---------------------------------------------------------------


def test_git_token_and_env_are_stored_encrypted() -> None:
    stack = _new_stack()
    form = _git_form()
    form.validate()
    form.apply(stack)

    assert stack.git_token_encrypted is not None and stack.env_encrypted is not None
    assert TOKEN.encode() not in stack.git_token_encrypted
    assert b"hunter2" not in stack.env_encrypted
    assert decrypt_secret(stack.git_token_encrypted) == TOKEN
    assert docker_stacks.env_text(stack) == ENV
    assert docker_stacks.git_source(stack).token == TOKEN


def test_token_is_kept_when_left_out_and_removed_when_emptied() -> None:
    stack = _new_stack()
    first = _git_form()
    first.validate()
    first.apply(stack)
    stored = stack.git_token_encrypted

    keep = _git_form(git_token=None, env=None)
    keep.validate()
    keep.apply(stack)
    assert stack.git_token_encrypted == stored
    assert docker_stacks.env_text(stack) == ENV

    clear = _git_form(git_token="", env="  ")
    clear.validate()
    clear.apply(stack)
    assert stack.git_token_encrypted is None
    assert stack.env_encrypted is None


def test_switching_a_stack_to_the_editor_drops_its_git_token() -> None:
    stack = _new_stack()
    git = _git_form()
    git.validate()
    git.apply(stack)

    editor = StackForm(name="my-app", source=StackSource.EDITOR.value, compose=COMPOSE)
    editor.validate()
    editor.apply(stack)

    assert stack.git_token_encrypted is None
    assert stack.git_url is None
    assert stack.auto_sync is False
    assert stack.compose_content == COMPOSE


def test_content_hash_tracks_compose_and_env_changes() -> None:
    stack = _new_stack()
    form = StackForm(name="web", source=StackSource.EDITOR.value, compose=COMPOSE, env=ENV)
    form.validate()
    form.apply(stack)
    assert not docker_stacks.is_changed(stack)  # never deployed: nothing to differ from

    stack.deployed_hash = docker_stacks.content_hash(stack)
    assert not docker_stacks.is_changed(stack)

    form.env = "DB_PASSWORD=rotated\n"
    form.apply(stack)
    assert docker_stacks.is_changed(stack)


async def test_webhook_token_is_stored_only_as_its_hash(db_session_factory: Any) -> None:
    token, digest = docker_stacks.new_webhook_token()
    async with db_session_factory() as db:
        machine = Machine(
            name="docker1",
            ip_address="10.0.0.7",
            username="root",
            auth_method=AuthMethod.PASSWORD,
        )
        db.add(machine)
        await db.flush()
        stack = DockerStack(
            machine_id=machine.id, name="web", source="git", webhook_token_hash=digest
        )
        db.add(stack)
        await db.commit()

        found = await docker_stacks.find_by_webhook(db, token)
        wrong = await docker_stacks.find_by_webhook(db, token + "x")
        by_hash = await docker_stacks.find_by_webhook(db, digest)
        empty = await docker_stacks.find_by_webhook(db, "")

    assert digest != token and token not in digest
    assert found is not None and found.id == stack.id
    assert (wrong, by_hash, empty) == (None, None, None)


# --- Backups ------------------------------------------------------------------------


REPOSITORY = "rest:https://backup:repo-pass-123@backup.example.com/repo"


def _backup_form(**overrides: Any) -> BackupForm:
    values: dict[str, Any] = {
        "name": "nightly",
        "repository": REPOSITORY,
        "password": "restic-password-456",
        "env": "AWS_ACCESS_KEY_ID=AKIAEXAMPLE\n",
        "volumes": "app_data\napp_data\nmedia",
        "paths": "/srv/www/\n",
        "excludes": "*.tmp",
        "keep_daily": "7",
    }
    values.update(overrides)
    return BackupForm(**values)


def _empty_backup() -> DockerBackup:
    return DockerBackup(machine_id=uuid.uuid4(), name="", volumes=[], paths=[], excludes=[])


def test_backup_secrets_are_stored_encrypted_with_a_redacted_display_copy() -> None:
    backup = _empty_backup()
    form = _backup_form()
    assert form.validate(existing=None) == []
    form.apply(backup)

    for secret, ciphertext in (
        ("repo-pass-123", backup.repository_encrypted),
        ("restic-password-456", backup.password_encrypted),
        ("AKIAEXAMPLE", backup.env_encrypted),
    ):
        assert ciphertext is not None and secret.encode() not in ciphertext
    assert "repo-pass-123" not in backup.repository_display
    assert backup.volumes == ["app_data", "media"]
    assert backup.paths == ["/srv/www"]
    assert backup.keep_daily == 7 and backup.keep_last is None

    machine = Machine(name="docker1", ip_address="10.0.0.7", username="root")
    config = docker_backups.config_for(backup, machine)
    assert config.repository == REPOSITORY
    assert config.password == "restic-password-456"
    assert config.env == ["AWS_ACCESS_KEY_ID=AKIAEXAMPLE"]


def test_editing_a_backup_with_empty_secrets_keeps_the_stored_ones() -> None:
    backup = _empty_backup()
    first = _backup_form()
    first.validate(existing=None)
    first.apply(backup)
    stored = (backup.repository_encrypted, backup.password_encrypted, backup.env_encrypted)

    edit = _backup_form(repository="", password="", env="", keep_daily="14")
    assert edit.validate(existing=backup) == []
    edit.apply(backup)

    assert (backup.repository_encrypted, backup.password_encrypted, backup.env_encrypted) == stored
    assert backup.keep_daily == 14


def test_a_new_backup_needs_a_repository_and_a_password() -> None:
    errors = _backup_form(repository="", password="").validate(existing=None)
    assert "docker.backup.error.repository" in errors
    assert "docker.backup.error.password" in errors


def test_backup_form_rejects_bad_input() -> None:
    cases: dict[str, dict[str, str]] = {
        "docker.backup.error.repository": {"repository": "ftp://example.com/repo"},
        "docker.backup.error.password": {"password": "two\nlines"},
        "docker.backup.error.env": {"env": "RESTIC_PASSWORD=override"},
        "docker.backup.error.volumes": {"volumes": "-rf"},
        "docker.backup.error.paths": {"paths": "/proc/self"},
        "docker.backup.error.keep": {"keep_last": "-1"},
        "docker.backup.error.name": {"name": "   "},
    }
    for error, override in cases.items():
        assert error in _backup_form(**override).validate(existing=None), override
    nothing = _backup_form(volumes="", paths="").validate(existing=None)
    assert "docker.backup.error.nothing" in nothing
    for root in ("/", "/sys", "/dev/sda"):
        assert "docker.backup.error.paths" in _backup_form(paths=root).validate(existing=None)


def test_retention_and_restore_narrowing() -> None:
    backup = _empty_backup()
    form = _backup_form(keep_daily="")
    form.validate(existing=None)
    form.apply(backup)
    assert not docker_backups.has_retention(backup)
    backup.keep_last = 3
    assert docker_backups.has_retention(backup)

    machine = Machine(name="docker1", ip_address="10.0.0.7", username="root")
    narrowed = docker_backups.config_for(
        backup, machine, volumes=["media", "not-in-backup"], paths=[]
    )
    assert narrowed.volumes == ["media"]
    assert narrowed.paths == []
