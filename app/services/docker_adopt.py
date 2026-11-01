"""Bringing what already runs on a machine under debcontrol's management:

- **Adopting a Compose project** debcontrol found but didn't deploy: a
  stack written in debcontrol is made from the project's compose file(s)
  and `.env`, keeping its name (the Compose project name) and directory,
  so the first deploy recreates only what differs. Adoption only writes
  the `.debcontrol-stack` marker on the machine; the project's own files
  stay where they are (the first deploy adds `compose.yaml` and `.env`).
- **A `docker run` container to a stack**: `app.ssh.docker_convert` turns
  its settings into a compose file; the stack takes the container over on
  its first deploy (`DockerStack.replace_container`).
- **Taking over changes made on the machine** to a managed stack's files
  (after drift): its `compose.yaml` and `.env` are read back and stored.

After that the stack has everything a stack made in debcontrol has:
history, rollback, checks, drift, Git (by switching its source), shared
variables.
"""

from __future__ import annotations

from typing import Any

from app.db.models.docker import DockerStack, StackSource
from app.services.docker_stacks import SHARED_ENV_MARKER, StackForm, validate_compose
from app.ssh.docker_cli import DockerCommandError, is_project_name_valid
from app.ssh.docker_compose import MAX_FILE_BYTES, normalize_stack_directory


def precheck_errors(project: str, working_dir: str, *, managed: bool, protected: bool) -> list[str]:
    """Why `project` can't be adopted, before reading it (i18n keys)."""
    if managed:
        return ["docker.adopt.error.managed"]
    if protected:
        return ["docker.protected"]
    if not is_project_name_valid(project):
        return ["docker.stack.error.name"]
    directory = normalize_stack_directory(working_dir)
    if not working_dir or directory is None or directory != working_dir.rstrip("/"):
        return ["docker.adopt.error.directory"]
    return []


def read_errors(read: dict[str, Any]) -> list[str]:
    """Why what was read from the project can't become a stack."""
    if read.get("no_directory"):
        return ["docker.adopt.error.no_directory"]
    if read.get("config_error"):
        return ["docker.adopt.error.config"]
    compose = read.get("compose")
    if not isinstance(compose, str):
        return ["docker.adopt.error.read"]
    try:
        validate_compose(compose)
    except DockerCommandError:
        return ["docker.stack.error.compose"]
    env = read.get("env")
    if isinstance(env, str) and len(env.encode()) > MAX_FILE_BYTES:
        return ["docker.stack.error.env"]
    if read.get("marked"):
        return ["docker.adopt.error.marked"]
    if not read.get("writable"):
        return ["docker.adopt.error.not_writable"]
    return []


def new_stack(
    machine_id: Any, project: str, working_dir: str, read: dict[str, Any], created_by: str
) -> DockerStack:
    """The stack for an adopted project (`adoption_errors` passed)."""
    env = read.get("env")
    form = StackForm(
        name=project,
        source=StackSource.EDITOR,
        compose=str(read.get("compose") or "").replace("\r\n", "\n"),
        env=env.replace("\r\n", "\n") if isinstance(env, str) else "",
        directory=working_dir.rstrip("/"),
    )
    errors = form.validate()
    if errors:
        raise DockerCommandError(", ".join(errors))
    stack = DockerStack(machine_id=machine_id, created_by=created_by)
    form.apply(stack)
    return stack


def strip_shared(env: str) -> str:
    """A `.env` read back from the machine without the shared variables
    debcontrol appended (they stay shared, not copied into the stack)."""
    lines = env.replace("\r\n", "\n").split("\n")
    if SHARED_ENV_MARKER in lines:
        lines = lines[: lines.index(SHARED_ENV_MARKER)]
    text = "\n".join(lines)
    return text.rstrip("\n") + "\n" if text.strip() else ""
