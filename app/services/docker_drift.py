"""Drift: a managed stack changed on the machine outside debcontrol — its
files edited there, another commit checked out, containers recreated by
hand (`docker run`, `docker compose up` with other files) or missing.

`check` reads the machine (`app.ssh.docker_drift`) and compares it with
what debcontrol deployed last; the result is stored on the stack
(`drift_status`, `drift_details`, `drift_checked_at`). A stack never
deployed by debcontrol (just adopted, or made and not deployed) is not
checked: there is nothing to compare with yet. Putting it right is a
deploy; for a stack written in debcontrol, the files on the machine can
be taken over instead (the stack import route, `app.services.docker_adopt`).

Checked when asked (the stack page, the API) and, for stacks with
`drift_check` on, hourly; turning to "drift" sends the
`docker.stack.drift` notification.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from app.core.security import decrypt_secret
from app.db.models.docker import DockerStack, StackSource
from app.ssh.docker_drift import DriftReading, build_drift_script


def _file_hash(content: str) -> str:
    """The SHA-256 of a file as the deploy wrote it (a heredoc: always
    ends with a newline)."""
    text = content if content.endswith("\n") else content + "\n"
    return hashlib.sha256(text.encode()).hexdigest()


def compose_paths(stack: DockerStack) -> list[str]:
    if stack.source == StackSource.GIT:
        paths = [stack.git_compose_path or "compose.yaml", *(stack.git_compose_overrides or [])]
        return [f"repo/{path}" for path in paths]
    return ["compose.yaml"]


def script(stack: DockerStack) -> str:
    return build_drift_script(
        stack.name, stack.directory or "", compose_paths(stack), git=stack.source == StackSource.GIT
    )


def is_checkable(stack: DockerStack) -> bool:
    """Deployed by debcontrol at least once."""
    return stack.deployed_hash is not None


def evaluate(stack: DockerStack, reading: DriftReading) -> tuple[str, dict[str, Any]]:
    """("ok" | "drift" | "error", details)."""
    if reading.no_directory:
        return "drift", {"message": "The stack's directory is gone from the machine.", "files": [],
                         "services": [], "commit": None}
    files: list[dict[str, str]] = []
    expected_files: dict[str, str] = {}
    if stack.source == StackSource.EDITOR and stack.deployed_compose is not None:
        expected_files["compose.yaml"] = _file_hash(stack.deployed_compose)
    if stack.deployed_env_encrypted is not None or stack.deployed_compose is not None:
        env = (
            decrypt_secret(stack.deployed_env_encrypted) if stack.deployed_env_encrypted else ""
        )
        expected_files[".env"] = _file_hash(env)
    for name, wanted in expected_files.items():
        found = reading.files.get(name)
        if found is None:
            continue
        if found == "-":
            files.append({"name": name, "state": "missing"})
        elif found != wanted:
            files.append({"name": name, "state": "changed"})
    commit: dict[str, str] | None = None
    if (
        stack.source == StackSource.GIT
        and stack.deployed_commit
        and reading.head
        and reading.head != stack.deployed_commit
    ):
        commit = {"expected": stack.deployed_commit, "found": reading.head}
    services: list[dict[str, str]] = []
    if not reading.config_failed:
        seen: set[str] = set()
        for service, config_hash, container, _state in reading.containers:
            seen.add(service)
            expected = reading.services.get(service)
            if expected is None:
                services.append({"service": service, "container": container, "state": "extra"})
            elif config_hash != expected:
                services.append(
                    {"service": service, "container": container, "state": "changed"}
                )
        services.extend(
            {"service": service, "container": "", "state": "missing"}
            for service in sorted(reading.services.keys() - seen)
        )
    details: dict[str, Any] = {
        "files": files,
        "commit": commit,
        "services": services,
        "message": (
            f"docker compose config failed: {reading.config_error}"
            if reading.config_failed
            else ""
        ),
    }
    if files or commit or services:
        return "drift", details
    if reading.config_failed:
        return "error", details
    return "ok", details


def store(stack: DockerStack, status: str, details: dict[str, Any]) -> bool:
    """Keep the result on the stack; True when it just turned to drift."""
    turned = status == "drift" and stack.drift_status != "drift"
    stack.drift_status = status
    stack.drift_details = details
    stack.drift_checked_at = datetime.now(UTC)
    return turned


def summary(details: dict[str, Any] | None) -> str:
    """One English line per finding, for notifications and the API."""
    if not details:
        return ""
    lines: list[str] = []
    if details.get("message"):
        lines.append(str(details["message"]))
    lines.extend(
        f"{item.get('name')}: {item.get('state')} on the machine"
        for item in details.get("files") or []
    )
    commit = details.get("commit")
    if isinstance(commit, dict):
        lines.append(
            f"Git: {str(commit.get('found'))[:12]} checked out, "
            f"{str(commit.get('expected'))[:12]} deployed"
        )
    for item in details.get("services") or []:
        state = item.get("state")
        if state == "missing":
            lines.append(f"service {item.get('service')}: no container")
        elif state == "extra":
            lines.append(
                f"container {item.get('container')}: service {item.get('service')} "
                "is not in the compose file"
            )
        else:
            lines.append(
                f"container {item.get('container')}: runs other settings than the compose file"
            )
    return "\n".join(lines)
