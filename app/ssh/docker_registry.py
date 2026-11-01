"""`docker login` / `docker logout` of a private registry on a machine
(`app.services.docker_registries`).

The password reaches docker on standard input only (`--password-stdin`),
never a command line, so it shows up in no process list or shell
history. Docker keeps the login in the configuration of the account it
runs as (`~/.docker/config.json`, or a credential helper when one is set
up there), the same account that pulls, deploys stacks and checks images
for updates — so all of those use it.
"""

from __future__ import annotations

import re

from app.ssh.docker_cli import DockerCommandError, q

# host[:port], lowercase, as `docker login` takes it.
_SERVER_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,252}(?::[0-9]{1,5})?\Z")
_USERNAME_RE = re.compile(r"^[^\s\x00-\x1f\x7f-][^\s\x00-\x1f\x7f]{0,254}\Z")
MAX_PASSWORD_LENGTH = 4096


def normalize_server(value: str) -> str | None:
    """A registry server as entered (`ghcr.io`, `https://registry.example.com:5000/`)
    reduced to host[:port]; None when it is not one."""
    server = value.strip().lower()
    for prefix in ("https://", "http://"):
        server = server.removeprefix(prefix)
    server = server.rstrip("/")
    if not _SERVER_RE.match(server) or ".." in server:
        return None
    if ":" in server:
        port = int(server.rsplit(":", 1)[1])
        if not 0 < port < 65536:
            return None
    return server


def is_username_valid(value: str) -> bool:
    return bool(_USERNAME_RE.match(value))


def is_password_valid(value: str) -> bool:
    return (
        0 < len(value) <= MAX_PASSWORD_LENGTH
        and not any(c in value for c in "\n\r\0")
    )


def build_login_command(server: str, username: str) -> str:
    """Log in with the password on standard input."""
    if normalize_server(server) != server or not is_username_valid(username):
        raise DockerCommandError("Invalid registry server or user name.")
    return f"$D login --username {q(username)} --password-stdin {q(server)}"


def build_logout_command(server: str) -> str:
    if normalize_server(server) != server:
        raise DockerCommandError("Invalid registry server.")
    return f"$D logout {q(server)}"


def login_message(output: str) -> str:
    """The useful part of docker's answer, without its warning about how
    the password is stored."""
    lines = [
        line.strip()
        for line in output.splitlines()
        if line.strip()
        and not line.startswith("WARNING!")
        and "docs.docker.com" not in line
        and "credential helper" not in line.lower()
        and "password will be stored" not in line.lower()
    ]
    return " ".join(lines)[-480:]
