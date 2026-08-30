#!/usr/bin/env python3
"""Interactive setup wizard for a new debcontrol deployment — the
recommended way to configure and start one for the first time.

Usage (from a fresh git checkout, before anything else):
    python scripts/setup.py

What it does, in order: copies `.env.example` to `.env`, fills in every
secret (`SECRET_KEY`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD`,
`REDIS_PASSWORD`, `INFORM_TOKEN`) with freshly generated random values,
asks a handful of questions (timezone, whether to use the bundled Caddy
reverse proxy and its domain/email if so, the two background-check
intervals, the Administrator account's password — or auto-generates one —
and the host port to publish), writes `.env`, brings the stack up with
`docker compose`, waits for the app to become healthy, and creates the
first Administrator account.

Pure standard library — no dependency on this project's own virtualenv, so
it runs with a bare system `python3` before anything has been installed.
See wiki/Installation.md for what this does step by step, and for the
manual alternative if you'd rather configure everything by hand instead.
"""

from __future__ import annotations

import base64
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = REPO_ROOT / ".env"
ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"

_HEALTH_TIMEOUT_SECONDS = 180
_HEALTH_POLL_SECONDS = 3


def _prompt(question: str, *, default: str) -> str:
    answer = input(f"{question} [{default}]: ").strip()
    return answer or default


def _prompt_required(question: str) -> str:
    while True:
        answer = input(f"{question}: ").strip()
        if answer:
            return answer
        print("  (required — please enter a value)")


def _prompt_yes_no(question: str, *, default: bool) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input(f"{question} {suffix}: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def _fernet_key() -> str:
    """A Fernet-format key (`cryptography.fernet.Fernet.generate_key()`'s
    own algorithm — 32 random bytes, url-safe base64) generated without
    needing that package installed on the host running this script."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def _set_env_line(lines: list[str], key: str, value: str) -> list[str]:
    """Replace `KEY=...` or a commented-out `# KEY=...` with `KEY=value`,
    appending a new line at the end if the key isn't present at all."""
    pattern = re.compile(rf"^#?\s*{re.escape(key)}=.*$")
    updated = False
    result = []
    for line in lines:
        if pattern.match(line):
            result.append(f"{key}={value}")
            updated = True
        else:
            result.append(line)
    if not updated:
        result.append(f"{key}={value}")
    return result


def _require_docker() -> str:
    """Return the full path to the `docker` executable, or exit with a
    clear error — resolved once via `shutil.which` (rather than passing the
    bare name to every `subprocess.run` below) so this doesn't depend on
    `subprocess`'s own PATH search behaving the way we expect it to."""
    docker_path = shutil.which("docker")
    if docker_path is None:
        print("error: 'docker' was not found on PATH.", file=sys.stderr)
        raise SystemExit(1)
    try:
        subprocess.run(  # noqa: S603 - fixed args, no user input
            [docker_path, "compose", "version"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
        )
    except (subprocess.CalledProcessError, OSError):
        print(
            "error: 'docker compose' (the v2 plugin, not the old standalone "
            "docker-compose) is required.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    return docker_path


def _git_commit() -> str:
    git_path = shutil.which("git")
    if git_path is None:
        return "unknown"
    try:
        result = subprocess.run(  # noqa: S603 - fixed args, no user input
            [git_path, "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip() or "unknown"
    except (subprocess.CalledProcessError, OSError):
        return "unknown"


def _wait_until_healthy(port: str) -> bool:
    deadline = time.monotonic() + _HEALTH_TIMEOUT_SECONDS
    url = f"http://localhost:{port}/healthz"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(_HEALTH_POLL_SECONDS)
    return False


def main() -> None:
    print("debcontrol setup — press Enter to accept a default shown in [brackets].\n")

    docker_path = _require_docker()

    if ENV_PATH.exists() and not _prompt_yes_no(
        ".env already exists. Overwrite it with a freshly configured one?", default=False
    ):
        print("Aborted — .env left untouched.")
        raise SystemExit(1)

    lines = ENV_EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()

    print("==> Generating secrets (SECRET_KEY, ENCRYPTION_KEY, POSTGRES_PASSWORD, "
          "REDIS_PASSWORD, INFORM_TOKEN)...")
    lines = _set_env_line(lines, "SECRET_KEY", secrets.token_urlsafe(64))
    lines = _set_env_line(lines, "ENCRYPTION_KEY", _fernet_key())
    lines = _set_env_line(lines, "POSTGRES_PASSWORD", secrets.token_urlsafe(24))
    lines = _set_env_line(lines, "REDIS_PASSWORD", secrets.token_urlsafe(24))
    lines = _set_env_line(lines, "INFORM_TOKEN", secrets.token_urlsafe(32))

    print()
    tz = _prompt("Timezone (IANA name, e.g. Europe/Prague)", default="UTC")
    lines = _set_env_line(lines, "TZ", tz)

    use_caddy = _prompt_yes_no(
        "Use the bundled Caddy reverse proxy for automatic HTTPS?", default=False
    )
    domain = None
    if use_caddy:
        domain = _prompt_required("Domain name pointing at this server's public IP")
        email = _prompt_required("Email address for Let's Encrypt account/expiry notices")
        lines = _set_env_line(lines, "DOMAIN", domain)
        lines = _set_env_line(lines, "ACME_EMAIL", email)

    print()
    facts_interval = _prompt("Facts refresh interval, in seconds", default="3600")
    reachability_interval = _prompt("Reachability check interval, in seconds", default="60")
    lines = _set_env_line(lines, "FACTS_REFRESH_INTERVAL_SECONDS", facts_interval)
    lines = _set_env_line(
        lines, "REACHABILITY_CHECK_INTERVAL_SECONDS", reachability_interval
    )

    print()
    admin_password = input(
        "Administrator account password (leave empty to auto-generate one): "
    ).strip()
    generated_password: str | None = None
    if not admin_password:
        generated_password = secrets.token_urlsafe(18)
        admin_password = generated_password

    print()
    port = _prompt("Host port to publish the app on", default="8080")
    lines = _set_env_line(lines, "APP_PORT", port)

    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n==> Wrote {ENV_PATH}")

    compose_files = ["-f", "docker-compose.yml"]
    if use_caddy:
        compose_files += ["-f", "docker-compose.caddy.yml"]

    print("==> Building and starting the stack (this can take a few minutes)...")
    build_env = {**os.environ, "GIT_COMMIT": _git_commit()}
    subprocess.run(  # noqa: S603 - fixed args plus this run's own choices, no user input
        [docker_path, "compose", *compose_files, "up", "-d", "--build"],
        cwd=REPO_ROOT,
        env=build_env,
        check=True,
    )

    print("==> Waiting for the app to become healthy...")
    if not _wait_until_healthy(port):
        print(
            "warning: the app didn't report healthy within "
            f"{_HEALTH_TIMEOUT_SECONDS}s — check 'docker compose logs -f web'. "
            "Continuing to try creating the admin account anyway.",
            file=sys.stderr,
        )

    print("==> Creating the first administrator account (username: admin)...")
    # Passed as a bare `-e DEBCONTROL_ADMIN_PASSWORD` (no `=value`) so Docker
    # forwards this process's own environment value into the container's
    # exec'd process — the password itself never appears as a command-line
    # argument, so it never shows up in this host's process listing. See
    # create_admin.py's own module docstring for why that distinction matters.
    exec_env = {**os.environ, "DEBCONTROL_ADMIN_PASSWORD": admin_password}
    try:
        subprocess.run(  # noqa: S603 - fixed args, no user input in the command itself
            [
                docker_path, "compose", *compose_files, "exec", "-T",
                "-e", "DEBCONTROL_ADMIN_PASSWORD",
                "web", "python", "scripts/create_admin.py", "--username", "admin",
            ],
            cwd=REPO_ROOT,
            env=exec_env,
            check=True,
        )
    except subprocess.CalledProcessError:
        print(
            "\nerror: creating the administrator account failed — the stack is "
            "running, but you'll need to create it yourself:\n"
            "  docker compose exec web python scripts/create_admin.py --username admin",
            file=sys.stderr,
        )
        raise SystemExit(1) from None

    print()
    print("=" * 64)
    print("debcontrol is running.")
    if use_caddy:
        print(f"URL:      https://{domain}")
    else:
        print(f"URL:      http://<this-host>:{port}")
    print("Username: admin")
    if generated_password:
        print(f"Password: {generated_password}   (shown once — save it now)")
    else:
        print("Password: the one you entered")
    print("You'll be asked to change it on first login.")
    print("=" * 64)


if __name__ == "__main__":
    main()
