#!/usr/bin/env python3
"""Interactive setup wizard for a new debcontrol deployment — the
recommended way to configure and start one for the first time.

Usage (from a fresh git checkout, before anything else):
    python3 scripts/setup.py

What it does, in order: copies `.env.example` to `.env`, fills in every
secret (`SECRET_KEY`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD`,
`REDIS_PASSWORD`, `INFORM_TOKEN`) with freshly generated random values,
asks a handful of questions (timezone, the default UI language for
accounts that haven't picked one for themselves, whether to use the
bundled Caddy reverse proxy and its domain/email if so, whether the app's
own port should only accept local connections, the two background-check
intervals, the Administrator account's password — typed twice, masked,
never printed — and the host port to publish), writes `.env`, brings the stack up with
`docker compose`, waits for the app to become healthy, and creates the
first Administrator account.

If `.env` already exists, declining to overwrite it doesn't abort anymore
— this tops it up instead (`scripts/env_sync.py`: adds whatever
`.env.example` variables this deployment's `.env` predates, touching
nothing already there) and just starts the stack against the existing
file, no secrets regenerated and no new admin account created. Useful for
re-running this script after `git pull` on a deployment that was never
switched to `scripts/upgrade.sh`.

Pure standard library — no dependency on this project's own virtualenv, so
it runs with a bare system `python3` before anything has been installed.
See wiki/Installation for what this does step by step, and for the
manual alternative if you'd rather configure everything by hand instead.
"""

from __future__ import annotations

import base64
import getpass
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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.i18n import available_locales
from scripts.env_sync import sync_env

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


# Same bound as `app.schemas.user.MIN_PASSWORD_LENGTH` — duplicated rather
# than imported since this script runs on the host, outside the app's own
# venv/container (`scripts/create_admin.py` keeps its own copy likewise).
_MIN_PASSWORD_LENGTH = 12


def _prompt_admin_password() -> str:
    """Asks for the Administrator password by hand — masked (`getpass`,
    never echoed or kept in shell history) and typed twice to catch a
    typo, the same flow `scripts/create_admin.py` uses interactively. No
    auto-generate option: a password printed to stdout would sit in clear
    text in the terminal's scrollback or session log."""
    while True:
        password = getpass.getpass("Administrator account password: ")
        if len(password) < _MIN_PASSWORD_LENGTH:
            print(f"  (must be at least {_MIN_PASSWORD_LENGTH} characters)")
            continue
        if getpass.getpass("Confirm password: ") != password:
            print("  (passwords didn't match — try again)")
            continue
        return password

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


def _read_env_value(path: Path, key: str) -> str | None:
    """The value of an uncommented `KEY=value` line in an existing `.env`,
    or `None` if it's absent or commented out — used only by the "keep my
    existing .env" path below to figure out `APP_PORT`/whether Caddy is
    configured without re-prompting for values already sitting in the file."""
    if not path.exists():
        return None
    pattern = re.compile(rf"^{re.escape(key)}=(.*)$")
    for line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match:
            return match.group(1)
    return None


def _compose_up(docker_path: str, compose_files: list[str]) -> None:
    """`docker compose up -d --build`, or a clear, actionable diagnosis
    instead of a raw traceback if it fails. The single most common failure
    here is `migrate` dying with "password authentication failed" — Postgres
    only ever applies `POSTGRES_PASSWORD` while initializing an *empty*
    `pg_data` volume, so a volume left over from any earlier attempt (this
    script run before, a manual `docker compose up`, ...) still has a
    different password baked in than whatever `.env` has now. The `down -v`
    right before this call already guards against that for a normal run of
    this script; this is the fallback explanation for whatever's left
    (e.g. the volume belongs to a *different* compose project name, or
    something else entirely)."""
    print("==> Building and starting the stack (this can take a few minutes)...")
    build_env = {**os.environ, "GIT_COMMIT": _git_commit()}
    try:
        subprocess.run(  # noqa: S603 - fixed args plus this run's own choices, no user input
            [docker_path, "compose", *compose_files, "up", "-d", "--build"],
            cwd=REPO_ROOT,
            env=build_env,
            check=True,
        )
    except subprocess.CalledProcessError:
        logs = subprocess.run(  # noqa: S603 - fixed args, no user input
            [docker_path, "compose", *compose_files, "logs", "migrate"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        print(file=sys.stderr)
        if "password authentication failed" in logs:
            print(
                "error: Postgres rejected the password in .env — almost always a "
                "leftover `pg_data` Docker volume from an earlier attempt, still "
                "holding a *different* password than the one .env has now "
                "(Postgres only applies POSTGRES_PASSWORD while initializing an "
                "empty data directory). Fix:\n"
                "    docker compose down -v\n"
                "then re-run this script.",
                file=sys.stderr,
            )
        else:
            print(
                "error: the stack failed to start. 'docker compose logs migrate' "
                "output:",
                file=sys.stderr,
            )
            print(logs, file=sys.stderr)
        raise SystemExit(1) from None


def _sync_and_start(docker_path: str) -> None:
    """The path taken when an existing `.env` is kept rather than
    regenerated: top it up with whatever `.env.example` variables it's
    missing (scripts/env_sync.py — never touches a line already there),
    then just bring the stack up against it, same as `upgrade.sh` would.
    No secrets are generated, no questions asked, and no admin account is
    (re-)created — this assumes a working deployment already exists and
    the operator just re-ran this script."""
    print("==> Checking .env against .env.example for anything new...")
    added = sync_env(ENV_PATH, ENV_EXAMPLE_PATH)
    if added:
        print(f"    Added: {', '.join(added)} (review the values before relying on this deploy).")
    else:
        print("    Nothing to add — .env already has every .env.example variable.")

    use_caddy = _read_env_value(ENV_PATH, "DOMAIN") is not None
    port = _read_env_value(ENV_PATH, "APP_PORT") or "8080"
    compose_files = ["-f", "docker-compose.yml"]
    if use_caddy:
        compose_files += ["-f", "docker-compose.caddy.yml"]

    _compose_up(docker_path, compose_files)

    print("==> Waiting for the app to become healthy...")
    if not _wait_until_healthy(port):
        print(
            "warning: the app didn't report healthy within "
            f"{_HEALTH_TIMEOUT_SECONDS}s — check 'docker compose logs -f web'.",
            file=sys.stderr,
        )
    else:
        print("\ndebcontrol is running — .env was kept as-is (plus anything just added above).")


def _wait_until_healthy(port: str) -> bool:
    deadline = time.monotonic() + _HEALTH_TIMEOUT_SECONDS
    url = f"http://localhost:{port}/healthz"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            # Not answering yet — expected while the stack starts; poll again.
            pass
        time.sleep(_HEALTH_POLL_SECONDS)
    return False


def main() -> None:
    print("debcontrol setup — press Enter to accept a default shown in [brackets].\n")

    docker_path = _require_docker()

    env_existed = ENV_PATH.exists()
    if env_existed and not _prompt_yes_no(
        ".env already exists. Overwrite it with a freshly configured one? "
        "(no just tops it up with any new .env.example variables and starts the stack)",
        default=False,
    ):
        _sync_and_start(docker_path)
        return

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

    print()
    locale_codes = [locale.code for locale in available_locales()]
    print("Available languages: " + ", ".join(
        f"{locale.code} ({locale.label})" for locale in available_locales()
    ))
    default_locale = _prompt(
        "Default language for accounts that haven't picked one "
        "(anyone can still switch for themselves later, in My account)",
        default="en",
    )
    if default_locale not in locale_codes:
        print(f"  (unrecognized code {default_locale!r} — falling back to English)")
        default_locale = "en"
    lines = _set_env_line(lines, "DEFAULT_LANGUAGE", default_locale)

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
    # Bundled Caddy reaches `web` over the compose network regardless of
    # this — it never needs the published host port at all — so anyone
    # using it almost always wants the app port itself restricted to this
    # host only. Someone with no reverse proxy at all still needs it
    # reachable from wherever their browser is, so the default flips the
    # other way for them.
    localhost_only = _prompt_yes_no(
        "Only allow local connections to the app's own port (recommended if "
        "a reverse proxy — bundled Caddy or your own — is the only thing "
        "that should reach it directly)?",
        default=use_caddy,
    )
    lines = _set_env_line(
        lines,
        "APP_BIND_ADDRESS",
        "127.0.0.1" if localhost_only else "0.0.0.0",  # noqa: S104 - explicit user choice, not a default
    )

    print()
    facts_interval = _prompt("Facts refresh interval, in seconds", default="3600")
    reachability_interval = _prompt("Reachability check interval, in seconds", default="60")
    lines = _set_env_line(lines, "FACTS_REFRESH_INTERVAL_SECONDS", facts_interval)
    lines = _set_env_line(
        lines, "REACHABILITY_CHECK_INTERVAL_SECONDS", reachability_interval
    )

    print()
    admin_password = _prompt_admin_password()

    print()
    port = _prompt("Host port to publish the app on", default="8080")
    lines = _set_env_line(lines, "APP_PORT", port)

    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n==> Wrote {ENV_PATH}")

    compose_files = ["-f", "docker-compose.yml"]
    if use_caddy:
        compose_files += ["-f", "docker-compose.caddy.yml"]

    # We just generated a fresh POSTGRES_PASSWORD/REDIS_PASSWORD above, but
    # Postgres only ever applies POSTGRES_PASSWORD while initializing an
    # *empty* data directory — if a `pg_data` volume already exists from an
    # earlier attempt (this script run before and got this far, a manual
    # `docker compose up` before ever running this script, one that failed
    # partway through and had its `.env` deleted by hand before rerunning,
    # ...), it still has the old password baked in, and every container that
    # connects with the new one fails with "password authentication failed"
    # the moment `migrate` tries to connect — regardless of whether `.env`
    # itself already existed a moment ago (`env_existed` above only tracks
    # the *file*, not whatever Docker volumes are separately still sitting
    # on disk from any earlier attempt). Since new secrets are always being
    # written at this point in the script, always drop any previous
    # containers/volumes first so they start from a clean, matching state —
    # a harmless no-op if there's nothing to remove.
    print("==> Removing any previous containers/volumes so the new secrets "
          "start from a clean database...")
    subprocess.run(  # noqa: S603 - fixed args, no user input
        [docker_path, "compose", *compose_files, "down", "-v"],
        cwd=REPO_ROOT,
        check=False,
    )

    _compose_up(docker_path, compose_files)

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
    print("Password: the one you entered")
    print("You'll be asked to change it on first login.")
    print("=" * 64)


if __name__ == "__main__":
    main()
