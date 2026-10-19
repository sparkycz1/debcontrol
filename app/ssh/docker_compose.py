"""Compose stacks on a machine: acting on any project (start, stop,
restart, pull and recreate, take down), reading its compose file, and
deploying the stacks debcontrol manages itself.

**A project debcontrol found** is acted on with its own files, from its
own directory (the `com.docker.compose.project.*` labels its containers
carry, or `docker compose ls`). Start/stop/restart/down work from the
project name alone, so they still work when the files are gone.

**A stack debcontrol manages** lives in
`~/.local/share/debcontrol/stacks/<name>/` of the account debcontrol
connects as — no root needed to write it, only to run `docker compose`
(which the Docker grant covers) — or in a directory chosen when the
stack is made (`normalize_stack_directory`), which that account must be
able to write. A chosen directory is marked with `.debcontrol-stack`
(holding the stack's name): a deploy refuses one that already holds
other files (or another stack), and removing the stack deletes only what
debcontrol wrote there, never the directory's other content:

- written in debcontrol: `compose.yaml` and `.env`, as stored;
- from Git: the repository, shallow-cloned into `repo/` by git in a helper
  container (`docker_cli.GIT_IMAGE`) running as the same account, plus
  `.env` next to it — the `.env` never goes into the repository.

Only HTTPS repositories are accepted (`is_git_url_valid`), with an
optional access token for a private one. The token reaches git through a
credential helper reading an environment variable, from an `--env-file`
written with mode 600 and removed again; never a command line or the
repository's config.

The deploy script carries the `.env` and the token, so it is only ever
sent on standard input and kept with mode 600 (`app.ssh.detached_jobs`).
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from app.ssh.docker_cli import (
    BUSYBOX_IMAGE,
    GIT_IMAGE,
    HELPER_LABEL,
    DockerCommandError,
    is_project_name_valid,
    q,
)

StackAction = Literal["up", "update", "restart", "stop", "start", "down"]
STACK_ACTIONS: tuple[StackAction, ...] = ("up", "update", "restart", "stop", "start", "down")
# Actions that need the project's files; the rest work from its name.
_NEEDS_FILES = {"up", "update"}

STACKS_DIR = '"${HOME:-/tmp}/.local/share/debcontrol/stacks"'
# Written into a stack's directory; a chosen directory without it that
# already has files in it is someone else's and is left alone.
STACK_MARKER = ".debcontrol-stack"
# A compose file or .env larger than this is refused (a typo, not a stack).
MAX_FILE_BYTES = 512 * 1024

_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$")


def is_git_url_valid(url: str) -> bool:
    """An `https://host/path` repository address — no credentials in it, no
    other scheme (git's `ext::`, `file://`, ssh), no whitespace."""
    if not url or len(url) > 512 or any(c.isspace() for c in url) or url.startswith("-"):
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and bool(_HOST_RE.match(parts.netloc))
        and "@" not in parts.netloc
        and bool(parts.path.strip("/"))
        and not parts.query
        and not parts.fragment
        and "'" not in url
        and '"' not in url
    )


def is_branch_valid(branch: str) -> bool:
    return bool(_BRANCH_RE.match(branch)) and ".." not in branch and not branch.endswith(".lock")


def normalize_compose_path(path: str) -> str | None:
    """A relative path inside the repository, or None."""
    cleaned = path.strip().lstrip("/")
    if not cleaned or len(cleaned) > 255 or "\0" in cleaned or "\\" in cleaned:
        return None
    normalized = posixpath.normpath(cleaned)
    if normalized == "." or normalized == ".." or normalized.startswith("../"):
        return None
    if not re.match(r"^[A-Za-z0-9._/ -]+$", normalized):
        return None
    return normalized


_STACK_DIR_RE = re.compile(r"^[A-Za-z0-9._/ @+-]+$")
# System directories a stack never goes into (or under).
_SYSTEM_DIRS = (
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc",
    "/run", "/sbin", "/sys", "/usr", "/var/lib/docker", "/var/lib/containerd",
)
# Directories that are fine to be under, but not to be the stack itself.
_TOO_BROAD = (
    "/", "/home", "/root", "/var", "/var/lib", "/opt", "/srv", "/mnt", "/media",
    "/tmp",  # noqa: S108 - refused as a stack directory, never written to
)


def normalize_stack_directory(value: str) -> str | None:
    """Where a new stack's files go: "" (the default,
    `STACKS_DIR/<name>`), an absolute path, or `~/...` in the SSH
    account's home. None when it is not acceptable: relative, `..`,
    unusual characters, a system directory or a too broad one."""
    value = value.strip()
    if not value:
        return ""
    if len(value) > 1024 or "\0" in value:
        return None
    home = value == "~" or value.startswith("~/")
    path = "/" + value[2:] if home else value
    if not path.startswith("/") or ".." in path.split("/"):
        return None
    normalized = posixpath.normpath(path)
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    if not _STACK_DIR_RE.match(normalized) or normalized.startswith("/-"):
        return None
    if home:
        return None if normalized == "/" else "~" + normalized
    if normalized in _TOO_BROAD or any(
        normalized == d or normalized.startswith(d + "/") for d in _SYSTEM_DIRS
    ):
        return None
    return normalized


def stack_dir_shell(name: str, directory: str = "") -> str:
    """The shell word for a stack's directory (validated again here)."""
    if not directory:
        return f"{STACKS_DIR}/{name}"
    checked = normalize_stack_directory(directory)
    if not checked or checked != directory:
        raise DockerCommandError("Invalid stack directory.")
    if checked.startswith("~/"):
        return '"${HOME:-/tmp}"/' + q(checked[2:])
    return q(checked)


def _compose_base(project: str, working_dir: str = "", files: list[str] | None = None) -> str:
    if not is_project_name_valid(project):
        raise DockerCommandError(f'"{project}" is not a valid Compose project name.')
    command = f"$D compose -p {q(project)}"
    if working_dir:
        command += f" --project-directory {q(working_dir)}"
    for path in files or []:
        command += f" -f {q(path)}"
    return command


def build_stack_action_script(
    project: str,
    action: str,
    *,
    working_dir: str = "",
    files: list[str] | None = None,
    env_file: str = "",
) -> str:
    """One action on one project. `update` pulls every image of the project
    and recreates what changed; `down` removes the containers and networks,
    never the volumes."""
    if action not in STACK_ACTIONS:
        raise DockerCommandError(f'Unknown stack action "{action}".')
    if action in _NEEDS_FILES and not files:
        raise DockerCommandError("This project's compose files are not known.")
    base = _compose_base(project, working_dir if action in _NEEDS_FILES else "", None)
    if action in _NEEDS_FILES:
        base = _compose_base(project, working_dir, files)
        if env_file:
            base += f" --env-file {q(env_file)}"
    prefix = f"cd {q(working_dir)} 2>/dev/null || true; " if working_dir else ""
    commands = {
        "up": f"{base} up -d --remove-orphans",
        "update": f"{base} pull && {base} up -d --remove-orphans",
        "restart": f"{base} restart",
        "stop": f"{base} stop",
        "start": f"{base} start",
        "down": f"{base} down --remove-orphans",
    }
    return prefix + commands[action]


def build_read_file_command(path: str) -> str:
    """Print one compose file (at most `MAX_FILE_BYTES`): as the account
    when it can read it, else through a helper container (the Docker grant
    can read any file anyway, so this hides nothing it could not)."""
    if not path.startswith("/") or "\0" in path or ":" in path or len(path) > 1024:
        raise DockerCommandError("Not an absolute path.")
    quoted = q(path)
    return (
        f"if [ -r {quoted} ]; then head -c {MAX_FILE_BYTES} {quoted}; "
        f"else $D run --rm --pull missing --label {HELPER_LABEL} -v {quoted}:/dc-file:ro "
        f"{BUSYBOX_IMAGE} head -c {MAX_FILE_BYTES} /dc-file; fi"
    )


def build_write_file_script(
    project: str, path: str, *, working_dir: str = "", files: list[str]
) -> str:
    """Replace one compose file of a project found on the machine with the
    text on standard input, then have `docker compose config` check the
    whole project; when it doesn't pass, the old text is put back. The
    file is written in place, so it keeps its owner and mode: as the
    account when it may write it, else through a helper container (the
    Docker grant can write any file anyway). Prints `@@DC_DONE`, or
    `@@DC_FAILED read|write|config`."""
    if not path.startswith("/") or "\0" in path or ":" in path or len(path) > 1024:
        raise DockerCommandError("Not an absolute path.")
    if path not in files:
        raise DockerCommandError("Not one of the project's compose files.")
    quoted = q(path)
    helper = f"$D run --rm --pull missing --label {HELPER_LABEL}"
    check = _compose_base(project, working_dir, files) + " config -q"
    prefix = f"cd {q(working_dir)} 2>/dev/null || true; " if working_dir else ""
    return "\n".join(
        [
            "set -u",
            'new="$(mktemp)"; old="$(mktemp)"; trap \'rm -f "$new" "$old"\' EXIT',
            f'head -c {MAX_FILE_BYTES + 1} > "$new"',
            f'[ "$(wc -c < "$new")" -le {MAX_FILE_BYTES} ] || '
            "{ echo 'The file is too large.'; echo '@@DC_FAILED write'; exit 1; }",
            f"if [ -r {quoted} ]; then cat {quoted} > \"$old\"; "
            f'else {helper} -v {quoted}:/dc-file:ro {BUSYBOX_IMAGE} cat /dc-file > "$old"; fi '
            "|| { echo '@@DC_FAILED read'; exit 1; }",
            "put() { "
            f'if [ -w {quoted} ]; then cat "$1" > {quoted}; '
            f"else {helper} -i -v {quoted}:/dc-file {BUSYBOX_IMAGE} "
            "sh -c 'cat > /dc-file' < \"$1\"; fi; }",
            "put \"$new\" || { put \"$old\"; echo '@@DC_FAILED write'; exit 1; }",
            f"{prefix}{check} || "
            "{ put \"$old\"; echo '@@DC_FAILED config'; exit 1; }",
            "echo '@@DC_DONE'",
        ]
    ) + "\n"


# --- Stacks debcontrol manages --------------------------------------------


def _heredoc(marker: str, content: str) -> str:
    if marker in content:
        raise DockerCommandError("The file contains a reserved line.")
    return f"<<'{marker}'\n{content}{'' if content.endswith(chr(10)) else chr(10)}{marker}"


def _check_size(content: str, what: str) -> None:
    if len(content.encode()) > MAX_FILE_BYTES:
        raise DockerCommandError(f"The {what} is too large.")
    if "\0" in content:
        raise DockerCommandError(f"The {what} contains a NUL byte.")


@dataclass(frozen=True)
class GitSource:
    url: str
    branch: str
    compose_path: str
    token: str = ""


def _git_env_file_lines(source: GitSource) -> list[str]:
    username, _, password = source.token.partition(":") if ":" in source.token else ("", "", "")
    if not password:
        username, password = "x-access-token", source.token
    lines = [f"DC_GIT_URL={source.url}", f"DC_GIT_BRANCH={source.branch}"]
    if password:
        lines += [f"DC_GIT_USER={username}", f"DC_GIT_TOKEN={password}"]
    for line in lines:
        if "\n" in line or "\r" in line:
            raise DockerCommandError("Invalid Git settings.")
    return lines


# Runs inside the git helper container, with the settings in its environment.
_GIT_SCRIPT = (
    "set -e; cd /work; "
    'if [ -n "${DC_GIT_TOKEN:-}" ]; then '
    "git config --global credential.helper "
    "'!f() { echo \"username=$DC_GIT_USER\"; echo \"password=$DC_GIT_TOKEN\"; }; f'; fi; "
    "git config --global advice.detachedHead false; "
    'if [ -d repo/.git ]; then git -C repo remote set-url origin "$DC_GIT_URL"; '
    'git -C repo fetch --depth 1 origin "$DC_GIT_BRANCH"; '
    "git -C repo checkout -q -f FETCH_HEAD; git -C repo clean -fdq; "
    'else rm -rf repo; git clone -q --depth 1 --branch "$DC_GIT_BRANCH" -- "$DC_GIT_URL" repo; fi; '
    'echo "@@DC_COMMIT $(git -C repo rev-parse HEAD)"'
)


def _git_run(env_file_var: str, workdir_var: str, script: str, *, pull: str) -> str:
    return (
        f"$D run --rm --pull {pull} --label {HELPER_LABEL} "
        '--user "$(id -u):$(id -g)" -e HOME=/tmp '
        f'--env-file "${env_file_var}" -v "${workdir_var}":/work '
        f"--entrypoint sh {GIT_IMAGE} -c {q(script)}"
    )


def build_deploy_script(
    name: str,
    *,
    compose: str | None = None,
    env: str = "",
    git: GitSource | None = None,
    pull: bool = True,
    directory: str = "",
) -> str:
    """The detached job that writes a managed stack's files and runs
    `docker compose up -d` (after `pull` when asked). Exactly one of
    `compose` (written in debcontrol) and `git` is given; `directory` is
    where they go when it isn't the default."""
    if not is_project_name_valid(name):
        raise DockerCommandError(f'"{name}" is not a valid stack name.')
    if (compose is None) == (git is None):
        raise DockerCommandError("A stack needs a compose file or a Git repository.")
    _check_size(env, ".env file")
    lines = [
        "set -u",
        "umask 077",
        f"dir={stack_dir_shell(name, directory)}",
    ]
    if directory:
        lines.append(
            f'if [ -d "$dir" ] && '
            f'[ "$(cat "$dir/{STACK_MARKER}" 2>/dev/null)" != {q(name)} ] && '
            '[ -n "$(ls -A "$dir" 2>/dev/null)" ]; then '
            'echo "$dir already holds other files; a stack goes into a new or empty directory."; '
            "echo '@@DC_FAILED directory_not_empty'; exit 1; fi"
        )
    lines += [
        "echo '@@DC_STEP files'",
        "mkdir -p \"$dir\" || { echo '@@DC_FAILED files'; exit 1; }",
        'cd "$dir" || exit 1',
        f'printf "%s\\n" {q(name)} > "$dir/{STACK_MARKER}" || '
        "{ echo '@@DC_FAILED files'; exit 1; }",
        f'cat > "$dir/.env" {_heredoc("DC_ENV_END", env)}',
    ]
    if compose is not None:
        _check_size(compose, "compose file")
        lines += [
            f'cat > "$dir/compose.yaml" {_heredoc("DC_COMPOSE_END", compose)}',
            'compose_file="$dir/compose.yaml"',
        ]
    else:
        assert git is not None
        if not is_git_url_valid(git.url) or not is_branch_valid(git.branch):
            raise DockerCommandError("Invalid Git repository or branch.")
        path = normalize_compose_path(git.compose_path)
        if path is None:
            raise DockerCommandError("Invalid compose file path.")
        env_lines = "\n".join(_git_env_file_lines(git)) + "\n"
        lines += [
            'genv="$(mktemp)"; trap \'rm -f "$genv"\' EXIT',
            f'cat > "$genv" {_heredoc("DC_GIT_ENV_END", env_lines)}',
            "echo '@@DC_STEP git'",
            f"{_git_run('genv', 'dir', _GIT_SCRIPT, pull='always')} || "
            "{ echo '@@DC_FAILED git'; exit 1; }",
            'rm -f "$genv"',
            f"compose_file=\"$dir/repo/{path}\"",
            "[ -f \"$compose_file\" ] || { echo '@@DC_FAILED compose_missing'; exit 1; }",
        ]
    compose_cmd = (
        f'$D compose -p {q(name)} -f "$compose_file" --env-file "$dir/.env"'
    )
    lines += [
        "echo '@@DC_STEP config'",
        f"{compose_cmd} config -q || {{ echo '@@DC_FAILED config'; exit 1; }}",
    ]
    if pull:
        lines += [
            "echo '@@DC_STEP pull'",
            # `--ignore-buildable` skips services built on the machine (Compose
            # 2.15+); an older Compose gets a plain pull.
            f"{compose_cmd} pull --ignore-buildable || {compose_cmd} pull || "
            "{ echo '@@DC_FAILED pull'; exit 1; }",
        ]
    lines += [
        "echo '@@DC_STEP up'",
        f"{compose_cmd} up -d --remove-orphans || {{ echo '@@DC_FAILED up'; exit 1; }}",
        "echo '@@DC_DONE'",
    ]
    return "\n".join(lines) + "\n"


def build_remove_script(name: str, *, volumes: bool, directory: str = "") -> str:
    """Take a managed stack down and delete its files; with `volumes` also
    its named volumes (the data — only after a typed confirmation). The
    default directory is debcontrol's own and goes entirely; in a chosen
    one only what debcontrol wrote goes (compose.yaml, .env, the Git
    clone, the marker), and the directory itself only if that empties it."""
    if not is_project_name_valid(name):
        raise DockerCommandError(f'"{name}" is not a valid stack name.')
    flag = " -v" if volumes else ""
    head = (
        f"dir={stack_dir_shell(name, directory)}; "
        f"$D compose -p {q(name)} down --remove-orphans{flag} || exit 1; "
    )
    if not directory:
        # Files git wrote as this account; nothing outside the directory.
        return head + 'rm -rf -- "$dir"; echo @@DC_DONE'
    return head + (
        f'if [ "$(cat "$dir/{STACK_MARKER}" 2>/dev/null)" = {q(name)} ]; then '
        f'rm -rf -- "$dir/compose.yaml" "$dir/.env" "$dir/repo" "$dir/{STACK_MARKER}"; '
        'rmdir -- "$dir" 2>/dev/null || true; fi; echo @@DC_DONE'
    )


def build_remote_head_command(source: GitSource) -> str:
    """The newest commit of the branch, without cloning (`git ls-remote`) —
    the auto-sync check. Prints `@@DC_COMMIT <sha>`."""
    if not is_git_url_valid(source.url) or not is_branch_valid(source.branch):
        raise DockerCommandError("Invalid Git repository or branch.")
    env_lines = "\n".join(_git_env_file_lines(source)) + "\n"
    script = (
        "set -e; "
        'if [ -n "${DC_GIT_TOKEN:-}" ]; then '
        "git config --global credential.helper "
        "'!f() { echo \"username=$DC_GIT_USER\"; echo \"password=$DC_GIT_TOKEN\"; }; f'; fi; "
        'sha="$(git ls-remote -- "$DC_GIT_URL" "refs/heads/$DC_GIT_BRANCH" | cut -f1)"; '
        'echo "@@DC_COMMIT $sha"'
    )
    return (
        'genv="$(mktemp)"; wd="$(mktemp -d)"; trap \'rm -rf "$genv" "$wd"\' EXIT; '
        f'cat > "$genv" {_heredoc("DC_GIT_ENV_END", env_lines)}\n'
        + _git_run("genv", "wd", script, pull="missing")
    )


_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


def parse_commit(raw: str) -> str | None:
    for line in raw.splitlines():
        if line.startswith("@@DC_COMMIT "):
            value = line[len("@@DC_COMMIT ") :].strip()
            return value if _SHA_RE.match(value) else None
    return None


def failed_step(raw: str) -> str | None:
    for line in raw.splitlines():
        if line.startswith("@@DC_FAILED "):
            return line[len("@@DC_FAILED ") :].strip()[:32]
    return None
