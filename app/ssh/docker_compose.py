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

A repository is reached over HTTPS (`is_git_url_valid`), with an optional
access token for a private one, or over SSH (`is_ssh_git_url_valid`) with
a deploy key. The token reaches git through a credential helper reading
an environment variable, from an `--env-file` written with mode 600 and
removed again; never a command line or the repository's config. The
deploy key and the repository host's known_hosts lines go into a mode-700
temporary directory mounted into the helper; ssh runs with
`StrictHostKeyChecking=yes` once a host key is pinned, and records it
(`accept-new`, printed as `@@DC_HOSTKEY`) on the first connection.

**Deploy safety** (`build_stack_script`): with a health check, `up` is
followed by waiting for every container to run and be healthy, and a
failure deploys the previous version again (`@@DC_ROLLED_BACK`). For the
vulnerability gate a deploy stops before `up` (`@@DC_PREPARED`, with the
old and new image of each tag), and either continues
(`build_stack_up_script`) or is undone (`build_stack_restore_script`).
`build_stack_check_script` shows what a deploy would change and runs
`docker compose config` on the new files, changing nothing.

The deploy script carries the `.env`, the token and the deploy key, so it
is only ever sent on standard input and kept with mode 600
(`app.ssh.detached_jobs`).
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
    is_image_id_valid,
    is_image_ref_valid,
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

_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}\Z")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?\Z")


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
    if not re.match(r"^[A-Za-z0-9._/ -]+\Z", normalized):
        return None
    return normalized


_STACK_DIR_RE = re.compile(r"^[A-Za-z0-9._/ @+-]+\Z")
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
    # No name that starts or ends with a space (it would not survive a re-check).
    if any(part != part.strip() for part in normalized.split("/")):
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
    # More compose files in the repository, applied after `compose_path`.
    overrides: tuple[str, ...] = ()
    # An SSH repository address: the deploy key (OpenSSH private key) and
    # the host's known_hosts lines ("" = record them on this connection).
    ssh_key: str = ""
    known_hosts: str = ""
    # Deploy exactly this commit instead of the branch's newest (a rollback).
    commit: str = ""

    @property
    def is_ssh(self) -> bool:
        return is_ssh_git_url_valid(self.url)

    def compose_paths(self) -> list[str]:
        return [self.compose_path, *self.overrides]


MAX_COMPOSE_OVERRIDES = 5
MAX_KNOWN_HOSTS_BYTES = 8 * 1024
_SSH_USER_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._-]{0,63}\Z")
_SSH_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z")
_SSH_PATH_RE = re.compile(r"^[A-Za-z0-9._~][A-Za-z0-9._~/-]{0,400}\Z")
_SCP_RE = re.compile(r"^(?P<user>[^@:/]{1,64})@(?P<host>[^@:/]{1,253}):(?P<path>[^:]{1,401})\Z")
_KNOWN_HOST_RE = re.compile(
    r"^[^\s#]{1,1024} (ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|"
    r"ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) "
    r"[A-Za-z0-9+/]{16,2048}={0,2}( [^\n]{0,200})?\Z"
)
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?\Z")


def is_ssh_git_url_valid(url: str) -> bool:
    """An SSH repository address — `git@host:owner/repo.git` or
    `ssh://git@host[:port]/owner/repo.git` — with a user, plain host and
    path characters only: nothing git or ssh would read as an option or
    a command (`-oProxyCommand=...`, `ext::`)."""
    if not url or len(url) > 512 or any(c.isspace() for c in url) or url.startswith("-"):
        return False
    if url.startswith("ssh://"):
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return False
        if parts.query or parts.fragment or parts.password is not None or not parts.username:
            return False
        host = parts.hostname or ""
        path = parts.path.lstrip("/")
        return (
            bool(_SSH_USER_RE.match(parts.username))
            and bool(_SSH_HOST_RE.match(host))
            and (port is None or 0 < port < 65536)
            and bool(_SSH_PATH_RE.match(path))
            and ".." not in path.split("/")
        )
    match = _SCP_RE.match(url)
    if match is None:
        return False
    path = match.group("path").lstrip("/")
    return (
        bool(_SSH_USER_RE.match(match.group("user")))
        and bool(_SSH_HOST_RE.match(match.group("host")))
        and bool(_SSH_PATH_RE.match(path))
        and ".." not in path.split("/")
    )


def is_repository_url_valid(url: str) -> bool:
    return is_git_url_valid(url) or is_ssh_git_url_valid(url)


def normalize_known_hosts(text: str) -> str | None:
    """known_hosts lines as pasted (comments and blank lines dropped), or
    None when a line is not one."""
    if len(text.encode()) > MAX_KNOWN_HOSTS_BYTES or "\0" in text:
        return None
    lines = [line.strip() for line in text.replace("\r\n", "\n").split("\n")]
    kept = [line for line in lines if line and not line.startswith("#")]
    if any(not _KNOWN_HOST_RE.match(line) for line in kept):
        return None
    return "\n".join(kept)


def is_commit_valid(value: str) -> bool:
    return bool(_COMMIT_RE.match(value))


def _check_git(git: GitSource) -> list[str]:
    """The source's compose paths, after checking every part of it."""
    if not is_repository_url_valid(git.url) or not is_branch_valid(git.branch):
        raise DockerCommandError("Invalid Git repository or branch.")
    if git.is_ssh != bool(git.ssh_key):
        raise DockerCommandError("An SSH repository needs a deploy key (and HTTPS none).")
    if git.commit and not is_commit_valid(git.commit):
        raise DockerCommandError("Invalid commit.")
    if git.known_hosts and normalize_known_hosts(git.known_hosts) != git.known_hosts:
        raise DockerCommandError("Invalid known_hosts lines.")
    if len(git.overrides) > MAX_COMPOSE_OVERRIDES:
        raise DockerCommandError("Too many compose files.")
    paths = [normalize_compose_path(path) for path in git.compose_paths()]
    if any(path is None for path in paths):
        raise DockerCommandError("Invalid compose file path.")
    return [path for path in paths if path is not None]


def _git_env_file_lines(source: GitSource, *, deployed: str = "") -> list[str]:
    lines = [f"DC_GIT_URL={source.url}", f"DC_GIT_BRANCH={source.branch}"]
    if source.commit:
        lines.append(f"DC_GIT_COMMIT={source.commit}")
    if deployed:
        lines.append(f"DC_GIT_DEPLOYED={deployed}")
    if source.is_ssh:
        # Without known host keys yet, the first connection records them
        # (printed as @@DC_HOSTKEY and kept); from then on they must match.
        strict = "yes" if source.known_hosts else "accept-new"
        lines += ["DC_SSH=1", f"DC_SSH_STRICT={strict}"]
    else:
        username, _, password = (
            source.token.partition(":") if ":" in source.token else ("", "", "")
        )
        if not password:
            username, password = "x-access-token", source.token
        if password:
            lines += [f"DC_GIT_USER={username}", f"DC_GIT_TOKEN={password}"]
    for line in lines:
        if "\n" in line or "\r" in line:
            raise DockerCommandError("Invalid Git settings.")
    return lines


# Runs first inside the git helper container: how to authenticate.
_GIT_AUTH = (
    "set -e; cd /work; "
    'if [ -n "${DC_GIT_TOKEN:-}" ]; then '
    "git config --global credential.helper "
    "'!f() { echo \"username=$DC_GIT_USER\"; echo \"password=$DC_GIT_TOKEN\"; }; f'; fi; "
    'if [ -n "${DC_SSH:-}" ]; then '
    'export GIT_SSH_COMMAND="ssh -i /dc-ssh/key -o IdentitiesOnly=yes -o BatchMode=yes '
    "-o UserKnownHostsFile=/dc-ssh/known_hosts -o StrictHostKeyChecking=$DC_SSH_STRICT\"; fi; "
    "git config --global advice.detachedHead false; "
)
# The host keys recorded on a first SSH connection.
_GIT_HOSTKEYS = (
    'if [ "${DC_SSH_STRICT:-}" = accept-new ] && [ -s /dc-ssh/known_hosts ]; then '
    "sed 's/^/@@DC_HOSTKEY /' /dc-ssh/known_hosts; fi; "
)
# Brings `repo/` to the branch's newest commit, or to DC_GIT_COMMIT (a
# rollback: fetched by its id, or from the branch's recent history when
# the server doesn't hand out single commits).
_GIT_SCRIPT = (
    _GIT_AUTH
    + 'if [ -d repo/.git ]; then git -C repo remote set-url origin "$DC_GIT_URL"; '
    'else rm -rf repo; git init -q repo; git -C repo remote add origin "$DC_GIT_URL"; fi; '
    'if [ -n "${DC_GIT_COMMIT:-}" ]; then '
    'git -C repo fetch -q --depth 1 origin "$DC_GIT_COMMIT" '
    '|| git -C repo fetch -q --depth 500 origin "$DC_GIT_BRANCH"; '
    'git -C repo checkout -q -f "$DC_GIT_COMMIT"; '
    'else git -C repo fetch -q --depth 1 origin "$DC_GIT_BRANCH"; '
    "git -C repo checkout -q -f FETCH_HEAD; fi; "
    "git -C repo clean -fdq; "
    + _GIT_HOSTKEYS
    + 'echo "@@DC_COMMIT $(git -C repo rev-parse HEAD)"'
)
# The check before a deploy: the branch's newest commit in a scratch clone,
# and what changed in the repository since the deployed commit.
_GIT_CHECK_SCRIPT = (
    _GIT_AUTH
    + 'git init -q repo; git -C repo remote add origin "$DC_GIT_URL"; '
    'git -C repo fetch -q --depth 1 origin "$DC_GIT_BRANCH"; '
    "git -C repo checkout -q -f FETCH_HEAD; "
    + _GIT_HOSTKEYS
    + 'echo "@@DC_COMMIT $(git -C repo rev-parse HEAD)"; '
    'if [ -n "${DC_GIT_DEPLOYED:-}" ]; then '
    'if [ "$(git -C repo rev-parse HEAD)" = "$DC_GIT_DEPLOYED" ]; then '
    "echo 'No new commits since the deployed one.'; "
    'elif git -C repo fetch -q --depth 1 origin "$DC_GIT_DEPLOYED" 2>/dev/null; then '
    'git -C repo --no-pager log --oneline -n 20 "$DC_GIT_DEPLOYED..HEAD" 2>/dev/null || true; '
    'git -C repo --no-pager diff --stat "$DC_GIT_DEPLOYED" HEAD; '
    'if [ -n "${DC_GIT_PATHS:-}" ]; then '
    'git -C repo --no-pager diff "$DC_GIT_DEPLOYED" HEAD -- $DC_GIT_PATHS; fi; '
    "else echo 'The deployed commit could not be fetched to compare with.'; fi; fi"
)


def _git_run(env_file_var: str, workdir_var: str, script: str, *, pull: str, ssh: bool) -> str:
    # For SSH: the key and known_hosts in a mode-700 directory, and a passwd
    # line for the account's uid (ssh refuses to run as a uid it can't name).
    ssh_mounts = '-v "$sshd":/dc-ssh -v "$sshd/passwd":/etc/passwd:ro ' if ssh else ""
    return (
        f"$D run --rm --pull {pull} --label {HELPER_LABEL} "
        '--user "$(id -u):$(id -g)" -e HOME=/tmp '
        f'--env-file "${env_file_var}" -v "${workdir_var}":/work {ssh_mounts}'
        f"--entrypoint sh {GIT_IMAGE} -c {q(script)}"
    )


def _git_setup_lines(
    git: GitSource, *, deployed: str = "", paths: list[str] | None = None
) -> list[str]:
    """Shell lines writing the git helper's env file (and, for SSH, its key
    directory) into temporary files removed on exit."""
    env_lines = _git_env_file_lines(git, deployed=deployed)
    if paths:
        env_lines.append("DC_GIT_PATHS=" + " ".join(paths))
    lines = ['genv="$(mktemp)"; sshd="$(mktemp -d)"; trap \'rm -rf "$genv" "$sshd"\' EXIT']
    lines.append(f'cat > "$genv" {_heredoc("DC_GIT_ENV_END", chr(10).join(env_lines) + chr(10))}')
    if git.is_ssh:
        key = git.ssh_key if git.ssh_key.endswith("\n") else git.ssh_key + "\n"
        lines += [
            f'cat > "$sshd/key" {_heredoc("DC_SSH_KEY_END", key)}',
            f'cat > "$sshd/known_hosts" {_heredoc("DC_KNOWN_HOSTS_END", git.known_hosts)}',
            'printf \'dc:x:%s:%s::/tmp:/bin/sh\\n\' "$(id -u)" "$(id -g)" > "$sshd/passwd"',
            'chmod 600 "$sshd/key" "$sshd/known_hosts"; chmod 644 "$sshd/passwd"',
        ]
    return lines


@dataclass(frozen=True)
class StackFiles:
    """What one version of a managed stack is made of: exactly one of
    `compose` (written in debcontrol) and `git`."""

    name: str
    compose: str | None = None
    env: str = ""
    git: GitSource | None = None
    directory: str = ""

    def check(self) -> list[str]:
        """Validates everything; returns the compose files' paths inside
        the stack directory (`repo/...` for Git)."""
        if not is_project_name_valid(self.name):
            raise DockerCommandError(f'"{self.name}" is not a valid stack name.')
        if (self.compose is None) == (self.git is None):
            raise DockerCommandError("A stack needs a compose file or a Git repository.")
        _check_size(self.env, ".env file")
        stack_dir_shell(self.name, self.directory)
        if self.compose is not None:
            _check_size(self.compose, "compose file")
            return ["compose.yaml"]
        assert self.git is not None
        return [f"repo/{path}" for path in _check_git(self.git)]


def _compose_fn(files: StackFiles, paths: list[str]) -> str:
    """`dc`: `docker compose` for the stack's project, files and .env."""
    file_args = " ".join(f'-f "$dir/{path}"' for path in paths)
    return f'dc() {{ $D compose -p {q(files.name)} {file_args} --env-file "$dir/.env" "$@"; }}'


def _write_files_lines(files: StackFiles, paths: list[str]) -> list[str]:
    """Write the stack's files into `$dir` (the Git ones: clone or fetch)."""
    lines: list[str] = []
    if files.directory:
        lines.append(
            f'if [ -d "$dir" ] && '
            f'[ "$(cat "$dir/{STACK_MARKER}" 2>/dev/null)" != {q(files.name)} ] && '
            '[ -n "$(ls -A "$dir" 2>/dev/null)" ]; then '
            'echo "$dir already holds other files; a stack goes into a new or empty directory."; '
            "echo '@@DC_FAILED directory_not_empty'; exit 1; fi"
        )
    lines += [
        "echo '@@DC_STEP files'",
        "mkdir -p \"$dir\" || { echo '@@DC_FAILED files'; exit 1; }",
        'cd "$dir" || exit 1',
        f'printf "%s\\n" {q(files.name)} > "$dir/{STACK_MARKER}" || '
        "{ echo '@@DC_FAILED files'; exit 1; }",
        f'cat > "$dir/.env" {_heredoc("DC_ENV_END", files.env)}',
    ]
    if files.compose is not None:
        lines.append(f'cat > "$dir/compose.yaml" {_heredoc("DC_COMPOSE_END", files.compose)}')
        return lines
    git = files.git
    assert git is not None
    lines += _git_setup_lines(git)
    lines += [
        "echo '@@DC_STEP git'",
        f"{_git_run('genv', 'dir', _GIT_SCRIPT, pull='always', ssh=git.is_ssh)} || "
        "{ echo '@@DC_FAILED git'; exit 1; }",
        'rm -rf "$genv" "$sshd"',
    ]
    for path in paths:
        lines.append(f"[ -f \"$dir/{path}\" ] || {{ echo '@@DC_FAILED compose_missing'; exit 1; }}")
    return lines


# After `up`: wait until every container runs (or exited 0, a one-off job),
# none is unhealthy or restarting, and that holds for three checks in a row.
_HEALTH_FUNCTIONS = r"""dc_restarts() {
  ids="$(dc ps -aq 2>/dev/null)"
  [ -n "$ids" ] || { echo 0; return; }
  $D inspect --format '{{.RestartCount}}' $ids 2>/dev/null | awk '{s+=$1} END {print s+0}'
}
dc_healthy() {
  sleep 5
  base="$(dc_restarts)"; good=0; i=0
  while [ "$i" -lt 36 ]; do
    out="$(dc ps -a --format '{{.Name}}|{{.State}}|{{.Health}}|{{.ExitCode}}')" || return 1
    bad="$(printf '%s\n' "$out" | awk -F'|' \
      '$2=="restarting"||$2=="dead"||$3=="unhealthy"||($2=="exited"&&$4!="0")')"
    if [ -n "$bad" ]; then
      echo "Not running or unhealthy:"; printf '%s\n' "$bad"; return 1
    fi
    if [ "$(dc_restarts)" != "$base" ]; then
      echo "A container restarted after the deploy."; return 1
    fi
    if printf '%s\n' "$out" | awk -F'|' '$3=="starting"||$2=="created"' | grep -q .; then
      good=0
    else
      good=$((good+1))
    fi
    [ "$good" -ge 3 ] && return 0
    i=$((i+1)); sleep 5
  done
  echo "The containers were still starting after 3 minutes."; return 1
}"""


def _up_command(files: StackFiles) -> str:
    # A Git stack may build images from the repository: rebuild them from
    # the new commit (cached layers make an unchanged build quick).
    build = " --build" if files.git is not None else ""
    return f"dc up -d --remove-orphans{build}"


def _restore_lines(previous: StackFiles, *, up: bool) -> list[str]:
    """Put the previous version's files back (and start it with `up`); runs
    in a subshell so its own failure is reported, not fatal."""
    paths = previous.check()
    inner = _write_files_lines(previous, paths)
    inner.append(_compose_fn(previous, paths))
    if up:
        inner.append(f"{_up_command(previous)} || exit 1")
    body = "\n".join(inner)
    return [
        "echo '@@DC_STEP rollback'",
        f"( set -u\n{body}\n) && echo '@@DC_ROLLED_BACK' || echo '@@DC_ROLLBACK_FAILED'",
    ]


def build_stack_script(
    files: StackFiles,
    *,
    pull: bool = True,
    up: bool = True,
    report_images: bool = False,
    health: bool = False,
    previous: StackFiles | None = None,
) -> str:
    """The detached job deploying a managed stack: write its files, check
    them with `docker compose config`, pull (when asked), then `up`.

    - `report_images`: print the image each container runs before the
      pull (`@@DC_OLD <ref> <id>`) and each image the stack uses after it
      (`@@DC_NEW <ref> <id>`) — for the vulnerability gate, which stops
      before `up` (`up=False`) and continues with `build_stack_up_script`.
    - `health`: after `up`, wait for the containers to run and be healthy;
      when they don't and `previous` is given, deploy `previous` again
      (`@@DC_ROLLED_BACK`). The job fails either way.
    """
    paths = files.check()
    lines = ["set -u", "umask 077", f"dir={stack_dir_shell(files.name, files.directory)}"]
    lines += _write_files_lines(files, paths)
    lines += [
        _compose_fn(files, paths),
        "echo '@@DC_STEP config'",
        "dc config -q || { echo '@@DC_FAILED config'; exit 1; }",
    ]
    if report_images:
        lines.append(
            'ids="$(dc ps -aq 2>/dev/null)"; [ -z "$ids" ] || '
            "$D inspect --format '@@DC_OLD {{.Config.Image}} {{.Image}}' $ids 2>/dev/null || true"
        )
    if pull:
        lines += [
            "echo '@@DC_STEP pull'",
            # `--ignore-buildable` skips services built on the machine (Compose
            # 2.15+); an older Compose gets a plain pull.
            "dc pull --ignore-buildable || dc pull || { echo '@@DC_FAILED pull'; exit 1; }",
        ]
    if report_images:
        lines.append(
            "dc config --images 2>/dev/null | while read -r ref; do "
            "id=\"$($D image inspect --format '{{.Id}}' \"$ref\" 2>/dev/null)\"; "
            'echo "@@DC_NEW $ref $id"; done'
        )
    if not up:
        lines.append("echo '@@DC_PREPARED'")
        return "\n".join(lines) + "\n"
    lines += _up_lines(files, health=health, previous=previous)
    return "\n".join(lines) + "\n"


def _up_lines(files: StackFiles, *, health: bool, previous: StackFiles | None) -> list[str]:
    on_failure = ["echo '@@DC_FAILED up'"]
    if health and previous is not None:
        on_failure = [*_restore_lines(previous, up=True), "echo '@@DC_FAILED up'"]
    lines = [
        "echo '@@DC_STEP up'",
        f"if ! {_up_command(files)}; then",
        *on_failure,
        "exit 1; fi",
    ]
    if health:
        unhealthy = ["echo '@@DC_FAILED health'"]
        if previous is not None:
            unhealthy = [*_restore_lines(previous, up=True), "echo '@@DC_FAILED health'"]
        lines += [
            _HEALTH_FUNCTIONS,
            "echo '@@DC_STEP health'",
            "if ! dc_healthy; then",
            *unhealthy,
            "exit 1; fi",
        ]
    lines.append("echo '@@DC_DONE'")
    return lines


def build_stack_up_script(
    files: StackFiles, *, health: bool = False, previous: StackFiles | None = None
) -> str:
    """`up` of files `build_stack_script(up=False)` already wrote and pulled."""
    paths = files.check()
    lines = [
        "set -u",
        "umask 077",
        f"dir={stack_dir_shell(files.name, files.directory)}",
        'cd "$dir" || { echo \'@@DC_FAILED files\'; exit 1; }',
        _compose_fn(files, paths),
    ]
    lines += _up_lines(files, health=health, previous=previous)
    return "\n".join(lines) + "\n"


def build_stack_restore_script(
    name: str, directory: str, previous: StackFiles | None, retag: dict[str, str]
) -> str:
    """After the vulnerability gate stopped a deploy: point each pulled tag
    at the image its container runs again (nothing starts the stopped
    image by accident) and put the previous version's files back."""
    for ref, image_id in retag.items():
        if not is_image_ref_valid(ref) or not is_image_id_valid(image_id):
            raise DockerCommandError("Invalid image.")
    lines = ["set -u", "umask 077", f"dir={stack_dir_shell(name, directory)}"]
    lines += [f"$D tag {q(image_id)} {q(ref)} || true" for ref, image_id in retag.items()]
    if previous is not None:
        lines += _restore_lines(previous, up=False)
    lines.append("echo '@@DC_DONE'")
    return "\n".join(lines) + "\n"


def build_deploy_script(
    name: str,
    *,
    compose: str | None = None,
    env: str = "",
    git: GitSource | None = None,
    pull: bool = True,
    directory: str = "",
) -> str:
    """The plain deploy (no gate, no health check): `build_stack_script`."""
    return build_stack_script(
        StackFiles(name=name, compose=compose, env=env, git=git, directory=directory), pull=pull
    )


def build_stack_check_script(
    files: StackFiles, *, diff: str = "", deployed_commit: str = ""
) -> str:
    """Check a stack before deploying it, changing nothing: print `diff`
    (written in debcontrol: what changed against the deployed version) or,
    for Git, the commits and compose changes since `deployed_commit`; then
    run `docker compose config -q` on the new files with the new `.env`, in
    a scratch directory. Prints `@@DC_CHECK_OK`, or `@@DC_FAILED <step>`."""
    paths = files.check()
    if deployed_commit and not is_commit_valid(deployed_commit):
        raise DockerCommandError("Invalid commit.")
    lines = [
        "set -u",
        "umask 077",
        f"dir={stack_dir_shell(files.name, files.directory)}",
        'tmp="$(mktemp -d)"',
    ]
    if files.compose is not None:
        lines += [
            "trap 'rm -rf \"$tmp\"' EXIT",
            f'cat > "$tmp/.env" {_heredoc("DC_ENV_END", files.env)}',
            f'cat > "$tmp/compose.yaml" {_heredoc("DC_COMPOSE_END", files.compose)}',
            "echo '@@DC_STEP diff'",
            f"cat {_heredoc('DC_DIFF_END', diff or 'No changes against the deployed version.')}",
            # Relative paths in the file mean the stack's own directory.
            'pd="$dir"; [ -d "$pd" ] || pd="$tmp"',
        ]
        check = (
            f'$D compose -p {q(files.name)} --project-directory "$pd" -f "$tmp/compose.yaml" '
            '--env-file "$tmp/.env" config -q'
        )
    else:
        git = files.git
        assert git is not None
        repo_paths = [path.removeprefix("repo/") for path in paths]
        # The compose changes are shown for paths git can take unquoted.
        plain = [path for path in repo_paths if " " not in path]
        setup = _git_setup_lines(git, deployed=deployed_commit, paths=plain)
        # One trap for all the temporary files.
        setup[0] = (
            'genv="$(mktemp)"; sshd="$(mktemp -d)"; '
            "trap 'rm -rf \"$genv\" \"$sshd\" \"$tmp\"' EXIT"
        )
        lines += setup
        lines += [
            f'cat > "$tmp/.env" {_heredoc("DC_ENV_END", files.env)}',
            "echo '@@DC_STEP git'",
            f"{_git_run('genv', 'tmp', _GIT_CHECK_SCRIPT, pull='always', ssh=git.is_ssh)} || "
            "{ echo '@@DC_FAILED git'; exit 1; }",
        ]
        for path in repo_paths:
            lines.append(
                f"[ -f \"$tmp/repo/{path}\" ] || {{ echo '@@DC_FAILED compose_missing'; exit 1; }}"
            )
        file_args = " ".join(f'-f "$tmp/repo/{path}"' for path in repo_paths)
        check = f'$D compose -p {q(files.name)} {file_args} --env-file "$tmp/.env" config -q'
    lines += [
        "echo '@@DC_STEP config'",
        f"{check} || {{ echo '@@DC_FAILED config'; exit 1; }}",
        "echo '@@DC_CHECK_OK'",
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
    the auto-sync check. Prints `@@DC_COMMIT <sha>` (and, on a first SSH
    connection, `@@DC_HOSTKEY` lines)."""
    _check_git(source)
    script = (
        _GIT_AUTH
        + 'sha="$(git ls-remote -- "$DC_GIT_URL" "refs/heads/$DC_GIT_BRANCH" | cut -f1)"; '
        + _GIT_HOSTKEYS
        + 'echo "@@DC_COMMIT $sha"'
    )
    setup = _git_setup_lines(source)
    setup[0] = (
        'genv="$(mktemp)"; sshd="$(mktemp -d)"; wd="$(mktemp -d)"; '
        "trap 'rm -rf \"$genv\" \"$sshd\" \"$wd\"' EXIT"
    )
    run = _git_run("genv", "wd", script, pull="missing", ssh=source.is_ssh)
    return "\n".join(setup) + "\n" + run


def parse_host_keys(raw: str) -> str:
    """The known_hosts lines a first SSH connection recorded, checked."""
    lines = [
        line[len("@@DC_HOSTKEY ") :].strip()
        for line in raw.splitlines()
        if line.startswith("@@DC_HOSTKEY ")
    ]
    return normalize_known_hosts("\n".join(lines)) or ""


def parse_stack_images(raw: str) -> tuple[dict[str, str], dict[str, str]]:
    """(image each container ran before the pull, image each service uses
    after it), both `{ref: image id}`; refs or ids that don't look right
    are left out."""
    old: dict[str, str] = {}
    new: dict[str, str] = {}
    for line in raw.splitlines():
        for prefix, target in (("@@DC_OLD ", old), ("@@DC_NEW ", new)):
            if line.startswith(prefix):
                parts = line[len(prefix) :].split()
                ref = parts[0] if parts else ""
                image_id = parts[1] if len(parts) > 1 else ""
                if is_image_ref_valid(ref):
                    target[ref] = image_id if is_image_id_valid(image_id) else ""
    return old, new


_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?\Z")


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
