"""Taking an existing Compose project or a `docker run` container under
debcontrol's management (`app.services.docker_adopt`).

- `build_project_read_script` reads a project's compose file(s) and its
  `.env` (base64, so no content can be mistaken for a marker), and says
  whether debcontrol's account can write the project directory. With
  several compose files it prints `docker compose config
  --no-interpolate` instead: one merged file, variables left as they are
  (so no secret from the environment ends up in it).
- `build_mark_script` writes the `.debcontrol-stack` marker into the
  project directory — the only change adoption makes on the machine; the
  first deploy then writes `compose.yaml` and `.env` next to the
  project's own files.
- `build_stack_files_read_script` reads a managed stack's `compose.yaml`
  and `.env` back from the machine (to take over changes made there).
"""

from __future__ import annotations

import base64
import binascii

from app.ssh.docker_cli import (
    BUSYBOX_IMAGE,
    HELPER_LABEL,
    DockerCommandError,
    is_project_name_valid,
    q,
)
from app.ssh.docker_compose import MAX_FILE_BYTES, STACK_MARKER, stack_dir_shell


def _check_path(path: str) -> None:
    if not path.startswith("/") or "\0" in path or ":" in path or len(path) > 1024:
        raise DockerCommandError("Not an absolute path.")


def _read_b64(path_word: str) -> str:
    """Shell: print the file (at most MAX_FILE_BYTES) as one base64 line;
    through a helper container when the account can't read it."""
    return (
        f"if [ -r {path_word} ]; then head -c {MAX_FILE_BYTES} {path_word}; "
        f"else $D run --rm --pull missing --label {HELPER_LABEL} -v {path_word}:/dc-file:ro "
        f"{BUSYBOX_IMAGE} head -c {MAX_FILE_BYTES} /dc-file; fi | base64 | tr -d '\\n'"
    )


def build_project_read_script(project: str, working_dir: str, files: list[str]) -> str:
    if not is_project_name_valid(project):
        raise DockerCommandError(f'"{project}" is not a valid Compose project name.')
    _check_path(working_dir)
    if not files or len(files) > 10:
        raise DockerCommandError("This project's compose files are not known.")
    for path in files:
        _check_path(path)
    wd = q(working_dir)
    env = q(working_dir.rstrip("/") + "/.env")
    lines = ["set -u", f"[ -d {wd} ] || {{ echo '@@DC_NODIR'; exit 0; }}"]
    if len(files) == 1:
        lines.append(f'echo "@@DC_COMPOSE $({_read_b64(q(files[0]))})"')
    else:
        args = " ".join(f"-f {q(path)}" for path in files)
        lines.append(
            f'out="$(cd {wd} && $D compose -p {q(project)} --project-directory {wd} {args} '
            'config --no-interpolate 2>&1)" '
            "|| { echo '@@DC_CONFIG_FAILED'; printf '%s\\n' \"$out\" | tail -n 3; exit 0; }; "
            "echo \"@@DC_COMPOSE $(printf '%s\\n' \"$out\" | head -c "
            f"{MAX_FILE_BYTES} | base64 | tr -d '\\n')\""
        )
    lines += [
        f'if [ -e {env} ]; then echo "@@DC_ENV $({_read_b64(env)})"; fi',
        f"[ -w {wd} ] && echo '@@DC_WRITABLE'",
        f"[ -e {wd}/{STACK_MARKER} ] && echo '@@DC_MARKED'",
        "true",
    ]
    return "\n".join(lines) + "\n"


def build_mark_script(name: str, directory: str) -> str:
    """Write the marker that lets the stack's deploys use `directory`."""
    if not is_project_name_valid(name):
        raise DockerCommandError(f'"{name}" is not a valid stack name.')
    return (
        f"dir={stack_dir_shell(name, directory)}; "
        f'if [ -e "$dir/{STACK_MARKER}" ] && [ "$(cat "$dir/{STACK_MARKER}")" != {q(name)} ]; '
        "then echo '@@DC_FAILED marked'; exit 1; fi; "
        f'printf "%s\\n" {q(name)} > "$dir/{STACK_MARKER}" && echo @@DC_DONE'
    )


def build_stack_files_read_script(name: str, directory: str) -> str:
    if not is_project_name_valid(name):
        raise DockerCommandError(f'"{name}" is not a valid stack name.')
    return "\n".join(
        [
            "set -u",
            f"dir={stack_dir_shell(name, directory)}",
            "[ -d \"$dir\" ] || { echo '@@DC_NODIR'; exit 0; }",
            'if [ -f "$dir/compose.yaml" ]; then '
            f'echo "@@DC_COMPOSE $(head -c {MAX_FILE_BYTES} "$dir/compose.yaml" | base64 | tr -d '
            "'\\n')\"; fi",
            'if [ -f "$dir/.env" ]; then '
            f'echo "@@DC_ENV $(head -c {MAX_FILE_BYTES} "$dir/.env" | base64 | tr -d '
            "'\\n')\"; fi",
            "true",
        ]
    ) + "\n"


def _decode(value: str) -> str | None:
    try:
        return base64.b64decode(value.strip(), validate=True).decode()
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def parse_read_output(raw: str) -> dict[str, object]:
    """{"compose", "env", "writable", "marked", "no_directory",
    "config_error"} from either read script."""
    out: dict[str, object] = {
        "compose": None,
        "env": None,
        "writable": False,
        "marked": False,
        "no_directory": False,
        "config_error": None,
    }
    lines = raw.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("@@DC_COMPOSE"):
            out["compose"] = _decode(line[len("@@DC_COMPOSE") :])
        elif line.startswith("@@DC_ENV"):
            out["env"] = _decode(line[len("@@DC_ENV") :])
        elif line == "@@DC_WRITABLE":
            out["writable"] = True
        elif line == "@@DC_MARKED":
            out["marked"] = True
        elif line == "@@DC_NODIR":
            out["no_directory"] = True
        elif line == "@@DC_CONFIG_FAILED":
            out["config_error"] = " ".join(lines[index + 1 : index + 4])[-400:]
    return out
