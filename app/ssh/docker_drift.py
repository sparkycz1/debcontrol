"""Drift of a stack debcontrol manages: what is on the machine against what
was deployed (`app.services.docker_drift`). Reads only, changes nothing.

The script prints, for the stack's directory:

- `@@DC_FILE <name> <sha256|->` for the files debcontrol wrote there
  (`compose.yaml` for a stack written in debcontrol, and `.env`);
- `@@DC_HEAD <commit>` for a Git stack: the commit checked out in `repo/`
  (read from `.git/HEAD`, so git need not be installed on the machine);
- `@@DC_SVC <service> <hash>` for each service, the configuration hash
  `docker compose config --hash` computes from the files there now;
- `@@DC_CTR <service>|<hash>|<name>|<state>` for each container of the
  project, with the configuration hash Compose stored on it when it
  created it (`com.docker.compose.config-hash`).

A container whose hash differs from its service's was created from
other settings than the files say (someone changed them, or ran
`docker run` / `docker compose up` by hand); a service without a
container, or a container without a service, is drift too.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.ssh.docker_cli import DockerCommandError, is_project_name_valid, q
from app.ssh.docker_compose import normalize_compose_path, stack_dir_shell


def build_drift_script(name: str, directory: str, compose_paths: list[str], *, git: bool) -> str:
    """`compose_paths`: the compose files inside the stack directory
    (`compose.yaml`, or `repo/<path>` for Git)."""
    if not is_project_name_valid(name):
        raise DockerCommandError(f'"{name}" is not a valid stack name.')
    if not compose_paths or any(normalize_compose_path(p) != p for p in compose_paths):
        raise DockerCommandError("Invalid compose file path.")
    files = " ".join(f'-f "$dir"/{q(path)}' for path in compose_paths)
    project = q(name)
    lines = [
        "set -u",
        f"dir={stack_dir_shell(name, directory)}",
        "[ -d \"$dir\" ] || { echo '@@DC_NODIR'; exit 0; }",
        'h() { if [ -f "$1" ]; then sha256sum < "$1" | cut -c1-64; else echo -; fi; }',
    ]
    if not git:
        lines.append('echo "@@DC_FILE compose.yaml $(h "$dir/compose.yaml")"')
    lines.append('echo "@@DC_FILE .env $(h "$dir/.env")"')
    if git:
        lines.append('echo "@@DC_HEAD $(head -c 80 "$dir/repo/.git/HEAD" 2>/dev/null)"')
    lines += [
        'cd "$dir" || exit 1',
        f'out="$($D compose -p {project} {files} --env-file "$dir/.env" config --hash "*" 2>&1)" '
        "&& printf '%s\\n' \"$out\" | sed 's/^/@@DC_SVC /' "
        "|| { echo '@@DC_CONFIG_FAILED'; printf '%s\\n' \"$out\" | tail -n 3; }",
        f"$D ps -a --filter label=com.docker.compose.project={project} "
        "--filter label=com.docker.compose.oneoff=False "
        "--format '@@DC_CTR {{.Label \"com.docker.compose.service\"}}|"
        "{{.Label \"com.docker.compose.config-hash\"}}|{{.Names}}|{{.State}}'",
    ]
    return "\n".join(lines) + "\n"


@dataclass
class DriftReading:
    """What the script found."""

    no_directory: bool = False
    files: dict[str, str] = field(default_factory=dict)
    head: str = ""
    config_failed: bool = False
    config_error: str = ""
    services: dict[str, str] = field(default_factory=dict)
    # (service, hash, container name, state)
    containers: list[tuple[str, str, str, str]] = field(default_factory=list)


def parse_drift_output(raw: str) -> DriftReading:
    reading = DriftReading()
    lines = raw.splitlines()
    for index, line in enumerate(lines):
        if line == "@@DC_NODIR":
            reading.no_directory = True
        elif line.startswith("@@DC_FILE "):
            parts = line.split()
            if len(parts) == 3:
                reading.files[parts[1]] = parts[2]
        elif line.startswith("@@DC_HEAD"):
            reading.head = line[len("@@DC_HEAD") :].strip()[:80]
        elif line.startswith("@@DC_SVC "):
            parts = line[len("@@DC_SVC ") :].split()
            if len(parts) == 2:
                reading.services[parts[0]] = parts[1]
        elif line == "@@DC_CONFIG_FAILED":
            reading.config_failed = True
            reading.config_error = " ".join(
                rest for rest in lines[index + 1 : index + 4] if not rest.startswith("@@DC_")
            )[-400:]
        elif line.startswith("@@DC_CTR "):
            parts = line[len("@@DC_CTR ") :].split("|")
            if len(parts) == 4:
                service, config_hash, container, state = parts
                reading.containers.append((service, config_hash, container, state))
    return reading
