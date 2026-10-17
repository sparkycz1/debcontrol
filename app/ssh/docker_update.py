"""Updating one container to the newest image of its tag, and rolling it
back to the image it ran before.

An update runs in two detached jobs (`app.ssh.detached_jobs`), with the
vulnerability gate between them (`app.services.docker_gate`):

1. **Pull** (`build_pull_script`): `docker pull` of the reference the
   container was created from, then, when the gate needs them, scans of
   the new image (and of the running one, when it has no scan yet). Pulling
   changes nothing that runs.
2. **Recreate**, only when the image changed and the gate let it through:
   - a container Compose created is recreated by Compose itself
     (`docker compose up -d --no-deps <service>` in the project's own
     directory, with its own files), so the project's definition stays
     the one source of truth;
   - any other container is recreated from its own `docker inspect`
     (`build_create_payload`), the way Watchtower does it: the same
     configuration, minus what came from the old image's defaults (so the
     new image's defaults apply), created through the Engine API with
     curl in a helper container (the CLI cannot create a container from an
     inspect record). Its volumes, anonymous ones too, are kept.
   The old container is renamed, not removed, until the new one is up; a
   new container that does not start or keeps restarting is removed and
   the old one is renamed back and started again (`build_recreate_script`).

A rollback is the second step alone, after tagging the previous image (by
id) with the container's reference again; the image must still be there.

An update the gate stops tags the old image back, so the reference keeps
pointing at what runs and nothing deploys the stopped image by accident.

Images built on the machine (no registry digest) can't be pulled and are
reported as such.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any

from app.ssh.docker_cli import (
    CURL_IMAGE,
    DOCKER_SOCKET,
    HELPER_LABEL,
    DockerCommandError,
    as_dict,
    as_list,
    is_container_name_valid,
    is_image_id_valid,
    is_image_ref_valid,
    is_network_name_valid,
    is_project_name_valid,
    q,
)
from app.ssh.docker_scan import build_scan_script

# How long a recreated container must stay up before it counts as started.
SETTLE_SECONDS = 15
# Docker's own stop timeout for the old container.
STOP_TIMEOUT_SECONDS = 30


# --- Step 1: pull ------------------------------------------------------------


def build_pull_script(
    ref: str, *, current: str, scan: bool, scan_old: str | None = None
) -> str:
    """Pull `ref`, print its image id before and after; with `scan`, scan
    the new image when it differs from `current` (the image id the
    container runs) — and `scan_old`, an image id, too."""
    if not is_image_ref_valid(ref) or is_image_id_valid(ref) or "@" in ref:
        raise DockerCommandError(f'"{ref}" is not an image reference that can be updated.')
    if not is_image_id_valid(current):
        raise DockerCommandError("Not an image id.")
    if scan_old is not None and not is_image_id_valid(scan_old):
        raise DockerCommandError("Not an image id.")
    lines = [
        f'old="$($D image inspect --format \'{{{{.Id}}}}\' {q(ref)} 2>/dev/null)"',
        'echo "@@DC_OLD_ID $old"',
        f"if ! $D pull {q(ref)}; then echo '@@DC_PULL_FAILED'; exit 2; fi",
        f'new="$($D image inspect --format \'{{{{.Id}}}}\' {q(ref)} 2>/dev/null)"',
        'echo "@@DC_NEW_ID $new"',
    ]
    script = "\n".join(lines) + "\n"
    if scan:
        targets = [ref] + ([scan_old] if scan_old else [])
        # Scanned only when there is a new image: nothing to decide otherwise.
        script += f'if [ -n "$new" ] && [ "$new" != {q(current)} ]; then\n'
        script += build_scan_script(targets) + "fi\n"
    return script


@dataclass
class PullResult:
    old_id: str = ""
    new_id: str = ""
    failed: bool = False

    @property
    def changed(self) -> bool:
        return bool(self.new_id) and self.new_id != self.old_id


def parse_pull_output(raw: str) -> PullResult:
    result = PullResult()
    for line in raw.splitlines():
        if line.startswith("@@DC_OLD_ID"):
            value = line[len("@@DC_OLD_ID") :].strip()
            result.old_id = value if is_image_id_valid(value) else ""
        elif line.startswith("@@DC_NEW_ID"):
            value = line[len("@@DC_NEW_ID") :].strip()
            result.new_id = value if is_image_id_valid(value) else ""
        elif line.strip() == "@@DC_PULL_FAILED":
            result.failed = True
    return result


def build_retag_command(image_id: str, ref: str) -> str:
    """Point `ref` at `image_id` again (a blocked update, a rollback)."""
    if not is_image_id_valid(image_id) or not is_image_ref_valid(ref):
        raise DockerCommandError("Invalid image.")
    return f"$D tag {q(image_id)} {q(ref)}"


# --- What the container is -------------------------------------------------


@dataclass
class ContainerPlan:
    """How a container is updated, from its `docker inspect` record."""

    name: str
    container_id: str
    ref: str
    image_id: str
    running: bool
    compose_project: str = ""
    compose_service: str = ""
    compose_working_dir: str = ""
    compose_files: list[str] = field(default_factory=list)
    # The old image's own repo digests: empty = built on the machine.
    repo_digests: list[str] = field(default_factory=list)

    @property
    def is_compose(self) -> bool:
        return bool(
            self.compose_project
            and self.compose_service
            and self.compose_working_dir
            and self.compose_files
        )


def build_plan_command(name: str) -> str:
    if not is_container_name_valid(name):
        raise DockerCommandError(f'"{name}" is not a valid container name.')
    return (
        f"$D inspect --type container {q(name)} || exit 3; echo '@@DC_SPLIT'; "
        f"img=\"$($D inspect --type container --format '{{{{.Image}}}}' {q(name)})\"; "
        '$D image inspect "$img"'
    )


def parse_plan_output(raw: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """(container inspect, image inspect) — raises `DockerCommandError` when
    either is missing."""
    first, sep, second = raw.partition("@@DC_SPLIT")
    try:
        containers = json.loads(first.strip()) if first.strip() else None
        images = json.loads(second.strip()) if sep and second.strip() else None
    except (ValueError, RecursionError) as exc:
        raise DockerCommandError("Unexpected answer from docker inspect.") from exc
    if not isinstance(containers, list) or not containers or not isinstance(containers[0], dict):
        raise DockerCommandError("No such container.")
    image: dict[str, Any] = {}
    if isinstance(images, list) and images and isinstance(images[0], dict):
        image = images[0]
    return containers[0], image


def plan_from_inspect(container: dict[str, Any], image: dict[str, Any]) -> ContainerPlan:
    config = as_dict(container.get("Config"))
    labels = as_dict(config.get("Labels"))
    state = as_dict(container.get("State"))
    files = str(labels.get("com.docker.compose.project.config_files") or "")
    digests = as_list(image.get("RepoDigests"))
    return ContainerPlan(
        name=str(container.get("Name") or "").lstrip("/"),
        container_id=str(container.get("Id") or ""),
        ref=str(config.get("Image") or ""),
        image_id=str(container.get("Image") or ""),
        running=bool(state.get("Running")),
        compose_project=str(labels.get("com.docker.compose.project") or ""),
        compose_service=str(labels.get("com.docker.compose.service") or ""),
        compose_working_dir=str(labels.get("com.docker.compose.project.working_dir") or ""),
        compose_files=[part for part in files.split(",") if part],
        repo_digests=[str(d) for d in digests if isinstance(d, str)],
    )


# --- Step 2: recreate ------------------------------------------------------

# Config keys whose value the old image supplied when the container did
# not set its own: dropped when they equal the old image's, so the new
# image's apply.
_IMAGE_DEFAULT_KEYS = ("Cmd", "Entrypoint", "WorkingDir", "User", "StopSignal", "Healthcheck")


def build_create_payload(
    container: dict[str, Any], old_image: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """The Engine API `POST /containers/create` body that recreates
    `container` (its `docker inspect` record) on the newest image of its
    reference, and the networks to connect it to after creation (the API
    takes one at creation on older daemons): `[{"name", "aliases",
    "ipv4", "ipv6"}]`."""
    config = copy.deepcopy(container.get("Config") or {})
    host = copy.deepcopy(container.get("HostConfig") or {})
    image_config = (old_image.get("Config") or {}) if isinstance(old_image, dict) else {}
    container_id = str(container.get("Id") or "")
    short_id = container_id[:12]

    # Environment and labels: keep what the container set itself.
    image_env = set(image_config.get("Env") or [])
    env = [item for item in (config.get("Env") or []) if item not in image_env]
    config["Env"] = env or None
    image_labels = image_config.get("Labels") or {}
    labels = {
        key: value
        for key, value in (config.get("Labels") or {}).items()
        if image_labels.get(key) != value
    }
    config["Labels"] = labels
    for key in _IMAGE_DEFAULT_KEYS:
        if key in config and config.get(key) == image_config.get(key):
            config.pop(key, None)
    for key in ("ExposedPorts", "Volumes"):
        own = {
            name: value
            for name, value in (config.get(key) or {}).items()
            if name not in (image_config.get(key) or {})
        }
        config[key] = own or None
    # The old container's id as hostname would stick to the new one.
    if config.get("Hostname") == short_id:
        config.pop("Hostname", None)
    config.pop("MacAddress", None)

    # Keep every volume the old container had — an anonymous one (an
    # image VOLUME, `-v /path`) included, which a new container would
    # otherwise get a fresh, empty copy of.
    binds = list(host.get("Binds") or [])
    mounted = {str(bind).split(":")[1] for bind in binds if ":" in str(bind)}
    mounted |= {
        str(m.get("Target")) for m in (host.get("Mounts") or []) if isinstance(m, dict)
    }
    for mount in container.get("Mounts") or []:
        if not isinstance(mount, dict) or mount.get("Type") != "volume":
            continue
        destination = str(mount.get("Destination") or "")
        name = str(mount.get("Name") or "")
        if not destination or not name or destination in mounted:
            continue
        binds.append(f"{name}:{destination}" + ("" if mount.get("RW", True) else ":ro"))
        mounted.add(destination)
    host["Binds"] = binds or None
    config["HostConfig"] = host

    networks: list[dict[str, Any]] = []
    mode = str(host.get("NetworkMode") or "")
    settings = (container.get("NetworkSettings") or {}).get("Networks") or {}
    if not (mode in ("host", "none") or mode.startswith("container:")):
        for name, endpoint in settings.items():
            if not isinstance(endpoint, dict):
                continue
            aliases = [
                alias
                for alias in (endpoint.get("Aliases") or [])
                if alias and alias != short_id and alias != container_id
            ]
            ipam = endpoint.get("IPAMConfig") or {}
            networks.append(
                {
                    "name": str(name),
                    "aliases": aliases,
                    "ipv4": str(ipam.get("IPv4Address") or ""),
                    "ipv6": str(ipam.get("IPv6Address") or ""),
                }
            )
    # The network the container is created on: its own mode's network when
    # that is one of them, else the first.
    networks.sort(key=lambda n: (n["name"] != mode, n["name"]))
    if networks:
        first = networks[0]
        endpoint_config: dict[str, Any] = {"Aliases": first["aliases"] or None}
        if first["ipv4"] or first["ipv6"]:
            endpoint_config["IPAMConfig"] = {
                key: value
                for key, value in (
                    ("IPv4Address", first["ipv4"]),
                    ("IPv6Address", first["ipv6"]),
                )
                if value
            }
        config["NetworkingConfig"] = {"EndpointsConfig": {first["name"]: endpoint_config}}
    return config, networks[1:]


def _connect_command(network: dict[str, Any]) -> str:
    name = str(network.get("name") or "")
    if not is_network_name_valid(name):
        raise DockerCommandError(f'"{name}" is not a valid network name.')
    options = "".join(
        f" --alias {q(str(alias))}" for alias in network.get("aliases") or [] if alias
    )
    if network.get("ipv4"):
        options += f" --ip {q(str(network['ipv4']))}"
    if network.get("ipv6"):
        options += f" --ip6 {q(str(network['ipv6']))}"
    return f'$D network connect{options} {q(name)} "$name"'


def build_recreate_script(
    plan: ContainerPlan,
    *,
    payload: dict[str, Any] | None = None,
    extra_networks: list[dict[str, Any]] | None = None,
    retag_to: str | None = None,
    previous_image_id: str | None = None,
) -> str:
    """The detached job that replaces the container — by Compose for a
    Compose service, else from `payload` (`build_create_payload`) — and
    puts the old one back when the new one does not stay up. `retag_to`
    (an image id) first points the reference at that image (rollback).
    `previous_image_id` is what a Compose service goes back to when its new
    container does not stay up."""
    if not is_container_name_valid(plan.name):
        raise DockerCommandError("Invalid container name.")
    lines = ["set -u", f"name={q(plan.name)}"]
    if retag_to is not None:
        lines.append(build_retag_command(retag_to, plan.ref) + " || exit 4")
    settle = (
        f"sleep {SETTLE_SECONDS}; "
        "st=\"$($D inspect --format '{{.State.Running}} {{.State.Restarting}} "
        "{{.RestartCount}}' \"$name\" 2>/dev/null)\"; "
        '[ "${st%% *}" = true ] && [ "$(echo "$st" | cut -d" " -f2)" = false ] '
        '&& [ "$(echo "$st" | cut -d" " -f3)" = 0 ]'
    )
    if plan.is_compose:
        if not is_project_name_valid(plan.compose_project):
            raise DockerCommandError("Invalid Compose project name.")
        files = " ".join(f"-f {q(path)}" for path in plan.compose_files)
        compose = (
            f"$D compose -p {q(plan.compose_project)} --project-directory "
            f"{q(plan.compose_working_dir)} {files}"
        )
        lines += [
            f"cd {q(plan.compose_working_dir)} 2>/dev/null || true",
            "echo '@@DC_STEP recreate'",
            f"if ! {compose} up -d --no-deps {q(plan.compose_service)}; then",
            "  echo '@@DC_FAILED compose'; exit 1",
            "fi",
            # Compose names the new container like the old one, by default.
            f'name="$({compose} ps -q {q(plan.compose_service)} | head -n 1)"',
            f"if {settle}; then echo '@@DC_DONE'; exit 0; fi",
            "echo '@@DC_UNSTABLE'; $D logs --tail 40 \"$name\" 2>&1 | sed 's/^/  | /'",
        ]
        if previous_image_id is not None:
            lines += [
                "echo '@@DC_RESTORE'",
                build_retag_command(previous_image_id, plan.ref)
                + f" && {compose} up -d --no-deps {q(plan.compose_service)}",
            ]
        lines.append("exit 1")
        return "\n".join(lines) + "\n"

    if payload is None:
        raise DockerCommandError("Nothing to create the container from.")
    body = json.dumps(payload, separators=(",", ":"))
    if "\n" in body or "DC_PAYLOAD_END" in body:
        raise DockerCommandError("Unexpected container configuration.")
    connects = [_connect_command(n) for n in extra_networks or []]
    backup = f"{plan.name[:200]}-debcontrol-old"
    if not is_container_name_valid(backup):
        raise DockerCommandError("Invalid container name.")
    curl = (
        f"$D run --rm -i --pull missing --label {HELPER_LABEL} --user 0:0 "
        f"-v {DOCKER_SOCKET}:{DOCKER_SOCKET} {CURL_IMAGE} -sS --fail-with-body "
        f"--unix-socket {DOCKER_SOCKET} -H 'Content-Type: application/json' "
        "--data-binary @- \"http://localhost/containers/create?name=$name\""
    )
    lines += [
        f"backup={q(backup)}",
        f"was_running={'1' if plan.running else '0'}",
        (
            'restore() { echo "@@DC_RESTORE"; $D rm -f "$name" >/dev/null 2>&1; '
            '$D rename "$backup" "$name" && { [ "$was_running" = 0 ] || $D start "$name"; }; }'
        ),
        "$D rm -f \"$backup\" >/dev/null 2>&1 || true",
        "echo '@@DC_STEP stop'",
        f'[ "$was_running" = 0 ] || $D stop -t {STOP_TIMEOUT_SECONDS} "$name" || exit 1',
        '$D rename "$name" "$backup" || { [ "$was_running" = 0 ] || $D start "$name"; exit 1; }',
        "echo '@@DC_STEP create'",
        f"answer=\"$({curl} <<'DC_PAYLOAD_END'",
        body,
        "DC_PAYLOAD_END",
        ')"; rc=$?',
        'echo "$answer"',
        'if [ "$rc" != 0 ]; then echo "@@DC_FAILED create"; restore; exit 1; fi',
    ]
    for command in connects:
        lines.append(f'{command} || {{ echo "@@DC_FAILED network"; restore; exit 1; }}')
    lines += [
        "echo '@@DC_STEP start'",
        'if [ "$was_running" = 1 ]; then',
        '  if ! $D start "$name"; then echo "@@DC_FAILED start"; restore; exit 1; fi',
        f"  if ! {{ {settle}; }}; then",
        "    echo '@@DC_UNSTABLE'; $D logs --tail 40 \"$name\" 2>&1 | sed 's/^/  | /'",
        "    restore; exit 1",
        "  fi",
        "fi",
        '$D rm "$backup" >/dev/null 2>&1 || true',
        "echo '@@DC_DONE'",
    ]
    return "\n".join(lines) + "\n"


@dataclass
class RecreateResult:
    done: bool
    restored: bool
    failed_step: str
    unstable: bool


def parse_recreate_output(raw: str) -> RecreateResult:
    failed = ""
    for line in raw.splitlines():
        if line.startswith("@@DC_FAILED "):
            failed = line.split(" ", 1)[1].strip()[:32]
    return RecreateResult(
        done="@@DC_DONE" in raw,
        restored="@@DC_RESTORE" in raw,
        failed_step=failed,
        unstable="@@DC_UNSTABLE" in raw,
    )
