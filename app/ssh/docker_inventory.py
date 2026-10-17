"""What is on a machine's Docker, read live when a Docker page needs it:
images, volumes, networks, Compose projects, every container's full
`docker inspect`, and the disk usage summary.

A monitoring sample (`app.ssh.monitoring`) already keeps the container
list with its numbers; this is the rest, which nothing needs on a
schedule. One script prints the requested sections, each after a
`===NAME===` line; the parsers never raise on what they get back — a
section that is missing or garbled is simply empty.

Environment variable *values* never leave the machine: a container's
environment usually holds its secrets. Only the names are kept.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from app.db.models.machine import Machine
from app.ssh.docker_cli import DockerCommandError, as_dict, run_script
from app.ssh.monitoring import (
    COMPOSE_PROJECT_LABEL,
    COMPOSE_SERVICE_LABEL,
    parse_docker_size,
    parse_label_string,
)

COMPOSE_WORKING_DIR_LABEL = "com.docker.compose.project.working_dir"
COMPOSE_CONFIG_FILES_LABEL = "com.docker.compose.project.config_files"
COMPOSE_VOLUME_LABEL = "com.docker.compose.volume"

_SECTIONS: dict[str, str] = {
    "version": "$D version --format '{{.Server.Version}}' 2>/dev/null",
    "images": "$D image ls --no-trunc --format '{{json .}}' 2>/dev/null",
    "inspect": 'ids="$($D ps -aq --no-trunc 2>/dev/null)"; '
    '[ -z "$ids" ] || $D inspect $ids 2>/dev/null',
    "volumes": "$D volume ls --format '{{json .}}' 2>/dev/null",
    "volume_sizes": "$D system df -v --format '{{json .Volumes}}' 2>/dev/null",
    "networks": "$D network ls --no-trunc --format '{{json .}}' 2>/dev/null",
    "compose": "$D compose ls -a --format json 2>/dev/null",
    "df": "$D system df --format '{{json .}}' 2>/dev/null",
}
SECTIONS = tuple(_SECTIONS)


def build_inventory_command(sections: Iterable[str]) -> str:
    wanted = [name for name in SECTIONS if name in set(sections)]
    if not wanted:
        raise DockerCommandError("Nothing to read.")
    return "; ".join(f"echo ==={name.upper()}===; {_SECTIONS[name]}" for name in wanted)


def split_sections(raw: str) -> dict[str, str]:
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    names = {f"==={name.upper()}===": name for name in SECTIONS}
    for line in raw.splitlines():
        name = names.get(line.strip())
        if name is not None:
            current = sections.setdefault(name, [])
        elif current is not None:
            current.append(line)
    return {name: "\n".join(lines) for name, lines in sections.items()}


def _json_lines(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _json_value(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None


def _s(value: Any, limit: int = 512) -> str:
    return str(value)[:limit] if value is not None else ""


def _labels(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(k)[:255]: _s(v, 2048) for k, v in value.items()}
    if isinstance(value, str):
        return parse_label_string(value)
    return {}


def _size(value: Any) -> int | None:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        return parse_docker_size(value.strip())
    return None


@dataclass
class Inventory:
    version: str = ""
    images: list[dict[str, Any]] = field(default_factory=list)
    containers: list[dict[str, Any]] = field(default_factory=list)
    volumes: list[dict[str, Any]] = field(default_factory=list)
    networks: list[dict[str, Any]] = field(default_factory=list)
    compose: list[dict[str, Any]] = field(default_factory=list)
    df: dict[str, dict[str, Any]] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_container(row: dict[str, Any]) -> dict[str, Any] | None:
    """One `docker inspect` entry, reduced to what the pages show."""
    name = _s(row.get("Name"), 256).lstrip("/")
    if not name:
        return None
    config = as_dict(row.get("Config"))
    host = as_dict(row.get("HostConfig"))
    state = as_dict(row.get("State"))
    net_settings = (
        as_dict(row.get("NetworkSettings"))
    )
    labels = _labels(config.get("Labels"))
    mounts: list[dict[str, Any]] = []
    for mount in row.get("Mounts") or []:
        if not isinstance(mount, dict):
            continue
        mounts.append(
            {
                "type": _s(mount.get("Type"), 16),
                "name": _s(mount.get("Name"), 255),
                "source": _s(mount.get("Source"), 1024),
                "destination": _s(mount.get("Destination"), 1024),
                "rw": bool(mount.get("RW", True)),
            }
        )
    networks = net_settings.get("Networks") if isinstance(net_settings, dict) else None
    env_names = sorted(
        {
            str(item).split("=", 1)[0][:255]
            for item in (config.get("Env") or [])
            if isinstance(item, str) and item
        }
    )
    ports: list[str] = []
    raw_ports = net_settings.get("Ports") if isinstance(net_settings, dict) else None
    if isinstance(raw_ports, dict):
        for container_port, bindings in raw_ports.items():
            if not bindings:
                ports.append(_s(container_port, 32))
                continue
            ports.extend(
                f"{_s(binding.get('HostIp'), 64)}:{_s(binding.get('HostPort'), 8)}"
                f"->{_s(container_port, 32)}"
                for binding in (bindings if isinstance(bindings, list) else [])
                if isinstance(binding, dict)
            )
    restart = as_dict(host.get("RestartPolicy"))
    health = as_dict(state.get("Health"))
    return {
        "id": _s(row.get("Id"), 64),
        "name": name,
        "image": _s(config.get("Image")),
        "image_id": _s(row.get("Image"), 80),
        "created": _s(row.get("Created"), 40),
        "state": _s(state.get("Status"), 16),
        "running": bool(state.get("Running")),
        "started_at": _s(state.get("StartedAt"), 40),
        "exit_code": state.get("ExitCode") if isinstance(state.get("ExitCode"), int) else None,
        "health": _s(health.get("Status"), 16),
        "restart_policy": _s(restart.get("Name"), 32),
        "restart_count": row.get("RestartCount")
        if isinstance(row.get("RestartCount"), int)
        else None,
        "privileged": bool(host.get("Privileged")),
        "network_mode": _s(host.get("NetworkMode"), 255),
        "networks": sorted(str(n)[:255] for n in networks) if isinstance(networks, dict) else [],
        "ports": ports,
        "mounts": mounts,
        "env_names": env_names,
        "command": " ".join(str(part) for part in (config.get("Cmd") or []))[:1024]
        if isinstance(config.get("Cmd"), list)
        else "",
        "compose_project": labels.get(COMPOSE_PROJECT_LABEL, "")[:255],
        "compose_service": labels.get(COMPOSE_SERVICE_LABEL, "")[:255],
        "compose_working_dir": labels.get(COMPOSE_WORKING_DIR_LABEL, "")[:1024],
        "compose_config_files": [
            part
            for part in labels.get(COMPOSE_CONFIG_FILES_LABEL, "")[:4096].split(",")
            if part
        ],
        "labels": dict(sorted(labels.items())[:200]),
    }


def _parse_images(text: str, in_use: set[str]) -> list[dict[str, Any]]:
    images: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in _json_lines(text):
        image_id = _s(row.get("ID"), 80)
        if not image_id:
            continue
        repository = _s(row.get("Repository"), 255)
        tag = _s(row.get("Tag"), 128)
        key = (image_id, f"{repository}:{tag}")
        if key in seen:
            continue
        seen.add(key)
        dangling = repository in ("", "<none>")
        ref = "" if dangling else (repository if tag in ("", "<none>") else f"{repository}:{tag}")
        images.append(
            {
                "id": image_id if image_id.startswith("sha256:") else f"sha256:{image_id}",
                "repository": "" if dangling else repository,
                "tag": "" if tag in ("", "<none>") else tag,
                "ref": ref,
                "digest": "" if _s(row.get("Digest")) == "<none>" else _s(row.get("Digest"), 80),
                "size_bytes": _size(row.get("Size")),
                "created": _s(row.get("CreatedAt"), 40),
                "dangling": dangling,
            }
        )
    for image in images:
        image["in_use"] = image["id"] in in_use
    images.sort(key=lambda i: (not i["in_use"], i["ref"] or "~", i["id"]))
    return images


def _parse_volumes(
    text: str, sizes_text: str | None, containers: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    sizes: dict[str, tuple[int | None, int | None]] = {}
    value = _json_value(sizes_text or "")
    if isinstance(value, list):
        for row in value:
            if isinstance(row, dict) and row.get("Name"):
                links = row.get("Links")
                sizes[_s(row.get("Name"), 255)] = (
                    _size(row.get("Size")),
                    int(str(links)) if str(links).isdigit() else None,
                )
    used_by: dict[str, list[str]] = {}
    for container in containers:
        for mount in container.get("mounts", []):
            if mount.get("type") == "volume" and mount.get("name"):
                used_by.setdefault(mount["name"], []).append(container["name"])
    volumes: list[dict[str, Any]] = []
    for row in _json_lines(text):
        name = _s(row.get("Name"), 255)
        if not name:
            continue
        labels = _labels(row.get("Labels"))
        size, links = sizes.get(name, (None, None))
        volumes.append(
            {
                "name": name,
                "driver": _s(row.get("Driver"), 64),
                "size_bytes": size,
                "links": links,
                "compose_project": labels.get(COMPOSE_PROJECT_LABEL, "")[:255],
                "anonymous": len(name) == 64
                and all(c in "0123456789abcdef" for c in name)
                and COMPOSE_VOLUME_LABEL not in labels,
                "used_by": sorted(used_by.get(name, [])),
            }
        )
    volumes.sort(key=lambda v: (v["anonymous"], v["name"]))
    return volumes


def _parse_networks(text: str, containers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    members: dict[str, list[str]] = {}
    for container in containers:
        for network in container.get("networks", []):
            members.setdefault(network, []).append(container["name"])
    networks: list[dict[str, Any]] = []
    for row in _json_lines(text):
        name = _s(row.get("Name"), 255)
        if not name:
            continue
        networks.append(
            {
                "id": _s(row.get("ID"), 64),
                "name": name,
                "driver": _s(row.get("Driver"), 64),
                "scope": _s(row.get("Scope"), 16),
                "internal": _s(row.get("Internal")).lower() == "true",
                "builtin": name in ("bridge", "host", "none"),
                "containers": sorted(members.get(name, [])),
            }
        )
    networks.sort(key=lambda n: (not n["builtin"], n["name"]))
    return networks


def _parse_compose(text: str) -> list[dict[str, Any]]:
    value = _json_value(text)
    projects: list[dict[str, Any]] = []
    for row in value if isinstance(value, list) else []:
        if not isinstance(row, dict) or not row.get("Name"):
            continue
        projects.append(
            {
                "name": _s(row.get("Name"), 255),
                "status": _s(row.get("Status"), 255),
                "config_files": [
                    part.strip()
                    for part in _s(row.get("ConfigFiles"), 4096).split(",")
                    if part.strip()
                ],
            }
        )
    projects.sort(key=lambda p: p["name"])
    return projects


def _parse_df(text: str) -> dict[str, dict[str, Any]]:
    usage: dict[str, dict[str, Any]] = {}
    keys = {
        "images": "images",
        "containers": "containers",
        "local volumes": "volumes",
        "build cache": "build_cache",
    }
    for row in _json_lines(text):
        key = keys.get(_s(row.get("Type"), 32).lower())
        if key is None:
            continue
        reclaimable = _s(row.get("Reclaimable"), 64).split("(")[0].strip()

        def count(value: Any) -> int | None:
            return int(value) if str(value).isdigit() else None

        usage[key] = {
            "total": count(row.get("TotalCount")),
            "active": count(row.get("Active")),
            "size_bytes": _size(row.get("Size")),
            "reclaimable_bytes": _size(reclaimable),
        }
    return usage


def parse_inventory(raw: str) -> Inventory:
    sections = split_sections(raw)
    inventory = Inventory(version=sections.get("version", "").strip()[:32])
    inspected = _json_value(sections.get("inspect", ""))
    if isinstance(inspected, list):
        for row in inspected:
            if isinstance(row, dict):
                container = parse_container(row)
                if container is not None:
                    inventory.containers.append(container)
    inventory.containers.sort(key=lambda c: c["name"])
    in_use = {c["image_id"] for c in inventory.containers if c.get("image_id")}
    if "images" in sections:
        inventory.images = _parse_images(sections["images"], in_use)
    if "volumes" in sections:
        inventory.volumes = _parse_volumes(
            sections["volumes"], sections.get("volume_sizes"), inventory.containers
        )
    if "networks" in sections:
        inventory.networks = _parse_networks(sections["networks"], inventory.containers)
    if "compose" in sections:
        inventory.compose = _parse_compose(sections["compose"])
    if "df" in sections:
        inventory.df = _parse_df(sections["df"])
    return inventory


async def read_inventory(
    machine: Machine,
    secret: str | None,
    connect_timeout_seconds: int,
    sections: Iterable[str],
) -> Inventory:
    """Raises `DockerAccessError` without Docker access and
    `SSHConnectionError` when the machine can't be reached."""
    wanted = set(sections)
    result = await run_script(
        machine,
        secret,
        connect_timeout_seconds,
        build_inventory_command(wanted),
        # `system df -v` adds up every volume; give it room.
        run_timeout_seconds=180 if "volume_sizes" in wanted else 60,
    )
    return parse_inventory(result.output)
