"""A container started with `docker run` turned into a Compose file
(`to_compose`), read from `docker container inspect` and the image's own
`docker image inspect` — what the image already sets (environment,
command, labels, health check) is left out, so the file holds what the
person running it chose.

- Environment variables go into the stack's `.env` (stored encrypted)
  and reach the container through `env_file: .env`, never into the
  compose file.
- Named and anonymous volumes become `external` volumes with their
  current names, so the data stays where it is; bind mounts stay as they
  are.
- Networks other than the default bridge become `external` networks; a
  container on the default bridge keeps `network_mode: bridge`.
- What has no Compose equivalent here (GPU requests, `--link`,
  `--volumes-from`) is listed as a warning to look at before deploying.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from app.ssh.docker_cli import DockerCommandError, as_dict, as_list, is_container_name_valid, q
from app.ssh.docker_compose import env_line

_PROJECT_CHARS = re.compile(r"[^a-z0-9_-]+")
# Docker's default shared memory size.
_DEFAULT_SHM = 64 * 1024 * 1024


def build_inspect_script(container: str) -> str:
    """The container's and its image's inspect output, each on one line."""
    if not is_container_name_valid(container):
        raise DockerCommandError("Invalid container name.")
    name = q(container)
    return (
        f"echo \"@@DC_CTR $($D container inspect --format '{{{{json .}}}}' {name})\" && "
        f"img=\"$($D container inspect --format '{{{{.Image}}}}' {name})\" && "
        'echo "@@DC_IMG $($D image inspect --format \'{{json .}}\' "$img" 2>/dev/null)"'
    )


def parse_inspect_output(raw: str) -> tuple[dict[str, Any], dict[str, Any]]:
    container: dict[str, Any] = {}
    image: dict[str, Any] = {}
    for line in raw.splitlines():
        for prefix in ("@@DC_CTR ", "@@DC_IMG "):
            if line.startswith(prefix):
                try:
                    value = as_dict(json.loads(line[len(prefix) :]))
                except ValueError:
                    value = {}
                if prefix == "@@DC_CTR ":
                    container = value
                else:
                    image = value
    return container, image


def project_name(container: str) -> str:
    """A Compose project/service name made from a container name."""
    name = _PROJECT_CHARS.sub("-", container.lower()).strip("-_")[:63]
    return name if name and name[0].isalnum() else f"app-{name}".strip("-")[:63] or "app"


def _seconds(nanoseconds: object) -> str | None:
    if isinstance(nanoseconds, int) and nanoseconds > 0:
        return f"{max(1, nanoseconds // 1_000_000_000)}s"
    return None


@dataclass
class Converted:
    service: str
    compose: str
    env: str
    warnings: list[str] = field(default_factory=list)


def _differs(value: object, default: object) -> bool:
    return bool(value) and value != default


def _basics(
    service: dict[str, Any], container: dict[str, Any], image_config: dict[str, Any]
) -> None:
    config = as_dict(container.get("Config"))
    host = as_dict(container.get("HostConfig"))
    restart = as_dict(host.get("RestartPolicy"))
    policy = str(restart.get("Name") or "")
    retries = int(restart.get("MaximumRetryCount") or 0)
    if policy == "on-failure" and retries > 0:
        service["restart"] = f"on-failure:{retries}"
    elif policy in ("always", "unless-stopped", "on-failure"):
        service["restart"] = policy
    for key, compose_key in (("Entrypoint", "entrypoint"), ("Cmd", "command")):
        if _differs(config.get(key), image_config.get(key)):
            service[compose_key] = list(as_list(config.get(key)))
    for key, compose_key in (
        ("User", "user"),
        ("WorkingDir", "working_dir"),
        ("StopSignal", "stop_signal"),
    ):
        if _differs(config.get(key), image_config.get(key)):
            service[compose_key] = str(config[key])
    for key, compose_key in (("Tty", "tty"), ("OpenStdin", "stdin_open")):
        if config.get(key):
            service[compose_key] = True
    hostname = str(config.get("Hostname") or "")
    if hostname and not str(container.get("Id") or "").startswith(hostname):
        service["hostname"] = hostname


def _environment(
    config: dict[str, Any], image_config: dict[str, Any], warnings: list[str]
) -> list[str]:
    """The `.env` lines for what the container sets beyond the image."""
    image_env = {str(item) for item in as_list(image_config.get("Env"))}
    lines: list[str] = []
    for item in as_list(config.get("Env")):
        entry = str(item)
        if entry in image_env or "=" not in entry:
            continue
        key, _, value = entry.partition("=")
        if any(c in value for c in "\n\r\0"):
            warnings.append(f"Environment variable {key} has a line break and was left out.")
            continue
        lines.append(env_line(key, value))
    return lines


def _ports(host: dict[str, Any]) -> list[str]:
    ports: list[str] = []
    for container_port, bindings in sorted(as_dict(host.get("PortBindings")).items()):
        target = str(container_port).removesuffix("/tcp")
        for item in as_list(bindings):
            binding = as_dict(item)
            host_ip = str(binding.get("HostIp") or "")
            host_port = str(binding.get("HostPort") or "")
            if host_ip and host_ip not in ("0.0.0.0", "::"):  # noqa: S104 - read, not bound
                ports.append(f"{host_ip}:{host_port}:{target}")
            elif host_port:
                ports.append(f"{host_port}:{target}")
            else:
                ports.append(target)
    return ports


def _mounts(service: dict[str, Any], container: dict[str, Any]) -> list[str]:
    """Volumes and tmpfs; returns the volume names to declare external."""
    volumes: list[str] = []
    named: list[str] = []
    tmpfs: list[str] = []
    for item in as_list(container.get("Mounts")):
        mount = as_dict(item)
        kind = mount.get("Type")
        destination = str(mount.get("Destination") or "")
        suffix = "" if mount.get("RW", True) else ":ro"
        if kind == "bind":
            volumes.append(f"{mount.get('Source')}:{destination}{suffix}")
        elif kind == "volume" and mount.get("Name"):
            named.append(str(mount["Name"]))
            volumes.append(f"{mount['Name']}:{destination}{suffix}")
        elif kind == "tmpfs":
            tmpfs.append(destination)
    if volumes:
        service["volumes"] = volumes
    if tmpfs:
        service["tmpfs"] = tmpfs
    return named


def _networks(service: dict[str, Any], container: dict[str, Any], warnings: list[str]) -> list[str]:
    """Network mode or networks; returns the networks to declare external."""
    mode = str(as_dict(container.get("HostConfig")).get("NetworkMode") or "default")
    attached = sorted(as_dict(as_dict(container.get("NetworkSettings")).get("Networks")))
    if mode in ("default", "bridge"):
        service["network_mode"] = "bridge"
        if any(n != "bridge" for n in attached):
            warnings.append("Networks besides the default bridge were left out.")
        return []
    if mode in ("host", "none") or mode.startswith("container:"):
        service["network_mode"] = mode
        return []
    networks = [n for n in attached if n not in ("bridge", "host", "none")] or [mode]
    service["networks"] = networks
    return networks


def _host_options(service: dict[str, Any], host: dict[str, Any]) -> None:
    for key, compose_key in (
        ("CapAdd", "cap_add"),
        ("CapDrop", "cap_drop"),
        ("Dns", "dns"),
        ("ExtraHosts", "extra_hosts"),
        ("SecurityOpt", "security_opt"),
    ):
        values = [str(v) for v in as_list(host.get(key))]
        if values:
            service[compose_key] = values
    devices = [
        f"{d.get('PathOnHost')}:{d.get('PathInContainer')}:{d.get('CgroupPermissions') or 'rwm'}"
        for d in (as_dict(item) for item in as_list(host.get("Devices")))
        if d.get("PathOnHost")
    ]
    if devices:
        service["devices"] = devices
    for key, compose_key in (("Privileged", "privileged"), ("Init", "init")):
        if host.get(key):
            service[compose_key] = True
    for key, compose_key in (("PidMode", "pid"), ("IpcMode", "ipc")):
        if host.get(key) == "host":
            service[compose_key] = "host"
    sysctls = {str(k): str(v) for k, v in as_dict(host.get("Sysctls")).items()}
    if sysctls:
        service["sysctls"] = sysctls
    if int(host.get("Memory") or 0) > 0:
        service["mem_limit"] = int(host["Memory"])
    if int(host.get("NanoCpus") or 0) > 0:
        service["cpus"] = round(int(host["NanoCpus"]) / 1e9, 3)
    shm = int(host.get("ShmSize") or 0)
    if shm and shm != _DEFAULT_SHM:
        service["shm_size"] = shm
    log = as_dict(host.get("LogConfig"))
    options = {str(k): str(v) for k, v in as_dict(log.get("Config")).items()}
    driver = str(log.get("Type") or "json-file")
    if driver != "json-file" or options:
        service["logging"] = {"driver": driver, **({"options": options} if options else {})}


def _healthcheck(config: dict[str, Any], image_config: dict[str, Any]) -> dict[str, Any] | None:
    health = as_dict(config.get("Healthcheck"))
    if not health or health == as_dict(image_config.get("Healthcheck")):
        return None
    check: dict[str, Any] = {"test": list(as_list(health.get("Test")))}
    for key, compose_key in (
        ("Interval", "interval"),
        ("Timeout", "timeout"),
        ("StartPeriod", "start_period"),
    ):
        seconds = _seconds(health.get(key))
        if seconds:
            check[compose_key] = seconds
    if int(health.get("Retries") or 0) > 0:
        check["retries"] = int(health["Retries"])
    return check


def _literal(value: Any) -> Any:
    """`value` with every `$` doubled, so Compose takes it as written
    instead of interpolating it (a label with a password hash, say)."""
    if isinstance(value, str):
        return value.replace("$", "$$")
    if isinstance(value, list):
        return [_literal(item) for item in value]
    if isinstance(value, dict):
        return {key: _literal(item) for key, item in value.items()}
    return value


def to_compose(container: dict[str, Any], image: dict[str, Any]) -> Converted:
    config = as_dict(container.get("Config"))
    host = as_dict(container.get("HostConfig"))
    image_config = as_dict(image.get("Config"))
    name = str(container.get("Name") or "").lstrip("/")
    if not name or not is_container_name_valid(name):
        raise DockerCommandError("The container could not be read.")
    service_name = project_name(name)
    service: dict[str, Any] = {
        "image": str(config.get("Image") or image.get("Id") or ""),
        "container_name": name,
    }
    warnings: list[str] = []
    _basics(service, container, image_config)
    env_lines = _environment(config, image_config, warnings)
    if env_lines:
        service["env_file"] = [".env"]
    image_labels = as_dict(image_config.get("Labels"))
    labels = {
        str(k): str(v)
        for k, v in as_dict(config.get("Labels")).items()
        if image_labels.get(k) != v and not str(k).startswith("com.docker.compose.")
    }
    if labels:
        service["labels"] = labels
    ports = _ports(host)
    if ports:
        service["ports"] = ports
    named = _mounts(service, container)
    networks = _networks(service, container, warnings)
    _host_options(service, host)
    health = _healthcheck(config, image_config)
    if health:
        service["healthcheck"] = health
    for key, message in (
        ("DeviceRequests", "GPU / device requests were left out; add a deploy.resources section."),
        ("Links", "Links (--link) were left out; use a shared network instead."),
        ("VolumesFrom", "--volumes-from was left out; mount the volumes by name instead."),
    ):
        if as_list(host.get(key)):
            warnings.append(message)
    document: dict[str, Any] = {"services": {service_name: _literal(service)}}
    if named:
        document["volumes"] = {v: {"external": True, "name": v} for v in sorted(set(named))}
    if networks:
        document["networks"] = {n: {"external": True, "name": n} for n in networks}
    compose = yaml.safe_dump(document, sort_keys=False, default_flow_style=False, width=1000)
    env = ("\n".join(env_lines) + "\n") if env_lines else ""
    return Converted(service=service_name, compose=compose, env=env, warnings=warnings)
