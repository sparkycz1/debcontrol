"""One image at a time: its layers and details, a new tag, removal, and
the pull script a job runs (`DockerJobKind.IMAGE_PULL`).

Image ids and references are validated (`docker_cli.is_image_*_valid`)
and quoted before they reach a command. Removing never forces: Docker
itself refuses an image a container still uses, and that refusal is
shown as it is. The details leave out the image's environment variables
(`Config.Env`), which can carry secrets baked into an image.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from app.ssh.docker_cli import (
    DockerCommandError,
    as_dict,
    as_list,
    is_image_id_valid,
    is_image_ref_valid,
    is_image_valid,
    q,
)
from app.ssh.monitoring import parse_docker_size

PULLED_MARKER = "@@DC_IMAGE_ID "
_INSPECT_MARKER = "@@DC_INSPECT"
MAX_LAYERS = 500


def _image(value: str) -> str:
    if not is_image_valid(value):
        raise DockerCommandError("Invalid image.")
    return q(value)


def build_details_command(image: str) -> str:
    """Layers (`docker history`) and `docker image inspect` of one image."""
    ref = _image(image)
    return (
        f"$D history --no-trunc --format '{{{{json .}}}}' {ref} && "
        f"echo '{_INSPECT_MARKER}' && $D image inspect {ref}"
    )


def build_remove_command(image: str) -> str:
    """`docker image rm` without `--force`: a tag is untagged, an id whose
    image a container uses is refused by Docker."""
    return f"$D image rm {_image(image)}"


def build_tag_command(source: str, target: str) -> str:
    if not is_image_ref_valid(target) or is_image_id_valid(target) or "@" in target:
        raise DockerCommandError("Invalid new tag.")
    return f"$D tag {_image(source)} {q(target)}"


def build_pull_script(ref: str) -> str:
    """The job's script: pull, then print the id the reference now names."""
    if not is_image_ref_valid(ref) or is_image_id_valid(ref):
        raise DockerCommandError("Invalid image reference.")
    return (
        f"$D pull {q(ref)} || exit $?\n"
        f'echo "{PULLED_MARKER}$($D image inspect --format \'{{{{.Id}}}}\' {q(ref)})"\n'
    )


def parse_pulled_id(output: str) -> str | None:
    for line in reversed(output.splitlines()):
        if line.startswith(PULLED_MARKER):
            value = line[len(PULLED_MARKER) :].strip()
            return value if is_image_id_valid(value) else None
    return None


@dataclass
class ImageDetails:
    id: str = ""
    tags: list[str] = field(default_factory=list)
    digests: list[str] = field(default_factory=list)
    created: str = ""
    architecture: str = ""
    os: str = ""
    size_bytes: int | None = None
    user: str = ""
    workdir: str = ""
    entrypoint: str = ""
    command: str = ""
    exposed_ports: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    layers: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "tags": self.tags,
            "digests": self.digests,
            "created": self.created,
            "architecture": self.architecture,
            "os": self.os,
            "size_bytes": self.size_bytes,
            "user": self.user,
            "workdir": self.workdir,
            "entrypoint": self.entrypoint,
            "command": self.command,
            "exposed_ports": self.exposed_ports,
            "labels": self.labels,
            "layers": self.layers,
        }


def _s(value: Any, limit: int = 512) -> str:
    return str(value)[:limit] if value is not None else ""


def _joined(value: Any) -> str:
    if isinstance(value, list):
        return " ".join(_s(part, 1024) for part in value)[:2048]
    return _s(value, 2048)


def parse_details(raw: str) -> ImageDetails | None:
    """`build_details_command`'s output, or None when it isn't there."""
    head, sep, tail = raw.partition(_INSPECT_MARKER)
    if not sep:
        return None
    try:
        inspected = json.loads(tail.strip() or "[]")
    except (ValueError, RecursionError):
        return None
    rows = as_list(inspected)
    info = as_dict(rows[0]) if rows else {}
    if not info:
        return None
    config = as_dict(info.get("Config"))
    details = ImageDetails(
        id=_s(info.get("Id"), 80),
        tags=[_s(t, 255) for t in as_list(info.get("RepoTags"))][:50],
        digests=[_s(d, 512) for d in as_list(info.get("RepoDigests"))][:50],
        created=_s(info.get("Created"), 40),
        architecture=_s(info.get("Architecture"), 32),
        os=_s(info.get("Os"), 32),
        size_bytes=info["Size"] if isinstance(info.get("Size"), int) else None,
        user=_s(config.get("User"), 255),
        workdir=_s(config.get("WorkingDir"), 1024),
        entrypoint=_joined(config.get("Entrypoint")),
        command=_joined(config.get("Cmd")),
        exposed_ports=sorted(str(p)[:32] for p in as_dict(config.get("ExposedPorts")))[:100],
        labels={
            str(k)[:255]: _s(v, 2048)
            for k, v in sorted(as_dict(config.get("Labels")).items())[:200]
        },
    )
    for line in head.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = as_dict(json.loads(line))
        except (ValueError, RecursionError):
            continue
        size_text = _s(row.get("Size"), 32)
        details.layers.append(
            {
                "id": _s(row.get("ID"), 80) if row.get("ID") != "<missing>" else "",
                "created": _s(row.get("CreatedAt"), 40),
                "created_by": _s(row.get("CreatedBy"), 4096),
                "size_bytes": parse_docker_size(size_text) if size_text else None,
                "comment": _s(row.get("Comment"), 512),
            }
        )
        if len(details.layers) >= MAX_LAYERS:
            break
    return details
