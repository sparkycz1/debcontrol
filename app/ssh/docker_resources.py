"""Limits of a running container, changed in place with `docker update`:
memory, CPUs and the restart policy (`ResourceChange`).

Only what the form filled in changes; an empty field keeps the current
value. A new memory limit also sets the memory+swap limit to twice the
memory, the default `docker run --memory` gives, so lowering memory below
an earlier swap limit works. Docker can't drop a memory limit again in
place (recreate the container for that); `--cpus 0` does lift a CPU limit.

A Compose service gets its compose file's values back the next time the
stack is recreated (`docker compose up`); the page says so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.ssh.docker_cli import DockerCommandError, is_container_name_valid, q

RESTART_POLICIES = ("no", "on-failure", "always", "unless-stopped")
MIN_MEMORY_BYTES = 6 * 1024 * 1024  # Docker refuses less than 6 MiB.
MAX_CPUS = 1024.0
_MEMORY_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?\s*$", re.IGNORECASE)
_UNITS = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_memory(value: str) -> int | None:
    """"512m", "1.5 GiB", "2g" → bytes; "" → None (unchanged)."""
    if not value.strip():
        return None
    match = _MEMORY_RE.match(value)
    if not match:
        raise DockerCommandError("Memory must be a number with an optional unit (512m, 2g).")
    amount = int(float(match.group(1)) * _UNITS[match.group(2).lower()])
    if amount < MIN_MEMORY_BYTES:
        raise DockerCommandError("Memory must be at least 6 MiB.")
    return amount


def parse_cpus(value: str) -> float | None:
    """"1.5" → 1.5; "0" → 0.0 (no limit); "" → None (unchanged)."""
    if not value.strip():
        return None
    try:
        cpus = float(value.strip().replace(",", "."))
    except ValueError:
        raise DockerCommandError("CPUs must be a number, e.g. 0.5 or 2.") from None
    if cpus < 0 or cpus > MAX_CPUS or cpus != cpus:
        raise DockerCommandError("CPUs must be between 0 and 1024.")
    return round(cpus, 3)


@dataclass(frozen=True)
class ResourceChange:
    memory_bytes: int | None = None
    cpus: float | None = None
    restart_policy: str | None = None
    restart_max_retries: int | None = None

    @property
    def empty(self) -> bool:
        return self.memory_bytes is None and self.cpus is None and self.restart_policy is None

    def as_dict(self) -> dict[str, object]:
        return {
            key: value
            for key, value in (
                ("memory_bytes", self.memory_bytes),
                ("cpus", self.cpus),
                ("restart_policy", self.restart_policy),
                ("restart_max_retries", self.restart_max_retries),
            )
            if value is not None
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ResourceChange:
        """`as_dict`'s output back, checked again (it crosses the task queue)."""
        memory = data.get("memory_bytes")
        cpus = data.get("cpus")
        policy = data.get("restart_policy")
        retries = data.get("restart_max_retries")
        if memory is not None and (not isinstance(memory, int) or memory < MIN_MEMORY_BYTES):
            raise DockerCommandError("Invalid memory limit.")
        if cpus is not None and (
            not isinstance(cpus, int | float) or not 0 <= float(cpus) <= MAX_CPUS
        ):
            raise DockerCommandError("Invalid CPU limit.")
        if policy is not None and policy not in RESTART_POLICIES:
            raise DockerCommandError("Unknown restart policy.")
        if retries is not None and (not isinstance(retries, int) or not 0 <= retries <= 1000):
            raise DockerCommandError("Invalid retry count.")
        return cls(
            memory_bytes=memory,
            cpus=float(cpus) if cpus is not None else None,
            restart_policy=str(policy) if policy is not None else None,
            restart_max_retries=retries,
        )

    @classmethod
    def parse(
        cls, *, memory: str = "", cpus: str = "", restart_policy: str = "", max_retries: str = ""
    ) -> ResourceChange:
        policy = restart_policy.strip() or None
        if policy is not None and policy not in RESTART_POLICIES:
            raise DockerCommandError("Unknown restart policy.")
        retries: int | None = None
        if policy == "on-failure" and max_retries.strip():
            if not max_retries.strip().isdigit() or int(max_retries) > 1000:
                raise DockerCommandError("Retries must be a whole number up to 1000.")
            retries = int(max_retries)
        return cls(
            memory_bytes=parse_memory(memory),
            cpus=parse_cpus(cpus),
            restart_policy=policy,
            restart_max_retries=retries,
        )


def build_update_command(container: str, change: ResourceChange) -> str:
    if not is_container_name_valid(container):
        raise DockerCommandError("Invalid container name.")
    if change.empty:
        raise DockerCommandError("Nothing to change.")
    args: list[str] = []
    if change.memory_bytes is not None:
        args += [f"--memory {change.memory_bytes}", f"--memory-swap {change.memory_bytes * 2}"]
    if change.cpus is not None:
        args.append(f"--cpus {change.cpus:g}")
    if change.restart_policy is not None:
        policy = change.restart_policy
        if policy == "on-failure" and change.restart_max_retries:
            policy = f"on-failure:{change.restart_max_retries}"
        args.append(f"--restart {q(policy)}")
    return f"$D update {' '.join(args)} {q(container)}"
