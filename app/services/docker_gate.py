"""The vulnerability gate: whether a container update may go ahead, from
the scans of the new image (and of the running one, for "worse").

The gate fails closed: when it is on and the new image could not be
scanned by either scanner, the update is stopped — "we could not check"
is never read as "nothing found". A stopped update changes nothing on the
machine (`app.ssh.docker_update`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.db.models.docker import VulnerabilityGate

GATES = tuple(gate.value for gate in VulnerabilityGate)


def normalize_gate(value: str | None, default: str = VulnerabilityGate.OFF.value) -> str:
    return value if value in GATES else default


@dataclass(frozen=True)
class GateVerdict:
    allowed: bool
    # i18n key under `docker.gate.reason.` — what stopped it, or why it passed.
    reason: str
    new_counts: dict[str, int] | None
    old_counts: dict[str, int] | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "new": self.new_counts,
            "old": self.old_counts,
        }


def _serious(counts: dict[str, int]) -> int:
    return int(counts.get("critical", 0)) + int(counts.get("high", 0))


def evaluate(
    gate: str,
    new_counts: dict[str, int] | None,
    old_counts: dict[str, int] | None,
) -> GateVerdict:
    """`new_counts` / `old_counts`: findings per severity of the new and the
    running image, None when that image has no successful scan."""
    gate = normalize_gate(gate)
    if gate == VulnerabilityGate.OFF:
        return GateVerdict(True, "off", new_counts, old_counts)
    if new_counts is None:
        return GateVerdict(False, "not_scanned", None, old_counts)
    critical = int(new_counts.get("critical", 0))
    high = int(new_counts.get("high", 0))
    if gate == VulnerabilityGate.CRITICAL:
        allowed = critical == 0
        return GateVerdict(allowed, "passed" if allowed else "critical", new_counts, old_counts)
    if gate == VulnerabilityGate.HIGH:
        allowed = critical == 0 and high == 0
        return GateVerdict(allowed, "passed" if allowed else "high", new_counts, old_counts)
    # WORSE: no more critical + high findings than what runs now. Without a
    # scan of the running image there is nothing to compare with.
    if old_counts is None:
        return GateVerdict(False, "old_not_scanned", new_counts, None)
    allowed = _serious(new_counts) <= _serious(old_counts)
    return GateVerdict(allowed, "passed" if allowed else "worse", new_counts, old_counts)
