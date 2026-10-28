"""Docker container events worth a notification — a container crashed,
was killed for running out of memory, keeps restarting, or its health
check turned unhealthy — read from `docker events` with every monitoring
sample (`app.ssh.monitoring`'s `@@EVENTS` block) and sent through the
notification rules like any other event type (Notifications → a rule's
"Docker container …" events).

Each sample reads the events since the previous sample, by the machine's
own clock (`Machine.docker_events_since`), so nothing is missed or sent
twice however the two clocks differ. A machine's first sample after an
upgrade only records where to start, so nothing that happened before is
reported. One notification per kind per sample, listing every container.

What counts:
- crashed: the container exited with a code other than 0 (clean), 130
  (Ctrl-C), 137 (killed — `docker stop` after its timeout, or an OOM
  kill, reported apart) or 143 (`docker stop`);
- restart loop: it exited `RESTART_LOOP_EXITS` or more times since the
  previous sample, whatever the codes (reported instead of "crashed");
- OOM: the kernel killed a process in it for running out of memory;
- unhealthy: its health check turned unhealthy (Docker reports only the
  change, so this fires once per change, not while it stays unhealthy).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine
from app.db.models.notification_rule import NotificationEventType
from app.services.notifications import notify

# Exit codes of a container stopped on purpose (see the module docstring).
CLEAN_EXIT_CODES = frozenset({0, 130, 137, 143})
# This many exits of one container since the previous sample is a loop.
RESTART_LOOP_EXITS = 3


@dataclass
class ContainerIncidents:
    # {container: [exit codes]}
    crashed: dict[str, list[int | None]] = field(default_factory=dict)
    # {container: exits since the previous sample}
    restart_loop: dict[str, int] = field(default_factory=dict)
    oom: list[str] = field(default_factory=list)
    unhealthy: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.crashed or self.restart_loop or self.oom or self.unhealthy)


def classify(events: list[dict[str, Any]]) -> ContainerIncidents:
    """Sort a sample's events (`app.ssh.monitoring._parse_docker_events`)
    into what is worth reporting."""
    exits: Counter[str] = Counter()
    codes: defaultdict[str, list[int | None]] = defaultdict(list)
    oom: list[str] = []
    health: dict[str, str] = {}
    for event in events:
        name = str(event.get("name") or "")
        if not name:
            continue
        action = event.get("action")
        if action == "die":
            exits[name] += 1
            codes[name].append(event.get("exit_code"))
        elif action == "oom" and name not in oom:
            oom.append(name)
        elif action in ("unhealthy", "healthy"):
            # Only the last change counts: unhealthy and healthy again
            # within one sample is nothing to wake anyone for.
            health[name] = str(action)
    incidents = ContainerIncidents(oom=sorted(oom))
    for name, count in sorted(exits.items()):
        if count >= RESTART_LOOP_EXITS:
            incidents.restart_loop[name] = count
            continue
        bad = [code for code in codes[name] if code not in CLEAN_EXIT_CODES]
        if bad:
            incidents.crashed[name] = bad
    incidents.unhealthy = sorted(name for name, state in health.items() if state == "unhealthy")
    return incidents


def _code(code: int | None) -> str:
    return "?" if code is None else str(code)


async def notify_incidents(
    db: AsyncSession, machine: Machine, incidents: ContainerIncidents
) -> None:
    """One notification per kind of incident, listing its containers."""
    if incidents.crashed:
        await notify(
            db,
            NotificationEventType.DOCKER_CONTAINER_CRASHED,
            machine=machine,
            context={
                "containers": ", ".join(incidents.crashed),
                "details": "\n".join(
                    f"{name}: exit code {', '.join(_code(c) for c in codes)}"
                    for name, codes in incidents.crashed.items()
                ),
            },
        )
    if incidents.restart_loop:
        await notify(
            db,
            NotificationEventType.DOCKER_CONTAINER_RESTART_LOOP,
            machine=machine,
            context={
                "containers": ", ".join(incidents.restart_loop),
                "details": "\n".join(
                    f"{name}: exited {count} times since the previous check"
                    for name, count in incidents.restart_loop.items()
                ),
            },
        )
    if incidents.oom:
        await notify(
            db,
            NotificationEventType.DOCKER_CONTAINER_OOM,
            machine=machine,
            context={"containers": ", ".join(incidents.oom), "details": "\n".join(incidents.oom)},
        )
    if incidents.unhealthy:
        await notify(
            db,
            NotificationEventType.DOCKER_CONTAINER_UNHEALTHY,
            machine=machine,
            context={
                "containers": ", ".join(incidents.unhealthy),
                "details": "\n".join(incidents.unhealthy),
            },
        )
