"""Registry of actions that can be attached to a scheduled task.

This is the extension point: adding a new schedulable action for some new
feature means writing one `run` function and calling `register_action()`
once (see `app.scheduling.builtin_actions` for the four that exist today) —
nothing about the schedule model, the scheduler tick, or the "New scheduled
task" form needs to change.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.machine import Machine


@dataclass(frozen=True)
class ActionRunResult:
    """What happened when a scheduled task fired, for `last_run_summary`."""

    attempted: int
    skipped: int


@dataclass(frozen=True)
class ScheduledActionParam:
    """One configurable option for an action, rendered as a `<select>` in
    the scheduling form (e.g. upgrade strategy for `system_update`)."""

    key: str
    label: str
    choices: list[tuple[str, str]]  # (value, display label)
    default: str


# (db session, target machines, the action's stored params) -> what happened.
# No queue handle is threaded through: an action enqueues Celery tasks by
# importing and calling them (see `app.services.machine_actions`).
ActionRunFunc = Callable[[AsyncSession, list[Machine], dict[str, str]], Awaitable[ActionRunResult]]


@dataclass(frozen=True)
class ScheduledActionSpec:
    key: str
    label: str
    description: str
    run: ActionRunFunc
    params: list[ScheduledActionParam] = field(default_factory=list)
    # Shown as a caution in the schedule form for actions with no undo.
    destructive: bool = False


_REGISTRY: dict[str, ScheduledActionSpec] = {}


def register_action(spec: ScheduledActionSpec) -> None:
    if spec.key in _REGISTRY:
        raise ValueError(f'A schedulable action "{spec.key}" is already registered.')
    _REGISTRY[spec.key] = spec


def get_action(key: str) -> ScheduledActionSpec | None:
    return _REGISTRY.get(key)


def all_actions() -> list[ScheduledActionSpec]:
    return list(_REGISTRY.values())
