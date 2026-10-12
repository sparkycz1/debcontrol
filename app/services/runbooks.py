"""Runbooks: defining them, filling in their parameters, starting them.

Shared by the web pages (`app/web/routes/runbooks.py`) and the REST API
(`app/web/routes/api_v1_runbooks.py`); the commands themselves run in
`app.tasks.jobs._run_runbook`.

**Parameters never reach a shell unchecked.** A value is limited to a
plain set of characters (letters, digits and `_ . : / @ = + , -`; no
spaces, quotes or anything a shell reads as syntax) *and* is shell-quoted
when it is put into the command. Who may run a runbook is deliberately a
wider group than who may write one, so what they type must not be able to
turn a documented step into a different command.
"""

from __future__ import annotations

import re
import shlex
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models.machine import Machine
from app.db.models.runbook import Runbook, RunbookRun, RunbookRunStatus
from app.db.models.user import User
from app.services.access_scope import machines_visible_to

MAX_STEPS = 30
MAX_PARAMS = 12
MAX_COMMAND_LENGTH = 2000
MAX_MACHINES_PER_RUN = 500
RECENT_RUN_LIMIT = 50

_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:/@=+,-]{0,200}$")
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([a-z][a-z0-9_]{0,31})\s*\}\}")


class RunbookError(ValueError):
    """What is wrong with a runbook or with the values given to it — text
    for the person who entered it."""


@dataclass(frozen=True)
class RunbookData:
    name: str
    description: str | None
    steps: list[dict[str, str]]
    params: list[dict[str, str]]


def parse_steps(text: str) -> list[dict[str, str]]:
    """Steps from the form's text: one command per line. A line starting
    with `#` names the step that follows; empty lines are ignored."""
    steps: list[dict[str, str]] = []
    pending_name = ""
    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            pending_name = line.lstrip("#").strip()[:120]
            continue
        steps.append({"name": pending_name or f"Step {len(steps) + 1}", "command": line})
        pending_name = ""
    return steps


def steps_as_text(steps: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for index, step in enumerate(steps, start=1):
        name = str(step.get("name") or "")
        if name and name != f"Step {index}":
            lines.append(f"# {name}")
        lines.append(str(step.get("command") or ""))
    return "\n".join(lines)


def parse_params(text: str) -> list[dict[str, str]]:
    """Parameters from the form's text: `key | label | default` per line
    (label and default optional)."""
    params: list[dict[str, str]] = []
    for raw in text.replace("\r\n", "\n").split("\n"):
        if not raw.strip():
            continue
        parts = [part.strip() for part in raw.split("|")]
        key = parts[0]
        params.append(
            {
                "key": key,
                "label": (parts[1] if len(parts) > 1 and parts[1] else key)[:120],
                "default": parts[2] if len(parts) > 2 else "",
            }
        )
    return params


def params_as_text(params: list[dict[str, Any]]) -> str:
    return "\n".join(
        " | ".join(str(param.get(field) or "") for field in ("key", "label", "default")).rstrip(
            " |"
        )
        for param in params
    )


def validate(
    name: str, description: str | None, steps: list[dict[str, Any]], params: list[dict[str, Any]]
) -> RunbookData:
    """A cleaned runbook, or `RunbookError` saying what to fix."""
    clean_name = name.strip()
    if not clean_name or len(clean_name) > 120:
        raise RunbookError("Give the runbook a name of at most 120 characters.")
    clean_params: list[dict[str, str]] = []
    for param in params[: MAX_PARAMS + 1]:
        key = str(param.get("key") or "")
        default = str(param.get("default") or "")
        if not _KEY_RE.match(key):
            raise RunbookError(
                f'Parameter "{key}": a key is lowercase letters, digits and "_", '
                "starting with a letter."
            )
        if key in {p["key"] for p in clean_params}:
            raise RunbookError(f'Parameter "{key}" is listed twice.')
        if not _VALUE_RE.match(default):
            raise RunbookError(
                f'Parameter "{key}": the default has characters that are not allowed.'
            )
        clean_params.append(
            {"key": key, "label": str(param.get("label") or key)[:120], "default": default}
        )
    if len(clean_params) > MAX_PARAMS:
        raise RunbookError(f"A runbook has at most {MAX_PARAMS} parameters.")
    keys = {p["key"] for p in clean_params}
    clean_steps: list[dict[str, str]] = []
    for step in steps:
        command = str(step.get("command") or "").strip()
        if not command:
            continue
        if len(command) > MAX_COMMAND_LENGTH or "\n" in command or "\x00" in command:
            raise RunbookError(f"A step is one line of at most {MAX_COMMAND_LENGTH} characters.")
        unknown = sorted(set(_PLACEHOLDER_RE.findall(command)) - keys)
        if unknown:
            raise RunbookError(
                f"A step uses {{{{{unknown[0]}}}}}, which is not among the parameters."
            )
        clean_steps.append(
            {
                "name": str(step.get("name") or f"Step {len(clean_steps) + 1}")[:120],
                "command": command,
            }
        )
    if not clean_steps:
        raise RunbookError("A runbook needs at least one step.")
    if len(clean_steps) > MAX_STEPS:
        raise RunbookError(f"A runbook has at most {MAX_STEPS} steps.")
    return RunbookData(
        name=clean_name,
        description=(description or "").strip()[:1024] or None,
        steps=clean_steps,
        params=clean_params,
    )


def render(runbook: Runbook, values: dict[str, str]) -> list[dict[str, str]]:
    """The runbook's steps with `values` filled in — exactly what will run.
    A parameter with no value given takes its default. `RunbookError` for
    a value with characters that are not allowed."""
    resolved: dict[str, str] = {}
    for param in runbook.params or []:
        key = str(param.get("key") or "")
        value = values.get(key)
        if value is None or value == "":
            value = str(param.get("default") or "")
        if not _VALUE_RE.match(value):
            raise RunbookError(
                f'"{param.get("label") or key}": only letters, digits and _ . : / @ = + , - '
                "are allowed (no spaces or quotes), at most 200 characters."
            )
        resolved[key] = value

    def fill(match: re.Match[str]) -> str:
        return shlex.quote(resolved.get(match.group(1), ""))

    return [
        {
            "name": str(step.get("name") or ""),
            "command": _PLACEHOLDER_RE.sub(fill, str(step.get("command") or "")),
        }
        for step in runbook.steps or []
    ]


async def start(
    db: AsyncSession,
    runbook: Runbook,
    machines: list[Machine],
    values: dict[str, str],
    started_by: str | None,
) -> tuple[uuid.UUID, list[RunbookRun], int]:
    """Create one run per machine with a confirmed host key and commit.
    Returns (batch id, the runs, how many machines were skipped). The
    caller enqueues `run_runbook` for each run."""
    commands = render(runbook, values)
    eligible = sorted(
        (m for m in machines if m.host_key_fingerprint), key=lambda m: m.name.lower()
    )[:MAX_MACHINES_PER_RUN]
    batch_id = uuid.uuid4()
    runs = [
        RunbookRun(
            runbook_id=runbook.id,
            runbook_name=runbook.name,
            machine_id=machine.id,
            batch_id=batch_id,
            commands=commands,
            started_by=started_by,
        )
        for machine in eligible
    ]
    db.add_all(runs)
    await db.commit()
    return batch_id, runs, len(machines) - len(eligible)


async def visible_batch(db: AsyncSession, user: User, batch_id: uuid.UUID) -> list[RunbookRun]:
    """One batch's runs on the machines `user` may see, by machine name."""
    visible_ids = (await machines_visible_to(db, user)).with_only_columns(Machine.id)
    result = await db.execute(
        select(RunbookRun)
        .options(selectinload(RunbookRun.machine))
        .where(RunbookRun.batch_id == batch_id, RunbookRun.machine_id.in_(visible_ids))
    )
    runs = list(result.scalars().all())
    runs.sort(key=lambda run: run.machine.name.lower())
    return runs


@dataclass(frozen=True)
class BatchRow:
    batch_id: uuid.UUID
    runbook_name: str
    started_by: str | None
    started_at: Any
    total: int
    failed: int
    unfinished: int


async def recent_batches(db: AsyncSession, user: User) -> list[BatchRow]:
    """The newest runbook batches on machines `user` may see."""
    visible_ids = (await machines_visible_to(db, user)).with_only_columns(Machine.id)
    result = await db.execute(
        select(RunbookRun)
        .where(RunbookRun.machine_id.in_(visible_ids))
        .order_by(RunbookRun.created_at.desc())
        .limit(RECENT_RUN_LIMIT * 20)
    )
    grouped: dict[uuid.UUID, list[RunbookRun]] = {}
    for run in result.scalars().all():
        grouped.setdefault(run.batch_id, []).append(run)
    rows = [
        BatchRow(
            batch_id=batch_id,
            runbook_name=runs[0].runbook_name,
            started_by=runs[0].started_by,
            started_at=min(run.created_at for run in runs),
            total=len(runs),
            failed=sum(1 for run in runs if run.status == RunbookRunStatus.FAILED),
            unfinished=sum(
                1
                for run in runs
                if run.status in (RunbookRunStatus.PENDING, RunbookRunStatus.RUNNING)
            ),
        )
        for batch_id, runs in grouped.items()
    ]
    return rows[:RECENT_RUN_LIMIT]


async def name_taken(db: AsyncSession, name: str, except_id: uuid.UUID | None = None) -> bool:
    query = (
        select(func.count())
        .select_from(Runbook)
        .where(func.lower(Runbook.name) == name.strip().lower())
    )
    if except_id is not None:
        query = query.where(Runbook.id != except_id)
    return bool((await db.execute(query)).scalar_one())


def as_dict(runbook: Runbook) -> dict[str, Any]:
    return {
        "id": str(runbook.id),
        "name": runbook.name,
        "description": runbook.description,
        "steps": list(runbook.steps or []),
        "params": list(runbook.params or []),
        "created_by": runbook.created_by,
        "updated_at": runbook.updated_at.isoformat() if runbook.updated_at else None,
    }


def run_as_dict(run: RunbookRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "batch_id": str(run.batch_id),
        "runbook_id": str(run.runbook_id) if run.runbook_id else None,
        "runbook_name": run.runbook_name,
        "machine_id": str(run.machine_id),
        "status": run.status.value,
        "commands": list(run.commands or []),
        "output": run.output,
        "error": run.error,
        "started_by": run.started_by,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
    }
