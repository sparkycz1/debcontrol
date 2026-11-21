"""Running what the AI assistant proposed (`AiMessage.pending_actions`):
the one place an AI-proposed action starts, for both callers.

- **A person's Confirm** (`app.web.routes.ai`: one action, optionally on a
  subset of its machines, or every pending action of a message at once).
- **The account's AI command mode at "allow"** (`User.ai_command_mode`,
  `app.tasks.ai_jobs._run_turn`): a proposed `run_ssh_command` starts right
  after the assistant's turn is saved. Only shell commands — an update, an
  update check, a reboot or a shutdown always waits for a Confirm.

Either way the same checks run here, immediately before anything starts:
the entry is still `pending` (read under a row lock, so two clicks or a
click racing the automatic start run it once), the account *currently*
has the tool's permission (permission check #3, see `app.ai.tools`), and
the target machines are re-loaded within the account's current scope.
Each started action is audit-logged with the literal command and every
machine.

Fire-and-forget tools (updates, update checks, power) are handed to the
same `app.services.machine_actions` functions their buttons use. A shell
command is marked `running` with one result row per machine and handed to
`app.tasks.ai_jobs.execute_ai_actions`, which runs it on every machine at
once, stores each machine's exit status and output in that row, and then
lets the assistant summarize the output — so the web request never waits
for SSH.
"""

from __future__ import annotations

import uuid
from collections.abc import Collection, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools import (
    CHECK_UPDATES,
    REBOOT,
    RUN_SSH_COMMAND,
    RUN_UPDATE,
    SHUTDOWN,
    TOOL_SPECS,
    load_machines,
    missing_permission,
)
from app.audit import log_event
from app.db.models.ai_conversation import AiConversation
from app.db.models.ai_message import AiMessage, PendingActionStatus
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine import Machine
from app.db.models.machine_update_run import UpgradeStrategy
from app.db.models.user import AiCommandMode, User
from app.services.machine_actions import (
    send_power_to_machines,
    trigger_check_updates,
    trigger_updates,
)
from app.ssh.power import PowerAction

#: What "allow" may start without a Confirm.
AUTO_RUN_TOOLS = frozenset({RUN_SSH_COMMAND})

#: How much of one machine's output is kept in its result row (the tail).
MAX_RESULT_OUTPUT_CHARS = 8000

#: A shell command still `running` after this was cut off (the worker was
#: restarted): shown as interrupted, and the chat stops polling for it.
STALE_AFTER = timedelta(minutes=20)

PENDING = PendingActionStatus.PENDING.value
RUNNING = PendingActionStatus.RUNNING.value
CONFIRMED = PendingActionStatus.CONFIRMED.value
DENIED = PendingActionStatus.DENIED.value
DISCARDED = PendingActionStatus.DISCARDED.value


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def is_stale(entry: Mapping[str, Any], now: datetime | None = None) -> bool:
    """A `running` entry whose run never finished."""
    if entry.get("status") != RUNNING:
        return False
    try:
        started = datetime.fromisoformat(str(entry.get("started_at")))
    except ValueError:
        return True
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    return (now or datetime.now(UTC)) - started > STALE_AFTER


def is_busy(messages: list[AiMessage]) -> bool:
    """A shell command of this conversation is still running (and not
    stale): the chat keeps polling until it is done."""
    return any(
        entry.get("status") == RUNNING and not is_stale(entry)
        for message in messages
        for entry in message.pending_actions or []
    )


async def lock_message(
    db: AsyncSession, conversation: AiConversation, message_id: uuid.UUID
) -> AiMessage | None:
    """The message, re-read and row-locked (`SELECT ... FOR UPDATE` on
    PostgreSQL) for a read-modify-write of its `pending_actions`: two
    writers (a Confirm and the run finishing, two Confirms) must not
    overwrite each other's change to the same JSON document."""
    result = await db.execute(
        select(AiMessage)
        .where(AiMessage.id == message_id, AiMessage.conversation_id == conversation.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    return result.scalar_one_or_none()


async def start_actions(
    db: AsyncSession,
    user: User,
    conversation: AiConversation,
    message_id: uuid.UUID,
    indexes: Collection[int],
    *,
    selected_machine_ids: Mapping[int, Collection[str]] | None = None,
    request: Request | None = None,
    automatic: bool = False,
) -> list[str]:
    """Start the pending actions at `indexes` of one message; returns the
    problems to show (an empty list when everything started).

    `selected_machine_ids` narrows an action to some of its machines (the
    checkboxes on a multi-machine proposal); machines not selected are kept
    in its result rows as skipped. `automatic` is the "allow" mode's start:
    only `AUTO_RUN_TOOLS` are started, and the audit entry says so.
    """
    message = await lock_message(db, conversation, message_id)
    if message is None:
        return ["Message not found."]
    actions = [dict(action) for action in message.pending_actions or []]
    errors: list[str] = []
    started: list[tuple[int, dict[str, Any], list[str]]] = []
    denied: list[tuple[dict[str, Any], str]] = []
    shell_indexes: list[int] = []

    for index in sorted(set(indexes)):
        if index < 0 or index >= len(actions):
            errors.append("Action not found.")
            continue
        entry = actions[index]
        tool_name = str(entry.get("tool") or "")
        if entry.get("status") != PENDING:
            errors.append("This action was already handled.")
            continue
        if tool_name not in TOOL_SPECS or not TOOL_SPECS[tool_name].mutating:
            errors.append("Unknown proposed action.")
            continue
        if automatic and (
            tool_name not in AUTO_RUN_TOOLS or user.ai_mode != AiCommandMode.ALLOW
        ):
            continue
        if user.ai_mode == AiCommandMode.DENY:
            entry["status"] = DENIED
            entry["reason"] = (
                "Your AI command setting (My account) does not let the assistant "
                "run anything. Nothing was run."
            )
            errors.append(str(entry["reason"]))
            continue

        # Permission check #3 — current role, right now, not when the
        # proposal was written.
        permission = missing_permission(user, tool_name)
        if permission is not None:
            entry["status"] = DENIED
            entry["reason"] = (
                f"Your role no longer has the '{permission.value}' permission — nothing was run."
            )
            errors.append(str(entry["reason"]))
            denied.append((entry, permission.value))
            continue

        wanted = [str(m) for m in entry.get("machine_ids") or []]
        if selected_machine_ids is not None and index in selected_machine_ids:
            chosen = {str(m) for m in selected_machine_ids[index]}
            wanted = [m for m in wanted if m in chosen]
            if not wanted:
                errors.append("Select at least one machine to run it on.")
                continue
        # Also covers "no longer visible to this account": `load_machines`
        # re-filters by machine-group scope.
        machines = await load_machines(db, user, wanted)
        if not machines:
            entry["status"] = DENIED
            entry["reason"] = "None of the target machines are still available to this account."
            errors.append(str(entry["reason"]))
            continue

        names = [machine.name for machine in machines]
        entry["started_at"] = now_iso()
        entry["started_by"] = user.username
        entry["automatic"] = automatic
        entry["ran_on"] = names
        if tool_name == RUN_SSH_COMMAND:
            entry["status"] = RUNNING
            entry["results"] = _result_rows(entry, {str(machine.id) for machine in machines})
            shell_indexes.append(index)
        else:
            await _dispatch(db, tool_name, entry, machines)
            entry["status"] = CONFIRMED
        started.append((index, entry, names))

    message.pending_actions = actions
    await db.commit()

    actor = f"{user.username} (AI assistant, automatic)" if automatic else None
    for entry, permission_value in denied:
        tool_name = str(entry.get("tool"))
        await log_event(
            db,
            request=request,
            actor=actor,
            action="ai.action.denied",
            summary=f"Blocked AI action {tool_name}: missing '{permission_value}'",
            outcome=AuditOutcome.DENIED,
            target_type="ai_conversation",
            target_id=conversation.id,
            target_label=conversation.title,
            details={"tool": tool_name, "permission": permission_value},
        )
    for _index, entry, names in started:
        tool_name = str(entry.get("tool"))
        verb = "Ran automatically" if automatic else "Confirmed"
        await log_event(
            db,
            request=request,
            actor=actor,
            action=f"ai.action.{tool_name}",
            summary=f"{verb} AI-proposed {tool_name} on {', '.join(names)}",
            target_type="ai_conversation",
            target_id=conversation.id,
            target_label=conversation.title,
            details={
                "conversation_id": str(conversation.id),
                "message_id": str(message.id),
                "tool": tool_name,
                "command": entry.get("command"),
                "strategy": entry.get("strategy"),
                "target_type": entry.get("target_type"),
                "target_name": entry.get("target_name"),
                "machines": names,
                "automatic": automatic,
            },
        )

    if shell_indexes:
        # Imported here: app.tasks.ai_jobs imports this module.
        from app.tasks import ai_jobs

        ai_jobs.execute_ai_actions.delay(str(conversation.id), str(message.id), shell_indexes)
    return errors


def _result_rows(entry: Mapping[str, Any], ran: set[str]) -> list[dict[str, Any]]:
    """One row per machine of the proposal; the ones not selected are
    `skipped`, the rest `running` until `execute_ai_actions` fills them."""
    return [
        {
            "machine_id": machine_id,
            "machine_name": name,
            "status": "running" if machine_id in ran else "skipped",
        }
        for machine_id, name in zip(
            [str(m) for m in entry.get("machine_ids") or []],
            entry.get("machine_names") or [],
            strict=False,
        )
    ]


async def _dispatch(
    db: AsyncSession, tool_name: str, entry: Mapping[str, Any], machines: list[Machine]
) -> None:
    """The fire-and-forget tools: the same functions their buttons call."""
    if tool_name == RUN_UPDATE:
        strategy = UpgradeStrategy(str(entry.get("strategy") or UpgradeStrategy.DIST_UPGRADE.value))
        await trigger_updates(db, machines, strategy)
    elif tool_name == CHECK_UPDATES:
        await trigger_check_updates(machines)
    elif tool_name == REBOOT:
        await send_power_to_machines(machines, PowerAction.REBOOT)
    elif tool_name == SHUTDOWN:
        await send_power_to_machines(machines, PowerAction.SHUTDOWN)


async def discard_actions(
    db: AsyncSession,
    conversation: AiConversation,
    message_id: uuid.UUID,
    indexes: Collection[int],
) -> None:
    """Mark pending actions discarded. Nothing runs, and there's no audit
    entry — declining to do something isn't a mutation of the fleet."""
    message = await lock_message(db, conversation, message_id)
    if message is None:
        return
    actions = [dict(action) for action in message.pending_actions or []]
    for index in indexes:
        if 0 <= index < len(actions) and actions[index].get("status") == PENDING:
            actions[index]["status"] = DISCARDED
    message.pending_actions = actions
    await db.commit()


def pending_indexes(message: AiMessage) -> list[int]:
    return [
        index
        for index, entry in enumerate(message.pending_actions or [])
        if entry.get("status") == PENDING
    ]
