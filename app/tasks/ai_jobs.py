"""The AI assistant's provider turn, as a Celery job.

Same two-part shape as `app.tasks.jobs` (async implementation + a one-line
synchronous task wrapper) and the same `db_session.AsyncSessionLocal()`
through-the-module rule — see that module's docstring, and
`app.tasks.celery_app`'s, for why both matter.

**Why this is a background task at all**, unlike the LDAP/OIDC HTTP calls
elsewhere in this app: one user message can drive several *sequential*
provider requests (the model asks for a machine list, gets it, then asks
for another lookup, then answers), each of which can take tens of seconds
on a slow model. That is the same "a single request would block a web
worker for a long time" situation every SSH operation in this app already
solves with Celery, so it's solved the same way — the web route enqueues
and waits on the result with `asyncio.to_thread(async_result.get, ...)`.

**What the turn can and cannot do.** It can read the fleet (the
read-only lookups execute here, immediately). It can *record* a proposed
mutating action into `AiMessage.pending_actions`. It never runs one
itself: an action starts only through `app.services.ai_actions.
start_actions` — after a human's confirmed POST (`app.web.routes.ai`), or,
for a shell command only, right after the turn when the account's AI
command mode is "allow" (`User.ai_command_mode`). `execute_ai_actions`
below then runs a started shell command; it does no authorization of its
own and is enqueued from nowhere else.

Permissions are re-derived from the conversation owner's account **fresh
from the database on every turn**, never from anything cached or passed in
by the caller: a role edited between two messages takes effect on the next
one.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.base import AiProviderError, BaseAiClient, ChatTurnResult, ToolCall
from app.ai.providers import build_client
from app.ai.tools import (
    MAX_TOOL_ROUNDTRIPS,
    RUN_SSH_COMMAND,
    TOOL_SPECS,
    available_tools,
    build_pending_action,
    execute_read_only_tool,
    system_prompt,
)
from app.ai.usage import check_within_limits, record_usage
from app.audit import log_event
from app.core.app_settings import get_or_create_app_settings
from app.db import session as db_session
from app.db.models.ai_conversation import AiConversation
from app.db.models.ai_message import AiMessage, AiMessageRole
from app.db.models.ai_provider import AiProviderConfig
from app.db.models.app_settings import FleetSummaryFrequency
from app.db.models.audit_log import AuditLogEntry, AuditOutcome
from app.db.models.fleet_summary import FleetSummary
from app.db.models.machine import Machine
from app.db.models.machine_change import MachineChange
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus
from app.db.models.notification_rule import NotificationEventType
from app.db.models.user import AiCommandMode, User
from app.services import ai_actions, ai_attachments
from app.services.fleet_stats import compute_fleet_stats
from app.services.notifications import notify
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

# What the model is told after a mutating tool call. It is important that
# this reads as "recorded, awaiting a human", not as "done" — the model's
# next sentence to the user is written from it.
_PROPOSAL_FEEDBACK = (
    "Recorded as a proposal and shown to the operator for confirmation. "
    "It has NOT run. Do not propose the same action again; instead tell the "
    "operator what you have proposed and that they need to confirm it."
)

# The same, for a shell command the account lets run without a Confirm
# (`AiCommandMode.ALLOW`): it starts as soon as this turn is saved.
_AUTO_RUN_FEEDBACK = (
    "Accepted: the operator's settings let this command run without a "
    "confirmation, so it starts as soon as this reply is sent, and its output "
    "will be given to you in the next message. Do not propose it again; tell "
    "the operator briefly what is running and why."
)

_NO_TEXT_FALLBACK = (
    "(The assistant returned no text for this turn — see the proposed actions below.)"
)


async def _load_history(
    db: Any, conversation_id: uuid.UUID, client: BaseAiClient | None = None
) -> list[Any]:
    """Replay every stored provider-native message, oldest first. Each
    `AiMessage.provider_native` holds the list of native messages that turn
    contributed (see `app.db.models.ai_message`), so the history is just
    those lists concatenated — no translation, which is the entire reason
    they're stored provider-shaped in the first place.

    The one exception is a user message with pictures (`AiAttachment`):
    its stored native form is text only, and `client` builds the turn again
    with the pictures in that provider's own shape."""
    result = await db.execute(
        select(AiMessage)
        .where(AiMessage.conversation_id == conversation_id)
        .order_by(AiMessage.created_at, AiMessage.id)
    )
    rows = list(result.scalars().all())
    images = (
        await ai_attachments.images_by_message(db, conversation_id) if client is not None else {}
    )
    messages: list[Any] = []
    for row in rows:
        if client is not None and row.id in images and row.provider_native is not None:
            messages.append(client.build_user_message(row.content, images[row.id]))
            continue
        native = row.provider_native
        if isinstance(native, list):
            messages.extend(native)
        elif native is not None:
            messages.append(native)
    return messages


async def _persist_assistant_error(
    db: Any, conversation_id: uuid.UUID, message: str
) -> dict[str, Any]:
    """Record a failure as a visible assistant message.

    `provider_native=None` deliberately: an error we generated is not part
    of the provider's own conversation state, and replaying it back to the
    provider next turn would be inventing history it never produced.
    """
    db.add(
        AiMessage(
            conversation_id=conversation_id,
            role=AiMessageRole.ASSISTANT,
            content=message,
            provider_native=None,
        )
    )
    await db.commit()
    return {"ok": False, "error": message}


async def _run_turn(
    conversation_id: str,
    user_message: str | None = None,
    *,
    allow_tools: bool,
    tool_output: bool = False,
) -> dict[str, Any]:
    """Run one provider turn and persist the assistant's reply.

    `user_message`, when given, means *this call* is responsible for
    recording that text as the turn's own user-role message (used by
    `summarize_tool_output`, whose "user" input is really tool output fed
    back to the model, not something a human typed and already on screen).
    When `None` (the interactive chat's own `run_ai_turn`), the caller
    (`app.web.routes.ai.post_message`) has already inserted the human's
    message itself — synchronously, before enqueueing this task — so the
    conversation page can show it immediately rather than waiting for a
    background task to get scheduled first. This function then just
    replays history, which already ends with that message.
    """
    async with db_session.AsyncSessionLocal() as db:
        conversation = await db.get(AiConversation, uuid.UUID(conversation_id))
        if conversation is None:
            return {"ok": False, "error": "Conversation not found."}

        owner = await db.get(User, conversation.user_id)
        if owner is None or not owner.is_active:
            return {"ok": False, "error": "The conversation's owner is no longer active."}

        app_settings = await get_or_create_app_settings(db)
        # Before the provider call, never after — see app.ai.usage.
        limit_error = await check_within_limits(db, app_settings)
        if limit_error is not None:
            if user_message is not None:
                db.add(
                    AiMessage(
                        conversation_id=conversation.id,
                        role=AiMessageRole.USER,
                        content=user_message,
                        provider_native=None,
                        is_tool_output=tool_output,
                    )
                )
                await db.commit()
            return await _persist_assistant_error(db, conversation.id, limit_error)

        provider = conversation.provider
        if provider is None or not provider.enabled:
            return await _persist_assistant_error(
                db, conversation.id, "This conversation's AI provider is no longer enabled."
            )

        try:
            client = build_client(provider)
        except AiProviderError as exc:
            return await _persist_assistant_error(db, conversation.id, str(exc))

        if user_message is not None:
            history = await _load_history(db, conversation.id, client)
            user_native = client.build_user_message(user_message)
            db.add(
                AiMessage(
                    conversation_id=conversation.id,
                    role=AiMessageRole.USER,
                    content=user_message,
                    provider_native=[user_native],
                    is_tool_output=tool_output,
                )
            )
            await db.commit()
            messages: list[Any] = [*history, user_native]
        else:
            messages = await _load_history(db, conversation.id, client)

        # Permission filter #1: re-derived from the owner's current role.
        tools = available_tools(owner) if allow_tools else []

        turn_native: list[Any] = []
        pending_actions: list[dict[str, Any]] = []
        final_text: str | None = None

        for round_index in range(MAX_TOOL_ROUNDTRIPS):
            try:
                result: ChatTurnResult = await client.send(
                    messages, tools, conversation.model_id, system_prompt(owner)
                )
            except AiProviderError as exc:
                return await _persist_assistant_error(db, conversation.id, str(exc))

            conversation.input_tokens += max(result.input_tokens, 0)
            conversation.output_tokens += max(result.output_tokens, 0)
            # Commits the conversation's counts too.
            await record_usage(
                db,
                user_id=owner.id,
                provider_kind=provider.kind,
                model_id=conversation.model_id,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
            )

            if result.text:
                final_text = result.text

            if not result.tool_calls:
                turn_native.append(result.raw_assistant_message)
                break

            outputs: list[tuple[ToolCall, str]] = []
            for call in result.tool_calls:
                spec = TOOL_SPECS.get(call.name)
                if spec is not None and not spec.mutating:
                    # Read-only: safe to execute here and now.
                    outputs.append((call, await execute_read_only_tool(db, owner, call)))
                    continue
                # Mutating (or unknown): recorded only. Permission check #2
                # happens inside build_pending_action, which records a
                # `denied` entry rather than dropping the call.
                entry = await build_pending_action(db, owner, call)
                pending_actions.append(entry)
                if entry.get("status") == "denied":
                    feedback = str(entry.get("reason") or "Refused.")
                elif (
                    call.name in ai_actions.AUTO_RUN_TOOLS
                    and owner.ai_mode == AiCommandMode.ALLOW
                ):
                    feedback = _AUTO_RUN_FEEDBACK
                else:
                    feedback = _PROPOSAL_FEEDBACK
                outputs.append((call, feedback))

            follow_up = client.build_tool_result_messages(result, outputs)
            messages.extend(follow_up)
            turn_native.extend(follow_up)

            if round_index == MAX_TOOL_ROUNDTRIPS - 1:
                logger.warning(
                    "AI turn for conversation %s hit the %d tool round-trip cap",
                    conversation_id,
                    MAX_TOOL_ROUNDTRIPS,
                )

        assistant_message = AiMessage(
            conversation_id=conversation.id,
            role=AiMessageRole.ASSISTANT,
            content=final_text or _NO_TEXT_FALLBACK,
            provider_native=turn_native or None,
            pending_actions=pending_actions or None,
        )
        db.add(assistant_message)
        await db.commit()

        # "allow": a proposed shell command starts now, through the same
        # checks a Confirm goes through (app.services.ai_actions).
        if owner.ai_mode == AiCommandMode.ALLOW:
            auto = [
                index
                for index, entry in enumerate(pending_actions)
                if entry.get("tool") == RUN_SSH_COMMAND
                and entry.get("status") == ai_actions.PENDING
            ]
            if auto:
                await ai_actions.start_actions(
                    db, owner, conversation, assistant_message.id, auto, automatic=True
                )

        return {
            "ok": True,
            "message_id": str(assistant_message.id),
            "pending_action_count": len(pending_actions),
        }


# A turn can make up to MAX_TOOL_ROUNDTRIPS (5) sequential provider calls,
# each with its own 90s timeout (CHAT_TIMEOUT_SECONDS in
# app/ai/providers.py) — worst case, a genuinely slow model's turn takes
# close to 450s. Both tasks below need a `time_limit` comfortably above
# that, or Celery's own default (60s, see task_time_limit in
# app/tasks/celery_app.py) kills the task via SIGKILL mid-call, long before
# it would ever hit its own internal timeout — silently: nothing gets
# persisted, and the conversation just never receives a reply. This was a
# real bug, not a hypothetical one.
_AI_TURN_TIME_LIMIT_SECONDS = 480


@celery_app.task(name="app.tasks.ai_jobs.run_ai_turn", time_limit=_AI_TURN_TIME_LIMIT_SECONDS)
def run_ai_turn(conversation_id: str) -> dict[str, Any]:
    """The interactive chat's own turn. Unlike `summarize_tool_output`
    below, this never receives the user's message text as an argument —
    `app.web.routes.ai.post_message` already persisted it (synchronously,
    before enqueueing this task) so the conversation page shows it
    immediately rather than waiting on a background task to even start."""
    return asyncio.run(_run_turn(conversation_id, allow_tools=True))


@celery_app.task(
    name="app.tasks.ai_jobs.summarize_tool_output", time_limit=_AI_TURN_TIME_LIMIT_SECONDS
)
def summarize_tool_output(conversation_id: str, output_text: str) -> dict[str, Any]:
    """One extra provider call after a confirmed `run_ssh_command`, so the
    assistant can explain the command's output in plain language.

    Deliberately runs with **no tools offered** (`allow_tools=False`): this
    turn's whole input is output that came off a managed machine, which is
    the one place in this feature where untrusted text enters the model's
    context (see the prompt-injection warning in wiki/AI-Assistant).
    Giving it no tools to call means the worst a malicious payload in that
    output can achieve is a misleading summary — it cannot reach a tool,
    and therefore cannot even produce a new proposal to confirm.
    """
    return asyncio.run(
        _run_turn(conversation_id, allow_tools=False, user_message=output_text, tool_output=True)
    )


# --- Running a started shell command (app.services.ai_actions) -------------


_MAX_PARALLEL_MACHINES = 8


def _tail_output(text: str) -> str:
    limit = ai_actions.MAX_RESULT_OUTPUT_CHARS
    return text if len(text) <= limit else "[... earlier output cut ...]\n" + text[-limit:]


async def _run_on_machine(machine_id: str, command: str, limit_seconds: int) -> dict[str, Any]:
    """One machine's run, as a result row; never raises."""
    # Imported here: app.tasks.jobs is the big SSH job module, and only
    # this task needs it.
    from app.tasks import jobs

    try:
        async with asyncio.timeout(limit_seconds):
            result = await jobs._run_remote_ssh_command(machine_id, command)
    except TimeoutError:
        return {
            "status": "timeout",
            "error": f"The command did not finish within {limit_seconds} s.",
        }
    except Exception as exc:  # one machine's failure must not lose the others'
        logger.warning("AI command on machine %s failed: %s", machine_id, exc)
        return {"status": "failed", "error": str(exc) or type(exc).__name__}
    if isinstance(result, dict) and result.get("ok"):
        exit_status = result.get("exit_status")
        return {
            "status": "ok" if exit_status == 0 else "failed",
            "exit_status": exit_status,
            "output": _tail_output(str(result.get("output") or "")),
        }
    error = str(result.get("error")) if isinstance(result, dict) else "Unknown error."
    return {"status": "failed", "error": error}


async def _execute_ai_actions(
    conversation_id: str, message_id: str, indexes: list[int]
) -> dict[str, Any]:
    """Run the started shell commands at `indexes` of one message on every
    machine at once (`app.services.ai_actions.start_actions` already checked
    and audit-logged them), store each machine's result in the action's
    `results`, then let the assistant summarize the output — with no tools
    (see `summarize_tool_output`). Bounded fan-out (`MAX_TARGET_MACHINES`
    per action) inside one task, because the summary needs every result."""
    conversation_uuid = uuid.UUID(conversation_id)
    message_uuid = uuid.UUID(message_id)
    async with db_session.AsyncSessionLocal() as db:
        conversation = await db.get(AiConversation, conversation_uuid)
        message = await db.get(AiMessage, message_uuid)
        if conversation is None or message is None:
            return {"ok": False, "error": "Conversation not found."}
        app_settings = await get_or_create_app_settings(db)
        timeout = app_settings.ssh_connect_timeout + 70
        work: list[tuple[int, str, str]] = []
        commands: dict[int, str] = {}
        for index in indexes:
            entries = message.pending_actions or []
            if not 0 <= index < len(entries):
                continue
            entry = entries[index]
            if entry.get("status") != ai_actions.RUNNING:
                continue
            commands[index] = str(entry.get("command") or "")
            work.extend(
                (index, str(row.get("machine_id")), str(row.get("machine_name")))
                for row in entry.get("results") or []
                if row.get("status") == "running"
            )

    # At most this many machines at once: each run holds a DB session for
    # its credential lookup, and the pool is not sized for 25 at a time.
    limit = asyncio.Semaphore(_MAX_PARALLEL_MACHINES)

    async def _limited(machine_id: str, command: str) -> dict[str, Any]:
        async with limit:
            return await _run_on_machine(machine_id, command, timeout)

    outcomes = await asyncio.gather(
        *(_limited(machine_id, commands[index]) for index, machine_id, _ in work)
    )
    by_key = {
        (index, machine_id): outcome
        for (index, machine_id, _), outcome in zip(work, outcomes, strict=True)
    }

    sections: list[str] = []
    async with db_session.AsyncSessionLocal() as db:
        conversation = await db.get(AiConversation, conversation_uuid)
        if conversation is None:
            return {"ok": False, "error": "Conversation not found."}
        message = await ai_actions.lock_message(db, conversation, message_uuid)
        if message is None:
            return {"ok": False, "error": "Message not found."}
        actions = [dict(action) for action in message.pending_actions or []]
        for index in commands:
            entry = actions[index]
            rows = []
            for row in entry.get("results") or []:
                outcome = by_key.get((index, str(row.get("machine_id"))))
                rows.append({**row, **outcome} if outcome is not None else dict(row))
            entry["results"] = rows
            entry["finished_at"] = ai_actions.now_iso()
            entry["status"] = ai_actions.CONFIRMED
            for row in rows:
                if row.get("status") == "skipped":
                    continue
                if row.get("status") in ("ok", "failed") and "exit_status" in row:
                    output = row.get("output") or "(no output)"
                    body = f"exit status: {row.get('exit_status')}\n{output}"
                else:
                    body = f"failed: {row.get('error') or 'unknown error'}"
                sections.append(f"### {row.get('machine_name')} — `{commands[index]}`\n{body}")
        message.pending_actions = actions
        await db.commit()

    if not sections:
        return {"ok": True, "summarized": False}
    summary_input = "Result of the confirmed command(s):\n\n" + "\n\n".join(sections)
    return await _run_turn(
        conversation_id, allow_tools=False, user_message=summary_input, tool_output=True
    )


# The SSH runs (connect timeout + 70 s each, 8 at a time, up to 25 machines)
# plus one summary
# turn (`_AI_TURN_TIME_LIMIT_SECONDS`).
_EXECUTE_TIME_LIMIT_SECONDS = _AI_TURN_TIME_LIMIT_SECONDS + 600


@celery_app.task(
    name="app.tasks.ai_jobs.execute_ai_actions", time_limit=_EXECUTE_TIME_LIMIT_SECONDS
)
def execute_ai_actions(conversation_id: str, message_id: str, indexes: list[int]) -> dict[str, Any]:
    """See `_execute_ai_actions`. Enqueued only by
    `app.services.ai_actions.start_actions`, which did the authorization."""
    return asyncio.run(_execute_ai_actions(conversation_id, message_id, indexes))


# --- Scheduled fleet summary (app.db.models.fleet_summary.FleetSummary) ---
#
# Deliberately display-only, for now: this only ever writes a FleetSummary
# row for the Dashboard to show. No email, Slack, or other notification is
# sent from here — that's a separate, not-yet-built feature (see the wiki),
# and bolting it on later only means adding a call after the `session.add`
# below, not restructuring anything here.
#
# Off by default (`FleetSummaryFrequency.DISABLED`) and checked on every
# tick of a *daily* Beat entry (see app.tasks.celery_app) regardless of
# whether the configured frequency is "daily" or "weekly" — `_is_due` below
# is what actually decides whether today's tick does anything, the same
# "cheap sweep, real work is conditional" shape `app.tasks.jobs._refresh_all_machine_readiness`
# and friends already use for their own settings-driven cadences.

_FLEET_SUMMARY_SYSTEM_PROMPT = (
    "You are a fleet-management assistant. You are given a snapshot of a "
    "fleet of Debian/Ubuntu servers managed by debcontrol: counts, and "
    "specific machines that need attention. Write a short, plain-language "
    "report for a system administrator: what changed or stands out, and "
    "what needs attention, roughly in that order. Use short paragraphs or "
    "a short bullet list. Do not invent facts beyond what's given — if "
    "nothing needs attention, say so briefly."
)

# Same time budget reasoning as _AI_TURN_TIME_LIMIT_SECONDS — this is one
# provider call, not several, but a slow model's single response can still
# take close to CHAT_TIMEOUT_SECONDS (90s, app/ai/providers.py).
_FLEET_SUMMARY_TIME_LIMIT_SECONDS = 120

# How large a "still needs attention" list gets before the prompt just says
# "and N more" — keeps the prompt (and therefore the token cost) bounded
# against a fleet with hundreds of matching machines, without hiding scale
# from the model entirely.
_FLEET_SUMMARY_LIST_LIMIT = 25


def _fleet_summary_due(
    last_generated_at: datetime | None, frequency: FleetSummaryFrequency, now: datetime
) -> bool:
    """Never generated yet is always due. Otherwise, due once comfortably
    more than a day (daily) or a week (weekly) has passed — the `-4 hours`
    margin absorbs the fact that this is checked on a fixed daily Beat tick
    (see app.tasks.celery_app), not a precise timer, without waiting an
    extra full day if that tick lands a little earlier one day than the
    last time a summary was actually written."""
    if last_generated_at is None:
        return True
    if last_generated_at.tzinfo is None:
        last_generated_at = last_generated_at.replace(tzinfo=UTC)
    elapsed = now - last_generated_at
    if frequency == FleetSummaryFrequency.WEEKLY:
        return elapsed >= timedelta(days=7) - timedelta(hours=4)
    return elapsed >= timedelta(days=1) - timedelta(hours=4)


def _format_named_list(names: list[str], total: int) -> str:
    if not names:
        return "none"
    shown = ", ".join(names)
    if total > len(names):
        shown += f", and {total - len(names)} more"
    return shown


async def _build_fleet_summary_prompt(
    session: AsyncSession, frequency: FleetSummaryFrequency, now: datetime
) -> str:
    """Everything the model gets to work with — counts plus specific,
    named machines, bounded to `_FLEET_SUMMARY_LIST_LIMIT` each so the
    prompt stays a fixed, small size regardless of fleet size."""
    is_weekly = frequency == FleetSummaryFrequency.WEEKLY
    since = now - (timedelta(days=7) if is_weekly else timedelta(days=1))
    period = "7 days" if is_weekly else "24 hours"

    stats = await compute_fleet_stats(session)

    offline_result = await session.execute(
        select(Machine.name)
        .where(Machine.is_active, Machine.is_reachable.is_(False))
        .order_by(Machine.name)
    )
    offline_names = [row[0] for row in offline_result.all()]

    security_result = await session.execute(
        select(Machine.name)
        .where(Machine.is_active, Machine.security_upgradable_count > 0)
        .order_by(Machine.security_upgradable_count.desc(), Machine.name)
    )
    security_names = [row[0] for row in security_result.all()]

    readiness_result = await session.execute(
        select(Machine.name, Machine.readiness_missing).where(
            Machine.is_active, Machine.readiness_missing.is_not(None)
        )
    )
    readiness_names = [name for name, missing in readiness_result.all() if missing]

    failed_updates_result = await session.execute(
        select(func.count())
        .select_from(MachineUpdateRun)
        .where(
            MachineUpdateRun.status == UpdateRunStatus.FAILED,
            MachineUpdateRun.created_at >= since,
        )
    )
    failed_update_count = failed_updates_result.scalar_one()

    denied_events_result = await session.execute(
        select(func.count())
        .select_from(AuditLogEntry)
        .where(AuditLogEntry.outcome != AuditOutcome.SUCCESS, AuditLogEntry.created_at >= since)
    )
    denied_event_count = denied_events_result.scalar_one()

    changes_result = await session.execute(
        select(Machine.name, MachineChange.field)
        .join(MachineChange, MachineChange.machine_id == Machine.id)
        .where(Machine.is_active, MachineChange.detected_at >= since)
    )
    changed_names: dict[str, set[str]] = {}
    for name, changed_field in changes_result.all():
        changed_names.setdefault(name, set()).add(changed_field)
    changed_shown = _format_named_list(
        [
            f"{name} ({', '.join(sorted(fields))})"
            for name, fields in sorted(changed_names.items())[:_FLEET_SUMMARY_LIST_LIMIT]
        ],
        len(changed_names),
    )

    offline_shown = _format_named_list(
        offline_names[:_FLEET_SUMMARY_LIST_LIMIT], len(offline_names)
    )
    return (
        f"Fleet snapshot (last {period}):\n"
        f"- Total machines: {stats['total']} "
        f"({stats['online']} online, {stats['offline']} offline)\n"
        f"- Currently offline: {offline_shown}\n"
        f"- Needs updates: {stats['needs_updates']} machine(s), "
        f"{stats['needs_security_updates']} with a security update pending\n"
        f"- Security updates pending on: "
        f"{_format_named_list(security_names[:_FLEET_SUMMARY_LIST_LIMIT], len(security_names))}\n"
        f"- Needs reboot: {stats['needs_reboot']} machine(s)\n"
        f"- Readiness check found something missing on: "
        f"{_format_named_list(readiness_names[:_FLEET_SUMMARY_LIST_LIMIT], len(readiness_names))}\n"
        f"- Configuration changes detected in the period on: {changed_shown}\n"
        f"- Failed update runs in the period: {failed_update_count}\n"
        f"- Denied/failed audit events in the period: {denied_event_count}\n"
    )


async def _generate_fleet_summary() -> None:
    async with db_session.AsyncSessionLocal() as session:
        app_settings = await get_or_create_app_settings(session)
        frequency = app_settings.fleet_summary_frequency
        if frequency == FleetSummaryFrequency.DISABLED:
            return
        if not app_settings.fleet_summary_provider_id or not app_settings.fleet_summary_model_id:
            logger.info("generate_fleet_summary: enabled but no model configured yet")
            return

        now = datetime.now(UTC)
        last_result = await session.execute(
            select(FleetSummary.created_at).order_by(FleetSummary.created_at.desc()).limit(1)
        )
        last_generated_at = last_result.scalar_one_or_none()
        if not _fleet_summary_due(last_generated_at, frequency, now):
            return

        provider = await session.get(AiProviderConfig, app_settings.fleet_summary_provider_id)
        if provider is None or not provider.enabled:
            logger.warning("generate_fleet_summary: configured provider is missing or disabled")
            return

        try:
            client = build_client(provider)
        except AiProviderError as exc:
            logger.warning("generate_fleet_summary: provider not usable: %s", exc)
            return

        prompt = await _build_fleet_summary_prompt(session, frequency, now)
        try:
            result = await client.send(
                [client.build_user_message(prompt)],
                [],
                app_settings.fleet_summary_model_id,
                _FLEET_SUMMARY_SYSTEM_PROMPT,
            )
        except AiProviderError as exc:
            logger.warning("generate_fleet_summary: provider call failed: %s", exc)
            return

        if not result.text:
            return

        session.add(
            FleetSummary(
                frequency=frequency.value,
                content=result.text,
                provider_kind=provider.kind.value,
                model_id=app_settings.fleet_summary_model_id,
            )
        )
        await session.commit()

        # Who (if anyone) actually gets emailed about this is configured in
        # Notifications, not here — see NotificationEventType.
        # FLEET_SUMMARY_GENERATED's own docstring. Not machine-scoped, so
        # every rule listening for this event matches regardless of its
        # machine/machine-group scope (see `app.services.notifications.
        # _rule_matches_scope`).
        await notify(
            session,
            NotificationEventType.FLEET_SUMMARY_GENERATED,
            context={"details": result.text},
        )


@celery_app.task(
    name="app.tasks.ai_jobs.generate_fleet_summary",
    time_limit=_FLEET_SUMMARY_TIME_LIMIT_SECONDS,
)
def generate_fleet_summary() -> None:
    asyncio.run(_generate_fleet_summary())


_FLEET_SUMMARY_PURGE_ACTOR = "retention policy (automatic)"


async def _purge_old_fleet_summaries() -> None:
    """Same shape as `app.tasks.jobs._purge_old_fleet_snapshots` — skipped
    entirely when retention is unset (`None` = keep forever)."""
    async with db_session.AsyncSessionLocal() as session:
        app_settings = await get_or_create_app_settings(session)
        retention_days = app_settings.fleet_summary_retention_days
        if not retention_days:
            return
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        count_result = await session.execute(
            select(func.count()).select_from(FleetSummary).where(FleetSummary.created_at < cutoff)
        )
        deleted_count = count_result.scalar_one()
        if not deleted_count:
            return

        await session.execute(delete(FleetSummary).where(FleetSummary.created_at < cutoff))
        await session.commit()

        await log_event(
            session,
            actor=_FLEET_SUMMARY_PURGE_ACTOR,
            action="fleet_summary.purge",
            summary=(
                f"Purged {deleted_count} fleet summar{'ies' if deleted_count != 1 else 'y'} "
                f"older than {retention_days} day(s)"
            ),
            details={"deleted_count": deleted_count, "retention_days": retention_days},
        )


@celery_app.task(name="app.tasks.ai_jobs.purge_old_fleet_summaries")
def purge_old_fleet_summaries() -> None:
    asyncio.run(_purge_old_fleet_summaries())
