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

**What this task can and cannot do.** It can read the fleet (the two
read-only lookups execute here, immediately). It can *record* a proposed
mutating action into `AiMessage.pending_actions`. It can never run one:
there is no call to `machine_actions`, to `run_remote_ssh_command`, or to
anything else that touches a machine anywhere in this module. Executing a
proposal requires a human's confirmed POST — see `app.web.routes.ai`.

Permissions are re-derived from the conversation owner's account **fresh
from the database on every turn**, never from anything cached or passed in
by the caller: a role edited between two messages takes effect on the next
one.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from sqlalchemy import select

from app.ai.base import AiProviderError, ChatTurnResult, ToolCall
from app.ai.providers import build_client
from app.ai.tools import (
    MAX_TOOL_ROUNDTRIPS,
    SYSTEM_PROMPT,
    TOOL_SPECS,
    available_tools,
    build_pending_action,
    execute_read_only_tool,
)
from app.ai.usage import check_within_limits, record_usage
from app.core.app_settings import get_or_create_app_settings
from app.db import session as db_session
from app.db.models.ai_conversation import AiConversation
from app.db.models.ai_message import AiMessage, AiMessageRole
from app.db.models.user import User
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

_NO_TEXT_FALLBACK = (
    "(The assistant returned no text for this turn — see the proposed actions below.)"
)


async def _load_history(db: Any, conversation_id: uuid.UUID) -> list[Any]:
    """Replay every stored provider-native message, oldest first. Each
    `AiMessage.provider_native` holds the list of native messages that turn
    contributed (see `app.db.models.ai_message`), so the history is just
    those lists concatenated — no translation, which is the entire reason
    they're stored provider-shaped in the first place."""
    result = await db.execute(
        select(AiMessage)
        .where(AiMessage.conversation_id == conversation_id)
        .order_by(AiMessage.created_at, AiMessage.id)
    )
    messages: list[Any] = []
    for row in result.scalars().all():
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
    conversation_id: str, user_message: str | None = None, *, allow_tools: bool
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
            history = await _load_history(db, conversation.id)
            user_native = client.build_user_message(user_message)
            db.add(
                AiMessage(
                    conversation_id=conversation.id,
                    role=AiMessageRole.USER,
                    content=user_message,
                    provider_native=[user_native],
                )
            )
            await db.commit()
            messages: list[Any] = [*history, user_native]
        else:
            messages = await _load_history(db, conversation.id)

        # Permission filter #1: re-derived from the owner's current role.
        tools = available_tools(owner) if allow_tools else []

        turn_native: list[Any] = []
        pending_actions: list[dict[str, Any]] = []
        final_text: str | None = None

        for round_index in range(MAX_TOOL_ROUNDTRIPS):
            try:
                result: ChatTurnResult = await client.send(
                    messages, tools, conversation.model_id, SYSTEM_PROMPT
                )
            except AiProviderError as exc:
                return await _persist_assistant_error(db, conversation.id, str(exc))

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
    context (see the prompt-injection warning in wiki/AI-Assistant.md).
    Giving it no tools to call means the worst a malicious payload in that
    output can achieve is a misleading summary — it cannot reach a tool,
    and therefore cannot even produce a new proposal to confirm.
    """
    return asyncio.run(_run_turn(conversation_id, allow_tools=False, user_message=output_text))
