"""The AI assistant's web routes — the chat UI, and the confirm/discard
gate in front of every action it proposes.

**Web-only, deliberately: there is no `/api/v1/ai*` surface for this
feature.** Same reasoning already applied to SSH key rotation and the
LDAP/OIDC configuration (see `app/web/routes/api_v1.py`'s module
docstring), only more so. A stolen bearer token that could reconfigure
which third-party provider receives this deployment's prompts, or that
could drive machine actions through a chat endpoint, is a bigger blast
radius than this feature needs to accept in its first version. Everything
here requires a browser session and a CSRF token.

**The confirm gate.** `POST .../messages/{message_id}/confirm` is the only
place in this application where an AI-proposed action can execute. It is:

- CSRF-protected (`Depends(verify_csrf)`), so it cannot be triggered
  cross-site;
- scoped to the conversation's owner, so nobody can confirm someone else's
  proposal;
- gated on the *current* permission for that specific tool, re-read from
  the user's role at this moment (permission check #3 — see
  `app.ai.tools`), so a role downgrade takes effect immediately even for a
  proposal written before it;
- restricted to entries still marked `pending`, so one proposal can be
  executed exactly once;
- audit-logged with the literal command and every resolved target.

Nothing else — not the chat route, not the Celery turn task, not the tool
layer — calls `machine_actions` or enqueues an SSH job. `app/tasks/ai_jobs.py`
only ever *records* a proposal.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

# NOT the builtin `TimeoutError` — see app/web/routes/machines.py's import
# of the same name for why that distinction is load-bearing.
from celery.exceptions import TimeoutError as CeleryTimeoutError
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.base import AiProviderError
from app.ai.config import get_or_create_ai_provider_configs, get_selectable_models
from app.ai.providers import build_client
from app.ai.tools import (
    CHECK_UPDATES,
    REBOOT,
    RUN_SSH_COMMAND,
    RUN_UPDATE,
    SHUTDOWN,
    load_machines,
    missing_permission,
)
from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.config import get_settings
from app.core.csrf import verify_csrf
from app.db.models.ai_conversation import AiConversation, derive_title
from app.db.models.ai_message import AiMessage, AiMessageRole, PendingActionStatus
from app.db.models.ai_model import AiModel
from app.db.models.ai_provider import AiProviderConfig
from app.db.models.audit_log import AuditOutcome
from app.db.models.machine_update_run import UpgradeStrategy
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.services.machine_actions import (
    send_power_to_machines,
    trigger_check_updates,
    trigger_updates,
)
from app.ssh.power import PowerAction
from app.tasks import ai_jobs
from app.tasks import jobs as tasks
from app.web.templating import templates

router = APIRouter(
    prefix="/ai", dependencies=[Depends(require_permission(Permission.AI_ACCESS))]
)

# How long the web request waits for the background turn. Comfortably above
# the provider client's own 90s per-call ceiling would mean holding a web
# worker for minutes; 90s matches one slow call plus change, and a timeout
# is reported honestly rather than hidden.
_TURN_WAIT_SECONDS = 90


async def _get_conversation(
    db: AsyncSession, conversation_id: uuid.UUID, user: User
) -> AiConversation:
    """A conversation is visible only to the account that created it — the
    query filters on `user_id`, so another user (admin included) gets a 404
    rather than a 403. 404 is the deliberate choice, matching how this app
    treats a machine id that doesn't exist: a 403 would confirm that
    somebody else's conversation with that id does exist."""
    result = await db.execute(
        select(AiConversation).where(
            AiConversation.id == conversation_id, AiConversation.user_id == user.id
        )
    )
    conversation = result.scalar_one_or_none()
    if conversation is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found."
        )
    return conversation


async def _get_messages(db: AsyncSession, conversation_id: uuid.UUID) -> list[AiMessage]:
    result = await db.execute(
        select(AiMessage)
        .where(AiMessage.conversation_id == conversation_id)
        .order_by(AiMessage.created_at, AiMessage.id)
    )
    return list(result.scalars().all())


def _is_awaiting_reply(messages: list[AiMessage]) -> bool:
    """True once the human's turn has been sent but the assistant hasn't
    answered yet — the compose form disables itself and
    `partials/ai_messages_panel.html` polls for the reply while this holds."""
    return bool(messages) and messages[-1].role == AiMessageRole.USER


async def _render_conversation(
    request: Request, db: AsyncSession, conversation: AiConversation, errors: list[str]
) -> Response:
    messages = await _get_messages(db, conversation.id)
    return templates.TemplateResponse(
        request,
        "ai/conversation.html",
        {
            "conversation": conversation,
            "messages": messages,
            "awaiting_reply": _is_awaiting_reply(messages),
            "errors": errors,
            "csrf_token": request.state.csrf_token,
        },
    )


async def _render_messages_panel(
    request: Request, db: AsyncSession, conversation: AiConversation
) -> Response:
    """The self-polling fragment — see `partials/ai_messages_panel.html`.
    No `errors`: a mid-conversation provider failure is persisted as a
    normal (if unhappy-looking) assistant message by `_run_turn`/
    `_persist_assistant_error`, so it shows up as the next polled message
    rather than needing a separate error channel here."""
    messages = await _get_messages(db, conversation.id)
    return templates.TemplateResponse(
        request,
        "partials/ai_messages_panel.html",
        {
            "conversation": conversation,
            "messages": messages,
            "awaiting_reply": _is_awaiting_reply(messages),
            "csrf_token": request.state.csrf_token,
        },
    )


@router.get("")
async def list_conversations(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    result = await db.execute(
        select(AiConversation)
        .where(AiConversation.user_id == user.id)
        .order_by(AiConversation.updated_at.desc(), AiConversation.created_at.desc())
    )
    conversations = list(result.scalars().all())
    # Creating the five provider rows lazily here as well as on the Settings
    # page keeps `get_selectable_models` meaningful before an admin has ever
    # opened Settings.
    await get_or_create_ai_provider_configs(db)
    selectable = await get_selectable_models(db)
    return templates.TemplateResponse(
        request,
        "ai/list.html",
        {
            "conversations": conversations,
            "selectable_models": selectable,
            "can_manage_settings": user.has_permission(Permission.SETTINGS_MANAGE),
            "csrf_token": request.state.csrf_token,
        },
    )


@router.post("/conversations", dependencies=[Depends(verify_csrf)])
async def create_conversation(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    provider_model: str = Form(""),
    first_message: str = Form(""),
) -> Response:
    """`provider_model` is a single `"<provider_id>:<model_id>"` select
    value rather than two fields, so the pair can never be mismatched by a
    hand-crafted form post — it's re-validated against the enabled
    provider/model rows below regardless."""
    raw = provider_model.strip()
    provider_id_str, _, model_id = raw.partition(":")
    try:
        provider_id = uuid.UUID(provider_id_str)
    except ValueError:
        return RedirectResponse(url="/ai", status_code=status.HTTP_303_SEE_OTHER)

    # Re-check that this provider+model really is enabled — never trust the
    # submitted pair just because the dropdown offered something.
    allowed = await db.execute(
        select(AiModel)
        .join(AiProviderConfig, AiProviderConfig.id == AiModel.provider_id)
        .where(
            AiModel.provider_id == provider_id,
            AiModel.model_id == model_id,
            AiModel.enabled,
            AiProviderConfig.enabled,
        )
    )
    if allowed.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That AI model isn't enabled for use.",
        )

    conversation = AiConversation(
        user_id=user.id,
        title=derive_title(first_message),
        provider_id=provider_id,
        model_id=model_id,
    )
    db.add(conversation)
    await db.commit()
    await db.refresh(conversation)

    await log_event(
        db,
        request=request,
        action="ai.conversation.create",
        summary=f'Started an AI conversation ("{conversation.title}")',
        target_type="ai_conversation",
        target_id=conversation.id,
        target_label=conversation.title,
        details={"model": conversation.model_id},
    )

    return RedirectResponse(
        url=f"/ai/conversations/{conversation.id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/conversations/{conversation_id}")
async def show_conversation(
    request: Request,
    conversation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    conversation = await _get_conversation(db, conversation_id, user)
    return await _render_conversation(request, db, conversation, [])


@router.get("/conversations/{conversation_id}/messages-panel")
async def conversation_messages_panel(
    request: Request,
    conversation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """Polled every ~2s by `partials/ai_messages_panel.html` while
    `awaiting_reply` — a plain DB read, no provider call of its own — so the
    conversation page picks up the assistant's reply as soon as `_run_turn`
    commits it, instead of the human having to reload."""
    conversation = await _get_conversation(db, conversation_id, user)
    return await _render_messages_panel(request, db, conversation)


@router.post("/conversations/{conversation_id}/messages", dependencies=[Depends(verify_csrf)])
async def post_message(
    request: Request,
    conversation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    message: str = Form(""),
) -> Response:
    """Persists the human's message and enqueues the reply, but does **not**
    wait for it — see `partials/ai_messages_panel.html`'s self-poll for how
    the reply actually shows up. This used to block the whole request on
    `AsyncResult.get(timeout=90)`, which was two bugs stacked on each other:
    a turn can make up to 5 sequential provider calls at up to 90s each
    (`MAX_TOOL_ROUNDTRIPS`/`CHAT_TIMEOUT` in `app/ai/tools.py`/`providers.py`)
    — comfortably longer than a 90s wait *or* the Celery task's own 60s
    default time limit, which could (and did) kill the task outright before
    either timeout ever fired, silently. Not waiting at all sidesteps both:
    there's no web-request timeout to size against an unpredictable model,
    and the fixed `time_limit` on the task itself
    (`app.tasks.ai_jobs._AI_TURN_TIME_LIMIT_SECONDS`) only has to be a true
    "this is stuck" ceiling, not a number a normal reply has to race.
    """
    conversation = await _get_conversation(db, conversation_id, user)
    text = message.strip()
    if not text:
        return await _render_conversation(request, db, conversation, ["Write a message first."])

    provider = conversation.provider
    if provider is None or not provider.enabled:
        return await _render_conversation(
            request, db, conversation, ["This conversation's AI provider is no longer enabled."]
        )
    try:
        client = build_client(provider)
    except AiProviderError as exc:
        return await _render_conversation(request, db, conversation, [str(exc)])

    if conversation.title in ("", "New conversation"):
        conversation.title = derive_title(text)

    db.add(
        AiMessage(
            conversation_id=conversation.id,
            role=AiMessageRole.USER,
            content=text,
            provider_native=[client.build_user_message(text)],
        )
    )
    await db.commit()

    ai_jobs.run_ai_turn.delay(str(conversation.id))

    return RedirectResponse(
        url=f"/ai/conversations/{conversation.id}", status_code=status.HTTP_303_SEE_OTHER
    )


async def _get_pending_action(
    db: AsyncSession, conversation: AiConversation, message_id: uuid.UUID, index: int
) -> tuple[AiMessage, list[dict[str, Any]], dict[str, Any]]:
    message = await db.get(AiMessage, message_id)
    if message is None or message.conversation_id != conversation.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found.")
    actions = list(message.pending_actions or [])
    if index < 0 or index >= len(actions):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found.")
    return message, actions, dict(actions[index])


def _store_actions(
    message: AiMessage, actions: list[dict[str, Any]], index: int, entry: dict[str, Any]
) -> None:
    """Write one modified entry back.

    A *new* list of new dicts is assigned rather than mutating the existing
    one in place: SQLAlchemy's plain `JSON` column doesn't track in-place
    mutation of the Python object it handed out, so an in-place edit would
    simply never be written to the database.
    """
    updated = [dict(action) for action in actions]
    updated[index] = entry
    message.pending_actions = updated


@router.post(
    "/conversations/{conversation_id}/messages/{message_id}/confirm",
    dependencies=[Depends(verify_csrf)],
)
async def confirm_action(
    request: Request,
    conversation_id: uuid.UUID,
    message_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    action_index: int = Form(0),
) -> Response:
    """Execute one proposed action. See this module's docstring — this is
    the only code path in the application that can."""
    conversation = await _get_conversation(db, conversation_id, user)
    message, actions, entry = await _get_pending_action(db, conversation, message_id, action_index)

    if entry.get("status") != PendingActionStatus.PENDING.value:
        return await _render_conversation(
            request, db, conversation, ["That action has already been handled."]
        )

    tool_name = str(entry.get("tool") or "")
    # Permission check #3 — current role, right now, not when the proposal
    # was written.
    denied = missing_permission(user, tool_name)
    if denied is not None:
        entry["status"] = PendingActionStatus.DENIED.value
        entry["reason"] = (
            f"Your role no longer has the '{denied.value}' permission — nothing was run."
        )
        _store_actions(message, actions, action_index, entry)
        await db.commit()
        await log_event(
            db,
            request=request,
            action="ai.action.denied",
            summary=f"Blocked AI action {tool_name}: missing '{denied.value}'",
            outcome=AuditOutcome.DENIED,
            target_type="ai_conversation",
            target_id=conversation.id,
            target_label=conversation.title,
            details={"tool": tool_name, "permission": denied.value},
        )
        return await _render_conversation(request, db, conversation, [str(entry["reason"])])

    machines = await load_machines(db, user, [str(m) for m in entry.get("machine_ids") or []])
    if not machines:
        entry["status"] = PendingActionStatus.DENIED.value
        # Also covers "no longer visible to this account": `load_machines`
        # re-filters by machine-group scope, so a proposal written before the
        # account was restricted resolves to nothing here.
        entry["reason"] = "None of the target machines are still available to this account."
        _store_actions(message, actions, action_index, entry)
        await db.commit()
        return await _render_conversation(request, db, conversation, [str(entry["reason"])])

    machine_names = [machine.name for machine in machines]
    command = entry.get("command")
    errors: list[str] = []

    if tool_name == RUN_UPDATE:
        strategy = UpgradeStrategy(str(entry.get("strategy") or UpgradeStrategy.DIST_UPGRADE.value))
        await trigger_updates(db, machines, strategy)
    elif tool_name == CHECK_UPDATES:
        await trigger_check_updates(machines)
    elif tool_name == REBOOT:
        await send_power_to_machines(machines, PowerAction.REBOOT)
    elif tool_name == SHUTDOWN:
        await send_power_to_machines(machines, PowerAction.SHUTDOWN)
    elif tool_name == RUN_SSH_COMMAND:
        errors.extend(
            await _run_command_and_summarize(conversation, machines, str(command or ""))
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown proposed action."
        )

    entry["status"] = PendingActionStatus.CONFIRMED.value
    _store_actions(message, actions, action_index, entry)
    await db.commit()

    await log_event(
        db,
        request=request,
        action=f"ai.action.{tool_name}",
        summary=f"Confirmed AI-proposed {tool_name} on {', '.join(machine_names)}",
        target_type="ai_conversation",
        target_id=conversation.id,
        target_label=conversation.title,
        details={
            "conversation_id": str(conversation.id),
            "message_id": str(message.id),
            "tool": tool_name,
            "command": command,
            "strategy": entry.get("strategy"),
            "target_type": entry.get("target_type"),
            "target_name": entry.get("target_name"),
            "machines": machine_names,
        },
    )

    conversation = await _get_conversation(db, conversation_id, user)
    return await _render_conversation(request, db, conversation, errors)


async def _run_command_and_summarize(
    conversation: AiConversation, machines: list[Any], command: str
) -> list[str]:
    """Run the confirmed command on each resolved machine, then hand the
    combined output back to the model for one plain-language summary.

    Unlike the fire-and-forget actions above, this one waits: the whole
    point of running an ad-hoc command is seeing what it printed. Each
    machine gets its own Celery task, using the same enqueue-then-
    `asyncio.to_thread`-on-`.get()` pattern as `test_connection_endpoint`
    in `app/web/routes/machines.py` — but every machine's task is
    dispatched *before* any of them are awaited, and all the waits run
    concurrently via `asyncio.gather`. Dispatching one at a time and
    waiting in between (dispatch, block, dispatch the next, block, ...)
    would turn the `MAX_TARGET_MACHINES`-machine cap into up to 25
    back-to-back per-task timeouts stacked serially on this one web
    request instead of one shared wait — the whole point of a "fan out to
    a group" tool is that it actually fans out.
    """
    settings = get_settings()
    per_task_timeout = settings.ssh_connect_timeout + 70
    errors: list[str] = []

    dispatched = [
        (machine, tasks.run_remote_ssh_command.delay(str(machine.id), command))
        for machine in machines
    ]

    async def _await_one(machine: Any, async_result: Any) -> str:
        try:
            result = await asyncio.to_thread(async_result.get, timeout=per_task_timeout)
        except CeleryTimeoutError:
            errors.append(f"{machine.name}: the command did not finish in time.")
            return f"### {machine.name}\n(the command did not finish in time)"
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            errors.append(f"{machine.name}: {exc}")
            return f"### {machine.name}\nfailed: {exc}"

        if isinstance(result, dict) and result.get("ok"):
            return (
                f"### {machine.name}\nexit status: {result.get('exit_status')}\n"
                f"{result.get('output') or '(no output)'}"
            )
        reason = str(result.get("error")) if isinstance(result, dict) else "Unknown error."
        errors.append(f"{machine.name}: {reason}")
        return f"### {machine.name}\nfailed: {reason}"

    # `errors.append` above runs from coroutines interleaved on one event
    # loop thread, never truly in parallel with each other, so appending
    # to a shared list from several of them here is safe without a lock.
    sections = await asyncio.gather(
        *(_await_one(machine, async_result) for machine, async_result in dispatched)
    )

    summary_input = (
        f"Result of the confirmed command `{command}`:\n\n" + "\n\n".join(sections)
    )
    async_result = ai_jobs.summarize_tool_output.delay(str(conversation.id), summary_input)
    try:
        await asyncio.to_thread(async_result.get, timeout=_TURN_WAIT_SECONDS)
    except CeleryTimeoutError:
        errors.append(
            "The command ran, but the assistant's summary did not arrive in time — "
            "reload this page shortly."
        )
    except Exception as exc:  # noqa: BLE001 - reported, not swallowed
        errors.append(f"The command ran, but the assistant could not summarize it: {exc}")
    return errors


@router.post(
    "/conversations/{conversation_id}/messages/{message_id}/discard",
    dependencies=[Depends(verify_csrf)],
)
async def discard_action(
    request: Request,
    conversation_id: uuid.UUID,
    message_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    action_index: int = Form(0),
) -> Response:
    """Mark a proposal discarded. Nothing runs, nothing is enqueued, and
    there's no audit entry beyond the ones already written — declining to
    do something isn't a mutation of the fleet."""
    conversation = await _get_conversation(db, conversation_id, user)
    message, actions, entry = await _get_pending_action(db, conversation, message_id, action_index)
    if entry.get("status") == PendingActionStatus.PENDING.value:
        entry["status"] = PendingActionStatus.DISCARDED.value
        _store_actions(message, actions, action_index, entry)
        await db.commit()
    return RedirectResponse(
        url=f"/ai/conversations/{conversation.id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/conversations/{conversation_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_conversation(
    request: Request,
    conversation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    conversation = await _get_conversation(db, conversation_id, user)
    title = conversation.title
    # Messages are deleted explicitly rather than relying only on the FK's
    # ON DELETE CASCADE: the cascade is real on Postgres, but SQLite (what
    # the test suite runs on) doesn't enforce foreign keys unless the
    # pragma is on, so leaning on it alone would leave orphans there and
    # hide the difference.
    await db.execute(delete(AiMessage).where(AiMessage.conversation_id == conversation.id))
    await db.delete(conversation)
    await db.commit()

    await log_event(
        db,
        request=request,
        action="ai.conversation.delete",
        summary=f'Deleted the AI conversation "{title}"',
        target_type="ai_conversation",
        target_id=conversation_id,
        target_label=title,
    )
    return RedirectResponse(url="/ai", status_code=status.HTTP_303_SEE_OTHER)
