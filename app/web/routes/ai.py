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

**Where an action starts.** `POST .../messages/{message_id}/confirm`
(one action, optionally on some of its machines) and `.../confirm-all`
hand over to `app.services.ai_actions.start_actions`, the only code that
starts an AI-proposed action — also for the one automatic case (the
account's AI command mode at "allow" starts a proposed shell command right
after the turn, see `app.tasks.ai_jobs`). The routes are:

- CSRF-protected (`Depends(verify_csrf)`), so they cannot be triggered
  cross-site;
- scoped to the conversation's owner, so nobody can confirm someone else's
  proposal;

and `start_actions` then checks, under a row lock on the message:

- the *current* permission for that specific tool, re-read from the
  user's role at this moment (permission check #3 — see `app.ai.tools`),
  so a role downgrade takes effect immediately even for a proposal
  written before it, and the account's command mode;
- that the entry is still `pending`, so one proposal runs exactly once;
- the target machines, re-loaded within the account's current scope;

and audit-logs the literal command and every machine it starts on. A
shell command then runs in the background (`ai_jobs.execute_ai_actions`);
the page polls for the per-machine results.
"""

from __future__ import annotations

import contextlib
import uuid
from typing import Any

# NOT the builtin `TimeoutError` — see app/web/routes/machines.py's import
# of the same name for why that distinction is load-bearing.
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.ai.base import AiProviderError, BaseAiClient
from app.ai.config import get_or_create_ai_provider_configs, get_selectable_models
from app.ai.providers import build_client
from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.csrf import verify_csrf
from app.db.models.ai_attachment import AiAttachment
from app.db.models.ai_conversation import TITLE_EDIT_MAX_CHARS, AiConversation, derive_title
from app.db.models.ai_message import AiMessage, AiMessageRole
from app.db.models.ai_model import AiModel
from app.db.models.ai_provider import AiProviderConfig
from app.db.models.endpoint_check import EndpointCheck
from app.db.models.machine import Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus
from app.db.models.role import Permission
from app.db.models.security_audit import SecurityAuditStatus
from app.db.models.user import AiCommandMode, User
from app.db.session import get_db
from app.i18n import get_locale, translate
from app.services import ai_actions, ai_attachments, ai_export, machine_timeline, security_audit
from app.services.access_scope import machines_visible_to
from app.services.endpoint_check_history import load_check_history
from app.tasks import ai_jobs
from app.web.flash import read_flash, sign_flash
from app.web.templating import t, templates

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


def _panel_state(messages: list[AiMessage]) -> dict[str, Any]:
    """What `partials/ai_messages_panel.html` needs besides the messages:
    whether a reply is still coming (`awaiting_reply`), whether a shell
    command is still running (`busy`) — the panel polls while either holds
    — and the "stale" test for a run that never finished."""
    awaiting = _is_awaiting_reply(messages)
    busy = ai_actions.is_busy(messages)
    return {
        "awaiting_reply": awaiting,
        "busy": busy,
        "polling": awaiting or busy,
        "is_stale": ai_actions.is_stale,
    }


async def _render_conversation(
    request: Request, db: AsyncSession, conversation: AiConversation, errors: list[str]
) -> Response:
    messages = await _get_messages(db, conversation.id)
    flashed = read_flash(request, "error")
    if flashed:
        errors = [*errors, flashed]
    return templates.TemplateResponse(
        request,
        "ai/conversation.html",
        {
            "conversation": conversation,
            "messages": messages,
            **_panel_state(messages),
            "attachments": await ai_attachments.by_message(db, conversation.id),
            "image_accept": ai_attachments.ACCEPT,
            "max_images": ai_attachments.MAX_IMAGES_PER_MESSAGE,
            "errors": errors,
            "csrf_token": request.state.csrf_token,
        },
    )


async def _send_user_message(
    db: AsyncSession,
    conversation: AiConversation,
    client: BaseAiClient,
    text: str,
    images: list[tuple[str, str, bytes]] | None = None,
) -> None:
    """Persists one human message and enqueues the turn that answers it —
    shared by `post_message` (an existing conversation's compose box) and
    `create_conversation` (the "New conversation" form's own message field,
    which used to only *name* the conversation from this text and silently
    throw the text itself away, never actually sending it — see that
    route's own comment).

    `images` (already checked by `ai_attachments.validate`) are stored as
    `AiAttachment` rows of this message; its `provider_native` stays text
    only and the turn adds the pictures in the provider's own shape (see
    `app.tasks.ai_jobs._load_history`)."""
    message = AiMessage(
        id=uuid.uuid4(),
        conversation_id=conversation.id,
        role=AiMessageRole.USER,
        content=text,
        provider_native=[client.build_user_message(text)],
    )
    db.add(message)
    if images:
        await db.flush()
        ai_attachments.add_to_message(db, conversation.id, message.id, images)
    await db.commit()
    ai_jobs.run_ai_turn.delay(str(conversation.id))


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
            **_panel_state(messages),
            "attachments": await ai_attachments.by_message(db, conversation.id),
            "csrf_token": request.state.csrf_token,
        },
    )


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("")
async def list_conversations(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    q: str = "",
) -> Response:
    """The account's conversations, newest activity first. `q` searches
    their titles and the text of every message (case-insensitive, LIKE
    metacharacters taken literally); only the account's own conversations
    are ever searched."""
    query = select(AiConversation).where(AiConversation.user_id == user.id)
    search = q.strip()[:200]
    if search:
        pattern = "%" + _escape_like(search) + "%"
        in_messages = (
            select(AiMessage.id)
            .where(
                AiMessage.conversation_id == AiConversation.id,
                AiMessage.content.ilike(pattern, escape="\\"),
            )
            .exists()
        )
        query = query.where(
            or_(AiConversation.title.ilike(pattern, escape="\\"), in_messages)
        )
    result = await db.execute(
        query.order_by(AiConversation.updated_at.desc(), AiConversation.created_at.desc())
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
            "search": search,
            "selectable_models": selectable,
            "can_manage_settings": user.has_permission(Permission.SETTINGS_MANAGE),
            "csrf_token": request.state.csrf_token,
        },
    )


async def _start_conversation(
    request: Request,
    db: AsyncSession,
    user: User,
    *,
    provider_id: uuid.UUID,
    model_id: str,
    text: str,
    audit_summary: str,
) -> Response:
    """Shared by `create_conversation` (the "New conversation" form) and
    `explain_with_ai` (the "Ask AI why" button) — everything past "we have
    a validated provider/model and the first message's text."""
    # Re-check that this provider+model really is enabled — never trust the
    # caller just because a dropdown (or a machine's own state) offered it.
    result = await db.execute(
        select(AiModel, AiProviderConfig)
        .join(AiProviderConfig, AiProviderConfig.id == AiModel.provider_id)
        .where(
            AiModel.provider_id == provider_id,
            AiModel.model_id == model_id,
            AiModel.enabled,
            AiProviderConfig.enabled,
        )
    )
    row = result.first()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That AI model isn't enabled for use.",
        )
    _model, provider = row

    try:
        client = build_client(provider)
    except AiProviderError:
        # Same provider row just confirmed enabled above — a config problem
        # here is the operator's to fix on the Settings AI tab, not
        # something to explain on this simpler form.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This provider isn't fully configured — check Settings.",
        ) from None

    conversation = AiConversation(
        user_id=user.id,
        title=derive_title(text),
        provider_id=provider_id,
        model_id=model_id,
    )
    db.add(conversation)
    await db.commit()
    await db.refresh(conversation)

    await _send_user_message(db, conversation, client, text)

    await log_event(
        db,
        request=request,
        action="ai.conversation.create",
        summary=audit_summary,
        target_type="ai_conversation",
        target_id=conversation.id,
        target_label=conversation.title,
        details={"model": conversation.model_id},
    )

    return RedirectResponse(
        url=f"/ai/conversations/{conversation.id}", status_code=status.HTTP_303_SEE_OTHER
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
    provider/model rows in `_start_conversation` regardless.

    `first_message`, despite the name, used to only *name* the new
    conversation (`derive_title`) — the text itself was thrown away, and
    the "New conversation" page told you as much ("you'll send the actual
    message on the next page"). That's a real trap: typing an actual
    question into a field labeled "What do you need?" and having it
    silently vanish is not what anyone reading that label expects, and it
    reads as "the assistant didn't respond" the same way the timeout bug
    this same release fixed did. It's a real first message now, same as
    typing it into an existing conversation's compose box.
    """
    text = first_message.strip()
    raw = provider_model.strip()
    provider_id_str, _, model_id = raw.partition(":")
    if not text:
        return RedirectResponse(url="/ai", status_code=status.HTTP_303_SEE_OTHER)
    try:
        provider_id = uuid.UUID(provider_id_str)
    except ValueError:
        return RedirectResponse(url="/ai", status_code=status.HTTP_303_SEE_OTHER)

    return await _start_conversation(
        request,
        db,
        user,
        provider_id=provider_id,
        model_id=model_id,
        text=text,
        audit_summary=f'Started an AI conversation ("{derive_title(text)}")',
    )


# How much of a stored command/update-run output to hand the assistant —
# comfortably enough to diagnose most failures without burning an
# unreasonable number of input tokens on a 200,000-char stored run (see
# `app.tasks.jobs._MAX_STORED_OUTPUT_CHARS`). The *tail* is kept, same
# reasoning as that constant: an apt failure's actual error is almost
# always in the last few dozen lines, not the top of a long, chatty run.
_EXPLAIN_OUTPUT_CHARS = 6000
# A question typed on a machine's page ("Ask AI about this machine").
_QUESTION_MAX_CHARS = 4000


def _tail(text: str, limit: int = _EXPLAIN_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return "[... earlier output truncated ...]\n" + text[-limit:]


async def _get_explain_machine(db: AsyncSession, user: User, machine_id: uuid.UUID) -> Machine:
    """Scoped exactly like every other machine lookup in this app — a
    machine outside this account's group access reads as missing, never
    forbidden. The "Ask AI why" button only ever appears on a page that
    already passed this same check, but the route re-checks independently
    since a form post is untrusted input regardless of what rendered it."""
    result = await db.execute(
        (await machines_visible_to(db, user))
        .options(selectinload(Machine.group))
        .where(Machine.id == machine_id)
    )
    machine = result.scalar_one_or_none()
    if machine is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found.")
    return machine


def _machine_state_lines(machine: Machine) -> str:
    """The machine's current state, as context for a history summary."""
    reachable = (
        "unknown" if machine.is_reachable is None else "yes" if machine.is_reachable else "no"
    )
    pending = "unknown" if machine.upgradable_count is None else str(machine.upgradable_count)
    lines = [
        f"- OS: {machine.os_version or 'unknown'}, kernel {machine.kernel_version or 'unknown'}",
        f"- Reachable right now: {reachable}",
        f"- Pending apt updates: {pending} (security: {machine.security_upgradable_count or 0})",
        f"- Reboot required: {'yes' if machine.reboot_required else 'no'}",
    ]
    lines.extend(
        f"- Filesystem {fs.get('mount')} is {fs.get('use_percent')}% full"
        for fs in machine.filesystems or []
        if isinstance(fs, dict) and (fs.get("use_percent") or 0) >= 85
    )
    if machine.readiness_missing:
        lines.append("- Readiness check found missing: " + "; ".join(machine.readiness_missing))
    return "\n".join(lines)


async def _build_endpoint_check_prompt(
    db: AsyncSession, check_id: uuid.UUID | None
) -> tuple[str, str]:
    if check_id is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing check_id.")
    check = await db.get(EndpointCheck, check_id)
    if check is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Check not found.")
    history = await load_check_history(db, check.id, "7d")
    prompt = (
        f'The endpoint check "{check.name}" ({check.kind.upper()} {check.target}) is '
        + ("currently DOWN" if check.last_ok is False else "currently up")
        + f".\nLast error: {check.last_error or 'none'}\n"
        f"Last 7 days: {history.sample_count} probes, uptime "
        f"{history.uptime_percent if history.uptime_percent is not None else 'unknown'}%, "
        f"{history.failure_count} failed, average response "
        f"{history.avg_latency_ms if history.avg_latency_ms is not None else 'unknown'} ms.\n"
    )
    if check.cert_expires_at:
        prompt += f"Certificate expires: {check.cert_expires_at:%Y-%m-%d}\n"
    if history.recent_failures:
        prompt += "Recent failures (newest first):\n" + "\n".join(
            f"- {f.checked_at:%Y-%m-%d %H:%M} UTC: "
            + (f"HTTP {f.status_code} " if f.status_code else "")
            + (f.error or "")
            for f in history.recent_failures
        ) + "\n"
    prompt += (
        "\nSummarize what has been happening with this endpoint (when it failed, how "
        "often, whether it looks intermittent or like one outage), what the errors most "
        "likely mean, and what I should check first."
    )
    return prompt, f'Asked the AI assistant about the endpoint check "{check.name}"'


async def _build_explain_prompt(
    db: AsyncSession,
    user: User,
    kind: str,
    machine_id: uuid.UUID | None,
    run_id: uuid.UUID | None,
    *,
    check_id: uuid.UUID | None = None,
    days: int = machine_timeline.DEFAULT_RANGE_DAYS,
    finding_key: str | None = None,
    question: str = "",
) -> tuple[str, str]:
    """Returns `(prompt_text, audit_summary)` for the "Ask AI why" button,
    or raises `HTTPException` if there's nothing to explain (an unknown
    run, or a readiness check that isn't actually missing anything —
    both would only happen via a hand-crafted request, not the button
    itself, which never renders in either case).

    `history` (a machine's History tab) and `endpoint_check` (a check's
    detail page) ask for a summary of what happened rather than an
    explanation of one failure — built from the same data those pages
    show, scoped the same way (the timeline includes audited actions only
    for a user with `audit.view`)."""
    if kind == "endpoint_check":
        if not user.has_permission(Permission.MACHINE_VIEW):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Check not found.")
        return await _build_endpoint_check_prompt(db, check_id)

    if machine_id is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing machine_id.")
    machine = await _get_explain_machine(db, user, machine_id)

    if kind == "history":
        timeline = await machine_timeline.load_timeline(
            db,
            machine,
            days=days,
            include_audit=user.has_permission(Permission.AUDIT_VIEW),
        )
        events = machine_timeline.timeline_as_text(machine, timeline) or "(nothing recorded)"
        prompt = (
            f'Here is the recorded history of machine "{machine.name}" over the last '
            f"{timeline.days} day(s), oldest first — notes people wrote, detected "
            "configuration changes, update runs, reachability outages"
            + (" and audited actions" if timeline.includes_audit else "")
            + f":\n{events}\n\nCurrent state:\n{_machine_state_lines(machine)}\n\n"
            "Summarize what happened to this machine in this period: any incidents "
            "(outages, failed updates) and what most likely caused them, judging by what "
            "changed around the same time, and whether anything still needs attention. "
            "Finish with the next step you'd recommend. Don't invent events that aren't listed."
        )
        return prompt, f'Asked the AI assistant to summarize the history of "{machine.name}"'

    if kind == "update_run":
        if run_id is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing run_id.")
        run = await db.get(MachineUpdateRun, run_id)
        if run is None or run.machine_id != machine.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Update run not found."
            )
        if run.status != UpdateRunStatus.FAILED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="This update run didn't fail."
            )
        prompt = (
            f'The system update on machine "{machine.name}" failed '
            f"(strategy: {run.strategy.value}).\n"
        )
        if run.error:
            prompt += f"Error: {run.error}\n"
        if run.output:
            prompt += f"Output (apt/flatpak/snap, most recent lines last):\n{_tail(run.output)}\n"
        prompt += (
            "\nWhy did this most likely fail, and what should I check or fix on the "
            "machine before trying again?"
        )
        return prompt, f'Asked the AI assistant why the update run on "{machine.name}" failed'

    if kind == "readiness":
        missing = machine.readiness_missing or []
        if not missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This machine's readiness check found nothing missing.",
            )
        prompt = (
            f'The post-onboarding readiness check on machine "{machine.name}" found the '
            "following missing:\n" + "\n".join(f"- {item}" for item in missing) + "\n\n"
            "What do these mean in practice, and how do I fix each one on this machine?"
        )
        return prompt, f'Asked the AI assistant about "{machine.name}"\'s readiness check'

    if kind == "security_finding":
        return await _build_security_finding_prompt(db, machine, finding_key or "")

    if kind == "machine":
        asked = question.strip()[:_QUESTION_MAX_CHARS]
        if not asked:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Type a question first."
            )
        prompt = (
            f'This is about machine "{machine.name}" ({machine.ip_address}'
            + (f", group {machine.group.name}" if machine.group else "")
            + f"). Its current state:\n{_machine_state_lines(machine)}\n\n"
            "You can look up more about it with the read-only tools before answering.\n\n"
            f"My question: {asked}"
        )
        return prompt, f'Asked the AI assistant about "{machine.name}"'

    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown context.")


def _english(key: str) -> str:
    """A locale string in English: the prompt's facts stay the same
    whatever the operator's UI language (they get "answer in <language>"
    appended instead)."""
    return translate(get_locale("en"), key)


async def _build_security_finding_prompt(
    db: AsyncSession, machine: Machine, key: str
) -> tuple[str, str]:
    """The "Fix with AI" button on a security audit finding: the finding
    as the newest successful audit of the machine has it, what is known
    about it (Lynis's own control page and solution, the setting's current
    and recommended value; for debcontrol's own checks — vps-audit's —
    what the check tests and how it is usually fixed), and a request for a
    fix proposed as commands for this one machine."""
    if not security_audit.valid_key(key):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown finding.")
    audits = await security_audit.history(db, machine.id)
    shown = next((a for a in audits if a.status == SecurityAuditStatus.SUCCEEDED), None)
    finding = security_audit.find_finding(shown, key) if shown else None
    if shown is None or finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found.")

    lines = [
        f'The latest security audit of machine "{machine.name}" '
        f"(OS: {machine.os_version or 'unknown'}) reported this finding:",
        "",
    ]
    if finding["kind"] == security_audit.CHECK:
        base = f"security_audit.check.{finding['id']}"
        lines += [
            f"- debcontrol check (based on vps-audit, https://github.com/nuver-labs/vps-audit): "
            f"{_english(base + '.title')} (id `{finding['id']}`)",
            f"- Result: {finding.get('status')}; found: {finding.get('value') or '-'}",
            f"- What it checks and why it matters: {_english(base + '.why')}",
            f"- Usual fix: {_english(base + '.fix')}",
        ]
    else:
        test = str(finding.get("test", ""))
        lines += [
            f"- Lynis {finding['severity'][:-1]} {test}: {finding.get('text')}",
        ]
        if finding.get("detail"):
            lines.append(f"- Detail: {finding['detail']}")
        if finding.get("solution"):
            lines.append(f"- Lynis's suggested solution: {finding['solution']}")
        for detail in finding.get("details") or []:
            lines.append(
                f"- Setting `{detail.get('field')}` ({detail.get('service')}): current "
                f"`{detail.get('value') or '-'}`, recommended `{detail.get('prefval') or '-'}`"
            )
        howto_key = f"security_audit.howto.{test}"
        howto = _english(howto_key)
        if howto != howto_key:
            lines.append(f"- debcontrol's note: {howto}")
        lines.append(
            f"- Lynis control description: {security_audit.CONTROL_URL.format(test=test)} "
            f"(`lynis show details {test}` on the machine prints the test's log)"
        )
    if shown.privileged is False:
        lines.append("- Lynis ran without root on this machine, so some tests were skipped.")
    lines += [
        "",
        "Explain briefly what this means and whether it is a real risk on this machine. "
        "Then fix it: first check the current state with a read-only command, then "
        f'propose the change as commands for machine "{machine.name}" only, keeping '
        "access working (never lock out SSH: keep the current SSH port and the account "
        "debcontrol connects with working). Say how to verify the fix (re-run the "
        "security audit).",
    ]
    label = finding.get("id") or finding.get("test")
    return "\n".join(lines), (
        f'Asked the AI assistant to fix security finding "{label}" on "{machine.name}"'
    )


@router.post("/explain", dependencies=[Depends(verify_csrf)])
async def explain_with_ai(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    kind: str = Form(...),
    machine_id: uuid.UUID | None = Form(None),
    run_id: uuid.UUID | None = Form(None),
    check_id: uuid.UUID | None = Form(None),
    days: int = Form(machine_timeline.DEFAULT_RANGE_DAYS),
    key: str = Form(""),
    question: str = Form(""),
) -> Response:
    """The "Ask AI why" button on a failed update run (`partials/
    update_run_status.html`) and a machine's readiness banner
    (`machines/detail.html`) — starts a brand-new conversation whose first
    message is the relevant failure/finding, pre-filled server-side so
    there's nothing for the user to type or copy-paste. Picks whichever
    model is first in `get_selectable_models` (same one the "New
    conversation" form lists first) rather than asking the user to choose
    again — this is meant to be one click, not a detour through a form."""
    prompt, audit_summary = await _build_explain_prompt(
        db,
        user,
        kind,
        machine_id,
        run_id,
        check_id=check_id,
        days=days,
        finding_key=key,
        question=question,
    )

    selectable = await get_selectable_models(db)
    if not selectable:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No AI model is enabled yet — enable one on Settings first.",
        )
    provider, model = selectable[0]

    locale = getattr(request.state, "locale", None)
    if locale is not None and locale.code != "en":
        prompt += f"\n\n(Please answer in {locale.label}.)"

    return await _start_conversation(
        request,
        db,
        user,
        provider_id=provider.id,
        model_id=model.model_id,
        text=prompt,
        audit_summary=audit_summary,
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


async def _read_images(uploads: list[UploadFile]) -> list[tuple[str, str, bytes]]:
    """The chosen pictures, checked (`ai_attachments.validate`). Reads at
    most one byte past the size limit per file, and stops once the total
    is over, so an oversized upload is refused without holding all of it."""
    chosen = [upload for upload in uploads if upload.filename]
    if len(chosen) > ai_attachments.MAX_IMAGES_PER_MESSAGE:
        raise ai_attachments.AttachmentError(
            "ai.attach.too_many", count=ai_attachments.MAX_IMAGES_PER_MESSAGE
        )
    read: list[ai_attachments.Upload] = []
    total = 0
    for upload in chosen:
        data = await upload.read(ai_attachments.MAX_IMAGE_BYTES + 1)
        total += len(data)
        read.append(ai_attachments.Upload(upload.filename or "", data))
        if total > ai_attachments.MAX_TOTAL_BYTES:
            break
    return ai_attachments.validate(read)


@router.post("/conversations/{conversation_id}/messages", dependencies=[Depends(verify_csrf)])
async def post_message(
    request: Request,
    conversation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    message: str = Form(""),
    images: list[UploadFile] = File(default_factory=list),
) -> Response:
    """Persists the human's message (and any attached pictures, see
    `app.services.ai_attachments`) and enqueues the reply, but does **not**
    wait for it — see `partials/ai_messages_panel.html`'s self-poll for how
    the reply actually shows up. This used to block the whole request on
    `AsyncResult.get(timeout=90)`, which was two bugs stacked on each other:
    a turn can make up to 5 sequential provider calls at up to 90s each
    (`MAX_TOOL_ROUNDTRIPS`/`CHAT_TIMEOUT_SECONDS` in `app/ai/tools.py`/`providers.py`)
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
    try:
        checked = await _read_images(images)
    except ai_attachments.AttachmentError as exc:
        return await _render_conversation(
            request, db, conversation, [t(request, exc.key, **exc.params)]
        )
    if not text and not checked:
        return await _render_conversation(
            request, db, conversation, [t(request, "ai.error.empty_message")]
        )

    provider = conversation.provider
    if provider is None or not provider.enabled:
        return await _render_conversation(
            request, db, conversation, [t(request, "ai.error.provider_disabled")]
        )
    try:
        client = build_client(provider)
    except AiProviderError as exc:
        return await _render_conversation(request, db, conversation, [str(exc)])

    if conversation.title in ("", "New conversation") and text:
        conversation.title = derive_title(text)

    await _send_user_message(db, conversation, client, text, checked)

    return RedirectResponse(
        url=f"/ai/conversations/{conversation.id}", status_code=status.HTTP_303_SEE_OTHER
    )


def _redirect_to(conversation: AiConversation, errors: list[str] | None = None) -> Response:
    url = f"/ai/conversations/{conversation.id}"
    if errors:
        url += "?error=" + sign_flash(" ".join(dict.fromkeys(errors))[:500])
    return RedirectResponse(url=url + "#chat-end", status_code=status.HTTP_303_SEE_OTHER)


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
    machine_id: list[str] | None = Form(None),
    machines_selectable: bool = Form(False),
) -> Response:
    """Start one proposed action — on all its machines, or, when the form
    offered machine checkboxes (`machines_selectable`), on the ones ticked.
    Every check happens in `app.services.ai_actions.start_actions`; see
    this module's docstring."""
    conversation = await _get_conversation(db, conversation_id, user)
    selected = {action_index: machine_id or []} if machines_selectable else None
    errors = await ai_actions.start_actions(
        db,
        user,
        conversation,
        message_id,
        [action_index],
        selected_machine_ids=selected,
        request=request,
    )
    return _redirect_to(conversation, errors)


@router.post(
    "/conversations/{conversation_id}/messages/{message_id}/confirm-all",
    dependencies=[Depends(verify_csrf)],
)
async def confirm_all_actions(
    request: Request,
    conversation_id: uuid.UUID,
    message_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """"Confirm all" on an assistant reply with several proposals: every
    one still pending, each on all its machines, through the same checks
    as one Confirm (each one audit-logged on its own)."""
    conversation = await _get_conversation(db, conversation_id, user)
    message = await db.get(AiMessage, message_id)
    if message is None or message.conversation_id != conversation.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found.")
    indexes = ai_actions.pending_indexes(message)
    errors = (
        await ai_actions.start_actions(db, user, conversation, message_id, indexes, request=request)
        if indexes
        else [t(request, "ai.error.action_handled")]
    )
    return _redirect_to(conversation, errors)


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
    await ai_actions.discard_actions(db, conversation, message_id, [action_index])
    return _redirect_to(conversation)


@router.post(
    "/conversations/{conversation_id}/messages/{message_id}/discard-all",
    dependencies=[Depends(verify_csrf)],
)
async def discard_all_actions(
    request: Request,
    conversation_id: uuid.UUID,
    message_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    conversation = await _get_conversation(db, conversation_id, user)
    message = await db.get(AiMessage, message_id)
    if message is None or message.conversation_id != conversation.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found.")
    await ai_actions.discard_actions(
        db, conversation, message_id, ai_actions.pending_indexes(message)
    )
    return _redirect_to(conversation)


@router.post("/command-mode", dependencies=[Depends(verify_csrf)])
async def update_command_mode(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    mode: str = Form(...),
    next: str = Form("/account"),
) -> Response:
    """My account -> AI assistant: what the assistant may do with a shell
    command it proposes for this account (`AiCommandMode`). Web-only like
    the rest of the assistant — see this module's docstring. Changing it
    is audit-logged, since "allow" lets proposals run without a Confirm."""
    try:
        new_mode = AiCommandMode(mode)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown mode."
        ) from None
    user = await db.get(User, current_user.id)
    assert user is not None
    old_mode = user.ai_mode
    user.ai_command_mode = new_mode.value
    await db.commit()
    if old_mode != new_mode:
        await log_event(
            db,
            request=request,
            action="ai.command_mode.update",
            summary=f'"{user.username}" set the AI command mode to "{new_mode.value}"',
            target_type="user",
            target_id=user.id,
            target_label=user.username,
            details={"from": old_mode.value, "to": new_mode.value},
        )
    # Back where the form was: a conversation (rebuilt from its parsed id,
    # never the submitted text) or My account — nowhere else.
    target = "/account"
    prefix = "/ai/conversations/"
    if next.startswith(prefix):
        with contextlib.suppress(ValueError):
            target = prefix + str(uuid.UUID(next.removeprefix(prefix)))
    return RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/conversations/{conversation_id}/rename", dependencies=[Depends(verify_csrf)])
async def rename_conversation(
    request: Request,
    conversation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    title: str = Form(""),
) -> Response:
    """A new title for the account's own conversation (one line, at most
    `TITLE_EDIT_MAX_CHARS`); an empty one is refused."""
    conversation = await _get_conversation(db, conversation_id, user)
    new_title = " ".join(title.split())[:TITLE_EDIT_MAX_CHARS]
    if not new_title:
        return _redirect_to(conversation, [t(request, "ai.rename.empty")])
    old_title = conversation.title
    if new_title != old_title:
        conversation.title = new_title
        await db.commit()
        await log_event(
            db,
            request=request,
            action="ai.conversation.rename",
            summary=f'Renamed the AI conversation "{old_title}" to "{new_title}"',
            target_type="ai_conversation",
            target_id=conversation.id,
            target_label=new_title,
        )
    return RedirectResponse(
        url=f"/ai/conversations/{conversation.id}", status_code=status.HTTP_303_SEE_OTHER
    )


@router.get("/conversations/{conversation_id}/export.md")
async def export_conversation(
    conversation_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """The conversation as a Markdown file (`app.services.ai_export`)."""
    conversation = await _get_conversation(db, conversation_id, user)
    messages = await _get_messages(db, conversation.id)
    attachments = await ai_attachments.by_message(db, conversation.id)
    return Response(
        content=ai_export.render(conversation, messages, attachments),
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{ai_export.filename(conversation)}"',
            "Cache-Control": "private, no-store",
        },
    )


@router.get("/conversations/{conversation_id}/attachments/{attachment_id}")
async def show_attachment(
    conversation_id: uuid.UUID,
    attachment_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Response:
    """One picture of the account's own conversation, served with the type
    debcontrol sniffed when it was uploaded (PNG, JPEG, GIF or WebP only)."""
    conversation = await _get_conversation(db, conversation_id, user)
    attachment = await ai_attachments.get(db, conversation.id, attachment_id)
    if attachment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Picture not found.")
    return Response(
        content=attachment.data,
        media_type=attachment.media_type,
        headers={
            "Content-Disposition": "inline",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, max-age=3600",
        },
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
    await db.execute(delete(AiAttachment).where(AiAttachment.conversation_id == conversation.id))
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
