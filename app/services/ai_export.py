"""A conversation as a Markdown file — the chat's *Export (Markdown)*.

What the person saw, oldest first: each message with who wrote it and
when, the assistant's text as it was written (it is Markdown already), and
every proposed action with its command, machines, status and per-machine
results. Command output handed to the assistant for a summary is kept, in a
fenced block. Pictures are named, not embedded (they are in the chat).
Times are in the instance's time zone, like the rest of the UI.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from app.core.config import get_settings
from app.core.timezones import zone
from app.db.models.ai_attachment import AiAttachment
from app.db.models.ai_conversation import AiConversation
from app.db.models.ai_message import AiMessage, AiMessageRole

_FENCE_RE = re.compile(r"`{3,}")


def _fence(text: str) -> str:
    """A fenced block that the content can't close early: one backtick more
    than the longest run inside it."""
    longest = max((len(m.group(0)) for m in _FENCE_RE.finditer(text)), default=2)
    fence = "`" * (longest + 1)
    return f"{fence}\n{text.rstrip()}\n{fence}"


def _when(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(zone(get_settings().tz)).strftime("%Y-%m-%d %H:%M")


def _action_lines(action: Mapping[str, Any]) -> list[str]:
    lines = [f"- **{action.get('summary') or action.get('tool')}** — {action.get('status')}"]
    if action.get("command"):
        lines.append("")
        lines.append(_fence(str(action["command"])))
    machines = action.get("ran_on") or action.get("machine_names") or []
    if machines and not action.get("results"):
        lines.append(f"  Machines: {', '.join(str(m) for m in machines)}")
    if action.get("status") == "denied" and action.get("reason"):
        lines.append(f"  {action['reason']}")
    for row in action.get("results") or []:
        if row.get("status") == "skipped":
            continue
        exit_status = row.get("exit_status")
        head = f"  - `{row.get('machine_name')}`: {row.get('status')}"
        if exit_status is not None:
            head += f" (exit {exit_status})"
        lines.append(head)
        if row.get("output"):
            lines.append("")
            lines.append(_fence(str(row["output"])))
        elif row.get("error"):
            lines.append(f"    {row['error']}")
    return lines


def filename(conversation: AiConversation) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", conversation.title).strip("-.")[:60] or "conversation"
    return f"ai-{stem}-{_when(conversation.created_at)[:10]}.md"


def render(
    conversation: AiConversation,
    messages: Sequence[AiMessage],
    attachments: Mapping[uuid.UUID, Sequence[AiAttachment]],
) -> str:
    total = conversation.input_tokens + conversation.output_tokens
    out = [
        f"# {conversation.title}",
        "",
        f"- Model: `{conversation.model_id}`",
        f"- Started: {_when(conversation.created_at)}",
        f"- Tokens: {total} ({conversation.input_tokens} in, {conversation.output_tokens} out)",
        "",
    ]
    for message in messages:
        if message.is_tool_output:
            out += [
                f"### Command output · {_when(message.created_at)}",
                "",
                _fence(message.content),
            ]
        else:
            who = "You" if message.role == AiMessageRole.USER else "Assistant"
            out += [f"### {who} · {_when(message.created_at)}", ""]
            if message.content:
                out.append(message.content.rstrip())
            for picture in attachments.get(message.id, []):
                out.append(f"\n*Picture: {picture.filename} ({picture.size} bytes)*")
            actions = message.pending_actions or []
            if actions:
                out.append("")
                for action in actions:
                    out += _action_lines(action)
        out.append("")
    return "\n".join(out).rstrip() + "\n"
