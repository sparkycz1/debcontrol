"""0.140.0: pictures in an AI conversation, the read-only lookups (machine
details, pending updates, security audit, service logs), "Ask AI" on the
machine page, searching and renaming conversations, the Markdown export
and the per-conversation token count.

No provider is contacted (`tests.test_ai_web.FakeClient` drives a turn, a
`MockTransport` stands in for the provider's HTTP) and no SSH happens (the
journal read is a fake `jobs._view_machine_journal`).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest
from sqlalchemy import select

from app.ai.base import ImageInput, ToolCall
from app.ai.providers import AnthropicClient, GeminiClient, OpenAICompatibleClient
from app.ai.tools import available_tools, execute_read_only_tool
from app.db.models.ai_attachment import AiAttachment
from app.db.models.ai_conversation import AiConversation
from app.db.models.ai_message import AiMessage, AiMessageRole
from app.db.models.ai_provider import AiProviderKind
from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import Machine
from app.db.models.role import Permission
from app.db.models.security_audit import SecurityAudit, SecurityAuditStatus
from app.services import ai_attachments, ai_export, security_audit
from app.tasks import ai_jobs, jobs
from tests.test_ai_web import (
    ALL_AI_PERMISSIONS,
    create_conversation,
    create_machine,
    get_user,
    install_fake_client,
    setup_provider,
    text_turn,
    tool_turn,
    use_test_db,
)

__all__ = ["use_test_db"]  # a fixture, used by name

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'


async def _conversation(db_session_factory: Any) -> uuid.UUID:
    user = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    return await create_conversation(db_session_factory, user.id, provider_id, model_id)


# --- Pictures: checking an upload --------------------------------------------


def test_the_type_comes_from_the_bytes_not_the_name() -> None:
    assert ai_attachments.sniff_media_type(PNG) == "image/png"
    assert ai_attachments.sniff_media_type(JPEG) == "image/jpeg"
    assert ai_attachments.sniff_media_type(b"GIF89a....") == "image/gif"
    assert ai_attachments.sniff_media_type(b"RIFF\x00\x00\x00\x00WEBPVP8 ") == "image/webp"
    assert ai_attachments.sniff_media_type(SVG) is None
    assert ai_attachments.sniff_media_type(b"%PDF-1.7") is None


def test_validate_refuses_svg_too_many_and_too_large() -> None:
    with pytest.raises(ai_attachments.AttachmentError) as bad:
        ai_attachments.validate([ai_attachments.Upload("x.png", SVG)])
    assert bad.value.key == "ai.attach.bad_type" and bad.value.params["name"] == "x.png"

    with pytest.raises(ai_attachments.AttachmentError) as many:
        ai_attachments.validate([ai_attachments.Upload(f"{i}.png", PNG) for i in range(5)])
    assert many.value.key == "ai.attach.too_many"

    big = PNG + b"\x00" * ai_attachments.MAX_IMAGE_BYTES
    with pytest.raises(ai_attachments.AttachmentError) as large:
        ai_attachments.validate([ai_attachments.Upload("big.png", big)])
    assert large.value.key == "ai.attach.too_large"

    two_mb = PNG + b"\x00" * 2_000_000
    with pytest.raises(ai_attachments.AttachmentError) as total:
        ai_attachments.validate([ai_attachments.Upload(f"{i}.png", two_mb) for i in range(3)])
    assert total.value.key == "ai.attach.too_large_total"

    checked = ai_attachments.validate([ai_attachments.Upload("C:\\shots\\err.png", PNG)])
    assert checked == [("err.png", "image/png", PNG)]


# --- Pictures: each provider's wire shape ------------------------------------


def test_each_provider_puts_a_picture_in_its_own_shape() -> None:
    image = ImageInput("image/png", PNG)
    anthropic = AnthropicClient("k").build_user_message("look", [image])
    assert anthropic["content"][0]["type"] == "image"
    assert anthropic["content"][0]["source"]["media_type"] == "image/png"
    assert anthropic["content"][-1] == {"type": "text", "text": "look"}

    openai = OpenAICompatibleClient(
        "k", "https://api.openai.com/v1", AiProviderKind.OPENAI
    ).build_user_message("look", [image])
    assert openai["content"][0] == {"type": "text", "text": "look"}
    assert openai["content"][1]["image_url"]["url"].startswith("data:image/png;base64,")

    gemini = GeminiClient("k").build_user_message("", [image])
    assert gemini["parts"] == [{"inlineData": {"mimeType": "image/png", "data": image.base64()}}]

    # No picture: exactly the old plain shapes.
    assert AnthropicClient("k").build_user_message("hi") == {"role": "user", "content": "hi"}


async def test_an_anthropic_request_carries_the_picture() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        captured["body"] = json.loads(request.content)
        return httpx2.Response(
            200,
            json={
                "id": "m",
                "type": "message",
                "role": "assistant",
                "model": "claude-x",
                "content": [{"type": "text", "text": "a cat"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 3, "output_tokens": 2},
            },
        )

    client = AnthropicClient("k", transport=httpx2.MockTransport(handler))
    message = client.build_user_message("what is it?", [ImageInput("image/jpeg", JPEG)])
    result = await client.send([message], [], "claude-x", "system")
    assert result.text == "a cat"
    block = captured["body"]["messages"][0]["content"][0]
    assert block["type"] == "image" and block["source"]["media_type"] == "image/jpeg"


# --- Pictures: sending, showing, replaying -----------------------------------


async def test_a_message_with_a_picture_is_stored_shown_and_replayed(
    client, login_as, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    conversation_id = await _conversation(db_session_factory)
    await client.get(f"/ai/conversations/{conversation_id}")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        f"/ai/conversations/{conversation_id}/messages",
        data={"csrf_token": csrf_token, "message": ""},
        files=[("images", ("screen.png", PNG, "text/plain"))],
    )
    assert response.status_code == 303
    assert celery_calls.names == ["app.tasks.ai_jobs.run_ai_turn"]

    async with db_session_factory() as db:
        attachment = (await db.execute(select(AiAttachment))).scalar_one()
    # The browser's "text/plain" claim is ignored; the bytes say PNG.
    assert attachment.media_type == "image/png" and attachment.filename == "screen.png"

    page = await client.get(f"/ai/conversations/{conversation_id}")
    src = f"/ai/conversations/{conversation_id}/attachments/{attachment.id}"
    assert f'src="{src}"' in page.text and 'enctype="multipart/form-data"' in page.text
    served = await client.get(src)
    assert served.status_code == 200 and served.content == PNG
    assert served.headers["content-type"] == "image/png"
    assert served.headers["x-content-type-options"] == "nosniff"
    assert (
        await client.get(f"/ai/conversations/{conversation_id}/attachments/{uuid.uuid4()}")
    ).status_code == 404

    # The turn sends the picture in the provider's shape.
    fake = install_fake_client(monkeypatch, [text_turn("It's an error dialog.")])
    await ai_jobs._run_turn(str(conversation_id), allow_tools=True)
    assert fake.calls[0]["messages"][-1]["images"] == [("image/png", len(PNG))]

    # Nobody else sees it.
    await login_as(client, permissions=ALL_AI_PERMISSIONS, username="someone-else")
    assert (await client.get(src)).status_code == 404


async def test_a_wrong_picture_is_refused_with_a_message(
    client, db_session_factory, use_test_db, celery_calls
):
    conversation_id = await _conversation(db_session_factory)
    await client.get(f"/ai/conversations/{conversation_id}")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        f"/ai/conversations/{conversation_id}/messages",
        data={"csrf_token": csrf_token, "message": "see"},
        files=[("images", ("x.svg", SVG, "image/svg+xml"))],
    )
    assert response.status_code == 200
    assert "is not a PNG, JPEG, GIF or WebP picture" in response.text
    assert celery_calls.names == []
    async with db_session_factory() as db:
        assert (await db.execute(select(AiAttachment))).first() is None
        assert (await db.execute(select(AiMessage))).first() is None


async def test_deleting_a_conversation_removes_its_pictures(
    client, db_session_factory, use_test_db, celery_calls
):
    conversation_id = await _conversation(db_session_factory)
    await client.get(f"/ai/conversations/{conversation_id}")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        f"/ai/conversations/{conversation_id}/messages",
        data={"csrf_token": csrf_token, "message": "x"},
        files=[("images", ("a.jpg", JPEG, "image/jpeg"))],
    )
    await client.post(
        f"/ai/conversations/{conversation_id}/delete", data={"csrf_token": csrf_token}
    )
    async with db_session_factory() as db:
        assert (await db.execute(select(AiAttachment))).first() is None


# --- Token count --------------------------------------------------------------


async def test_every_provider_call_adds_to_the_conversations_tokens(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    conversation_id = await _conversation(db_session_factory)
    install_fake_client(monkeypatch, [tool_turn("list_groups", {}), text_turn("none")])
    await ai_jobs._run_turn(str(conversation_id), "groups?", allow_tools=True)

    async with db_session_factory() as db:
        conversation = await db.get(AiConversation, conversation_id)
        assert conversation is not None
        assert (conversation.input_tokens, conversation.output_tokens) == (20, 10)

    page = await client.get(f"/ai/conversations/{conversation_id}")
    assert "Tokens: 30" in page.text
    listing = await client.get("/ai")
    assert ">30</td>" in listing.text


# --- Search, rename, export -----------------------------------------------------


async def test_search_finds_titles_and_message_text_of_my_own_conversations(
    client, db_session_factory
):
    user = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    first = await create_conversation(db_session_factory, user.id, provider_id, model_id)
    second = await create_conversation(db_session_factory, user.id, provider_id, model_id)
    async with db_session_factory() as db:
        conversation = await db.get(AiConversation, first)
        assert conversation is not None
        conversation.title = "Nginx keeps restarting"
        db.add(
            AiMessage(
                conversation_id=second,
                role=AiMessageRole.USER,
                content="disk usage is 100% on /var",
            )
        )
        await db.commit()

    by_title = await client.get("/ai", params={"q": "NGINX"})
    assert f"/ai/conversations/{first}" in by_title.text
    assert f"/ai/conversations/{second}" not in by_title.text
    # "%" is a literal, not a LIKE wildcard.
    by_text = await client.get("/ai", params={"q": "100%"})
    assert f"/ai/conversations/{second}" in by_text.text
    assert f"/ai/conversations/{first}" not in by_text.text
    nothing = await client.get("/ai", params={"q": "zzz"})
    assert "No conversation matches that search." in nothing.text


async def test_rename_is_audited_and_refuses_an_empty_title(client, db_session_factory):
    conversation_id = await _conversation(db_session_factory)
    await client.get(f"/ai/conversations/{conversation_id}")
    csrf_token = client.cookies.get("csrftoken")

    renamed = await client.post(
        f"/ai/conversations/{conversation_id}/rename",
        data={"csrf_token": csrf_token, "title": "  Disk   on web1 "},
    )
    assert renamed.status_code == 303
    empty = await client.post(
        f"/ai/conversations/{conversation_id}/rename", data={"csrf_token": csrf_token, "title": " "}
    )
    assert "?error=" in empty.headers["location"]
    assert (
        await client.post(f"/ai/conversations/{conversation_id}/rename", data={"title": "x"})
    ).status_code == 403

    async with db_session_factory() as db:
        conversation = await db.get(AiConversation, conversation_id)
        assert conversation is not None and conversation.title == "Disk on web1"
        entry = (
            await db.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "ai.conversation.rename")
            )
        ).scalar_one()
    assert entry.target_label == "Disk on web1"


async def test_export_is_markdown_with_messages_and_command_results(client, db_session_factory):
    conversation_id = await _conversation(db_session_factory)
    async with db_session_factory() as db:
        conversation = await db.get(AiConversation, conversation_id)
        assert conversation is not None
        conversation.title = "Check uptime"
        db.add(
            AiMessage(conversation_id=conversation_id, role=AiMessageRole.USER, content="uptime?")
        )
        db.add(
            AiMessage(
                conversation_id=conversation_id,
                role=AiMessageRole.ASSISTANT,
                content="I propose **uptime**.",
                pending_actions=[
                    {
                        "tool": "run_ssh_command",
                        "summary": 'Run "uptime" on "web1"',
                        "status": "confirmed",
                        "command": "echo ``` && uptime",
                        "results": [
                            {
                                "machine_name": "web1",
                                "status": "ok",
                                "exit_status": 0,
                                "output": "up 3 days",
                            }
                        ],
                    }
                ],
            )
        )
        await db.commit()

    response = await client.get(f"/ai/conversations/{conversation_id}/export.md")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert 'filename="ai-Check-uptime-' in response.headers["content-disposition"]
    body = response.text
    assert body.startswith("# Check uptime\n")
    assert "### You ·" in body and "uptime?" in body and "I propose **uptime**." in body
    # A fence longer than any backtick run inside the command.
    assert "````\necho ``` && uptime\n````" in body
    assert "`web1`: ok (exit 0)" in body and "up 3 days" in body


def test_export_filename_is_header_safe() -> None:
    conversation = AiConversation(title='a"b\r\nc/../d', model_id="m")
    conversation.created_at = datetime(2026, 11, 21, tzinfo=UTC)
    name = ai_export.filename(conversation)
    assert name == "ai-a-b-c-..-d-2026-11-21.md"
    assert all(ch.isalnum() or ch in "._-" for ch in name)


# --- Read-only lookups ------------------------------------------------------------


def _call(name: str, **arguments: Any) -> ToolCall:
    return ToolCall(id="t", name=name, arguments=arguments)


async def test_machine_details_and_updates_come_from_stored_facts(client, db_session_factory):
    machine_id = await create_machine(db_session_factory, "web1")
    async with db_session_factory() as db:
        machine = await db.get(Machine, machine_id)
        assert machine is not None
        machine.os_version = "Debian GNU/Linux 13 (trixie)"
        machine.kernel_version = "6.12.0"
        machine.failed_units = ["nginx.service"]
        machine.filesystems = [{"mount": "/", "use_percent": 91, "size_bytes": 20 * 1024**3}]
        machine.upgradable_count = 2
        machine.security_upgradable_count = 1
        machine.apt_upgradable_packages = [
            {
                "name": "openssl",
                "current_version": "3.0.1",
                "new_version": "3.0.2",
                "security": True,
                "cves": ["CVE-2026-1"],
            },
            {"name": "curl", "current_version": "8.1", "new_version": "8.2"},
        ]
        await db.commit()
    user = await get_user(db_session_factory)

    async with db_session_factory() as db:
        details = await execute_read_only_tool(
            db, user, _call("get_machine_details", machine_name="WEB1")
        )
        updates = await execute_read_only_tool(
            db, user, _call("get_pending_updates", machine_name="web1")
        )
        missing = await execute_read_only_tool(
            db, user, _call("get_machine_details", machine_name="db9")
        )
    assert "Debian GNU/Linux 13" in details and "nginx.service" in details
    assert "Filesystem /: 91% used of 20.0 GiB" in details
    assert "apt 2 pending, 1 of them security" in updates
    assert "- openssl 3.0.1 -> 3.0.2 [security] fixes CVE-2026-1" in updates
    assert "Last update run: none" in updates
    assert missing.startswith('No machine named "db9" exists.')


async def test_machine_lookups_respect_the_accounts_scope(client, login_as, db_session_factory):
    await create_machine(db_session_factory, "web1")
    limited = await login_as(client, permissions={Permission.AI_ACCESS}, username="viewer")
    async with db_session_factory() as db:
        refused = await execute_read_only_tool(
            db, limited, _call("get_machine_details", machine_name="web1")
        )
    assert refused.startswith("Refused:")
    assert "get_machine_details" not in {t.name for t in available_tools(limited)}


async def test_security_audit_summary_leaves_out_findings_marked_ok(client, db_session_factory):
    machine_id = await create_machine(db_session_factory, "web1")
    async with db_session_factory() as db:
        db.add(
            SecurityAudit(
                machine_id=machine_id,
                status=SecurityAuditStatus.SUCCEEDED,
                hardening_index=63,
                lynis_version="3.1.6",
                privileged=True,
                checks=[
                    {"id": "ssh_root_login", "status": "fail", "value": "yes"},
                    {"id": "firewall", "status": "pass"},
                ],
                warnings=[{"test": "SSH-7408", "text": "Weak SSH setting"}],
                suggestions=[{"test": "KRNL-6000", "text": "Harden sysctl", "detail": "fs.x"}],
            )
        )
        await db.commit()
        await security_audit.suppress(
            db,
            machine_id,
            f"lynis:SSH-7408:{_digest('Weak SSH setting', '')}",
            label="",
            note=None,
            created_by="tester",
        )
        await db.commit()
    user = await get_user(db_session_factory)
    async with db_session_factory() as db:
        text = await execute_read_only_tool(
            db, user, _call("get_security_audit", machine_name="web1")
        )
    assert "hardening index 63" in text
    assert "[fail] ssh_root_login: yes" in text and "firewall" not in text
    assert "KRNL-6000: Harden sysctl (fs.x)" in text
    assert "SSH-7408" not in text and "marked OK 1" in text


def _digest(text: str, detail: str) -> str:
    return hashlib.sha256(f"{text}|{detail}".encode()).hexdigest()[:16]


async def test_service_logs_read_the_journal_and_are_audited(
    client, db_session_factory, use_test_db, monkeypatch
):
    await create_machine(db_session_factory, "web1")
    seen: dict[str, Any] = {}

    async def fake_journal(machine_id: str, **options: Any) -> dict[str, Any]:
        seen.update(options, machine_id=machine_id)
        return {"ok": True, "output": "nginx[1]: bind() failed", "entries": [], "hidden": 0}

    monkeypatch.setattr(jobs, "_view_machine_journal", fake_journal)
    user = await get_user(db_session_factory)
    async with db_session_factory() as db:
        text = await execute_read_only_tool(
            db,
            user,
            _call(
                "get_service_logs",
                machine_name="web1",
                unit="nginx.service",
                lines="9999",
                priority="err",
                since="-1h",
            ),
        )
        bad = await execute_read_only_tool(
            db, user, _call("get_service_logs", machine_name="web1", unit="x; rm -rf /")
        )
    assert text == "nginx[1]: bind() failed"
    assert seen["unit"] == "nginx.service" and seen["lines"] == 200
    assert seen["priority"] == "err" and seen["since"] == "-1h" and seen["hide_own"] is True
    assert "not a valid systemd unit name" in bad

    async with db_session_factory() as db:
        entry = (
            await db.execute(
                select(AuditLogEntry).where(AuditLogEntry.action == "machine.logs.view")
            )
        ).scalar_one()
    assert entry.details == {"via": "ai_assistant", "lines": 200, "unit": "nginx.service"}
    assert entry.actor.endswith("(AI assistant)")


async def test_service_logs_need_the_terminal_permission(client, login_as, db_session_factory):
    await create_machine(db_session_factory, "web1")
    viewer = await login_as(
        client, permissions={Permission.AI_ACCESS, Permission.MACHINE_VIEW}, username="viewer"
    )
    offered = {t.name for t in available_tools(viewer)}
    assert "get_machine_details" in offered and "get_service_logs" not in offered
    async with db_session_factory() as db:
        refused = await execute_read_only_tool(
            db, viewer, _call("get_service_logs", machine_name="web1")
        )
    assert refused.startswith("Refused:")


# --- Ask AI on the machine page --------------------------------------------------


async def test_ask_ai_on_the_machine_page_starts_a_conversation_with_context(
    client, db_session_factory, celery_calls
):
    machine_id = await create_machine(db_session_factory, "web1")
    await setup_provider(db_session_factory)
    page = await client.get(f"/machines/{machine_id}")
    assert 'name="kind" value="machine"' in page.text
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/ai/explain",
        data={
            "csrf_token": csrf_token,
            "kind": "machine",
            "machine_id": str(machine_id),
            "question": "Why is nginx down?",
        },
    )
    assert response.status_code == 303
    async with db_session_factory() as db:
        message = (await db.execute(select(AiMessage))).scalar_one()
    assert (
        'machine "web1"' in message.content and "My question: Why is nginx down?" in message.content
    )

    empty = await client.post(
        "/ai/explain",
        data={"csrf_token": csrf_token, "kind": "machine", "machine_id": str(machine_id)},
    )
    assert empty.status_code == 400
