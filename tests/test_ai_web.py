"""AI assistant: permission gating, the confirm-before-execute gate, token
limits, and conversation ownership.

No provider is ever contacted here — `app.tasks.ai_jobs.build_client` is
monkeypatched to a fake client whose canned responses drive the turn loop,
which also lets the tests assert on exactly *which tools* were offered.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.ai.base import BaseAiClient, ChatTurnResult, ModelInfo, ToolCall
from app.ai.tools import MAX_TARGET_MACHINES
from app.ai.usage import (
    DAY_WINDOW,
    MONTH_WINDOW,
    WEEK_WINDOW,
    check_within_limits,
    get_usage_totals,
)
from app.core.security import decrypt_secret, encrypt_secret
from app.db import session as db_session
from app.db.models.ai_conversation import AiConversation
from app.db.models.ai_message import AiMessage, AiMessageRole
from app.db.models.ai_model import AiModel
from app.db.models.ai_provider import AiProviderConfig, AiProviderKind
from app.db.models.ai_usage import AiUsageRecord
from app.db.models.app_settings import SINGLETON_ID, AppSettings
from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.role import Permission
from app.db.models.user import User
from app.tasks import ai_jobs
from app.web.routes import settings as settings_routes
from tests.conftest import ADMIN_USERNAME

ALL_AI_PERMISSIONS = {
    Permission.AI_ACCESS,
    Permission.MACHINE_VIEW,
    Permission.GROUP_VIEW,
    Permission.ACTION_UPDATES,
    Permission.ACTION_POWER,
    Permission.ACTION_TERMINAL,
}


class FakeClient(BaseAiClient):
    """Anthropic-shaped fake — enough to exercise the loop and record what
    the turn task offered the model."""

    kind_value = "anthropic"

    def __init__(self, results: list[ChatTurnResult]) -> None:
        self.results = list(results)
        self.calls: list[dict[str, Any]] = []

    async def list_models(self) -> list[Any]:
        return []

    async def send(
        self, messages: list[Any], tools: list[Any], model: str, system_prompt: str
    ) -> ChatTurnResult:
        self.calls.append(
            {"messages": list(messages), "tools": list(tools), "model": model}
        )
        return self.results.pop(0)

    def build_user_message(self, text: str) -> Any:
        return {"role": "user", "content": text}

    def build_tool_result_messages(
        self, result: ChatTurnResult, outputs: list[Any]
    ) -> list[Any]:
        return [
            result.raw_assistant_message,
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": call.id, "content": output}
                    for call, output in outputs
                ],
            },
        ]


def text_turn(text: str) -> ChatTurnResult:
    return ChatTurnResult(
        text=text,
        input_tokens=10,
        output_tokens=5,
        raw_assistant_message={"role": "assistant", "content": text},
    )


def tool_turn(name: str, arguments: dict[str, Any]) -> ChatTurnResult:
    call = ToolCall(id="tu_1", name=name, arguments=arguments)
    return ChatTurnResult(
        text=None,
        tool_calls=[call],
        input_tokens=10,
        output_tokens=5,
        raw_assistant_message={"role": "assistant", "content": [{"type": "tool_use"}]},
    )


@pytest.fixture
def use_test_db(db_session_factory: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """`app.tasks.ai_jobs` opens its own session through
    `app.db.session.AsyncSessionLocal` (see that module's docstring on why it
    goes through the module) — point it at the test's SQLite factory."""
    monkeypatch.setattr(db_session, "AsyncSessionLocal", db_session_factory)
    return db_session_factory


def install_fake_client(
    monkeypatch: pytest.MonkeyPatch, results: list[ChatTurnResult]
) -> FakeClient:
    fake = FakeClient(results)
    monkeypatch.setattr(ai_jobs, "build_client", lambda config: fake)
    return fake


async def setup_provider(
    db_session_factory: Any, *, model_id: str = "fake-model"
) -> tuple[uuid.UUID, str]:
    async with db_session_factory() as db:
        provider = AiProviderConfig(
            kind=AiProviderKind.ANTHROPIC,
            enabled=True,
            # A validly-encrypted (if fake) key — needed because
            # `app.web.routes.ai.post_message` now calls the *real*
            # `build_client` itself (only `.build_user_message()`, never
            # `.send()`, which stays test-doubled via `install_fake_client`
            # patching `ai_jobs.build_client` for the actual turn). A
            # decryptable value here, not the network, is what that needs.
            api_key_encrypted=encrypt_secret("fake-key"),
        )
        db.add(provider)
        await db.flush()
        db.add(AiModel(provider_id=provider.id, model_id=model_id, enabled=True))
        await db.commit()
        return provider.id, model_id


async def get_user(db_session_factory: Any, username: str = ADMIN_USERNAME) -> User:
    async with db_session_factory() as db:
        result = await db.execute(select(User).where(User.username == username))
        user: User = result.scalar_one()
        return user


async def create_conversation(
    db_session_factory: Any, user_id: uuid.UUID, provider_id: uuid.UUID, model_id: str
) -> uuid.UUID:
    async with db_session_factory() as db:
        conversation = AiConversation(
            user_id=user_id, title="t", provider_id=provider_id, model_id=model_id
        )
        db.add(conversation)
        await db.commit()
        return conversation.id


async def create_machine(
    db_session_factory: Any, name: str = "web1", *, pinned: bool = True
) -> uuid.UUID:
    async with db_session_factory() as db:
        machine = Machine(
            name=name,
            ip_address="10.0.0.5",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            host_key_fingerprint="SHA256:abc" if pinned else None,
        )
        db.add(machine)
        await db.commit()
        return machine.id


async def pending_actions_of(
    db_session_factory: Any, conversation_id: uuid.UUID
) -> tuple[uuid.UUID | None, list[dict[str, Any]]]:
    async with db_session_factory() as db:
        result = await db.execute(
            select(AiMessage)
            .where(AiMessage.conversation_id == conversation_id)
            .order_by(AiMessage.created_at, AiMessage.id)
        )
        for message in reversed(list(result.scalars().all())):
            if message.pending_actions:
                return message.id, message.pending_actions
    return None, []


# --- Sending a message: async turn, not a blocking wait ---------------------
#
# `post_message` used to enqueue the turn and block the whole HTTP request on
# `AsyncResult.get(timeout=90)` — a real bug (see app/tasks/ai_jobs.py's
# `_AI_TURN_TIME_LIMIT_SECONDS` comment): a turn can make several sequential
# provider calls, easily exceeding both that wait and the Celery task's own
# time limit, which could kill the task before either timeout ever fired,
# silently. It now persists the human's message immediately, enqueues the
# turn, and redirects without waiting — `partials/ai_messages_panel.html`
# polls for the reply. These tests exercise that route directly (never
# `_run_turn`), so `celery_calls`'s autouse `.delay()` stub means the turn
# itself never actually runs — exactly the "still waiting" state being
# tested.


async def test_sending_a_message_persists_it_immediately_and_redirects(
    client, db_session_factory, celery_calls
):
    user = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, user.id, provider_id, model_id)

    await client.get(f"/ai/conversations/{conversation_id}")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/ai/conversations/{conversation_id}/messages",
        data={"csrf_token": csrf_token, "message": "hello there"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"/ai/conversations/{conversation_id}"

    async with db_session_factory() as db:
        result = await db.execute(
            select(AiMessage).where(AiMessage.conversation_id == conversation_id)
        )
        messages = list(result.scalars().all())
    assert len(messages) == 1
    assert messages[0].content == "hello there"
    assert messages[0].role.value == "user"
    # Provider-native shape built eagerly too (not left for the task) — see
    # post_message's docstring.
    assert messages[0].provider_native == [{"role": "user", "content": "hello there"}]

    # Enqueued with just the conversation id — the task reads the message
    # back from history rather than receiving it as an argument, now that
    # the route itself is what persisted it.
    assert celery_calls.names == ["app.tasks.ai_jobs.run_ai_turn"]
    assert celery_calls[0][1] == (str(conversation_id),)


async def test_conversation_page_shows_disabled_form_while_awaiting_reply(
    client, db_session_factory, celery_calls
):
    user = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, user.id, provider_id, model_id)

    await client.get(f"/ai/conversations/{conversation_id}")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        f"/ai/conversations/{conversation_id}/messages",
        data={"csrf_token": csrf_token, "message": "hello there"},
    )

    page = await client.get(f"/ai/conversations/{conversation_id}")
    assert page.status_code == 200
    assert "hello there" in page.text
    assert "disabled" in page.text
    assert f'hx-get="/ai/conversations/{conversation_id}/messages-panel"' in page.text
    assert 'hx-trigger="every 2s"' in page.text


async def test_messages_panel_stops_polling_once_the_reply_arrives(
    client, db_session_factory, celery_calls
):
    user = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, user.id, provider_id, model_id)

    await client.get(f"/ai/conversations/{conversation_id}")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        f"/ai/conversations/{conversation_id}/messages",
        data={"csrf_token": csrf_token, "message": "hello there"},
    )

    # Simulate the (never-actually-run, per celery_calls) task completing.
    async with db_session_factory() as db:
        db.add(
            AiMessage(
                conversation_id=conversation_id,
                role=AiMessageRole.ASSISTANT,
                content="Hi! How can I help?",
                provider_native=[{"role": "assistant", "content": "Hi! How can I help?"}],
            )
        )
        await db.commit()

    panel = await client.get(f"/ai/conversations/{conversation_id}/messages-panel")
    assert panel.status_code == 200
    assert "Hi! How can I help?" in panel.text
    assert "hx-trigger" not in panel.text
    assert "disabled" not in panel.text


# --- Permission gating -------------------------------------------------------


async def test_every_ai_route_is_refused_without_ai_access(client, login_as):
    await login_as(client, permissions={Permission.MACHINE_VIEW})
    some_id = uuid.uuid4()

    assert (await client.get("/ai")).status_code == 403
    assert (await client.post("/ai/conversations", data={})).status_code == 403
    assert (await client.get(f"/ai/conversations/{some_id}")).status_code == 403
    assert (await client.post(f"/ai/conversations/{some_id}/messages", data={})).status_code == 403
    assert (
        await client.post(
            f"/ai/conversations/{some_id}/messages/{some_id}/confirm", data={}
        )
    ).status_code == 403
    assert (
        await client.post(
            f"/ai/conversations/{some_id}/messages/{some_id}/discard", data={}
        )
    ).status_code == 403
    assert (await client.post(f"/ai/conversations/{some_id}/delete", data={})).status_code == 403


async def test_ai_page_is_reachable_with_only_ai_access(client, login_as):
    await login_as(client, permissions={Permission.AI_ACCESS})
    response = await client.get("/ai")
    assert response.status_code == 200
    assert "No AI model is enabled yet" in response.text


async def test_tools_offered_are_filtered_by_the_users_permissions(
    client, login_as, db_session_factory, use_test_db, monkeypatch
):
    """A user without `action.terminal` must never even be *offered*
    run_ssh_command — permission check #1."""
    user = await login_as(
        client,
        permissions={Permission.AI_ACCESS, Permission.MACHINE_VIEW, Permission.ACTION_UPDATES},
        username="no-terminal",
    )
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, user.id, provider_id, model_id)

    fake = install_fake_client(monkeypatch, [text_turn("Sure.")])
    result = await ai_jobs._run_turn(str(conversation_id), "hi", allow_tools=True)

    assert result["ok"] is True
    offered = {tool.name for tool in fake.calls[0]["tools"]}
    assert "run_ssh_command" not in offered
    assert "list_groups" not in offered  # no group.view either
    assert {"list_machines", "run_update", "check_updates"} <= offered


async def test_a_tool_call_the_user_may_not_use_is_denied_not_executed(
    client, login_as, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    """Permission check #2: even if the model calls a tool that was never
    offered, the call is recorded as `denied`, never run."""
    user = await login_as(
        client,
        permissions={Permission.AI_ACCESS, Permission.MACHINE_VIEW},
        username="no-terminal-2",
    )
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, user.id, provider_id, model_id)
    await create_machine(db_session_factory, "web1")

    install_fake_client(
        monkeypatch,
        [
            tool_turn(
                "run_ssh_command",
                {"target_type": "machine", "target_name": "web1", "command": "rm -rf /"},
            ),
            text_turn("I could not do that."),
        ],
    )
    await ai_jobs._run_turn(str(conversation_id), "wipe web1", allow_tools=True)

    _message_id, actions = await pending_actions_of(db_session_factory, conversation_id)
    assert len(actions) == 1
    assert actions[0]["status"] == "denied"
    assert "action.terminal" in actions[0]["reason"]
    assert celery_calls.names == []


# --- Token limits ------------------------------------------------------------


async def test_a_turn_over_the_daily_limit_is_rejected_before_any_provider_call(
    client, db_session_factory, use_test_db, monkeypatch
):
    user = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, user.id, provider_id, model_id)

    async with db_session_factory() as db:
        db.add(AppSettings(id=SINGLETON_ID, ai_daily_token_limit=100))
        db.add(
            AiUsageRecord(
                user_id=user.id,
                provider_kind=AiProviderKind.ANTHROPIC,
                model_id=model_id,
                input_tokens=90,
                output_tokens=30,
            )
        )
        await db.commit()

    fake = install_fake_client(monkeypatch, [text_turn("should never be sent")])
    result = await ai_jobs._run_turn(str(conversation_id), "hello", allow_tools=True)

    assert result["ok"] is False
    assert "Daily AI token limit (100) reached" in result["error"]
    assert fake.calls == []


# --- Confirm / discard: the gate --------------------------------------------


async def _propose_update(
    client: Any, db_session_factory: Any, monkeypatch: pytest.MonkeyPatch
) -> tuple[uuid.UUID, uuid.UUID | None, list[dict[str, Any]], uuid.UUID]:
    user = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, user.id, provider_id, model_id)
    machine_id = await create_machine(db_session_factory, "web1")

    install_fake_client(
        monkeypatch,
        [
            tool_turn(
                "run_update",
                {"target_type": "machine", "target_name": "web1", "strategy": "dist_upgrade"},
            ),
            text_turn("Proposed a dist-upgrade on web1 — confirm it to run."),
        ],
    )
    await ai_jobs._run_turn(str(conversation_id), "update web1", allow_tools=True)
    message_id, actions = await pending_actions_of(db_session_factory, conversation_id)
    return conversation_id, message_id, actions, machine_id


async def test_a_proposed_update_is_pending_and_runs_nothing_until_confirmed(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    conversation_id, message_id, actions, _machine_id = await _propose_update(
        client, db_session_factory, monkeypatch
    )

    assert len(actions) == 1
    action = actions[0]
    assert action["tool"] == "run_update"
    assert action["status"] == "pending"
    assert action["machine_names"] == ["web1"]
    assert action["strategy"] == "dist_upgrade"
    # Nothing enqueued by merely proposing it.
    assert "app.tasks.jobs.run_machine_update" not in celery_calls.names

    # The page shows the literal target and both buttons.
    page = await client.get(f"/ai/conversations/{conversation_id}")
    assert page.status_code == 200
    assert "Confirm and run" in page.text
    assert "web1" in page.text

    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/ai/conversations/{conversation_id}/messages/{message_id}/confirm",
        data={"csrf_token": csrf_token, "action_index": "0"},
    )
    assert response.status_code == 200
    assert "app.tasks.jobs.run_machine_update" in celery_calls.names

    _mid, actions_after = await pending_actions_of(db_session_factory, conversation_id)
    assert actions_after[0]["status"] == "confirmed"

    async with db_session_factory() as db:
        result = await db.execute(
            select(AuditLogEntry).where(AuditLogEntry.action == "ai.action.run_update")
        )
        entries = list(result.scalars().all())
    assert len(entries) == 1
    assert entries[0].details["machines"] == ["web1"]

    # The "auto-confirm further commands" banner only appears *after* a
    # human has confirmed at least one command by hand in this
    # conversation — see app.web.routes.ai._any_action_confirmed.
    assert "data-ai-auto-confirm-toggle" in response.text
    assert "data-ai-confirm-form" not in response.text  # nothing pending right now


async def test_auto_confirm_banner_absent_before_any_confirmation(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    conversation_id, _message_id, _actions, _machine_id = await _propose_update(
        client, db_session_factory, monkeypatch
    )
    page = await client.get(f"/ai/conversations/{conversation_id}")
    assert page.status_code == 200
    assert "data-ai-auto-confirm-toggle" not in page.text
    # The one still-pending action's own confirm form is there, though.
    assert "data-ai-confirm-form" in page.text


async def test_confirm_requires_a_csrf_token(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    conversation_id, message_id, _actions, _machine_id = await _propose_update(
        client, db_session_factory, monkeypatch
    )

    response = await client.post(
        f"/ai/conversations/{conversation_id}/messages/{message_id}/confirm",
        data={"csrf_token": "wrong", "action_index": "0"},
    )
    assert response.status_code == 403
    assert "app.tasks.jobs.run_machine_update" not in celery_calls.names


async def test_discarding_a_proposal_runs_nothing(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    conversation_id, message_id, _actions, _machine_id = await _propose_update(
        client, db_session_factory, monkeypatch
    )

    await client.get(f"/ai/conversations/{conversation_id}")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/ai/conversations/{conversation_id}/messages/{message_id}/discard",
        data={"csrf_token": csrf_token, "action_index": "0"},
    )
    assert response.status_code == 303

    _mid, actions_after = await pending_actions_of(db_session_factory, conversation_id)
    assert actions_after[0]["status"] == "discarded"
    assert "app.tasks.jobs.run_machine_update" not in celery_calls.names


async def test_confirming_twice_only_runs_it_once(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    conversation_id, message_id, _actions, _machine_id = await _propose_update(
        client, db_session_factory, monkeypatch
    )
    await client.get(f"/ai/conversations/{conversation_id}")
    csrf_token = client.cookies.get("csrftoken")
    url = f"/ai/conversations/{conversation_id}/messages/{message_id}/confirm"
    data = {"csrf_token": csrf_token, "action_index": "0"}

    await client.post(url, data=data)
    await client.post(url, data=data)

    assert celery_calls.names.count("app.tasks.jobs.run_machine_update") == 1


async def test_confirm_is_refused_after_the_permission_is_taken_away(
    client, login_as, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    """Permission check #3 — the role is re-read at confirm time, so a
    proposal written while the user had `action.updates` is not still
    executable once they don't."""
    user = await login_as(
        client, permissions=ALL_AI_PERMISSIONS, username="downgraded"
    )
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, user.id, provider_id, model_id)
    await create_machine(db_session_factory, "web1")

    install_fake_client(
        monkeypatch,
        [
            tool_turn(
                "run_update",
                {"target_type": "machine", "target_name": "web1", "strategy": "dist_upgrade"},
            ),
            text_turn("Proposed."),
        ],
    )
    await ai_jobs._run_turn(str(conversation_id), "update web1", allow_tools=True)
    message_id, actions = await pending_actions_of(db_session_factory, conversation_id)
    assert actions[0]["status"] == "pending"

    # Strip the permission from the role the user still holds.
    async with db_session_factory() as db:
        db_user = await db.get(User, user.id)
        db_user.role.permission_grants = [
            grant
            for grant in db_user.role.permission_grants
            if grant.permission != Permission.ACTION_UPDATES
        ]
        await db.commit()

    await client.get(f"/ai/conversations/{conversation_id}")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/ai/conversations/{conversation_id}/messages/{message_id}/confirm",
        data={"csrf_token": csrf_token, "action_index": "0"},
    )

    assert response.status_code == 200
    assert "app.tasks.jobs.run_machine_update" not in celery_calls.names
    _mid, actions_after = await pending_actions_of(db_session_factory, conversation_id)
    assert actions_after[0]["status"] == "denied"


async def test_confirming_a_shell_command_runs_it_and_asks_for_a_summary(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    user = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, user.id, provider_id, model_id)
    await create_machine(db_session_factory, "web1")

    install_fake_client(
        monkeypatch,
        [
            tool_turn(
                "run_ssh_command",
                {
                    "target_type": "machine",
                    "target_name": "web1",
                    "command": "sudo -n apt-get -y install apache2",
                },
            ),
            text_turn("Proposed."),
        ],
    )
    await ai_jobs._run_turn(str(conversation_id), "install apache2 on web1", allow_tools=True)
    message_id, actions = await pending_actions_of(db_session_factory, conversation_id)
    assert actions[0]["command"] == "sudo -n apt-get -y install apache2"

    page = await client.get(f"/ai/conversations/{conversation_id}")
    assert "sudo -n apt-get -y install apache2" in page.text
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        f"/ai/conversations/{conversation_id}/messages/{message_id}/confirm",
        data={"csrf_token": csrf_token, "action_index": "0"},
    )
    assert response.status_code == 200

    assert "app.tasks.jobs.run_remote_ssh_command" in celery_calls.names
    enqueued = [c for c in celery_calls if c[0] == "app.tasks.jobs.run_remote_ssh_command"]
    assert enqueued[0][1][1] == "sudo -n apt-get -y install apache2"
    assert "app.tasks.ai_jobs.summarize_tool_output" in celery_calls.names


# --- Read-only tools auto-execute -------------------------------------------


async def test_read_only_lookups_execute_immediately_and_feed_back(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    user = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, user.id, provider_id, model_id)
    await create_machine(db_session_factory, "web1")

    fake = install_fake_client(
        monkeypatch,
        [tool_turn("list_machines", {}), text_turn("You have one machine, web1.")],
    )
    result = await ai_jobs._run_turn(str(conversation_id), "what machines?", allow_tools=True)

    assert result["ok"] is True
    assert result["pending_action_count"] == 0
    # The lookup ran and its output went back into the second request.
    assert len(fake.calls) == 2
    assert "web1" in str(fake.calls[1]["messages"])
    # Read-only means read-only: nothing was enqueued.
    assert celery_calls.names == []


# --- Ownership ---------------------------------------------------------------


async def test_a_conversation_is_invisible_to_another_user(
    client, login_as, db_session_factory, use_test_db, monkeypatch
):
    owner = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, owner.id, provider_id, model_id)

    await login_as(client, permissions=ALL_AI_PERMISSIONS, username="someone-else")
    await client.get("/ai")
    csrf_token = client.cookies.get("csrftoken")
    fake_message_id = uuid.uuid4()

    assert (await client.get(f"/ai/conversations/{conversation_id}")).status_code == 404
    assert (
        await client.post(
            f"/ai/conversations/{conversation_id}/messages",
            data={"csrf_token": csrf_token, "message": "hi"},
        )
    ).status_code == 404
    assert (
        await client.post(
            f"/ai/conversations/{conversation_id}/messages/{fake_message_id}/confirm",
            data={"csrf_token": csrf_token, "action_index": "0"},
        )
    ).status_code == 404
    assert (
        await client.post(
            f"/ai/conversations/{conversation_id}/delete", data={"csrf_token": csrf_token}
        )
    ).status_code == 404


async def test_settings_page_never_echoes_a_stored_api_key(client, db_session_factory):
    """The key is write-only from the browser's side: the page may say one
    exists, never what it is."""
    async with db_session_factory() as db:
        db.add(
            AiProviderConfig(
                kind=AiProviderKind.ANTHROPIC,
                enabled=True,
                api_key_encrypted=encrypt_secret("sk-super-secret-value"),
            )
        )
        await db.commit()

    response = await client.get("/settings?tab=ai")
    assert response.status_code == 200
    assert "sk-super-secret-value" not in response.text
    assert "unchanged" in response.text


async def test_saving_a_provider_with_a_blank_key_keeps_the_existing_one(
    client, db_session_factory
):
    async with db_session_factory() as db:
        db.add(
            AiProviderConfig(
                kind=AiProviderKind.OPENAI,
                enabled=False,
                api_key_encrypted=encrypt_secret("sk-original"),
            )
        )
        await db.commit()

    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/ai/provider",
        data={"csrf_token": csrf_token, "kind": "openai", "enabled": "1", "api_key": ""},
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        result = await db.execute(
            select(AiProviderConfig).where(AiProviderConfig.kind == AiProviderKind.OPENAI)
        )
        config = result.scalar_one()
    assert config.enabled is True
    assert decrypt_secret(config.api_key_encrypted) == "sk-original"


async def test_enabling_an_openai_compatible_provider_requires_a_base_url(
    client, db_session_factory
):
    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/ai/provider",
        data={
            "csrf_token": csrf_token,
            "kind": "openai_compatible",
            "enabled": "1",
            "api_key": "sk-x",
            "base_url": "",
        },
    )
    assert response.status_code == 200
    assert "needs a base URL" in response.text


async def test_refetching_models_preserves_the_enabled_flag_and_drops_stale_ids(
    client, db_session_factory, monkeypatch
):
    async with db_session_factory() as db:
        provider = AiProviderConfig(
            kind=AiProviderKind.ANTHROPIC, enabled=True, api_key_encrypted=encrypt_secret("k")
        )
        db.add(provider)
        await db.flush()
        db.add_all(
            [
                AiModel(provider_id=provider.id, model_id="keep-me", enabled=True),
                AiModel(provider_id=provider.id, model_id="gone-upstream", enabled=True),
            ]
        )
        await db.commit()

    class StubClient:
        async def list_models(self):
            return [ModelInfo(id="keep-me"), ModelInfo(id="brand-new")]

    monkeypatch.setattr(settings_routes, "build_client", lambda config: StubClient())

    await client.get("/settings")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/settings/ai/fetch-models", data={"csrf_token": csrf_token, "kind": "anthropic"}
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        rows = (await db.execute(select(AiModel))).scalars().all()
    by_id = {row.model_id: row for row in rows}
    assert set(by_id) == {"keep-me", "brand-new"}
    assert by_id["keep-me"].enabled is True
    # A newly discovered model is never auto-approved for chat.
    assert by_id["brand-new"].enabled is False


async def test_a_group_larger_than_the_fan_out_cap_is_refused_not_truncated(
    client, db_session_factory, use_test_db, monkeypatch
):
    user = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    conversation_id = await create_conversation(db_session_factory, user.id, provider_id, model_id)

    async with db_session_factory() as db:
        group = MachineGroup(name="huge")
        db.add(group)
        await db.flush()
        for index in range(MAX_TARGET_MACHINES + 1):
            db.add(
                Machine(
                    name=f"node{index}",
                    ip_address=f"10.0.1.{index}",
                    port=22,
                    username="root",
                    auth_method=AuthMethod.PASSWORD,
                    host_key_fingerprint="SHA256:abc",
                    group_id=group.id,
                )
            )
        await db.commit()

    install_fake_client(
        monkeypatch,
        [
            tool_turn("reboot", {"target_type": "group", "target_name": "huge"}),
            text_turn("That group is too large."),
        ],
    )
    await ai_jobs._run_turn(str(conversation_id), "reboot the huge group", allow_tools=True)

    _message_id, actions = await pending_actions_of(db_session_factory, conversation_id)
    assert actions[0]["status"] == "denied"
    assert "limit for one proposed action" in actions[0]["reason"]


# --- Rolling-window limits ---------------------------------------------------


async def test_usage_windows_are_rolling_not_calendar_aligned(db_session_factory):
    now = datetime.now(UTC)
    async with db_session_factory() as db:
        db.add_all(
            [
                # 2 hours ago — inside every window.
                AiUsageRecord(
                    provider_kind=AiProviderKind.OPENAI,
                    model_id="m",
                    input_tokens=10,
                    output_tokens=0,
                    created_at=now - timedelta(hours=2),
                ),
                # 3 days ago — outside 24h, inside 7d/30d.
                AiUsageRecord(
                    provider_kind=AiProviderKind.OPENAI,
                    model_id="m",
                    input_tokens=100,
                    output_tokens=0,
                    created_at=now - timedelta(days=3),
                ),
                # 45 days ago — outside all of them.
                AiUsageRecord(
                    provider_kind=AiProviderKind.OPENAI,
                    model_id="m",
                    input_tokens=1000,
                    output_tokens=0,
                    created_at=now - timedelta(days=45),
                ),
            ]
        )
        await db.commit()

        assert await get_usage_totals(db, now - DAY_WINDOW) == 10
        assert await get_usage_totals(db, now - WEEK_WINDOW) == 110
        assert await get_usage_totals(db, now - MONTH_WINDOW) == 110

        settings_row = AppSettings(id=SINGLETON_ID, ai_weekly_token_limit=110)
        db.add(settings_row)
        await db.commit()
        message = await check_within_limits(db, settings_row)

    assert message is not None
    assert "Weekly AI token limit (110) reached" in message


async def test_no_configured_limit_means_unlimited(db_session_factory):
    async with db_session_factory() as db:
        settings_row = AppSettings(id=SINGLETON_ID)
        db.add(settings_row)
        await db.commit()
        assert await check_within_limits(db, settings_row) is None


async def test_creating_a_conversation_rejects_a_model_that_is_not_enabled(
    client, db_session_factory
):
    async with db_session_factory() as db:
        provider = AiProviderConfig(
            kind=AiProviderKind.ANTHROPIC, enabled=True, api_key_encrypted=b"x"
        )
        db.add(provider)
        await db.flush()
        db.add(AiModel(provider_id=provider.id, model_id="not-approved", enabled=False))
        await db.commit()
        provider_id = provider.id

    await client.get("/ai")
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        "/ai/conversations",
        data={
            "csrf_token": csrf_token,
            "provider_model": f"{provider_id}:not-approved",
            "first_message": "hello",
        },
    )
    assert response.status_code == 400
