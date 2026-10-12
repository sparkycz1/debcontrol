"""The AI's reading of the likely cause in a notification
(`app.services.ai_cause`): only for a rule that asks, only for a failed
service or a failed update, and never in the way of the notification."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select

from app.ai.base import AiProviderError, ChatTurnResult
from app.db.models.ai_model import AiModel
from app.db.models.ai_provider import AiProviderConfig, AiProviderKind
from app.db.models.ai_usage import AiUsageRecord
from app.db.models.notification_rule import NotificationEventType, NotificationRule
from app.services import ai_cause
from app.services.notification_rules import rule_to_portable_dict
from app.services.notifications import notify
from tests.test_notification_throttle import _capture_webhook, _machine


class _FakeClient:
    def __init__(self, answer: str | Exception) -> None:
        self.answer = answer
        self.prompts: list[str] = []

    def build_user_message(self, text: str) -> str:
        return text

    async def send(self, messages: list[Any], tools: list[Any], model: str, system: str) -> Any:
        self.prompts.append(messages[0])
        if isinstance(self.answer, Exception):
            raise self.answer
        return ChatTurnResult(text=self.answer, input_tokens=120, output_tokens=30)


async def _setup(db: Any, *, with_model: bool = True) -> Any:
    machine = _machine("web1", "10.0.0.1")
    db.add(machine)
    for name, wants_ai in (("with-ai", True), ("plain", False)):
        db.add(
            NotificationRule(
                name=name,
                enabled=True,
                event_types=[
                    NotificationEventType.UPDATE_RUN_FAILED.value,
                    NotificationEventType.MACHINE_UNREACHABLE.value,
                ],
                delivery_channel="webhook",
                webhook_url=f"https://hooks.example.com/{name}",
                ai_summary=wants_ai,
            )
        )
    if with_model:
        provider = AiProviderConfig(kind=AiProviderKind.ANTHROPIC, enabled=True)
        db.add(provider)
        await db.flush()
        db.add(AiModel(provider_id=provider.id, model_id="some-model", enabled=True))
    await db.commit()
    return machine


def _use(monkeypatch: pytest.MonkeyPatch, answer: str | Exception) -> _FakeClient:
    client = _FakeClient(answer)
    monkeypatch.setattr(ai_cause, "build_client", lambda _provider: client)
    return client


async def test_only_the_rule_that_asks_gets_the_reading(db_session_factory, monkeypatch):
    posted = _capture_webhook(monkeypatch)
    client = _use(monkeypatch, "dpkg was interrupted. Run dpkg --configure -a.")
    async with db_session_factory() as db:
        machine = await _setup(db)
        await notify(
            db,
            NotificationEventType.UPDATE_RUN_FAILED,
            machine=machine,
            context={
                "details": "apt exited with status 100.",
                ai_cause.EVIDENCE_KEY: "E: dpkg was interrupted, you must manually run ...",
            },
        )
        # An event the AI is never asked about.
        await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=machine)
        usage = list((await db.execute(select(AiUsageRecord))).scalars().all())

    failed = [p for p in posted if p["event"] == NotificationEventType.UPDATE_RUN_FAILED.value]
    with_ai = next(p for p in failed if "Likely cause" in p["body"])
    plain = next(p for p in failed if "Likely cause" not in p["body"])
    assert "Likely cause (AI, not verified): dpkg was interrupted." in with_ai["body"]
    assert with_ai["ai_summary"].endswith("Run dpkg --configure -a.")
    assert plain["ai_summary"] == "" and plain["details"] == "apt exited with status 100."
    # The excerpt went to the model once, and nowhere else.
    assert len(client.prompts) == 1 and "dpkg was interrupted" in client.prompts[0]
    assert all(ai_cause.EVIDENCE_KEY not in p for p in posted)
    assert [(u.input_tokens, u.output_tokens) for u in usage] == [(120, 30)]


@pytest.mark.parametrize("problem", ["no_model", "provider_error", "no_evidence"])
async def test_the_notification_goes_out_without_it(db_session_factory, monkeypatch, problem):
    posted = _capture_webhook(monkeypatch)
    client = _use(
        monkeypatch, AiProviderError("upstream 500") if problem == "provider_error" else "text"
    )
    async with db_session_factory() as db:
        machine = await _setup(db, with_model=problem != "no_model")
        context = {"details": "apt exited with status 100."}
        if problem != "no_evidence":
            context[ai_cause.EVIDENCE_KEY] = "E: something"
        await notify(db, NotificationEventType.UPDATE_RUN_FAILED, machine=machine, context=context)

    assert len(posted) == 2
    assert all("Likely cause" not in p["body"] for p in posted)
    assert len(client.prompts) == (1 if problem == "provider_error" else 0)


async def test_a_failed_service_is_explained_from_its_journal(db_session_factory, monkeypatch):
    posted = _capture_webhook(monkeypatch)
    client = _use(monkeypatch, "x" * 2000)
    asked: list[str] = []

    async def fake_journal(_db: Any, _settings: Any, _machine: Any, units: list[str]) -> str:
        asked.extend(units)
        return "--- journal of nginx.service ---\nnginx: bind() to 0.0.0.0:80 failed"

    monkeypatch.setattr(ai_cause, "_journal_evidence", fake_journal)
    async with db_session_factory() as db:
        machine = _machine("web1", "10.0.0.1")
        db.add(machine)
        db.add(
            NotificationRule(
                name="services",
                enabled=True,
                event_types=[NotificationEventType.SERVICE_FAILED.value],
                delivery_channel="webhook",
                webhook_url="https://hooks.example.com/s",
                ai_summary=True,
            )
        )
        provider = AiProviderConfig(kind=AiProviderKind.ANTHROPIC, enabled=True)
        db.add(provider)
        await db.flush()
        db.add(AiModel(provider_id=provider.id, model_id="some-model", enabled=True))
        await db.commit()
        await notify(
            db,
            NotificationEventType.SERVICE_FAILED,
            machine=machine,
            context={"units": "nginx.service, php-fpm.service", "details": "nginx.service"},
        )
        rule = (await db.execute(select(NotificationRule))).scalars().one()
        exported = rule_to_portable_dict(rule)

    assert asked == ["nginx.service", "php-fpm.service"]
    assert "bind() to 0.0.0.0:80 failed" in client.prompts[0]
    # A long answer is cut, not passed on whole.
    assert len(posted[0]["ai_summary"]) < 760 and posted[0]["ai_summary"].endswith("…")
    assert exported["ai_summary"] is True
