"""Smaller usability fixes: audit labels that say what an action was about,
empty pages that explain themselves, one form of address in Czech."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from httpx2 import AsyncClient

from app.db.models.audit_log import AuditLogEntry
from app.services import audit_subject

_CS = json.loads(Path("app/i18n/locales/cs.json").read_text(encoding="utf-8"))["strings"]


def test_subject_names_what_an_entry_was_about() -> None:
    assert audit_subject.subject({"vmid": 111, "action": "reboot"}) == "111"
    assert audit_subject.subject({"package": "nginx", "strategy": "full_upgrade"}) == (
        "nginx, full-upgrade"
    )
    assert audit_subject.subject({"usernames": ["alice", "bob"], "skipped": 0}) == "alice, bob"
    assert audit_subject.subject({"skipped": 2, "ok": True, "error": "boom"}) == ""
    assert audit_subject.subject(None) == "" and audit_subject.subject("text") == ""
    assert len(audit_subject.subject({"file": "x" * 200})) <= 60


async def test_translated_activity_says_which_guest(
    client: AsyncClient, db_session_factory: Any
) -> None:
    async with db_session_factory() as db:
        for vmid in (111, 112):
            db.add(
                AuditLogEntry(
                    actor="alice",
                    action="machine.guest.reboot",
                    summary=f"Sent reboot to guest {vmid}",
                    target_type="machine",
                    target_label="pve1",
                    details={"vmid": vmid, "action": "reboot"},
                )
            )
        await db.commit()
    await client.get("/account")
    await client.post(
        "/account/locale", data={"csrf_token": client.cookies.get("csrftoken"), "locale": "cs"}
    )

    dashboard = await client.get("/dashboard")

    assert "pve1 (111)" in dashboard.text and "pve1 (112)" in dashboard.text


async def test_empty_pages_say_what_they_are_for(client: AsyncClient) -> None:
    for path, sentence, target in (
        ("/checks", "A check watches something from the outside", "/checks/new"),
        ("/scheduling", "A scheduled task runs an action by itself", "/scheduling/new"),
        ("/notifications", "A rule says what to be told about", "/notifications/rules/new"),
    ):
        page = await client.get(path)
        empty = page.text[page.text.index('class="empty-state"') :]
        assert sentence in empty, path
        assert f'class="button" href="{target}"' in empty, path


def test_czech_uses_one_form_of_address_and_one_word_for_a_machine() -> None:
    informal = re.compile(
        r"\b(můžeš|musíš|chceš|máš|budeš|jsi|tvůj|tvoje|tvé|tvou|tebe|tobě|zadej|vyber|klikni|"
        r"zkus|zkontroluj|použij|přidej|napiš|potvrď|vlož|spusť|ulož|sám/sama)\b",
        re.IGNORECASE,
    )
    other_word = re.compile(r"\b(stroj\w*|mašin\w*)\b", re.IGNORECASE)

    offenders = [
        key
        for key, text in _CS.items()
        if isinstance(text, str) and (informal.search(text) or other_word.search(text))
    ]

    assert offenders == []
