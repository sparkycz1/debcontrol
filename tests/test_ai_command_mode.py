"""0.139.0: the account's AI command mode (deny / ask / allow), proposals
for several machines (one card, pick the machines, confirm all), "Fix
with AI" on a security audit finding, and the security audit's run log.

As in `tests/test_ai_web.py`, no provider is contacted (a fake client
drives the turn) and no SSH happens (`celery_calls` records what would be
enqueued; the execution job gets a fake `_run_remote_ssh_command`).
"""

from __future__ import annotations

import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.security_audit import SecurityAudit, SecurityAuditStatus
from app.db.models.user import AiCommandMode, User
from app.services import ai_actions, security_audit
from app.ssh import lynis
from app.ssh.lynis import AuditRunError, LynisResult, parse_audit_output
from app.ssh.onboarding import build_onboarding_command
from app.tasks import ai_jobs, jobs
from tests.test_ai_web import (
    create_conversation,
    create_machine,
    get_user,
    install_fake_client,
    pending_actions_of,
    setup_provider,
    text_turn,
    tool_turn,
    use_test_db,
)
from tests.test_update_history import _api_token

__all__ = ["use_test_db"]  # a fixture, used by name


async def _set_mode(db_session_factory: Any, user_id: uuid.UUID, mode: AiCommandMode) -> None:
    async with db_session_factory() as db:
        user = await db.get(User, user_id)
        assert user is not None
        user.ai_command_mode = mode.value
        await db.commit()


async def _conversation(db_session_factory: Any) -> tuple[User, uuid.UUID]:
    user = await get_user(db_session_factory)
    provider_id, model_id = await setup_provider(db_session_factory)
    return user, await create_conversation(db_session_factory, user.id, provider_id, model_id)


# --- The setting -------------------------------------------------------------


async def test_the_mode_is_set_on_my_account_and_audit_logged(
    client, db_session_factory, celery_calls
):
    page = await client.get("/account")
    assert 'id="ai-assistant"' in page.text and 'value="ask" checked' in page.text
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/ai/command-mode", data={"mode": "allow", "csrf_token": csrf_token, "next": "/account"}
    )
    assert response.status_code == 303 and response.headers["location"] == "/account"
    user = await get_user(db_session_factory)
    assert user.ai_mode == AiCommandMode.ALLOW

    bad = await client.post("/ai/command-mode", data={"mode": "yolo", "csrf_token": csrf_token})
    assert bad.status_code == 400
    # An outside `next` is never followed.
    away = await client.post(
        "/ai/command-mode",
        data={"mode": "ask", "csrf_token": csrf_token, "next": "https://evil.example/"},
    )
    assert away.headers["location"] == "/account"
    back = await client.post(
        "/ai/command-mode",
        data={
            "mode": "ask",
            "csrf_token": csrf_token,
            "next": f"/ai/conversations/{uuid.UUID(int=1)}",
        },
    )
    assert back.headers["location"] == f"/ai/conversations/{uuid.UUID(int=1)}"
    no_csrf = await client.post("/ai/command-mode", data={"mode": "allow"})
    assert no_csrf.status_code == 403

    async with db_session_factory() as db:
        result = await db.execute(
            select(AuditLogEntry).where(AuditLogEntry.action == "ai.command_mode.update")
        )
        entries = list(result.scalars().all())
    assert [e.details["to"] for e in entries] == ["allow", "ask"]

    # The API shows it, read-only.
    headers = await _api_token(client)
    account = await client.get("/api/v1/account", headers=headers)
    assert account.json()["ai_command_mode"] == "ask"


def test_an_unknown_stored_mode_reads_as_ask() -> None:
    assert User(ai_command_mode="nonsense").ai_mode == AiCommandMode.ASK


async def test_deny_offers_no_mutating_tool_and_refuses_one(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    user, conversation_id = await _conversation(db_session_factory)
    await create_machine(db_session_factory, "web1")
    await _set_mode(db_session_factory, user.id, AiCommandMode.DENY)

    fake = install_fake_client(
        monkeypatch,
        [
            tool_turn(
                "run_ssh_command",
                {"target_type": "machine", "target_name": "web1", "command": "uptime"},
            ),
            text_turn("Run uptime yourself."),
        ],
    )
    await ai_jobs._run_turn(str(conversation_id), "uptime on web1", allow_tools=True)

    offered = {tool.name for tool in fake.calls[0]["tools"]}
    assert offered == {"list_machines", "list_groups"}
    _mid, actions = await pending_actions_of(db_session_factory, conversation_id)
    assert actions[0]["status"] == "denied" and "AI command setting" in actions[0]["reason"]
    assert celery_calls.names == []


async def test_allow_runs_a_shell_command_at_once_but_not_a_reboot(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    user, conversation_id = await _conversation(db_session_factory)
    await create_machine(db_session_factory, "web1")
    await _set_mode(db_session_factory, user.id, AiCommandMode.ALLOW)

    fake = install_fake_client(
        monkeypatch,
        [
            tool_turn(
                "run_ssh_command",
                {"target_type": "machine", "target_name": "web1", "command": "uptime"},
            ),
            tool_turn("reboot", {"target_type": "machine", "target_name": "web1"}),
            text_turn("Running uptime; the reboot waits for you."),
        ],
    )
    await ai_jobs._run_turn(str(conversation_id), "uptime, then reboot web1", allow_tools=True)

    message_id, actions = await pending_actions_of(db_session_factory, conversation_id)
    assert [a["tool"] for a in actions] == ["run_ssh_command", "reboot"]
    assert actions[0]["status"] == "running" and actions[0]["automatic"] is True
    assert actions[1]["status"] == "pending"
    assert [c[0] for c in celery_calls] == ["app.tasks.ai_jobs.execute_ai_actions"]
    assert celery_calls[0][1] == (str(conversation_id), str(message_id), [0])
    # The model was told it runs now, and the system prompt says so.
    tool_feedback = fake.calls[1]["messages"][-1]["content"][0]["content"]
    assert "without a confirmation" in tool_feedback

    async with db_session_factory() as db:
        result = await db.execute(
            select(AuditLogEntry).where(AuditLogEntry.action == "ai.action.run_ssh_command")
        )
        entry = result.scalar_one()
    assert entry.details["automatic"] is True and entry.actor.endswith("(AI assistant, automatic)")


# --- Several machines --------------------------------------------------------


async def _propose_on_three(
    db_session_factory: Any, monkeypatch: Any, tool: str = "run_ssh_command"
) -> tuple[uuid.UUID, uuid.UUID, list[dict[str, Any]], list[uuid.UUID]]:
    _user, conversation_id = await _conversation(db_session_factory)
    ids = [await create_machine(db_session_factory, name) for name in ("a1", "b2", "c3")]
    arguments: dict[str, Any] = {"target_type": "machines", "target_name": "a1, B2,c3"}
    if tool == "run_ssh_command":
        arguments["command"] = "cat /etc/os-release"
    install_fake_client(monkeypatch, [tool_turn(tool, arguments), text_turn("Proposed.")])
    await ai_jobs._run_turn(str(conversation_id), "check all three", allow_tools=True)
    message_id, actions = await pending_actions_of(db_session_factory, conversation_id)
    assert message_id is not None
    return conversation_id, message_id, actions, ids


async def test_one_proposal_can_name_several_machines(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    _cid, _mid, actions, _ids = await _propose_on_three(db_session_factory, monkeypatch)
    assert actions[0]["status"] == "pending"
    assert actions[0]["machine_names"] == ["a1", "b2", "c3"]
    assert actions[0]["summary"] == "Run a shell command on 3 machines"


async def test_confirming_on_some_machines_skips_the_others(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    conversation_id, message_id, _actions, ids = await _propose_on_three(
        db_session_factory, monkeypatch
    )
    page = await client.get(f"/ai/conversations/{conversation_id}")
    assert page.text.count('name="machine_id"') == 3
    csrf_token = client.cookies.get("csrftoken")
    url = f"/ai/conversations/{conversation_id}/messages/{message_id}/confirm"

    nothing = await client.post(
        url, data={"csrf_token": csrf_token, "action_index": "0", "machines_selectable": "true"}
    )
    assert "error=" in nothing.headers["location"]
    assert celery_calls.names == []

    await client.post(
        url,
        data={
            "csrf_token": csrf_token,
            "action_index": "0",
            "machines_selectable": "true",
            "machine_id": [str(ids[0]), str(ids[2])],
        },
    )
    _mid, actions = await pending_actions_of(db_session_factory, conversation_id)
    assert {r["machine_name"]: r["status"] for r in actions[0]["results"]} == {
        "a1": "running",
        "b2": "skipped",
        "c3": "running",
    }

    async def fake_ssh(machine_id: str, command: str) -> dict[str, Any]:
        if machine_id == str(ids[2]):
            return {"ok": False, "error": "Connection refused"}
        return {"ok": True, "exit_status": 0, "output": "ID=debian"}

    monkeypatch.setattr(jobs, "_run_remote_ssh_command", fake_ssh)
    fake = install_fake_client(monkeypatch, [text_turn("a1 is Debian; c3 is unreachable.")])
    await ai_jobs._execute_ai_actions(str(conversation_id), str(message_id), [0])

    _mid, actions = await pending_actions_of(db_session_factory, conversation_id)
    results = {r["machine_name"]: r for r in actions[0]["results"]}
    assert results["a1"]["status"] == "ok" and results["c3"]["status"] == "failed"
    assert results["c3"]["error"] == "Connection refused"
    assert results["b2"]["status"] == "skipped"
    summary_input = fake.calls[0]["messages"][-1]["content"]
    assert "a1" in summary_input and "c3" in summary_input and "b2" not in summary_input

    panel = await client.get(f"/ai/conversations/{conversation_id}/messages-panel")
    # Problems first in the result table.
    assert panel.text.index("<code>c3</code>") < panel.text.index("<code>a1</code>")


async def test_confirm_all_starts_every_pending_proposal(
    client, db_session_factory, use_test_db, monkeypatch, celery_calls
):
    _user, conversation_id = await _conversation(db_session_factory)
    await create_machine(db_session_factory, "web1")
    install_fake_client(
        monkeypatch,
        [
            tool_turn("check_updates", {"target_type": "machine", "target_name": "web1"}),
            tool_turn(
                "run_ssh_command",
                {"target_type": "machine", "target_name": "web1", "command": "df -h"},
            ),
            text_turn("Two things to confirm."),
        ],
    )
    await ai_jobs._run_turn(str(conversation_id), "check web1", allow_tools=True)
    message_id, _actions = await pending_actions_of(db_session_factory, conversation_id)

    page = await client.get(f"/ai/conversations/{conversation_id}")
    assert "/confirm-all" in page.text
    csrf_token = client.cookies.get("csrftoken")
    response = await client.post(
        f"/ai/conversations/{conversation_id}/messages/{message_id}/confirm-all",
        data={"csrf_token": csrf_token},
    )
    assert response.status_code == 303

    _mid, actions = await pending_actions_of(db_session_factory, conversation_id)
    assert [a["status"] for a in actions] == ["confirmed", "running"]
    assert "app.tasks.jobs.check_machine_updates" in celery_calls.names
    assert "app.tasks.ai_jobs.execute_ai_actions" in celery_calls.names

    # Twice is a no-op.
    celery_calls.clear()
    await client.post(
        f"/ai/conversations/{conversation_id}/messages/{message_id}/confirm-all",
        data={"csrf_token": csrf_token},
    )
    assert celery_calls.names == []


async def test_discard_all(client, db_session_factory, use_test_db, monkeypatch, celery_calls):
    conversation_id, message_id, _actions, _ids = await _propose_on_three(
        db_session_factory, monkeypatch, tool="reboot"
    )
    await client.get(f"/ai/conversations/{conversation_id}")
    csrf_token = client.cookies.get("csrftoken")
    await client.post(
        f"/ai/conversations/{conversation_id}/messages/{message_id}/discard-all",
        data={"csrf_token": csrf_token},
    )
    _mid, actions = await pending_actions_of(db_session_factory, conversation_id)
    assert actions[0]["status"] == "discarded"
    assert celery_calls.names == []


def test_a_run_that_never_finished_stops_polling() -> None:
    old = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    fresh = datetime.now(UTC).isoformat()
    assert ai_actions.is_stale({"status": "running", "started_at": old})
    assert not ai_actions.is_stale({"status": "running", "started_at": fresh})
    assert not ai_actions.is_stale({"status": "confirmed", "started_at": old})


async def test_assistant_replies_render_markdown_safely(
    client, db_session_factory, use_test_db, monkeypatch
):
    _user, conversation_id = await _conversation(db_session_factory)
    install_fake_client(
        monkeypatch, [text_turn("**Done.** <script>alert(1)</script>\n\n- one\n- two")]
    )
    await ai_jobs._run_turn(str(conversation_id), "hi", allow_tools=True)
    page = await client.get(f"/ai/conversations/{conversation_id}")
    assert "<strong>Done.</strong>" in page.text and "<li>one</li>" in page.text
    assert "<script>alert(1)</script>" not in page.text


# --- Fix with AI on a security finding --------------------------------------


async def _audited_machine(db_session_factory: Any) -> uuid.UUID:
    machine_id = await create_machine(db_session_factory, "web1")
    async with db_session_factory() as db:
        db.add(
            SecurityAudit(
                machine_id=machine_id,
                status=SecurityAuditStatus.SUCCEEDED,
                lynis_version="3.1.6",
                hardening_index=61,
                warnings=[
                    {"test": "SSH-7408", "text": "Root login", "detail": "PermitRootLogin",
                     "solution": "Set PermitRootLogin to no"}
                ],
                suggestions=[],
                details=[
                    {"test": "SSH-7408", "service": "sshd", "desc": "", "field": "PermitRootLogin",
                     "prefval": "NO", "value": "YES"}
                ],
                checks=[{"id": "firewall", "status": "fail", "value": "none"}],
                run_log="debcontrol 0.139.0 security audit of web1\n== Lynis log ==\nline\n",
                started_at=datetime(2026, 11, 21, 20, 0, tzinfo=UTC),
                finished_at=datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
        )
        await db.commit()
    return machine_id


async def test_fix_with_ai_starts_a_conversation_about_the_finding(
    client, db_session_factory, celery_calls
):
    machine_id = await _audited_machine(db_session_factory)
    await setup_provider(db_session_factory)
    page = await client.get(f"/machines/{machine_id}/security")
    assert 'value="security_finding"' in page.text
    csrf_token = client.cookies.get("csrftoken")
    lynis_key = security_audit.finding_key(
        security_audit.LYNIS,
        {"test": "SSH-7408", "text": "Root login", "detail": "PermitRootLogin"},
    )

    response = await client.post(
        "/ai/explain",
        data={
            "kind": "security_finding",
            "machine_id": str(machine_id),
            "key": lynis_key,
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303
    conversation = await client.get(response.headers["location"])
    assert "https://cisofy.com/lynis/controls/SSH-7408/" in conversation.text
    assert "Set PermitRootLogin to no" in conversation.text
    assert "current `YES`, recommended `NO`" in conversation.text

    check = await client.post(
        "/ai/explain",
        data={
            "kind": "security_finding",
            "machine_id": str(machine_id),
            "key": "check:firewall",
            "csrf_token": csrf_token,
        },
    )
    conversation = await client.get(check.headers["location"])
    assert "vps-audit" in conversation.text and "firewall" in conversation.text

    missing = await client.post(
        "/ai/explain",
        data={
            "kind": "security_finding",
            "machine_id": str(machine_id),
            "key": "check:ssh_port",
            "csrf_token": csrf_token,
        },
    )
    assert missing.status_code == 404
    bad = await client.post(
        "/ai/explain",
        data={
            "kind": "security_finding",
            "machine_id": str(machine_id),
            "key": "nonsense",
            "csrf_token": csrf_token,
        },
    )
    assert bad.status_code == 400


# --- The security audit's run log -------------------------------------------


async def test_the_run_log_can_be_downloaded(client, db_session_factory):
    machine_id = await _audited_machine(db_session_factory)
    page = await client.get(f"/machines/{machine_id}/security")
    async with db_session_factory() as db:
        audit_id = (await db.execute(select(SecurityAudit.id))).scalar_one()
    assert f"/security/audits/{audit_id}/log" in page.text

    response = await client.get(f"/machines/{machine_id}/security/audits/{audit_id}/log")
    assert response.status_code == 200
    assert "== Lynis log ==" in response.text
    assert "security-audit-web1-20261121-2000.log" in response.headers["content-disposition"]
    missing = await client.get(f"/machines/{machine_id}/security/audits/{uuid.uuid4()}/log")
    assert missing.status_code == 404

    headers = await _api_token(client)
    api = await client.get(
        f"/api/v1/machines/{machine_id}/security-audits/{audit_id}/log", headers=headers
    )
    assert api.status_code == 200 and "== Lynis log ==" in api.text


def test_the_script_keeps_the_lynis_log_in_var_log_emptied_each_run() -> None:
    command = lynis.build_audit_command()
    subprocess.run(["sh", "-n", "-c", command], check=True)  # noqa: S603, S607
    assert f"G={lynis.MACHINE_LOGFILE}" in command and ': > "$G"' in command
    assert '--logfile "$G"' in command and "--no-log" not in command
    onboarding = build_onboarding_command("ssh-ed25519 AAAA test")
    assert f"/dev/null {lynis.MACHINE_LOGFILE}" in onboarding


def test_the_output_is_split_into_report_console_and_log() -> None:
    text = (
        "+ apt-get update\nHit:1 http://deb.debian.org\n"
        f"{lynis.PRIVILEGED_MARKER}\nLynis 3.1.6 running\n{lynis.EXIT_MARKER}0\n"
        f"{lynis.REPORT_DELIMITER}\nhardening_index=70\n"
        f"{lynis.OUTPUT_DELIMITER}\n"
        f"{lynis.LOGFILE_DELIMITER}\n2026-11-21 Starting Lynis\n"
    )
    result = parse_audit_output(text)
    assert result.hardening_index == 70 and result.privileged is True
    assert "Hit:1" in result.console and "Lynis 3.1.6 running" in result.console
    assert result.logfile == "2026-11-21 Starting Lynis"
    assert result.output == ""


async def test_the_job_keeps_a_log_also_when_the_run_times_out(
    db_session_factory: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    machine_id = await create_machine(db_session_factory, "slow1")
    async with db_session_factory() as db:
        audit = SecurityAudit(machine_id=machine_id, created_at=datetime.now(UTC))
        db.add(audit)
        await db.commit()

    async def fake_run(machine: Any, secret: Any, **_kw: Any) -> LynisResult:
        raise AuditRunError(
            "Security audit failed on slow1: it did not finish within 1200 seconds",
            partial_log="+ apt-get update\nLynis 3.1.6 halfway",
        )

    monkeypatch.setattr(jobs, "run_lynis_audit", fake_run)
    await jobs._run_security_audit(str(audit.id))

    async with db_session_factory() as db:
        found = await security_audit.get_run_log(db, machine_id, audit.id)
    assert found is not None
    stored, log = found
    assert stored.status == SecurityAuditStatus.FAILED
    assert "did not finish within 1200 seconds" in (stored.error or "")
    assert "Lynis 3.1.6 halfway" in log and "outcome:  Security audit failed" in log
