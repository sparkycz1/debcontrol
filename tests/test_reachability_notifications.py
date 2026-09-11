"""`app.tasks.jobs._check_machine_reachability_now` fires a Notifications
event on an actual reachability *transition* — never on a tick that just
confirms the same state, and never on a machine's first-ever check (no
prior state to transition from). See `app.services.notifications`'s module
docstring for the full list of call sites."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import encrypt_secret
from app.db.models.app_settings import AppSettings, SmtpEncryption
from app.db.models.machine import AuthMethod, Machine
from app.db.models.notification_rule import NotificationEventType, NotificationRule
from app.db.models.role import Role
from app.db.models.user import User
from app.ssh.reachability import ReachabilityResult
from app.tasks.jobs import _check_machine_reachability_now


async def _make_recipient(db: AsyncSession) -> None:
    role = Role(name="role-recipient")
    db.add(role)
    await db.flush()
    db.add(User(username="oncall", auth_provider="local", email="oncall@example.com", role=role))


async def test_first_ever_check_does_not_notify(db_session_factory, monkeypatch):
    sent: list[object] = []
    import app.services.notifications as notifications_module

    monkeypatch.setattr(
        notifications_module, "_send_smtp_message", lambda *a, **k: sent.append(1)
    )
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    async def _fake_check_reachable(*a, **k):
        return ReachabilityResult(reachable=False, latency_ms=None)

    monkeypatch.setattr("app.tasks.jobs.check_reachable", _fake_check_reachable)

    async with db_session_factory() as db:
        db.add(
            AppSettings(
                id=1,
                smtp_enabled=True,
                smtp_host="smtp.example.com",
                smtp_encryption=SmtpEncryption.STARTTLS,
                smtp_password_encrypted=encrypt_secret("x"),
            )
        )
        await _make_recipient(db)
        machine = Machine(
            name="new1",
            ip_address="10.0.0.30",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
        )
        db.add(machine)
        await db.flush()
        rule = NotificationRule(
            name="new1 unreachable",
            enabled=True,
            event_types=[NotificationEventType.MACHINE_UNREACHABLE.value],
        )
        rule.users = list((await db.execute(select(User))).scalars())
        db.add(rule)
        machine_id = machine.id
        await db.commit()

    await _check_machine_reachability_now(str(machine_id))
    assert sent == []


async def test_transition_to_unreachable_notifies(db_session_factory, monkeypatch):
    sent: list[tuple[str, str, str]] = []
    import app.services.notifications as notifications_module

    def _fake_send(app_settings, to_address, subject, body):  # noqa: ANN001 - test double
        sent.append((to_address, subject, body))

    monkeypatch.setattr(notifications_module, "_send_smtp_message", _fake_send)
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

    async def _fake_check_reachable(*a, **k):
        return ReachabilityResult(reachable=False, latency_ms=None)

    monkeypatch.setattr("app.tasks.jobs.check_reachable", _fake_check_reachable)

    async with db_session_factory() as db:
        db.add(
            AppSettings(
                id=1,
                smtp_enabled=True,
                smtp_host="smtp.example.com",
                smtp_encryption=SmtpEncryption.STARTTLS,
                smtp_password_encrypted=encrypt_secret("x"),
            )
        )
        await _make_recipient(db)
        machine = Machine(
            name="flappy1",
            ip_address="10.0.0.31",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            is_reachable=True,  # was reachable — this check finds it isn't anymore
        )
        db.add(machine)
        await db.flush()
        rule = NotificationRule(
            name="flappy1 unreachable",
            enabled=True,
            event_types=[NotificationEventType.MACHINE_UNREACHABLE.value],
        )
        rule.users = list((await db.execute(select(User))).scalars())
        db.add(rule)
        machine_id = machine.id
        await db.commit()

    await _check_machine_reachability_now(str(machine_id))
    assert len(sent) == 1
    assert sent[0][0] == "oncall@example.com"
