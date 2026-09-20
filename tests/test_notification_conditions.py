"""Condition-based notification rules — the field registry
(`app.services.condition_fields`) and the evaluation sweep
(`app.tasks.jobs._evaluate_notification_conditions`)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import encrypt_secret
from app.db.models.app_settings import AppSettings, SmtpEncryption
from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.notification_condition import NotificationCondition
from app.db.models.notification_rule import NotificationEventType, NotificationRule
from app.db.models.role import Role
from app.db.models.user import User
from app.services.condition_fields import evaluate_condition
from app.tasks.jobs import _evaluate_notification_conditions


def _machine(**overrides: object) -> Machine:
    defaults: dict[str, object] = {
        "name": "db1",
        "ip_address": "10.0.0.5",
        "port": 22,
        "username": "root",
        "auth_method": AuthMethod.PASSWORD,
    }
    defaults.update(overrides)
    return Machine(**defaults)


# --- Field registry ---------------------------------------------------------


def test_evaluate_condition_cpu_percent_gt():
    machine = _machine()
    sample = MachineMonitoringSample(cpu_percent=95.0)
    assert evaluate_condition("monitoring.cpu_percent", "gt", "90", machine, sample, None) is True
    assert evaluate_condition("monitoring.cpu_percent", "gt", "99", machine, sample, None) is False


def test_evaluate_condition_no_sample_never_matches():
    machine = _machine()
    assert evaluate_condition("monitoring.cpu_percent", "gt", "0", machine, None, None) is False


def test_evaluate_condition_ram_percent_is_computed():
    machine = _machine()
    sample = MachineMonitoringSample(ram_used_bytes=90, ram_total_bytes=100)
    assert evaluate_condition("monitoring.ram_percent", "gte", "90", machine, sample, None) is True


def test_evaluate_condition_filesystem_needs_matching_mount():
    machine = _machine()
    sample = MachineMonitoringSample(
        filesystems=[{"mount": "/", "use_percent": 40}, {"mount": "/var", "use_percent": 92}]
    )
    assert (
        evaluate_condition(
            "monitoring.filesystem_use_percent", "gt", "85", machine, sample, "/var"
        )
        is True
    )
    assert (
        evaluate_condition("monitoring.filesystem_use_percent", "gt", "85", machine, sample, "/")
        is False
    )


def test_evaluate_condition_os_id_string_equality():
    machine = _machine(os_id="debian")
    assert evaluate_condition("machine.os_id", "eq", "debian", machine, None, None) is True
    assert evaluate_condition("machine.os_id", "ne", "debian", machine, None, None) is False


def test_evaluate_condition_unknown_field_or_operator_never_matches():
    machine = _machine()
    sample = MachineMonitoringSample(cpu_percent=99.0)
    assert evaluate_condition("nope.nope", "gt", "1", machine, sample, None) is False
    assert (
        evaluate_condition("monitoring.cpu_percent", "contains", "9", machine, sample, None)
        is False
    )


# --- Evaluation sweep --------------------------------------------------------


async def _make_recipient(db: AsyncSession) -> None:
    role = Role(name="ops")
    db.add(role)
    await db.flush()
    db.add(User(username="alice", auth_provider="local", email="alice@example.com", role=role))


async def test_condition_matched_fires_once_then_not_again(db_session_factory, monkeypatch):
    sent: list[tuple[str, str, str]] = []
    import app.services.notifications as notifications_module

    monkeypatch.setattr(
        notifications_module, "_send_smtp_message", lambda *a, **k: sent.append(a[1:])
    )
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

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
        machine = _machine()
        db.add(machine)
        await db.flush()

        rule = NotificationRule(
            name="High CPU",
            enabled=True,
            event_types=[NotificationEventType.CONDITION_MATCHED.value],
            conditions=[
                NotificationCondition(field="monitoring.cpu_percent", operator="gt", value="90")
            ],
        )
        rule.users = list((await db.execute(select(User))).scalars())
        db.add(rule)
        db.add(
            MachineMonitoringSample(
                machine_id=machine.id, sampled_at=datetime.now(UTC), cpu_percent=95.0
            )
        )
        await db.commit()

    await _evaluate_notification_conditions()
    assert len(sent) == 1
    assert sent[0][0] == "alice@example.com"

    # Second tick, still matching — must NOT re-fire.
    await _evaluate_notification_conditions()
    assert len(sent) == 1


async def test_condition_not_matched_never_notifies(db_session_factory, monkeypatch):
    sent: list[object] = []
    import app.services.notifications as notifications_module

    monkeypatch.setattr(notifications_module, "_send_smtp_message", lambda *a, **k: sent.append(1))
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

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
        machine = _machine()
        db.add(machine)
        await db.flush()
        rule = NotificationRule(
            name="High CPU",
            enabled=True,
            event_types=[NotificationEventType.CONDITION_MATCHED.value],
            conditions=[
                NotificationCondition(field="monitoring.cpu_percent", operator="gt", value="90")
            ],
        )
        rule.users = list((await db.execute(select(User))).scalars())
        db.add(rule)
        db.add(
            MachineMonitoringSample(
                machine_id=machine.id, sampled_at=datetime.now(UTC), cpu_percent=10.0
            )
        )
        await db.commit()

    await _evaluate_notification_conditions()
    assert sent == []


async def test_condition_re_fires_after_a_false_true_cycle(db_session_factory, monkeypatch):
    sent: list[object] = []
    import app.services.notifications as notifications_module

    monkeypatch.setattr(notifications_module, "_send_smtp_message", lambda *a, **k: sent.append(1))
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)

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
        machine = _machine()
        db.add(machine)
        await db.flush()
        rule = NotificationRule(
            name="High CPU",
            enabled=True,
            event_types=[NotificationEventType.CONDITION_MATCHED.value],
            conditions=[
                NotificationCondition(field="monitoring.cpu_percent", operator="gt", value="90")
            ],
        )
        rule.users = list((await db.execute(select(User))).scalars())
        db.add(rule)
        db.add(
            MachineMonitoringSample(
                machine_id=machine.id, sampled_at=datetime.now(UTC), cpu_percent=95.0
            )
        )
        await db.commit()

    await _evaluate_notification_conditions()
    assert len(sent) == 1

    # Drops back below the threshold — no new notification, but the
    # per-rule/machine state resets so a later re-cross fires again.
    async with db_session_factory() as db:
        result = await db.execute(select(MachineMonitoringSample))
        sample = result.scalar_one()
        sample.cpu_percent = 10.0
        await db.commit()
    await _evaluate_notification_conditions()
    assert len(sent) == 1

    async with db_session_factory() as db:
        result = await db.execute(select(MachineMonitoringSample))
        sample = result.scalar_one()
        sample.cpu_percent = 95.0
        await db.commit()
    await _evaluate_notification_conditions()
    assert len(sent) == 2
