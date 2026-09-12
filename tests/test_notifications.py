"""Tests for Notifications: rules, role-based targeting, templates, and
the dispatch/send logic in `app.services.notifications`."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import encrypt_secret
from app.db.models.app_settings import AppSettings, SmtpEncryption
from app.db.models.machine import AuthMethod, Machine
from app.db.models.notification_rule import (
    NotificationCustomTemplate,
    NotificationEventType,
    NotificationRule,
    NotificationTemplate,
)
from app.db.models.role import Role
from app.db.models.user import User
from app.services.notifications import default_template, notify, render_template


async def _make_role(db: AsyncSession, name: str) -> Role:
    role = Role(name=name)
    db.add(role)
    await db.flush()
    return role


def _smtp_ready_settings() -> AppSettings:
    return AppSettings(
        id=1,
        smtp_enabled=True,
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_encryption=SmtpEncryption.STARTTLS,
        smtp_username="relay@example.com",
        smtp_password_encrypted=encrypt_secret("s3cret"),
        smtp_from_address="debcontrol@example.com",
        smtp_from_name="debcontrol",
    )


async def test_list_notifications_renders(client):
    response = await client.get("/notifications")
    assert response.status_code == 200
    assert "Notifications" in response.text


async def test_new_rule_form_lists_custom_templates_and_empty_conditions_hint(
    client, db_session_factory
):
    async with db_session_factory() as db:
        db.add(NotificationCustomTemplate(name="Weekend on-call", subject="s", body="b"))
        await db.commit()

    response = await client.get("/notifications/rules/new")
    assert response.status_code == 200
    assert "Weekend on-call" in response.text
    # A brand new rule starts with zero condition rows (no more pre-filled
    # blank rows) — the "add a condition" empty-state hint should show.
    assert "No conditions yet" in response.text


async def test_create_rule_persists_recipients_and_scope(client, db_session_factory):
    async with db_session_factory() as db:
        role = await _make_role(db, "role-alice")
        user = User(username="alice", auth_provider="local", email="alice@example.com", role=role)
        db.add(user)
        machine = Machine(
            name="db1",
            ip_address="10.0.0.5",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
        )
        db.add(machine)
        await db.commit()
        await db.refresh(user)
        await db.refresh(machine)
        user_id, machine_id = user.id, machine.id

    await client.get("/notifications/rules/new")
    csrf_token = client.cookies.get("csrftoken")

    missing_events = await client.post(
        "/notifications/rules",
        data={
            "name": "db1 down",
            "csrf_token": csrf_token,
        },
    )
    assert "Choose at least one event" in missing_events.text

    response = await client.post(
        "/notifications/rules",
        data={
            "name": "db1 down",
            "description": "Alert on db1 going unreachable",
            "enabled": "1",
            "event_types": [NotificationEventType.MACHINE_UNREACHABLE.value],
            "user_ids": [str(user_id)],
            "machine_ids": [str(machine_id)],
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        rule = (await db.execute(select(NotificationRule))).scalar_one()
        assert rule.name == "db1 down"
        assert rule.event_types == [NotificationEventType.MACHINE_UNREACHABLE.value]
        assert [u.id for u in rule.users] == [user_id]
        assert [m.id for m in rule.machines] == [machine_id]

    log = await client.get("/audit")
    assert "notification_rule.create" in log.text


async def test_create_rule_targeting_a_role(client, db_session_factory):
    async with db_session_factory() as db:
        role = await _make_role(db, "role-oncall-team")
        db.add(role)
        await db.commit()
        await db.refresh(role)
        role_id = role.id

    await client.get("/notifications/rules/new")
    csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        "/notifications/rules",
        data={
            "name": "role-targeted rule",
            "event_types": [NotificationEventType.MACHINE_UNREACHABLE.value],
            "role_ids": [str(role_id)],
            "csrf_token": csrf_token,
        },
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        rule = (await db.execute(select(NotificationRule))).scalar_one()
        assert [r.id for r in rule.roles] == [role_id]


async def test_create_and_select_custom_template(client, db_session_factory):
    csrf_token = client.cookies.get("csrftoken")
    if csrf_token is None:
        await client.get("/notifications")
        csrf_token = client.cookies.get("csrftoken")

    create = await client.post(
        "/notifications/templates/custom",
        data={
            "name": "Urgent CPU alert",
            "subject": "URGENT: {machine_name} is on fire",
            "body": "{machine_name} tripped a condition: {details}",
            "csrf_token": csrf_token,
        },
    )
    assert create.status_code == 303

    async with db_session_factory() as db:
        template = (await db.execute(select(NotificationCustomTemplate))).scalar_one()
        assert template.name == "Urgent CPU alert"
        template_id = template.id

    # Duplicate name is rejected, not silently overwritten.
    dupe = await client.post(
        "/notifications/templates/custom",
        data={
            "name": "Urgent CPU alert",
            "subject": "x",
            "body": "y",
            "csrf_token": csrf_token,
        },
    )
    assert dupe.status_code == 409

    templates_page = await client.get("/notifications/templates")
    assert "Urgent CPU alert" in templates_page.text

    rule_response = await client.post(
        "/notifications/rules",
        data={
            "name": "cpu rule",
            "event_types": [NotificationEventType.MACHINE_UNREACHABLE.value],
            "custom_template_id": str(template_id),
            "csrf_token": csrf_token,
        },
    )
    assert rule_response.status_code == 303

    async with db_session_factory() as db:
        rule = (await db.execute(select(NotificationRule))).scalar_one()
        assert rule.custom_template_id == template_id

    edit_page = await client.get(f"/notifications/rules/{rule.id}/edit")
    assert f'value="{template_id}" selected' in edit_page.text


async def test_deleting_custom_template_clears_rule_reference(client, db_session_factory):
    async with db_session_factory() as db:
        template = NotificationCustomTemplate(name="Temp", subject="s", body="b")
        db.add(template)
        await db.flush()
        rule = NotificationRule(
            name="uses temp template",
            enabled=True,
            event_types=[NotificationEventType.MACHINE_UNREACHABLE.value],
            custom_template_id=template.id,
        )
        db.add(rule)
        await db.commit()
        rule_id, template_id = rule.id, template.id

    csrf_token = client.cookies.get("csrftoken")
    if csrf_token is None:
        await client.get("/notifications")
        csrf_token = client.cookies.get("csrftoken")

    response = await client.post(
        f"/notifications/templates/custom/{template_id}/delete",
        data={"csrf_token": csrf_token},
    )
    assert response.status_code == 303

    async with db_session_factory() as db:
        refreshed = await db.get(NotificationRule, rule_id)
        assert refreshed is not None
        assert refreshed.custom_template_id is None


async def test_notify_uses_rules_own_custom_template(db_session_factory, monkeypatch):
    sent: list[tuple[str, str]] = []

    def _fake_send(app_settings, to_address, subject, body):  # noqa: ANN001 - test double
        sent.append((subject, body))

    import app.services.notifications as notifications_module

    monkeypatch.setattr(notifications_module, "_send_smtp_message", _fake_send)

    async with db_session_factory() as db:
        db.add(_smtp_ready_settings())
        role = await _make_role(db, "role-custom-template")
        recipient = User(
            username="templated", auth_provider="local", email="templated@example.com", role=role
        )
        machine = Machine(
            name="web9",
            ip_address="10.0.0.20",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
        )
        db.add_all([recipient, machine])
        await db.flush()

        custom = NotificationCustomTemplate(
            name="Custom unreachable",
            subject="Custom subject for {machine_name}",
            body="Custom body",
        )
        db.add(custom)
        await db.flush()

        rule = NotificationRule(
            name="uses custom template",
            enabled=True,
            event_types=[NotificationEventType.MACHINE_UNREACHABLE.value],
            custom_template_id=custom.id,
        )
        rule.roles = [role]
        db.add(rule)
        await db.commit()

        await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=machine)

    assert len(sent) == 1
    subject, body = sent[0]
    assert subject == "Custom subject for web9"
    assert body == "Custom body"


async def test_template_default_then_override_then_reset(client, db_session_factory):
    response = await client.get("/notifications/templates")
    assert response.status_code == 200
    assert "default" in response.text

    edit_page = await client.get(
        f"/notifications/templates/{NotificationEventType.MACHINE_UNREACHABLE.value}/edit"
    )
    assert edit_page.status_code == 200
    csrf_token = client.cookies.get("csrftoken")

    update = await client.post(
        f"/notifications/templates/{NotificationEventType.MACHINE_UNREACHABLE.value}/edit",
        data={
            "subject": "Custom subject {machine_name}",
            "body": "Custom body",
            "csrf_token": csrf_token,
        },
    )
    assert update.status_code == 303

    async with db_session_factory() as db:
        template = (
            await db.execute(select(NotificationTemplate))
        ).scalar_one()
        assert template.subject == "Custom subject {machine_name}"

    reset = await client.post(
        f"/notifications/templates/{NotificationEventType.MACHINE_UNREACHABLE.value}/reset",
        data={"csrf_token": csrf_token},
    )
    assert reset.status_code == 303

    async with db_session_factory() as db:
        remaining = (
            await db.execute(select(NotificationTemplate))
        ).scalars().all()
        assert remaining == []


def test_default_template_is_localized():
    en_subject, _ = default_template(NotificationEventType.MACHINE_UNREACHABLE, "en")
    cs_subject, _ = default_template(NotificationEventType.MACHINE_UNREACHABLE, "cs")
    assert "unreachable" in en_subject
    assert "nedostupný" in cs_subject
    # Unknown locale falls back to English rather than raising.
    assert default_template(NotificationEventType.MACHINE_UNREACHABLE, "xx") == (
        en_subject,
        default_template(NotificationEventType.MACHINE_UNREACHABLE, "en")[1],
    )


def test_render_template_leaves_unknown_placeholder_literal():
    subject, body = render_template(
        NotificationEventType.MACHINE_UNREACHABLE,
        None,
        {"machine_name": "db1", "machine_ip": "10.0.0.5", "timestamp": "now", "details": ""},
    )
    assert "db1" in subject
    assert "10.0.0.5" in body


async def test_notify_sends_to_matching_recipients_only(db_session_factory, monkeypatch):
    sent: list[tuple[str, str, str]] = []

    def _fake_send(app_settings, to_address, subject, body):  # noqa: ANN001 - test double
        sent.append((to_address, subject, body))

    import app.services.notifications as notifications_module

    monkeypatch.setattr(notifications_module, "_send_smtp_message", _fake_send)

    async with db_session_factory() as db:
        db.add(_smtp_ready_settings())

        in_scope = Machine(
            name="web1",
            ip_address="10.0.0.10",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
        )
        out_of_scope = Machine(
            name="web2",
            ip_address="10.0.0.11",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
        )
        role1 = await _make_role(db, "role-oncall")
        role2 = await _make_role(db, "role-noemail")
        recipient = User(
            username="oncall", auth_provider="local", email="oncall@example.com", role=role1
        )
        no_email_user = User(username="noemail", auth_provider="local", role=role2)
        db.add_all([in_scope, out_of_scope, recipient, no_email_user])
        await db.flush()

        rule = NotificationRule(
            name="web1 unreachable",
            enabled=True,
            event_types=[NotificationEventType.MACHINE_UNREACHABLE.value],
        )
        rule.users = [recipient]
        # role2's only member has no usable email — deliberately dropped.
        rule.roles = [role2]
        rule.machines = [in_scope]
        db.add(rule)
        await db.commit()

        # Matches: event + in-scope machine.
        await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=in_scope)
        # Doesn't match: right event, wrong machine (out of this rule's scope).
        await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=out_of_scope)
        # Doesn't match: right machine, wrong event.
        await notify(db, NotificationEventType.UPDATE_RUN_FAILED, machine=in_scope)

    assert len(sent) == 1
    to_address, subject, body = sent[0]
    assert to_address == "oncall@example.com"
    assert "web1" in subject


async def test_notify_is_noop_when_smtp_disabled(db_session_factory, monkeypatch):
    sent: list[object] = []
    import app.services.notifications as notifications_module

    monkeypatch.setattr(
        notifications_module, "_send_smtp_message", lambda *a, **k: sent.append(1)
    )

    async with db_session_factory() as db:
        # No AppSettings row at all — get_or_create_app_settings makes one
        # with smtp_enabled defaulting to False.
        machine = Machine(
            name="db2",
            ip_address="10.0.0.20",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
        )
        role = await _make_role(db, "role-carol")
        recipient = User(
            username="carol", auth_provider="local", email="carol@example.com", role=role
        )
        db.add_all([machine, recipient])
        await db.flush()
        rule = NotificationRule(
            name="db2 unreachable",
            enabled=True,
            event_types=[NotificationEventType.MACHINE_UNREACHABLE.value],
        )
        rule.users = [recipient]
        db.add(rule)
        await db.commit()

        await notify(db, NotificationEventType.MACHINE_UNREACHABLE, machine=machine)

    assert sent == []
