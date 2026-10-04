"""Saving notification rules and custom templates — shared by the web UI
(`app/web/routes/notifications.py`: the rule form, YAML import/export) and
the REST API (`app/web/routes/api_v1_notifications.py`), so both doors
validate and persist a rule through exactly the same code.

The **portable rule shape** (`rule_to_portable_dict`) is what the YAML
export produces and what both YAML import and the API accept: natural keys
(recipient email/role name, machine name, group name, custom template
name) rather than database ids, so a rule can be reviewed,
version-controlled and moved between instances. See wiki/Notifications
for the full shape and an example.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import encrypt_secret
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.notification_condition import NotificationCondition
from app.db.models.notification_rule import (
    NotificationCustomTemplate,
    NotificationEventType,
    NotificationRule,
)
from app.db.models.role import Role
from app.db.models.user import User
from app.schemas.notification import NotificationConditionCreate, NotificationRuleCreate
from app.services.push_channels import (
    CHANNEL_NAMES,
    OPTIONAL_TOKEN_CHANNELS,
    TOKEN_CHANNELS,
    redact_url,
)


def build_conditions_and_event_types(
    event_types: list[str],
    raw_conditions: list[dict[str, Any]],
) -> tuple[list[str], list[NotificationConditionCreate]]:
    """Validates `raw_conditions` against the field registry and, if any
    survive, adds `CONDITION_MATCHED` to `event_types` automatically — a
    rule with conditions is always dispatched through the same
    `notify()`/`_matching_rules` path as an event-type rule (see
    `NotificationEventType.CONDITION_MATCHED`'s docstring), so the admin
    never has to remember to check that box themselves. Raises `ValueError`
    (surfaced as a form error) on the first invalid condition."""
    conditions: list[NotificationConditionCreate] = []
    for raw in raw_conditions:
        try:
            conditions.append(NotificationConditionCreate(**raw))
        except Exception as exc:
            raise ValueError(f'Invalid condition "{raw.get("field")}": {exc}') from exc
    updated_event_types = list(event_types)
    if conditions and NotificationEventType.CONDITION_MATCHED.value not in updated_event_types:
        updated_event_types.append(NotificationEventType.CONDITION_MATCHED.value)
    return updated_event_types, conditions


def rule_to_portable_dict(
    rule: NotificationRule, *, include_secrets: bool = True
) -> dict[str, Any]:
    return {
        "name": rule.name,
        "description": rule.description,
        "enabled": rule.enabled,
        "event_types": [
            e.value for e in rule.event_type_enums if e != NotificationEventType.CONDITION_MATCHED
        ],
        "conditions": [
            {
                "field": c.field,
                "operator": c.operator,
                "value": c.value,
                **({"mount_point": c.mount_point} if c.mount_point else {}),
                **(
                    {"sustained_seconds": c.sustained_seconds}
                    if c.sustained_seconds
                    else {}
                ),
            }
            for c in rule.conditions
        ],
        "recipients": {
            "users": [u.email for u in rule.users if u.email],
            "roles": [r.name for r in rule.roles],
        },
        "scope": {
            "machines": [m.name for m in rule.machines],
            "machine_groups": [g.name for g in rule.machine_groups],
        },
        "delivery_channel": rule.delivery_channel,
        # A webhook URL's path is its secret (Discord/Slack/ntfy) — only an
        # account that could edit the rule anyway gets it back in full.
        **(
            {"webhook_url": rule.webhook_url if include_secrets else redact_url(rule.webhook_url)}
            if rule.webhook_url
            else {}
        ),
        # Never the token itself — an import supplies `channel_token` anew
        # (or keeps the one already stored on a same-named rule).
        **({"channel_recipient": rule.channel_recipient} if rule.channel_recipient else {}),
        **({"template_name": rule.custom_template.name} if rule.custom_template else {}),
        **({"throttle_minutes": rule.throttle_minutes} if rule.throttle_minutes else {}),
    }


async def apply_portable_rule(
    db: AsyncSession, data: Any, *, rule: NotificationRule | None = None
) -> tuple[NotificationRule, bool]:
    """Writes one rule from `rule_to_portable_dict`'s shape. Returns
    `(rule, created)`; the caller commits (and rolls back on error).

    With `rule=None` this is an upsert matched by `name` (YAML import,
    `POST /api/v1/notifications/rules/import`). With an existing `rule` it
    updates that one in place — renaming it if `name` differs — which is
    what `PUT /api/v1/notifications/rules/{id}` needs. A name that collides
    with another rule surfaces as an `IntegrityError` at commit, same as the
    form.

    Raises `ValueError` on anything invalid. A recipient/scope entry that
    matches nothing is dropped rather than rejected, like the form's
    pickers; an unknown `template_name` is an error, since silently falling
    back to the default template would change what gets sent."""
    if not isinstance(data, dict) or not data.get("name"):
        raise ValueError('Each rule needs at least a "name".')
    name = str(data["name"])

    created = False
    if rule is None:
        result = await db.execute(select(NotificationRule).where(NotificationRule.name == name))
        rule = result.scalar_one_or_none()
        if rule is None:
            rule = NotificationRule(name=name)
            created = True

    raw_conditions = [dict(c) for c in (data.get("conditions") or [])]
    event_types = [str(e) for e in (data.get("event_types") or [])]
    try:
        resolved_event_types, conditions = build_conditions_and_event_types(
            event_types, raw_conditions
        )
        payload = NotificationRuleCreate(
            name=name,
            description=data.get("description") or None,
            enabled=bool(data.get("enabled", True)),
            event_types=resolved_event_types,
            delivery_channel=str(data.get("delivery_channel") or "email"),
            webhook_url=(str(data["webhook_url"]) if data.get("webhook_url") else None),
            channel_token=(str(data["channel_token"]) if data.get("channel_token") else None),
            channel_recipient=(
                str(data["channel_recipient"]) if data.get("channel_recipient") else None
            ),
            throttle_minutes=data.get("throttle_minutes") or None,
        )
        apply_channel_settings(rule, payload)
    except ValueError as exc:
        raise ValueError(f'Rule "{name}": {exc}') from exc

    rule.name = payload.name
    rule.description = payload.description
    rule.enabled = payload.enabled
    rule.event_types = payload.event_types

    template_name = data.get("template_name")
    if template_name:
        template_result = await db.execute(
            select(NotificationCustomTemplate).where(
                NotificationCustomTemplate.name == str(template_name)
            )
        )
        custom_template = template_result.scalar_one_or_none()
        if custom_template is None:
            raise ValueError(f'Rule "{name}": no custom template named "{template_name}".')
        rule.custom_template_id = custom_template.id
    else:
        rule.custom_template_id = None

    rule.conditions = [
        NotificationCondition(
            field=c.field,
            operator=c.operator,
            value=c.value,
            mount_point=c.mount_point,
            sustained_seconds=c.sustained_seconds,
        )
        for c in conditions
    ]

    recipients = data.get("recipients") or {}
    emails = [str(e) for e in (recipients.get("users") or [])]
    role_names = [str(r) for r in (recipients.get("roles") or [])]
    if emails:
        user_result = await db.execute(select(User).where(User.email.in_(emails)))
        rule.users = list(user_result.scalars().all())
    else:
        rule.users = []
    if role_names:
        role_result = await db.execute(select(Role).where(Role.name.in_(role_names)))
        rule.roles = list(role_result.scalars().all())
    else:
        rule.roles = []

    scope = data.get("scope") or {}
    machine_names = [str(m) for m in (scope.get("machines") or [])]
    group_names = [str(g) for g in (scope.get("machine_groups") or [])]
    if machine_names:
        machine_result = await db.execute(select(Machine).where(Machine.name.in_(machine_names)))
        rule.machines = list(machine_result.scalars().all())
    else:
        rule.machines = []
    if group_names:
        group_result = await db.execute(
            select(MachineGroup).where(MachineGroup.name.in_(group_names))
        )
        rule.machine_groups = list(group_result.scalars().all())
    else:
        rule.machine_groups = []

    if created:
        db.add(rule)
    return rule, created


async def delete_custom_template(db: AsyncSession, template: NotificationCustomTemplate) -> None:
    """Deletes `template` and commits. Any rule using it falls back to its
    per-event default/override rather than being blocked or broken. Done
    explicitly here (not left to the FK's `ondelete="SET NULL"` alone)
    since that's a database-level action SQLite — the test suite's own
    database (`tests/conftest.py`) — never enforces without an explicit
    `PRAGMA foreign_keys=ON` this app doesn't set; Postgres would apply it
    too, but this keeps behavior identical on both."""
    await db.execute(
        update(NotificationRule)
        .where(NotificationRule.custom_template_id == template.id)
        .values(custom_template_id=None)
    )
    await db.delete(template)
    await db.commit()


def apply_channel_settings(rule: NotificationRule, payload: NotificationRuleCreate) -> None:
    """Delivery settings from a validated payload onto `rule`: the channel,
    its URL and recipient, its throttle window, and — only when a new one was given — its token
    (encrypted; an empty token keeps the stored one, like a password field).
    Raises ValueError when the channel needs a token and none is stored."""
    rule.delivery_channel = payload.delivery_channel
    rule.webhook_url = payload.webhook_url
    rule.channel_recipient = (payload.channel_recipient or "").strip() or None
    rule.throttle_minutes = payload.throttle_minutes
    token = (payload.channel_token or "").strip()
    if token:
        rule.channel_token_encrypted = encrypt_secret(token)
    if payload.delivery_channel not in (TOKEN_CHANNELS | OPTIONAL_TOKEN_CHANNELS):
        rule.channel_token_encrypted = None
    if payload.delivery_channel in TOKEN_CHANNELS and not rule.channel_token_encrypted:
        raise ValueError(f"{CHANNEL_NAMES[payload.delivery_channel]} needs a token.")
