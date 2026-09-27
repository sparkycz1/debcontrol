"""Notifications — rules ("when X happens, tell these people about these
machines") and per-event email templates. See
`app.db.models.notification_rule`'s module docstring for the data model
(recipients are directly-listed users plus every active user holding one
of the rule's target roles — no separate notification-only grouping
concept) and `app.services.notifications` for how a rule actually turns
into a sent email.

The REST equivalent is `app/web/routes/api_v1_notifications.py`; rule
validation/persistence shared by both lives in
`app.services.notification_rules`.
"""

from __future__ import annotations

import uuid
from typing import Any

import yaml
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import get_current_user, require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.notification_condition import NotificationCondition
from app.db.models.notification_log import NotificationDeliveryChannel, NotificationLog
from app.db.models.notification_rule import (
    NotificationCustomTemplate,
    NotificationEventType,
    NotificationRule,
    NotificationTemplate,
)
from app.db.models.role import Permission, Role
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.notification import (
    NotificationCustomTemplateCreate,
    NotificationRuleCreate,
    NotificationTemplateUpdate,
)
from app.services.condition_fields import ALL_OPERATORS, CONDITION_FIELDS
from app.services.notification_rules import (
    apply_channel_settings,
    apply_portable_rule,
    build_conditions_and_event_types,
    rule_to_portable_dict,
)
from app.services.notification_rules import (
    delete_custom_template as delete_custom_template_row,
)
from app.services.notifications import default_template, send_test_notification
from app.web.flash import read_flash, sign_flash
from app.web.templating import t, templates

# A rule starts with no condition rows at all — the "+ Add condition" button
# on rule_form.html (app/web/static/js/notification-conditions.js) appends
# blank rows client-side, and the "…or as YAML" textarea below the rows is
# the no-JS fallback (see wiki/Notifications.md's "Condition-based rules"
# section for the YAML shape). Kept as a module constant, not inlined,
# purely so `_condition_rows_for_rule` below reads as "pad by this many"
# rather than a bare `0` whose meaning isn't obvious at the call site.
_BLANK_CONDITION_ROWS = 0

router = APIRouter(
    prefix="/notifications",
    dependencies=[Depends(require_permission(Permission.NOTIFICATION_VIEW))],
)
_manage = Depends(require_permission(Permission.NOTIFICATION_MANAGE))


async def _smtp_configured(db: AsyncSession) -> bool:
    app_settings = await get_or_create_app_settings(db)
    return bool(app_settings.smtp_enabled and app_settings.smtp_host)


async def _get_rule_or_404(rule_id: uuid.UUID, db: AsyncSession) -> NotificationRule:
    rule = await db.get(NotificationRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found.")
    return rule


async def _all_users(db: AsyncSession) -> list[User]:
    result = await db.execute(select(User).order_by(User.username))
    return list(result.scalars().all())


async def _all_roles(db: AsyncSession) -> list[Role]:
    result = await db.execute(select(Role).order_by(Role.name))
    return list(result.scalars().all())


async def _all_machines(db: AsyncSession) -> list[Machine]:
    result = await db.execute(select(Machine).order_by(Machine.name))
    return list(result.scalars().all())


async def _all_machine_groups(db: AsyncSession) -> list[MachineGroup]:
    result = await db.execute(select(MachineGroup).order_by(MachineGroup.name))
    return list(result.scalars().all())


async def _all_custom_templates(db: AsyncSession) -> list[NotificationCustomTemplate]:
    result = await db.execute(
        select(NotificationCustomTemplate).order_by(NotificationCustomTemplate.name)
    )
    return list(result.scalars().all())


async def _resolve_custom_template_id(
    db: AsyncSession, raw: str
) -> uuid.UUID | None:
    """`""` (the "use the per-event default" option) and any id that no
    longer matches an existing template both resolve to `None` — the same
    permissive "silently drop what doesn't match" the scope/recipient
    pickers already use, so a template deleted out from under a rule never
    turns saving that rule into an error."""
    if not raw.strip():
        return None
    try:
        template_id = uuid.UUID(raw)
    except ValueError:
        return None
    exists = await db.execute(
        select(NotificationCustomTemplate.id).where(NotificationCustomTemplate.id == template_id)
    )
    return template_id if exists.scalar_one_or_none() is not None else None


def _condition_row(
    *,
    field: str = "",
    operator: str = "",
    value: str = "",
    mount_point: str | None = None,
    sustained_seconds: int | None = None,
) -> dict[str, Any]:
    return {
        "field": field,
        "operator": operator,
        "value": value,
        "mount_point": mount_point,
        "sustained_seconds": sustained_seconds,
    }


def _condition_rows_for_rule(rule: NotificationRule | None) -> list[dict[str, Any]]:
    rows = (
        [
            _condition_row(
                field=c.field,
                operator=c.operator,
                value=c.value,
                mount_point=c.mount_point,
                sustained_seconds=c.sustained_seconds,
            )
            for c in rule.conditions
        ]
        if rule
        else []
    )
    rows.extend(_condition_row() for _ in range(_BLANK_CONDITION_ROWS))
    return rows


def _rule_form_context(rule: NotificationRule | None = None) -> dict[str, object]:
    return {
        # CONDITION_MATCHED is managed automatically (added whenever a rule
        # has conditions — see `_build_conditions_and_event_types` below),
        # not a manually-checkable event on the form.
        "event_types": [
            e for e in NotificationEventType if e != NotificationEventType.CONDITION_MATCHED
        ],
        "selected_event_types": [e.value for e in rule.event_type_enums] if rule else [],
        "selected_user_ids": [str(u.id) for u in rule.users] if rule else [],
        "selected_role_ids": [str(r.id) for r in rule.roles] if rule else [],
        "selected_machine_ids": [str(m.id) for m in rule.machines] if rule else [],
        "selected_machine_group_ids": [str(g.id) for g in rule.machine_groups] if rule else [],
        "selected_custom_template_id": (
            str(rule.custom_template_id) if rule and rule.custom_template_id else ""
        ),
        "selected_delivery_channel": (
            rule.delivery_channel if rule else NotificationDeliveryChannel.EMAIL.value
        ),
        "selected_webhook_url": rule.webhook_url if rule else "",
        "selected_channel_recipient": (rule.channel_recipient or "") if rule else "",
        "channel_token_set": bool(rule and rule.channel_token_encrypted),
        "condition_rows": _condition_rows_for_rule(rule),
        "condition_field_choices": [(k, f.label_key) for k, f in CONDITION_FIELDS.items()],
        "condition_operator_choices": ALL_OPERATORS,
    }


def _parse_condition_rows(
    fields: list[str],
    operators: list[str],
    values: list[str],
    mounts: list[str],
    sustains: list[str],
) -> list[dict[str, Any]]:
    """One row per parallel form-array index — a row with no field or no
    value is silently skipped (the empty padding rows `_BLANK_CONDITION_ROWS`
    adds, or a row the admin cleared out to remove it)."""
    rows: list[dict[str, Any]] = []
    for field, operator, value, mount, sustain in zip(
        fields, operators, values, mounts, sustains, strict=False
    ):
        if not field.strip() or not value.strip():
            continue
        sustained: int | None = None
        if sustain.strip():
            try:
                sustained = int(sustain.strip())
            except ValueError:
                sustained = None
        rows.append(
            {
                "field": field.strip(),
                "operator": operator.strip(),
                "value": value.strip(),
                "mount_point": mount.strip() or None,
                "sustained_seconds": sustained,
            }
        )
    return rows


def _parse_conditions_yaml_block(text: str) -> list[dict[str, Any]]:
    """The rule form's "Conditions as YAML" textarea — a YAML list of
    condition dicts only (not a whole rule; see `_rule_to_yaml_dict` below
    for the full-rule export/import shape). Empty input means "use the
    form rows instead" (see the callers of this function)."""
    if not text.strip():
        return []
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc
    if not isinstance(parsed, list):
        raise ValueError("Conditions YAML must be a list of condition entries.")
    rows: list[dict[str, Any]] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            raise ValueError("Each condition entry must be a mapping.")
        rows.append(
            {
                "field": str(entry.get("field", "")),
                "operator": str(entry.get("operator", "")),
                "value": str(entry.get("value", "")),
                "mount_point": (
                    str(entry["mount_point"]) if entry.get("mount_point") else None
                ),
                "sustained_seconds": entry.get("sustained_seconds"),
            }
        )
    return rows


def _parse_ids(raw_ids: list[str]) -> list[uuid.UUID]:
    """Parsed and de-duplicated, dropping anything unparseable — same
    "a tampered/stale id is rejected, not silently trusted" reasoning
    `app/web/routes/users.py`'s `_parse_group_access` applies, except here a
    bad id is simply dropped from the selection rather than rejecting the
    whole form: a recipient/scope list is much lower-stakes than an
    account's access scope."""
    parsed: list[uuid.UUID] = []
    for raw in raw_ids:
        if not raw.strip():
            continue
        try:
            parsed.append(uuid.UUID(raw.strip()))
        except ValueError:
            continue
    return list(dict.fromkeys(parsed))


async def _resolve_users(db: AsyncSession, raw_ids: list[str]) -> list[User]:
    ids = _parse_ids(raw_ids)
    if not ids:
        return []
    result = await db.execute(select(User).where(User.id.in_(ids)))
    return list(result.scalars().all())


async def _resolve_roles(db: AsyncSession, raw_ids: list[str]) -> list[Role]:
    ids = _parse_ids(raw_ids)
    if not ids:
        return []
    result = await db.execute(select(Role).where(Role.id.in_(ids)))
    return list(result.scalars().all())


async def _resolve_machines(db: AsyncSession, raw_ids: list[str]) -> list[Machine]:
    ids = _parse_ids(raw_ids)
    if not ids:
        return []
    result = await db.execute(select(Machine).where(Machine.id.in_(ids)))
    return list(result.scalars().all())


async def _resolve_machine_groups(db: AsyncSession, raw_ids: list[str]) -> list[MachineGroup]:
    ids = _parse_ids(raw_ids)
    if not ids:
        return []
    result = await db.execute(select(MachineGroup).where(MachineGroup.id.in_(ids)))
    return list(result.scalars().all())


@router.get("")
async def list_notifications(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    result = await db.execute(
        select(NotificationRule)
        .options(
            selectinload(NotificationRule.users),
            selectinload(NotificationRule.roles),
            selectinload(NotificationRule.machines),
            selectinload(NotificationRule.machine_groups),
        )
        .order_by(NotificationRule.name)
    )
    rules = result.scalars().all()
    return templates.TemplateResponse(
        request,
        "notifications/list.html",
        {
            "rules": rules,
            "smtp_configured": await _smtp_configured(db),
            "csrf_token": request.state.csrf_token,
        },
    )


@router.get("/rules/new")
async def new_rule_form(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "notifications/rule_form.html",
        {
            "rule": None,
            "all_users": await _all_users(db),
            "all_roles": await _all_roles(db),
            "all_machines": await _all_machines(db),
            "all_machine_groups": await _all_machine_groups(db),
            "all_custom_templates": await _all_custom_templates(db),
            "errors": [],
            "form": {"enabled": True},
            "csrf_token": csrf_token,
            **_rule_form_context(),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


async def _apply_rule_recipients_and_scope(
    db: AsyncSession,
    rule: NotificationRule,
    *,
    user_ids: list[str],
    role_ids: list[str],
    machine_ids: list[str],
    machine_group_ids: list[str],
) -> None:
    rule.users = await _resolve_users(db, user_ids)
    rule.roles = await _resolve_roles(db, role_ids)
    rule.machines = await _resolve_machines(db, machine_ids)
    rule.machine_groups = await _resolve_machine_groups(db, machine_group_ids)


@router.post("/rules", dependencies=[_manage, Depends(verify_csrf)])
async def create_rule(
    request: Request,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    description: str = Form(""),
    enabled: str = Form(""),
    event_types: list[str] = Form(default=[]),
    user_ids: list[str] = Form(default=[]),
    role_ids: list[str] = Form(default=[]),
    machine_ids: list[str] = Form(default=[]),
    machine_group_ids: list[str] = Form(default=[]),
    condition_field: list[str] = Form(default=[]),
    condition_operator: list[str] = Form(default=[]),
    condition_value: list[str] = Form(default=[]),
    condition_mount: list[str] = Form(default=[]),
    condition_sustained: list[str] = Form(default=[]),
    conditions_yaml: str = Form(""),
    custom_template_id: str = Form(""),
    delivery_channel: str = Form(NotificationDeliveryChannel.EMAIL.value),
    webhook_url: str = Form(""),
    channel_token: str = Form(""),
    channel_recipient: str = Form(""),
) -> Response:
    async def _rerender(
        errors: list[str], status_code: int, condition_rows: list[dict[str, Any]]
    ) -> Response:
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "notifications/rule_form.html",
            {
                "rule": None,
                "all_users": await _all_users(db),
                "all_roles": await _all_roles(db),
                "all_machines": await _all_machines(db),
                "all_machine_groups": await _all_machine_groups(db),
                "all_custom_templates": await _all_custom_templates(db),
                "errors": errors,
                "form": {
                    "name": name,
                    "description": description,
                    "enabled": bool(enabled),
                    "conditions_yaml": conditions_yaml,
                },
                "csrf_token": csrf_token,
                "event_types": [
                    e
                    for e in NotificationEventType
                    if e != NotificationEventType.CONDITION_MATCHED
                ],
                "selected_event_types": event_types,
                "selected_user_ids": user_ids,
                "selected_role_ids": role_ids,
                "selected_machine_ids": machine_ids,
                "selected_machine_group_ids": machine_group_ids,
                "selected_custom_template_id": custom_template_id,
                "selected_delivery_channel": delivery_channel,
                "selected_webhook_url": webhook_url,
                "selected_channel_recipient": channel_recipient,
                "condition_rows": condition_rows,
                "condition_field_choices": [
                    (k, f.label_key) for k, f in CONDITION_FIELDS.items()
                ],
                "condition_operator_choices": ALL_OPERATORS,
            },
            status_code=status_code,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    try:
        raw_conditions = _parse_conditions_yaml_block(
            conditions_yaml
        ) or _parse_condition_rows(
            condition_field, condition_operator, condition_value, condition_mount,
            condition_sustained,
        )
    except ValueError as exc:
        return await _rerender(
            [str(exc)],
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            _condition_rows_for_rule(None),
        )

    try:
        resolved_event_types, conditions = build_conditions_and_event_types(
            event_types, raw_conditions
        )
    except ValueError as exc:
        rows = raw_conditions + [
            _condition_row() for _ in range(_BLANK_CONDITION_ROWS)
        ]
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT, rows)

    try:
        payload = NotificationRuleCreate(
            name=name,
            description=description or None,
            enabled=bool(enabled),
            event_types=resolved_event_types,
            delivery_channel=delivery_channel,
            webhook_url=webhook_url or None,
            channel_token=channel_token or None,
            channel_recipient=channel_recipient or None,
        )
    except ValueError as exc:
        rows = raw_conditions + [
            _condition_row() for _ in range(_BLANK_CONDITION_ROWS)
        ]
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT, rows)

    rule = NotificationRule(
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        event_types=payload.event_types,
        custom_template_id=await _resolve_custom_template_id(db, custom_template_id),
        conditions=[
            NotificationCondition(
                field=c.field,
                operator=c.operator,
                value=c.value,
                mount_point=c.mount_point,
                sustained_seconds=c.sustained_seconds,
            )
            for c in conditions
        ],
    )
    try:
        apply_channel_settings(rule, payload)
    except ValueError as exc:
        rows = raw_conditions + [_condition_row() for _ in range(_BLANK_CONDITION_ROWS)]
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT, rows)
    await _apply_rule_recipients_and_scope(
        db,
        rule,
        user_ids=user_ids,
        role_ids=role_ids,
        machine_ids=machine_ids,
        machine_group_ids=machine_group_ids,
    )
    db.add(rule)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        rows = raw_conditions + [_condition_row() for _ in range(_BLANK_CONDITION_ROWS)]
        return await _rerender(
            [t(request, "notifications.error.rule_name_taken", name=payload.name)],
            status.HTTP_409_CONFLICT,
            rows,
        )
    await db.refresh(rule)

    await log_event(
        db,
        request=request,
        action="notification_rule.create",
        summary=f'Created notification rule "{rule.name}"',
        target_type="notification_rule",
        target_id=rule.id,
        target_label=rule.name,
        details={"event_types": rule.event_types},
    )
    return RedirectResponse(url="/notifications", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/rules/{rule_id}/edit")
async def edit_rule_form(
    request: Request, rule_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    rule = await _get_rule_or_404(rule_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "notifications/rule_form.html",
        {
            "rule": rule,
            "all_users": await _all_users(db),
            "all_roles": await _all_roles(db),
            "all_machines": await _all_machines(db),
            "all_machine_groups": await _all_machine_groups(db),
            "all_custom_templates": await _all_custom_templates(db),
            "errors": [],
            "form": {
                "name": rule.name,
                "description": rule.description,
                "enabled": rule.enabled,
            },
            "csrf_token": csrf_token,
            "test_sent": request.query_params.get("test_sent") is not None,
            "test_error": read_flash(request, "test_error"),
            **_rule_form_context(rule),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/rules/{rule_id}/test", dependencies=[_manage, Depends(verify_csrf)])
async def test_rule(
    request: Request,
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """"Send test" button on a rule's edit page — one synthetic delivery
    through the rule's own configured channel/template, never its real
    recipients (email goes only to the admin clicking the button — see
    `app.services.notifications.send_test_notification`). Redirects back
    to the edit page with a query-string result flag rather than an inline
    partial, since a full navigation already happened to get here and the
    result is a one-line pass/fail, not worth an extra htmx round trip."""
    rule = await _get_rule_or_404(rule_id, db)
    ok, error = await send_test_notification(
        db,
        rule,
        to_email=current_user.email,
        locale=request.state.locale.code,
    )
    await log_event(
        db,
        request=request,
        action="notification_rule.test",
        summary=f'Sent a test notification for rule "{rule.name}"',
        target_type="notification_rule",
        target_id=rule.id,
        target_label=rule.name,
        details={"ok": ok, "channel": rule.delivery_channel},
    )
    query = (
        "test_sent=1"
        if ok
        else "test_error=" + sign_flash(error or t(request, "common.error.unknown"))
    )
    return RedirectResponse(
        url=f"/notifications/rules/{rule_id}/edit?{query}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.post("/rules/{rule_id}/edit", dependencies=[_manage, Depends(verify_csrf)])
async def update_rule(
    request: Request,
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    description: str = Form(""),
    enabled: str = Form(""),
    event_types: list[str] = Form(default=[]),
    user_ids: list[str] = Form(default=[]),
    role_ids: list[str] = Form(default=[]),
    machine_ids: list[str] = Form(default=[]),
    machine_group_ids: list[str] = Form(default=[]),
    condition_field: list[str] = Form(default=[]),
    condition_operator: list[str] = Form(default=[]),
    condition_value: list[str] = Form(default=[]),
    condition_mount: list[str] = Form(default=[]),
    condition_sustained: list[str] = Form(default=[]),
    conditions_yaml: str = Form(""),
    custom_template_id: str = Form(""),
    delivery_channel: str = Form(NotificationDeliveryChannel.EMAIL.value),
    webhook_url: str = Form(""),
    channel_token: str = Form(""),
    channel_recipient: str = Form(""),
) -> Response:
    rule = await _get_rule_or_404(rule_id, db)

    async def _rerender(
        errors: list[str], status_code: int, condition_rows: list[dict[str, Any]]
    ) -> Response:
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "notifications/rule_form.html",
            {
                "rule": rule,
                "all_users": await _all_users(db),
                "all_roles": await _all_roles(db),
                "all_machines": await _all_machines(db),
                "all_machine_groups": await _all_machine_groups(db),
                "all_custom_templates": await _all_custom_templates(db),
                "errors": errors,
                "form": {
                    "name": name,
                    "description": description,
                    "enabled": bool(enabled),
                    "conditions_yaml": conditions_yaml,
                },
                "csrf_token": csrf_token,
                "event_types": [
                    e
                    for e in NotificationEventType
                    if e != NotificationEventType.CONDITION_MATCHED
                ],
                "selected_event_types": event_types,
                "selected_user_ids": user_ids,
                "selected_role_ids": role_ids,
                "selected_machine_ids": machine_ids,
                "selected_machine_group_ids": machine_group_ids,
                "selected_custom_template_id": custom_template_id,
                "selected_delivery_channel": delivery_channel,
                "selected_webhook_url": webhook_url,
                "selected_channel_recipient": channel_recipient,
                "condition_rows": condition_rows,
                "condition_field_choices": [
                    (k, f.label_key) for k, f in CONDITION_FIELDS.items()
                ],
                "condition_operator_choices": ALL_OPERATORS,
            },
            status_code=status_code,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    try:
        raw_conditions = _parse_conditions_yaml_block(
            conditions_yaml
        ) or _parse_condition_rows(
            condition_field, condition_operator, condition_value, condition_mount,
            condition_sustained,
        )
    except ValueError as exc:
        return await _rerender(
            [str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT, _condition_rows_for_rule(rule)
        )

    try:
        resolved_event_types, conditions = build_conditions_and_event_types(
            event_types, raw_conditions
        )
    except ValueError as exc:
        rows = raw_conditions + [
            _condition_row() for _ in range(_BLANK_CONDITION_ROWS)
        ]
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT, rows)

    try:
        payload = NotificationRuleCreate(
            name=name,
            description=description or None,
            enabled=bool(enabled),
            event_types=resolved_event_types,
            delivery_channel=delivery_channel,
            webhook_url=webhook_url or None,
            channel_token=channel_token or None,
            channel_recipient=channel_recipient or None,
        )
    except ValueError as exc:
        rows = raw_conditions + [
            _condition_row() for _ in range(_BLANK_CONDITION_ROWS)
        ]
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT, rows)

    rule.name = payload.name
    rule.description = payload.description
    rule.enabled = payload.enabled
    rule.event_types = payload.event_types
    rule.custom_template_id = await _resolve_custom_template_id(db, custom_template_id)
    try:
        apply_channel_settings(rule, payload)
    except ValueError as exc:
        rows = raw_conditions + [_condition_row() for _ in range(_BLANK_CONDITION_ROWS)]
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT, rows)
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
    await _apply_rule_recipients_and_scope(
        db,
        rule,
        user_ids=user_ids,
        role_ids=role_ids,
        machine_ids=machine_ids,
        machine_group_ids=machine_group_ids,
    )

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        rows = raw_conditions + [_condition_row() for _ in range(_BLANK_CONDITION_ROWS)]
        return await _rerender(
            [t(request, "notifications.error.rule_name_taken", name=payload.name)],
            status.HTTP_409_CONFLICT,
            rows,
        )

    await log_event(
        db,
        request=request,
        action="notification_rule.update",
        summary=f'Updated notification rule "{rule.name}"',
        target_type="notification_rule",
        target_id=rule.id,
        target_label=rule.name,
        details={"event_types": rule.event_types},
    )
    return RedirectResponse(url="/notifications", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/rules/{rule_id}/delete", dependencies=[_manage, Depends(verify_csrf)])
async def delete_rule(
    request: Request, rule_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    rule = await _get_rule_or_404(rule_id, db)
    name = rule.name
    await db.delete(rule)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="notification_rule.delete",
        summary=f'Deleted notification rule "{name}"',
        target_type="notification_rule",
        target_id=rule_id,
        target_label=name,
    )
    return RedirectResponse(url="/notifications", status_code=status.HTTP_303_SEE_OTHER)


# --- YAML export/import ---------------------------------------------------
#
# A portable, human-editable representation of a whole rule — natural keys
# (email/role name/machine name/group name) rather than raw database ids,
# so a rule exported from one instance can be reviewed, version-controlled,
# and re-imported into another. Import upserts by `name` (the same unique
# key `NotificationRule.name` already enforces), so re-importing an
# unmodified export is a no-op and editing the YAML and re-importing is
# "update in place." The shape and the upsert live in
# `app.services.notification_rules` (shared with the REST API); see
# `wiki/Notifications.md`'s "Condition-based rules" section for an example.


@router.get("/rules/{rule_id}/export")
async def export_rule(
    request: Request, rule_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    rule = await _get_rule_or_404(rule_id, db)
    text = yaml.safe_dump(rule_to_portable_dict(rule), sort_keys=False, allow_unicode=True)
    return Response(content=text, media_type="application/yaml")


@router.get("/rules/export")
async def export_all_rules(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    result = await db.execute(
        select(NotificationRule)
        .options(
            selectinload(NotificationRule.users),
            selectinload(NotificationRule.roles),
            selectinload(NotificationRule.machines),
            selectinload(NotificationRule.machine_groups),
        )
        .order_by(NotificationRule.name)
    )
    rules = result.scalars().all()
    text = yaml.safe_dump(
        [rule_to_portable_dict(r) for r in rules], sort_keys=False, allow_unicode=True
    )
    return Response(content=text, media_type="application/yaml")


@router.get("/rules/import")
async def import_rules_form(request: Request) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "notifications/rule_import.html",
        {"errors": [], "form": {}, "imported": None, "csrf_token": csrf_token},
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/rules/import", dependencies=[_manage, Depends(verify_csrf)])
async def import_rules(
    request: Request, db: AsyncSession = Depends(get_db), yaml_text: str = Form(...)
) -> Response:
    async def _rerender(errors: list[str], status_code: int) -> Response:
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "notifications/rule_import.html",
            {
                "errors": errors,
                "form": {"yaml_text": yaml_text},
                "imported": None,
                "csrf_token": csrf_token,
            },
            status_code=status_code,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    try:
        parsed = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        return await _rerender([f"Invalid YAML: {exc}"], status.HTTP_422_UNPROCESSABLE_CONTENT)

    entries = parsed if isinstance(parsed, list) else [parsed]
    created_count = 0
    updated_count = 0
    try:
        for entry in entries:
            _rule, created = await apply_portable_rule(db, entry)
            created_count += 1 if created else 0
            updated_count += 0 if created else 1
        await db.commit()
    except (ValueError, IntegrityError) as exc:
        await db.rollback()
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    await log_event(
        db,
        request=request,
        action="notification_rule.import",
        summary=f"Imported {created_count + updated_count} notification rule(s) from YAML",
        details={"created": created_count, "updated": updated_count},
    )
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "notifications/rule_import.html",
        {
            "errors": [],
            "form": {},
            "imported": {"created": created_count, "updated": updated_count},
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


# --- Delivery history -------------------------------------------------------


@router.get("/history")
async def notification_history(
    request: Request, db: AsyncSession = Depends(get_db), rule_id: uuid.UUID | None = None
) -> Response:
    """The last 200 `NotificationLog` rows, newest first — one row per
    actual send attempt (real or "Send test"), for troubleshooting "did
    that alert actually go out." See `AppSettings.notification_log_retention_days`
    for how long these are kept (Settings → Checks & retention).

    Optionally narrowed to one rule via `?rule_id=` (linked from that rule's
    own edit page) — `NotificationLog.rule_id` carries an index specifically
    for this filter, since without one this scan would only get slower as
    delivery history accumulates."""
    query = select(NotificationLog).order_by(NotificationLog.sent_at.desc()).limit(200)
    rule_filter_name: str | None = None
    if rule_id is not None:
        query = query.where(NotificationLog.rule_id == rule_id)
        rule = await db.get(NotificationRule, rule_id)
        rule_filter_name = rule.name if rule is not None else str(rule_id)
    result = await db.execute(query)
    logs = result.scalars().all()
    return templates.TemplateResponse(
        request,
        "notifications/history.html",
        {"logs": logs, "rule_filter_name": rule_filter_name},
    )


# --- Templates -----------------------------------------------------------


@router.get("/templates")
async def list_templates(request: Request, db: AsyncSession = Depends(get_db)) -> Response:
    result = await db.execute(select(NotificationTemplate))
    overrides = {t.event_type: t for t in result.scalars().all()}
    locale_code = request.state.locale.code
    rows = [
        {
            "event_type": event_type,
            "is_override": event_type.value in overrides,
            "subject": (
                overrides[event_type.value].subject
                if event_type.value in overrides
                else default_template(event_type, locale_code)[0]
            ),
        }
        for event_type in NotificationEventType
    ]
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "notifications/templates.html",
        {
            "rows": rows,
            "custom_templates": await _all_custom_templates(db),
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.get("/templates/{event_type}/edit")
async def edit_template_form(
    request: Request, event_type: NotificationEventType, db: AsyncSession = Depends(get_db)
) -> Response:
    result = await db.execute(
        select(NotificationTemplate).where(NotificationTemplate.event_type == event_type.value)
    )
    template = result.scalar_one_or_none()
    default_subject, default_body = default_template(event_type, request.state.locale.code)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "notifications/template_form.html",
        {
            "event_type": event_type,
            "is_override": template is not None,
            "subject": template.subject if template else default_subject,
            "body": template.body if template else default_body,
            "default_subject": default_subject,
            "default_body": default_body,
            "errors": [],
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/templates/{event_type}/edit", dependencies=[_manage, Depends(verify_csrf)])
async def update_template(
    request: Request,
    event_type: NotificationEventType,
    db: AsyncSession = Depends(get_db),
    subject: str = Form(...),
    body: str = Form(...),
) -> Response:
    try:
        payload = NotificationTemplateUpdate(subject=subject, body=body)
    except ValueError as exc:
        default_subject, default_body = default_template(event_type, request.state.locale.code)
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "notifications/template_form.html",
            {
                "event_type": event_type,
                "is_override": True,
                "subject": subject,
                "body": body,
                "default_subject": default_subject,
                "default_body": default_body,
                "errors": [str(exc)],
                "csrf_token": csrf_token,
            },
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    result = await db.execute(
        select(NotificationTemplate).where(NotificationTemplate.event_type == event_type.value)
    )
    template = result.scalar_one_or_none()
    if template is None:
        template = NotificationTemplate(event_type=event_type.value, subject="", body="")
        db.add(template)
    template.subject = payload.subject
    template.body = payload.body
    await db.commit()

    await log_event(
        db,
        request=request,
        action="notification_template.update",
        summary=f'Updated notification template for "{event_type.value}"',
        target_type="notification_template",
        target_id=event_type.value,
        target_label=event_type.value,
    )
    return RedirectResponse(url="/notifications/templates", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/templates/{event_type}/reset", dependencies=[_manage, Depends(verify_csrf)])
async def reset_template(
    request: Request, event_type: NotificationEventType, db: AsyncSession = Depends(get_db)
) -> Response:
    result = await db.execute(
        select(NotificationTemplate).where(NotificationTemplate.event_type == event_type.value)
    )
    template = result.scalar_one_or_none()
    if template is not None:
        await db.delete(template)
        await db.commit()
        await log_event(
            db,
            request=request,
            action="notification_template.reset",
            summary=f'Reset notification template for "{event_type.value}" to default',
            target_type="notification_template",
            target_id=event_type.value,
            target_label=event_type.value,
        )
    return RedirectResponse(url="/notifications/templates", status_code=status.HTTP_303_SEE_OTHER)


# --- Custom templates ------------------------------------------------------
#
# A named, reusable template any rule can select instead of the per-event
# default/override above — see `NotificationCustomTemplate`'s docstring.


async def _get_custom_template_or_404(
    template_id: uuid.UUID, db: AsyncSession
) -> NotificationCustomTemplate:
    template = await db.get(NotificationCustomTemplate, template_id)
    if template is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found.")
    return template


@router.get("/templates/custom/new")
async def new_custom_template_form(request: Request) -> Response:
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "notifications/custom_template_form.html",
        {
            "template": None,
            "form": {"name": "", "subject": "", "body": ""},
            "errors": [],
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/templates/custom", dependencies=[_manage, Depends(verify_csrf)])
async def create_custom_template(
    request: Request,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
) -> Response:
    async def _rerender(errors: list[str], status_code: int) -> Response:
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "notifications/custom_template_form.html",
            {
                "template": None,
                "form": {"name": name, "subject": subject, "body": body},
                "errors": errors,
                "csrf_token": csrf_token,
            },
            status_code=status_code,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    try:
        payload = NotificationCustomTemplateCreate(name=name, subject=subject, body=body)
    except ValueError as exc:
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    template = NotificationCustomTemplate(
        name=payload.name, subject=payload.subject, body=payload.body
    )
    db.add(template)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await _rerender(
            [t(request, "notifications.error.template_name_taken", name=payload.name)],
            status.HTTP_409_CONFLICT,
        )
    await db.refresh(template)

    await log_event(
        db,
        request=request,
        action="notification_custom_template.create",
        summary=f'Created notification template "{template.name}"',
        target_type="notification_custom_template",
        target_id=template.id,
        target_label=template.name,
    )
    return RedirectResponse(url="/notifications/templates", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/templates/custom/{template_id}/edit")
async def edit_custom_template_form(
    request: Request, template_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    template = await _get_custom_template_or_404(template_id, db)
    csrf_token, new_cookie = get_or_create_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "notifications/custom_template_form.html",
        {
            "template": template,
            "form": {"name": template.name, "subject": template.subject, "body": template.body},
            "errors": [],
            "csrf_token": csrf_token,
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


@router.post("/templates/custom/{template_id}/edit", dependencies=[_manage, Depends(verify_csrf)])
async def update_custom_template(
    request: Request,
    template_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    name: str = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
) -> Response:
    template = await _get_custom_template_or_404(template_id, db)

    async def _rerender(errors: list[str], status_code: int) -> Response:
        csrf_token, new_cookie = get_or_create_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "notifications/custom_template_form.html",
            {
                "template": template,
                "form": {"name": name, "subject": subject, "body": body},
                "errors": errors,
                "csrf_token": csrf_token,
            },
            status_code=status_code,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    try:
        payload = NotificationCustomTemplateCreate(name=name, subject=subject, body=body)
    except ValueError as exc:
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    template.name = payload.name
    template.subject = payload.subject
    template.body = payload.body
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await _rerender(
            [t(request, "notifications.error.template_name_taken", name=payload.name)],
            status.HTTP_409_CONFLICT,
        )

    await log_event(
        db,
        request=request,
        action="notification_custom_template.update",
        summary=f'Updated notification template "{template.name}"',
        target_type="notification_custom_template",
        target_id=template.id,
        target_label=template.name,
    )
    return RedirectResponse(url="/notifications/templates", status_code=status.HTTP_303_SEE_OTHER)


@router.post(
    "/templates/custom/{template_id}/delete", dependencies=[_manage, Depends(verify_csrf)]
)
async def delete_custom_template(
    request: Request, template_id: uuid.UUID, db: AsyncSession = Depends(get_db)
) -> Response:
    template = await _get_custom_template_or_404(template_id, db)
    name = template.name
    await delete_custom_template_row(db, template)
    await log_event(
        db,
        request=request,
        action="notification_custom_template.delete",
        summary=f'Deleted notification template "{name}"',
        target_type="notification_custom_template",
        target_id=template_id,
        target_label=name,
    )
    return RedirectResponse(url="/notifications/templates", status_code=status.HTTP_303_SEE_OTHER)
