"""Notifications — rules ("when X happens, tell these people about these
machines") and per-event email templates. See
`app.db.models.notification_rule`'s module docstring for the data model
(recipients are directly-listed users plus every active user holding one
of the rule's target roles — no separate notification-only grouping
concept) and `app.services.notifications` for how a rule actually turns
into a sent email.

Web-UI-only this round, same as LDAP/OIDC/syslog config (see
`api_v1.py`'s module docstring) — a REST equivalent is a reasonable
follow-up, not included here.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit import log_event
from app.auth.dependencies import require_permission
from app.core.app_settings import get_or_create_app_settings
from app.core.csrf import get_or_create_csrf_token, set_csrf_cookie, verify_csrf
from app.db.models.machine import Machine
from app.db.models.machine_group import MachineGroup
from app.db.models.notification_rule import (
    NotificationEventType,
    NotificationRule,
    NotificationTemplate,
)
from app.db.models.role import Permission, Role
from app.db.models.user import User
from app.db.session import get_db
from app.schemas.notification import (
    NotificationRuleCreate,
    NotificationTemplateUpdate,
)
from app.services.notifications import default_template
from app.web.templating import templates

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


def _rule_form_context(rule: NotificationRule | None = None) -> dict[str, object]:
    return {
        "event_types": list(NotificationEventType),
        "selected_event_types": [e.value for e in rule.event_type_enums] if rule else [],
        "selected_user_ids": [str(u.id) for u in rule.users] if rule else [],
        "selected_role_ids": [str(r.id) for r in rule.roles] if rule else [],
        "selected_machine_ids": [str(m.id) for m in rule.machines] if rule else [],
        "selected_machine_group_ids": [str(g.id) for g in rule.machine_groups] if rule else [],
    }


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
) -> Response:
    async def _rerender(errors: list[str], status_code: int) -> Response:
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
                "errors": errors,
                "form": {"name": name, "description": description, "enabled": bool(enabled)},
                "csrf_token": csrf_token,
                "event_types": list(NotificationEventType),
                "selected_event_types": event_types,
                "selected_user_ids": user_ids,
                "selected_role_ids": role_ids,
                "selected_machine_ids": machine_ids,
                "selected_machine_group_ids": machine_group_ids,
            },
            status_code=status_code,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    try:
        payload = NotificationRuleCreate(
            name=name,
            description=description or None,
            enabled=bool(enabled),
            event_types=event_types,
        )
    except ValueError as exc:
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    rule = NotificationRule(
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        event_types=payload.event_types,
    )
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
        return await _rerender(
            [f'A notification rule named "{payload.name}" already exists.'],
            status.HTTP_409_CONFLICT,
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
            "errors": [],
            "form": {
                "name": rule.name,
                "description": rule.description,
                "enabled": rule.enabled,
            },
            "csrf_token": csrf_token,
            **_rule_form_context(rule),
        },
    )
    if new_cookie:
        set_csrf_cookie(response, new_cookie)
    return response


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
) -> Response:
    rule = await _get_rule_or_404(rule_id, db)

    async def _rerender(errors: list[str], status_code: int) -> Response:
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
                "errors": errors,
                "form": {"name": name, "description": description, "enabled": bool(enabled)},
                "csrf_token": csrf_token,
                "event_types": list(NotificationEventType),
                "selected_event_types": event_types,
                "selected_user_ids": user_ids,
                "selected_role_ids": role_ids,
                "selected_machine_ids": machine_ids,
                "selected_machine_group_ids": machine_group_ids,
            },
            status_code=status_code,
        )
        if new_cookie:
            set_csrf_cookie(response, new_cookie)
        return response

    try:
        payload = NotificationRuleCreate(
            name=name,
            description=description or None,
            enabled=bool(enabled),
            event_types=event_types,
        )
    except ValueError as exc:
        return await _rerender([str(exc)], status.HTTP_422_UNPROCESSABLE_CONTENT)

    rule.name = payload.name
    rule.description = payload.description
    rule.enabled = payload.enabled
    rule.event_types = payload.event_types
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
        return await _rerender(
            [f'A notification rule named "{payload.name}" already exists.'],
            status.HTTP_409_CONFLICT,
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
    return templates.TemplateResponse(
        request, "notifications/templates.html", {"rows": rows}
    )


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
