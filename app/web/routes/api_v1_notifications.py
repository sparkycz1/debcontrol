"""REST API for Notifications — rules, per-event templates, named custom
templates and the delivery history, mirroring `/notifications`
(`app/web/routes/notifications.py`) with the same permissions
(`notification.view` to read, `notification.manage` to change), the same
validation/persistence (`app.services.notification_rules`) and the same
audit action codes.

Rules are read and written in the **portable shape** the YAML export uses
(`rule_to_portable_dict`: recipients by email/role name, scope by machine/
group name, custom template by name) plus a read-only `id` — so a rule
fetched here can be edited and PUT straight back, or POSTed to another
instance. `POST /rules/import` is the YAML import's upsert-by-name, taking
a JSON list instead of YAML text.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_event
from app.auth.dependencies import get_api_token_user, require_api_permission
from app.db.models.maintenance_window import MaintenanceWindow
from app.db.models.notification_log import NotificationLog
from app.db.models.notification_rule import (
    NotificationCustomTemplate,
    NotificationEventType,
    NotificationRule,
    NotificationTemplate,
)
from app.db.models.role import Permission
from app.db.models.user import User
from app.db.session import get_db
from app.i18n import DEFAULT_LOCALE_CODE
from app.schemas.maintenance_window import MaintenanceWindowSave
from app.schemas.notification import NotificationCustomTemplateCreate, NotificationTemplateUpdate
from app.services.maintenance_windows import apply_window_data, window_state
from app.services.notification_rules import (
    apply_portable_rule,
    delete_custom_template,
    rule_to_portable_dict,
)
from app.services.notifications import default_template, send_test_notification
from app.web.routes.maintenance import window_summary

router = APIRouter(prefix="/api/v1/notifications")
_view = Depends(require_api_permission(Permission.NOTIFICATION_VIEW))
_manage = Depends(require_api_permission(Permission.NOTIFICATION_MANAGE))

# Same page size the web history page shows.
_HISTORY_MAX_LIMIT = 200


def _rule_to_dict(rule: NotificationRule) -> dict[str, Any]:
    return {"id": str(rule.id), **rule_to_portable_dict(rule)}


def _custom_template_to_dict(template: NotificationCustomTemplate) -> dict[str, Any]:
    return {
        "id": str(template.id),
        "name": template.name,
        "subject": template.subject,
        "body": template.body,
    }


async def _get_rule_or_404(rule_id: uuid.UUID, db: AsyncSession) -> NotificationRule:
    rule = await db.get(NotificationRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Rule not found.")
    return rule


async def _get_custom_template_or_404(
    template_id: uuid.UUID, db: AsyncSession
) -> NotificationCustomTemplate:
    template = await db.get(NotificationCustomTemplate, template_id)
    if template is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Template not found.")
    return template


async def _save_rule(
    db: AsyncSession, data: dict[str, Any], *, rule: NotificationRule | None
) -> tuple[NotificationRule, bool]:
    try:
        saved, created = await apply_portable_rule(db, data, rule=rule)
        await db.commit()
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f'A notification rule named "{data.get("name")}" already exists.',
        ) from exc
    await db.refresh(saved)
    return saved, created


# --- Rules ------------------------------------------------------------------


@router.get("/rules", dependencies=[_view])
async def list_rules_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, Any]]:
    result = await db.execute(select(NotificationRule).order_by(NotificationRule.name))
    return [_rule_to_dict(r) for r in result.scalars().all()]


@router.get("/rules/{rule_id}", dependencies=[_view])
async def get_rule_api(
    rule_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    return _rule_to_dict(await _get_rule_or_404(rule_id, db))


@router.post("/rules", dependencies=[_manage], status_code=status.HTTP_201_CREATED)
async def create_rule_api(
    request: Request,
    data: dict[str, Any] = Body(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Create a rule from the portable shape (see this module's docstring).
    Unlike `POST /rules/import`, an existing name is a 409, not an update."""
    name = str(data.get("name") or "")
    existing = await db.execute(select(NotificationRule.id).where(NotificationRule.name == name))
    if name and existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f'A notification rule named "{name}" already exists.',
        )
    rule, _created = await _save_rule(db, data, rule=None)
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
    return _rule_to_dict(rule)


@router.put("/rules/{rule_id}", dependencies=[_manage])
async def update_rule_api(
    rule_id: uuid.UUID,
    request: Request,
    data: dict[str, Any] = Body(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Replace a rule with the portable shape — every field, like the edit
    form (an omitted list clears it). `name` may differ, which renames it."""
    rule = await _get_rule_or_404(rule_id, db)
    rule, _created = await _save_rule(db, data, rule=rule)
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
    return _rule_to_dict(rule)


@router.delete("/rules/{rule_id}", dependencies=[_manage], status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule_api(
    rule_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> None:
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


@router.post("/rules/import", dependencies=[_manage])
async def import_rules_api(
    request: Request,
    entries: list[dict[str, Any]] = Body(...),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, int]:
    """Upsert rules by name — the web YAML import, as a JSON list. All or
    nothing: the first invalid rule rolls the whole import back."""
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
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    await log_event(
        db,
        request=request,
        action="notification_rule.import",
        summary=f"Imported {created_count + updated_count} notification rule(s) via the API",
        details={"created": created_count, "updated": updated_count},
    )
    return {"created": created_count, "updated": updated_count}


@router.post("/rules/{rule_id}/test", dependencies=[_manage])
async def test_rule_api(
    rule_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """The edit page's "Send test": one synthetic delivery through the
    rule's own channel/template — an email goes only to the token owner's
    own address, never the rule's real recipients."""
    rule = await _get_rule_or_404(rule_id, db)
    ok, error = await send_test_notification(
        db, rule, to_email=user.email, locale=user.locale or DEFAULT_LOCALE_CODE
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
    return {"ok": ok, "error": error}


# --- Delivery history ---------------------------------------------------------


@router.get("/history", dependencies=[_view])
async def notification_history_api(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
    rule_id: uuid.UUID | None = None,
    limit: int = Query(100, ge=1, le=_HISTORY_MAX_LIMIT),
    offset: int = Query(0, ge=0),
) -> list[dict[str, Any]]:
    """Send attempts, newest first — the History page, paginated."""
    query = select(NotificationLog).order_by(NotificationLog.sent_at.desc())
    if rule_id is not None:
        query = query.where(NotificationLog.rule_id == rule_id)
    result = await db.execute(query.limit(limit).offset(offset))
    return [
        {
            "id": str(log.id),
            "rule_id": str(log.rule_id) if log.rule_id else None,
            "rule_name": log.rule_name,
            "event_type": log.event_type,
            "channel": log.channel,
            "target": log.target,
            "machine_name": log.machine_name,
            "status": log.status,
            "error": log.error,
            "is_test": log.is_test,
            "sent_at": log.sent_at.isoformat(),
        }
        for log in result.scalars().all()
    ]


# --- Per-event templates ------------------------------------------------------


@router.get("/templates", dependencies=[_view])
async def list_templates_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, Any]]:
    """Every event type's effective template — the override if one is set,
    otherwise the built-in default in the token owner's language."""
    result = await db.execute(select(NotificationTemplate))
    overrides = {tpl.event_type: tpl for tpl in result.scalars().all()}
    locale = user.locale or DEFAULT_LOCALE_CODE
    rows: list[dict[str, Any]] = []
    for event_type in NotificationEventType:
        override = overrides.get(event_type.value)
        subject, body = (
            (override.subject, override.body)
            if override is not None
            else default_template(event_type, locale)
        )
        rows.append(
            {
                "event_type": event_type.value,
                "is_override": override is not None,
                "subject": subject,
                "body": body,
            }
        )
    return rows


@router.put("/templates/{event_type}", dependencies=[_manage])
async def update_template_api(
    event_type: NotificationEventType,
    payload: NotificationTemplateUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
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
    return {
        "event_type": event_type.value,
        "is_override": True,
        "subject": template.subject,
        "body": template.body,
    }


@router.delete(
    "/templates/{event_type}", dependencies=[_manage], status_code=status.HTTP_204_NO_CONTENT
)
async def reset_template_api(
    event_type: NotificationEventType,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> None:
    """"Reset to default" — drops the override; a no-op if there is none."""
    result = await db.execute(
        select(NotificationTemplate).where(NotificationTemplate.event_type == event_type.value)
    )
    template = result.scalar_one_or_none()
    if template is None:
        return
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


# --- Named custom templates ---------------------------------------------------


@router.get("/custom-templates", dependencies=[_view])
async def list_custom_templates_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, Any]]:
    result = await db.execute(
        select(NotificationCustomTemplate).order_by(NotificationCustomTemplate.name)
    )
    return [_custom_template_to_dict(tpl) for tpl in result.scalars().all()]


@router.post("/custom-templates", dependencies=[_manage], status_code=status.HTTP_201_CREATED)
async def create_custom_template_api(
    payload: NotificationCustomTemplateCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    template = NotificationCustomTemplate(
        name=payload.name, subject=payload.subject, body=payload.body
    )
    db.add(template)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f'A template named "{payload.name}" already exists.'
        ) from exc
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
    return _custom_template_to_dict(template)


@router.put("/custom-templates/{template_id}", dependencies=[_manage])
async def update_custom_template_api(
    template_id: uuid.UUID,
    payload: NotificationCustomTemplateCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    template = await _get_custom_template_or_404(template_id, db)
    template.name = payload.name
    template.subject = payload.subject
    template.body = payload.body
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail=f'A template named "{payload.name}" already exists.'
        ) from exc
    await log_event(
        db,
        request=request,
        action="notification_custom_template.update",
        summary=f'Updated notification template "{template.name}"',
        target_type="notification_custom_template",
        target_id=template.id,
        target_label=template.name,
    )
    return _custom_template_to_dict(template)


@router.delete(
    "/custom-templates/{template_id}",
    dependencies=[_manage],
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_custom_template_api(
    template_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> None:
    """Rules using it fall back to their per-event template."""
    template = await _get_custom_template_or_404(template_id, db)
    name = template.name
    await delete_custom_template(db, template)
    await log_event(
        db,
        request=request,
        action="notification_custom_template.delete",
        summary=f'Deleted notification template "{name}"',
        target_type="notification_custom_template",
        target_id=template_id,
        target_label=name,
    )


# --- Maintenance windows --------------------------------------------------------


def _window_to_dict(window: MaintenanceWindow) -> dict[str, Any]:
    return {
        "id": str(window.id),
        "name": window.name,
        "reason": window.reason,
        "starts_at": window.starts_at.isoformat(),
        "ends_at": window.ends_at.isoformat(),
        "state": window_state(window),
        "all_machines": window.all_machines,
        "machine_group_ids": [str(g.id) for g in window.machine_groups],
        "machine_ids": [str(m.id) for m in window.machines],
        "created_by": window.created_by,
    }


async def _get_window_or_404(window_id: uuid.UUID, db: AsyncSession) -> MaintenanceWindow:
    window = await db.get(MaintenanceWindow, window_id)
    if window is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Maintenance window not found.")
    return window


@router.get("/maintenance-windows", dependencies=[_view])
async def list_maintenance_windows_api(
    db: AsyncSession = Depends(get_db), user: User = Depends(get_api_token_user)
) -> list[dict[str, Any]]:
    """Every maintenance window, newest start first, with its `state`
    (`active`/`upcoming`/`ended`)."""
    result = await db.execute(
        select(MaintenanceWindow).order_by(MaintenanceWindow.starts_at.desc())
    )
    return [_window_to_dict(w) for w in result.scalars().all()]


@router.post(
    "/maintenance-windows", dependencies=[_manage], status_code=status.HTTP_201_CREATED
)
async def create_maintenance_window_api(
    payload: MaintenanceWindowSave,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """Schedule a window — e.g. from a deployment pipeline right before it
    reboots machines. Times are ISO 8601 (naive = UTC); at most 31 days."""
    window = MaintenanceWindow(created_by=user.username)
    await apply_window_data(db, window, payload)
    db.add(window)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="maintenance_window.create",
        summary=f'Scheduled maintenance window "{window.name}" ({window_summary(window)})',
        target_type="maintenance_window",
        target_id=window.id,
        target_label=window.name,
        details={
            "starts_at": window.starts_at.isoformat(),
            "ends_at": window.ends_at.isoformat(),
            "scope": window_summary(window),
        },
    )
    return _window_to_dict(window)


@router.put("/maintenance-windows/{window_id}", dependencies=[_manage])
async def update_maintenance_window_api(
    window_id: uuid.UUID,
    payload: MaintenanceWindowSave,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    window = await _get_window_or_404(window_id, db)
    await apply_window_data(db, window, payload)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="maintenance_window.update",
        summary=f'Updated maintenance window "{window.name}" ({window_summary(window)})',
        target_type="maintenance_window",
        target_id=window.id,
        target_label=window.name,
        details={
            "starts_at": window.starts_at.isoformat(),
            "ends_at": window.ends_at.isoformat(),
            "scope": window_summary(window),
        },
    )
    return _window_to_dict(window)


@router.post("/maintenance-windows/{window_id}/end", dependencies=[_manage])
async def end_maintenance_window_api(
    window_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> dict[str, Any]:
    """End an active window now (or cancel an upcoming one); a no-op for
    one that already ended. Notifications resume immediately."""
    window = await _get_window_or_404(window_id, db)
    now = datetime.now(UTC)
    state = window_state(window, now)
    if state != "ended":
        if state == "upcoming":
            window.starts_at = now
        window.ends_at = now
        await db.commit()
        await log_event(
            db,
            request=request,
            action="maintenance_window.end",
            summary=f'Ended maintenance window "{window.name}" early',
            target_type="maintenance_window",
            target_id=window.id,
            target_label=window.name,
        )
    return _window_to_dict(window)


@router.delete(
    "/maintenance-windows/{window_id}",
    dependencies=[_manage],
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_maintenance_window_api(
    window_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_api_token_user),
) -> None:
    window = await _get_window_or_404(window_id, db)
    name = window.name
    await db.delete(window)
    await db.commit()
    await log_event(
        db,
        request=request,
        action="maintenance_window.delete",
        summary=f'Deleted maintenance window "{name}"',
        target_type="maintenance_window",
        target_id=window_id,
        target_label=name,
    )
