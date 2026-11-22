"""Sending what a rule held back (`app.services.notification_timing`): one
message per rule, through the rule's own channel, listing the held
notifications, and with `digest_fleet_status` the state of the rule's
machines — health, the worst machines, unreachable ones, pending security
updates, snoozed problems.

Run every minute by `app.tasks.jobs.send_due_notification_digests`. Each
email recipient gets the text in their own language; push and webhook
channels get the default language, like every other notification.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.app_settings import get_or_create_app_settings
from app.db.models.app_settings import AppSettings
from app.db.models.machine import Machine
from app.db.models.notification_log import (
    NotificationDeliveryChannel,
    NotificationDeliveryStatus,
    NotificationHeldItem,
    NotificationLog,
)
from app.db.models.notification_rule import (
    NotificationEventType,
    NotificationRule,
    NotificationTemplate,
)
from app.i18n import DEFAULT_LOCALE_CODE, get_locale, translate
from app.services import machine_health, notification_timing, push_channels
from app.services import notifications as sender

logger = logging.getLogger(__name__)

DIGEST_EVENT = "notification.digest"
# Lines listed in one message; the rest are counted.
MAX_LINES = 100
WORST_MACHINES = 5


@dataclass
class FleetStatus:
    machines: int = 0
    counts: dict[str, int] = field(default_factory=dict)
    score: int | None = None
    worst: list[tuple[str, str, str]] = field(default_factory=list)  # name, status, problem key
    worst_findings: list[machine_health.Finding | None] = field(default_factory=list)
    unreachable: list[str] = field(default_factory=list)
    security_updates: int = 0
    security_machines: int = 0
    snoozed: int = 0


async def fleet_status(db: AsyncSession, rule: NotificationRule) -> FleetStatus:
    """The state of the active machines in `rule`'s scope."""
    machines = [
        m
        for m in (await db.execute(select(Machine).where(Machine.is_active))).scalars().all()
        if sender._rule_matches_scope(rule, m)
    ]
    status = FleetStatus(machines=len(machines))
    counts: dict[str, int] = dict.fromkeys(machine_health.STATUSES, 0)
    for machine in machines:
        if machine.health_status in counts:
            counts[machine.health_status] += 1
    status.counts = counts
    status.score = machine_health.score_of(counts)
    status.unreachable = sorted(m.name for m in machines if m.is_reachable is False)
    with_security = [m for m in machines if (m.security_upgradable_count or 0) > 0]
    status.security_machines = len(with_security)
    status.security_updates = sum(m.security_upgradable_count or 0 for m in with_security)
    in_scope = {m.id for m in machines}
    worst = [
        (m, view)
        for m, view in await machine_health.worst_machines(db, None, limit=0)
        if m.id in in_scope
    ][:WORST_MACHINES]
    for machine, view in worst:
        top = next((f for f in view.active if f.severity != "info"), None)
        status.worst.append((machine.name, view.status or "", top.key if top else ""))
        status.worst_findings.append(top)
    status.snoozed = sum(
        1 for m, _s, _f in await machine_health.all_snoozes(db, None) if m.id in in_scope
    )
    return status


def _item_line(
    item: NotificationHeldItem,
    template: Any,
    locale_code: str,
) -> str:
    try:
        event = NotificationEventType(item.event_type)
    except ValueError:
        return f"- {item.event_type}"
    subject, _body = sender.render_template(
        event, template, dict(item.context or {}), locale=locale_code
    )
    when = notification_timing.local_now(
        item.created_at.replace(tzinfo=UTC) if item.created_at.tzinfo is None
        else item.created_at
    ).strftime("%H:%M")
    return f"- {when}  {subject}"


def compose(
    rule: NotificationRule,
    items: list[NotificationHeldItem],
    templates: dict[str, Any],
    status: FleetStatus | None,
    locale_code: str,
) -> tuple[str, str]:
    """Subject and body of one summary in `locale_code`."""
    locale = get_locale(locale_code)
    daily = notification_timing.parse_hhmm(rule.digest_time) is not None
    if daily:
        subject = translate(locale, "notifications.digest.subject_daily", count=len(items))
    else:
        subject = translate(locale, "notifications.digest.subject_quiet", count=len(items))
    lines: list[str] = []
    if status is not None:
        lines.append(translate(locale, "notifications.digest.fleet_heading"))
        lines.append(
            translate(
                locale,
                "notifications.digest.fleet_counts",
                machines=status.machines,
                score="—" if status.score is None else status.score,
                ok=status.counts.get("ok", 0) + status.counts.get("info", 0),
                warning=status.counts.get("warning", 0),
                critical=status.counts.get("critical", 0),
            )
        )
        if status.unreachable:
            lines.append(
                translate(
                    locale,
                    "notifications.digest.unreachable",
                    names=", ".join(status.unreachable[:20]),
                )
            )
        if status.security_updates:
            lines.append(
                translate(
                    locale,
                    "notifications.digest.security_updates",
                    count=status.security_updates,
                    machines=status.security_machines,
                )
            )
        if status.snoozed:
            lines.append(
                translate(locale, "notifications.digest.snoozed", count=status.snoozed)
            )
        if status.worst:
            lines.append(translate(locale, "notifications.digest.worst_heading"))
            for (name, health, _key), finding in zip(
                status.worst, status.worst_findings, strict=True
            ):
                problem = machine_health.finding_text(finding, locale_code) if finding else ""
                lines.append(f"- {name} ({health}){': ' + problem if problem else ''}")
        lines.append("")
    if items:
        lines.append(
            translate(locale, "notifications.digest.held_heading", count=len(items))
        )
        lines.extend(
            _item_line(item, templates.get(item.event_type), locale_code)
            for item in items[:MAX_LINES]
        )
        if len(items) > MAX_LINES:
            lines.append(
                translate(locale, "notifications.digest.more", count=len(items) - MAX_LINES)
            )
    else:
        lines.append(translate(locale, "notifications.digest.nothing_held"))
    return subject, "\n".join(lines).strip() + "\n"


async def _deliver(
    db: AsyncSession,
    app_settings: AppSettings,
    rule: NotificationRule,
    render: Callable[[str], tuple[str, str]],
) -> list[NotificationLog]:
    """One summary through the rule's channel — the same senders `notify`
    uses, one history row per attempt."""
    channel = rule.delivery_channel

    def log(
        target: str, status: NotificationDeliveryStatus, error: str | None
    ) -> NotificationLog:
        return sender._delivery_log(
            rule=rule,
            rule_name=rule.name,
            event_type=DIGEST_EVENT,
            channel=NotificationDeliveryChannel(channel),
            target=target,
            machine=None,
            status=status,
            error=error,
        )

    if channel in push_channels.PUSH_CHANNELS:
        subject, body = render(DEFAULT_LOCALE_CODE)
        status, error = await sender._send_push(rule, subject, body)
        target = push_channels.delivery_target(channel, rule.webhook_url, rule.channel_recipient)
        return [log(target, status, error)]
    if channel == NotificationDeliveryChannel.WEBHOOK.value:
        if not rule.webhook_url:
            return []
        subject, body = render(DEFAULT_LOCALE_CODE)
        status, error = await sender._send_webhook(
            rule.webhook_url,
            DIGEST_EVENT,
            rule.name,
            subject,
            body,
            {"timestamp": datetime.now(UTC).isoformat()},
        )
        return [log(push_channels.redact_url(rule.webhook_url), status, error)]
    if not app_settings.smtp_enabled or not app_settings.smtp_host:
        return []
    logs: list[NotificationLog] = []
    for user in await sender._recipients(db, [rule]):
        assert user.email is not None
        subject, body = render(user.locale or DEFAULT_LOCALE_CODE)
        status, error = NotificationDeliveryStatus.SENT, None
        try:
            await asyncio.to_thread(
                sender.send_smtp_message, app_settings, user.email, subject, body
            )
        except Exception as exc:
            logger.warning("Failed to send a notification summary to %s", user.email)
            status, error = NotificationDeliveryStatus.FAILED, str(exc)[:2000]
        logs.append(log(user.email, status, error))
    return logs


async def send_digest(
    db: AsyncSession, rule: NotificationRule, now: datetime | None = None
) -> list[NotificationLog]:
    """Send `rule`'s summary now (whether due or not) and forget the held
    items it listed. Commits."""
    now = now or datetime.now(UTC)
    app_settings = await get_or_create_app_settings(db)
    items = list(
        (
            await db.execute(
                select(NotificationHeldItem)
                .where(NotificationHeldItem.rule_id == rule.id)
                .order_by(NotificationHeldItem.created_at, NotificationHeldItem.id)
            )
        )
        .scalars()
        .all()
    )
    daily = notification_timing.parse_hhmm(rule.digest_time) is not None
    status = await fleet_status(db, rule) if daily and rule.digest_fleet_status else None
    templates: dict[str, Any] = {}
    if rule.custom_template_id and rule.custom_template is not None:
        templates = {item.event_type: rule.custom_template for item in items}
    else:
        rows = (
            await db.execute(
                select(NotificationTemplate).where(
                    NotificationTemplate.event_type.in_({i.event_type for i in items})
                )
            )
        ).scalars().all()
        templates = {row.event_type: row for row in rows}

    logs = await _deliver(
        db,
        app_settings,
        rule,
        lambda locale_code: compose(rule, items, templates, status, locale_code),
    )
    for item in items:
        await db.delete(item)
    rule.digest_last_sent_at = now.astimezone(UTC).replace(tzinfo=None)
    db.add_all(logs)
    await db.commit()
    return logs


async def send_due_digests(db: AsyncSession, now: datetime | None = None) -> int:
    """Every enabled rule whose summary is due — see
    `notification_timing.digest_due`. Returns how many were sent; one
    rule's failure never stops the others."""
    now = now or datetime.now(UTC)
    rules = (
        await db.execute(select(NotificationRule).where(NotificationRule.enabled.is_(True)))
    ).scalars().all()
    waiting = set(
        (await db.execute(select(NotificationHeldItem.rule_id).distinct())).scalars().all()
    )
    due = [
        (rule.id, rule.name)
        for rule in rules
        if notification_timing.digest_due(rule, now, rule.id in waiting)
    ]
    sent = 0
    for rule_id, name in due:
        try:
            # Loaded again: a rollback after another rule's failure expires
            # every object the session holds.
            rule = await db.get(NotificationRule, rule_id)
            if rule is None:
                continue
            await send_digest(db, rule, now)
            sent += 1
        except Exception:
            logger.warning("Notification summary for rule %s failed", name, exc_info=True)
            await db.rollback()
    return sent
