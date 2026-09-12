"""Notification dispatch and email delivery — the "when X happens, tell
these people" pipeline behind Notifications (`app/web/routes/notifications.py`,
`app.db.models.notification_rule`). See that model module's docstring for
what a rule/template actually holds; this module is the one place that
reads them and turns a matching event into a sent email.

Call `notify(db, event_type, machine=..., context=...)` right after the
triggering fact is committed. Every failure here — no SMTP configured, no
matching rule, no recipient with an email set, the SMTP server itself
refusing the connection — is caught and logged, never raised: a
notification that fails to send must never break the background job that
triggered it, the same "best-effort, never load-bearing" spirit
`app.audit_syslog.forward_to_syslog` already has for the audit log's own
external mirror.

Current call sites (see `NotificationEventType`'s own docstring for how to
add another):
- `app.tasks.jobs._ping_all_machines` / `_check_machine_reachability_now`
  — MACHINE_UNREACHABLE / MACHINE_REACHABLE_AGAIN, fired only on a
  reachability *transition*, never on every poll tick that confirms the
  same state.
- `app.tasks.jobs._run_machine_update` — UPDATE_RUN_FAILED / UPDATE_RUN_SUCCEEDED.
- `app.tasks.jobs._run_machine_onboarding` — MACHINE_ONBOARDED, on success.
- `app.tasks.ai_jobs._generate_fleet_summary` — FLEET_SUMMARY_GENERATED.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.app_settings import get_or_create_app_settings
from app.core.security import decrypt_secret
from app.db.models.app_settings import AppSettings, SmtpEncryption
from app.db.models.machine import Machine
from app.db.models.notification_rule import (
    NotificationEventType,
    NotificationRule,
    NotificationTemplate,
)
from app.db.models.user import User
from app.i18n import DEFAULT_LOCALE_CODE

logger = logging.getLogger(__name__)

# Built-in subject/body used whenever no `NotificationTemplate` row
# overrides a given event type, keyed by locale code (same codes as
# `app.i18n` — currently "en"/"cs") — every `NotificationEventType` member
# needs an entry in every locale here. A locale with no entry falls back
# to `DEFAULT_LOCALE_CODE` (English), same "never worse than doing
# nothing" fallback `app.i18n.translate` itself uses. Which locale is
# used for a given recipient is `User.locale` (see `notify`'s "one email
# per recipient, rendered in *their* language" below) — an admin-edited
# `NotificationTemplate` override is a single value, not per-locale, since
# an admin who customizes the wording is expected to write it in
# whichever language they want every recipient to see it in.
_DEFAULT_TEMPLATES: dict[str, dict[NotificationEventType, tuple[str, str]]] = {
    "en": {
        NotificationEventType.MACHINE_UNREACHABLE: (
            "debcontrol: {machine_name} is unreachable",
            "{machine_name} ({machine_ip}) stopped responding to reachability checks "
            "at {timestamp}.\n\n{details}",
        ),
        NotificationEventType.MACHINE_REACHABLE_AGAIN: (
            "debcontrol: {machine_name} is reachable again",
            "{machine_name} ({machine_ip}) responded to a reachability check again "
            "at {timestamp}, after previously being unreachable.\n\n{details}",
        ),
        NotificationEventType.UPDATE_RUN_FAILED: (
            "debcontrol: update run failed on {machine_name}",
            "An update run on {machine_name} ({machine_ip}) failed at {timestamp}.\n\n{details}",
        ),
        NotificationEventType.UPDATE_RUN_SUCCEEDED: (
            "debcontrol: update run succeeded on {machine_name}",
            "An update run on {machine_name} ({machine_ip}) finished successfully at "
            "{timestamp}.\n\n{details}",
        ),
        NotificationEventType.MACHINE_ONBOARDED: (
            "debcontrol: {machine_name} finished onboarding",
            "{machine_name} ({machine_ip}) finished onboarding at {timestamp} and is now "
            "managed with debcontrol's own SSH identity.",
        ),
        NotificationEventType.FLEET_SUMMARY_GENERATED: (
            "debcontrol: new fleet summary ({timestamp})",
            "The scheduled AI fleet summary generated at {timestamp} is ready.\n\n{details}",
        ),
    },
    "cs": {
        NotificationEventType.MACHINE_UNREACHABLE: (
            "debcontrol: {machine_name} je nedostupný",
            "{machine_name} ({machine_ip}) přestal reagovat na kontrolu dostupnosti "
            "v {timestamp}.\n\n{details}",
        ),
        NotificationEventType.MACHINE_REACHABLE_AGAIN: (
            "debcontrol: {machine_name} je opět dostupný",
            "{machine_name} ({machine_ip}) znovu reagoval na kontrolu dostupnosti "
            "v {timestamp}, poté co byl nedostupný.\n\n{details}",
        ),
        NotificationEventType.UPDATE_RUN_FAILED: (
            "debcontrol: aktualizace na {machine_name} selhala",
            "Aktualizace na stroji {machine_name} ({machine_ip}) selhala v {timestamp}."
            "\n\n{details}",
        ),
        NotificationEventType.UPDATE_RUN_SUCCEEDED: (
            "debcontrol: aktualizace na {machine_name} proběhla úspěšně",
            "Aktualizace na stroji {machine_name} ({machine_ip}) úspěšně doběhla v "
            "{timestamp}.\n\n{details}",
        ),
        NotificationEventType.MACHINE_ONBOARDED: (
            "debcontrol: {machine_name} dokončil onboarding",
            "{machine_name} ({machine_ip}) dokončil onboarding v {timestamp} a je nyní "
            "spravován pod vlastní SSH identitou debcontrolu.",
        ),
        NotificationEventType.FLEET_SUMMARY_GENERATED: (
            "debcontrol: nové shrnutí flotily ({timestamp})",
            "Plánované AI shrnutí flotily vygenerované v {timestamp} je hotové.\n\n{details}",
        ),
    },
}


class _SafeDict(dict[str, str]):
    """Used with `str.format_map` so a placeholder an admin-edited template
    doesn't recognize (a typo, or a context key this event type doesn't
    provide) is left as literal text instead of raising `KeyError` and
    losing the whole notification."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def default_template(
    event_type: NotificationEventType, locale: str = DEFAULT_LOCALE_CODE
) -> tuple[str, str]:
    """The built-in (subject, body) for `event_type` in `locale`, used
    whenever no `NotificationTemplate` row overrides it — also what the
    Notifications → Templates page shows as the starting point to edit
    (in the viewing admin's own UI language — see
    `app/web/routes/notifications.py`), and what "Reset to default" puts
    back. A `locale` with no translations here falls back to English."""
    return _DEFAULT_TEMPLATES.get(locale, _DEFAULT_TEMPLATES[DEFAULT_LOCALE_CODE])[event_type]


def render_template(
    event_type: NotificationEventType,
    template: NotificationTemplate | None,
    context: dict[str, Any],
    *,
    locale: str = DEFAULT_LOCALE_CODE,
) -> tuple[str, str]:
    """Subject and body for one event, substituting `{placeholder}` values
    from `context` into the stored (or built-in default for `locale`, if
    `template` is None) text — plain `str.format_map`, not a template
    engine, so an admin-edited body can never execute code or reach
    outside its own string (see `NotificationTemplate`'s docstring).
    Missing placeholders are left as literal text rather than raising.

    Placeholders every event type provides: `{event}` (the event type's
    code, e.g. "machine.unreachable"), `{timestamp}` (UTC ISO-8601).
    Machine-scoped events additionally provide `{machine_name}` and
    `{machine_ip}`. `{details}` is free-form, event-specific text passed
    via `notify`'s `context`."""
    if template is not None:
        subject_tpl, body_tpl = template.subject, template.body
    else:
        subject_tpl, body_tpl = default_template(event_type, locale)
    safe_context = _SafeDict({k: "" if v is None else str(v) for k, v in context.items()})
    return subject_tpl.format_map(safe_context), body_tpl.format_map(safe_context)


def _rule_matches_scope(rule: NotificationRule, machine: Machine | None) -> bool:
    """Empty `machines` and `machine_groups` means "every machine" — see
    `NotificationRule`'s own docstring. An event with no machine at all
    (none currently fire that way, but nothing here assumes one always
    will) matches every rule's scope, since there's nothing to check it
    against."""
    if machine is None:
        return True
    if not rule.machines and not rule.machine_groups:
        return True
    if any(m.id == machine.id for m in rule.machines):
        return True
    return machine.group_id is not None and any(
        g.id == machine.group_id for g in rule.machine_groups
    )


async def _matching_rules(
    db: AsyncSession, event_type: NotificationEventType, machine: Machine | None
) -> list[NotificationRule]:
    # Rules are admin-authored config, not fleet-scale data — loading every
    # enabled one and filtering in Python (rather than a JSON-contains query
    # that would need different SQL per database backend) is the simplest
    # correct thing, same reasoning `app.audit_syslog` gives for not
    # over-engineering a low-cardinality lookup.
    result = await db.execute(select(NotificationRule).where(NotificationRule.enabled.is_(True)))
    rules = list(result.scalars().all())
    return [
        rule
        for rule in rules
        if event_type in rule.event_type_enums and _rule_matches_scope(rule, machine)
    ]


async def _recipients(db: AsyncSession, rules: list[NotificationRule]) -> list[User]:
    """The union of every matching rule's recipients — directly-listed
    users plus every active user holding one of its target roles —
    deduplicated by id, and silently dropping a disabled account or one
    with no `User.email` set (see `NotificationRule`'s docstring). Returns
    full `User` objects, not just addresses, so `notify` can render each
    one's email in *their* own `User.locale` (see this module's i18n note
    above)."""
    by_id: dict[object, User] = {u.id: u for u in (u for rule in rules for u in rule.users)}
    role_ids = {role.id for rule in rules for role in rule.roles}
    if role_ids:
        result = await db.execute(select(User).where(User.role_id.in_(role_ids)))
        for user in result.scalars().all():
            by_id[user.id] = user
    return [u for u in by_id.values() if u.is_active and u.email]


def _send_smtp_message(
    app_settings: AppSettings, to_address: str, subject: str, body: str
) -> None:
    """Synchronous SMTP send (stdlib `smtplib`) — run via `asyncio.to_thread`
    from `notify` below, the same "sync library, async caller" seam every
    Celery task in `app.tasks.jobs` already crosses, rather than adding an
    async SMTP client dependency for one feature. One connection per
    recipient — simple and correct at the small recipient counts a
    notification rule realistically has; reusing one connection for a
    multi-recipient send is a possible future optimization, not a
    correctness issue."""
    message = EmailMessage()
    message["Subject"] = subject
    from_name = app_settings.smtp_from_name or "debcontrol"
    from_address = app_settings.smtp_from_address or app_settings.smtp_username or to_address
    message["From"] = f"{from_name} <{from_address}>"
    message["To"] = to_address
    message.set_content(body)

    assert app_settings.smtp_host is not None  # checked by the caller (notify)
    connect: type[smtplib.SMTP] = (
        smtplib.SMTP_SSL
        if app_settings.smtp_encryption == SmtpEncryption.SSL_TLS
        else smtplib.SMTP
    )
    with connect(app_settings.smtp_host, app_settings.smtp_port, timeout=15) as client:
        if app_settings.smtp_encryption == SmtpEncryption.STARTTLS:
            client.starttls()
        if app_settings.smtp_username and app_settings.smtp_password_encrypted:
            client.login(
                app_settings.smtp_username, decrypt_secret(app_settings.smtp_password_encrypted)
            )
        client.send_message(message)


async def notify(
    db: AsyncSession,
    event_type: NotificationEventType,
    *,
    machine: Machine | None = None,
    context: dict[str, Any] | None = None,
) -> None:
    """Fire `event_type` — find every enabled rule that lists it and whose
    scope includes `machine` (or has no scope at all), resolve their
    recipients, and email each one. A complete no-op when SMTP isn't
    enabled, no rule matches, or no recipient has an email address — see
    the module docstring for why this never raises."""
    try:
        app_settings = await get_or_create_app_settings(db)
        if not app_settings.smtp_enabled or not app_settings.smtp_host:
            return
        rules = await _matching_rules(db, event_type, machine)
        if not rules:
            return
        recipients = await _recipients(db, rules)
        if not recipients:
            return

        template = (
            await db.execute(
                select(NotificationTemplate).where(
                    NotificationTemplate.event_type == event_type.value
                )
            )
        ).scalar_one_or_none()
        full_context: dict[str, Any] = dict(context or {})
        full_context.setdefault("event", event_type.value)
        full_context.setdefault("timestamp", datetime.now(UTC).isoformat())
        full_context.setdefault("details", "")
        if machine is not None:
            full_context.setdefault("machine_name", machine.name)
            full_context.setdefault("machine_ip", machine.ip_address)

        # Rendered once per recipient, in *their* own UI language
        # (`User.locale`, same field the rest of the app already uses for
        # this) rather than once for everyone — an admin-set template
        # override is still a single value regardless of locale (see the
        # module-level note above `_DEFAULT_TEMPLATES`).
        for user in recipients:
            assert user.email is not None  # guaranteed by `_recipients`
            subject, body = render_template(
                event_type, template, full_context, locale=user.locale or DEFAULT_LOCALE_CODE
            )
            try:
                await asyncio.to_thread(
                    _send_smtp_message, app_settings, user.email, subject, body
                )
            except Exception:
                logger.warning(
                    "Failed to send notification email to %s", user.email, exc_info=True
                )
    except Exception:
        logger.warning(
            "Notification dispatch failed for event=%s", event_type.value, exc_info=True
        )
