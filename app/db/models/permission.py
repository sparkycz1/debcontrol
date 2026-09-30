"""Every permission a role can grant — see `app.db.models.role` for how roles
bundle them and `app.db.models.user` for how MANAGE implies VIEW.

Its own module, with no model imports, so that `role`, `user` and
`temporary_permission_grant` can all use it at class-definition time
without importing each other (no import cycle between the models).
"""

import enum


class Permission(enum.StrEnum):
    MACHINE_VIEW = "machine.view"
    MACHINE_MANAGE = "machine.manage"
    GROUP_VIEW = "group.view"
    GROUP_MANAGE = "group.manage"
    # Triggering "check for updates" / "run updates", per-machine, per-group,
    # or against all machines — separate from MACHINE_MANAGE since running
    # updates isn't the same trust level as editing a machine's connection
    # details, and separate from ACTION_POWER since it isn't destructive.
    ACTION_UPDATES = "action.updates"
    # Reboot/shutdown/power-off — kept apart from ACTION_UPDATES since it's
    # destructive (see `destructive=True` on scheduled actions) and often
    # warrants a smaller set of trusted people than "can run apt upgrade".
    ACTION_POWER = "action.power"
    # Interactive SSH terminal in the browser — the single most powerful
    # capability in this app (arbitrary command execution as whatever
    # user/sudo rights the machine's configured account has), so it's its
    # own dedicated permission rather than folded into ACTION_UPDATES or
    # MACHINE_MANAGE. See app/web/routes/terminal_ws.py and
    # wiki/Architecture's "Interactive SSH terminal" section.
    ACTION_TERMINAL = "action.terminal"
    # The AI assistant page (`/ai`, app/web/routes/ai.py). This gates
    # *reaching the feature at all* and nothing else — it grants no new
    # capability against any machine on its own. Every tool the assistant
    # can invoke is separately gated by the very same permission a human
    # clicking the equivalent button would need: `machine.view` /
    # `group.view` for the two read-only lookups, `action.updates` for
    # update runs and update checks, `action.power` for reboot/shutdown,
    # `action.terminal` for an arbitrary SSH command. A role granted only
    # AI_ACCESS can chat, and can do nothing else. See
    # wiki/AI-Assistant's permission model section.
    AI_ACCESS = "ai.access"
    SCHEDULING_VIEW = "scheduling.view"
    SCHEDULING_MANAGE = "scheduling.manage"
    # Notification rules, recipient user groups, and email templates
    # (`/notifications`, app/web/routes/notifications.py) — kept apart from
    # SETTINGS_MANAGE since "who gets emailed about what" is a different,
    # narrower trust level than the rest of Settings (SMTP relay, LDAP/OIDC,
    # syslog), and apart from USER_MANAGE since a user group here is a
    # notification-recipient list, not an account-administration concept.
    NOTIFICATION_VIEW = "notification.view"
    NOTIFICATION_MANAGE = "notification.manage"
    AUDIT_VIEW = "audit.view"
    SETTINGS_VIEW = "settings.view"
    SETTINGS_MANAGE = "settings.manage"
    # Users, roles, and sessions ("log out everywhere") are bundled under one
    # permission rather than split further — none of it is meaningful
    # without the others (a role editor who can't also assign roles to users
    # isn't useful on its own).
    USER_MANAGE = "user.manage"
    # Log in as any other account without knowing their password — "Sign in
    # as" from the user list (app/web/routes/impersonation.py). Deliberately
    # its own permission, not implied by USER_MANAGE: editing accounts and
    # roles is one trust level, being able to silently act *as* one of them
    # is a materially bigger one (everything the impersonated session does is
    # audit-logged under both identities — see that module's docstring).
    USER_IMPERSONATE = "user.impersonate"
