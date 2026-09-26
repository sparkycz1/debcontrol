"""Valid ranges and audit action codes for the operational (non-secret)
settings a `settings.manage` user can change — shared by Settings →
Checks & retention / AI (`app/web/routes/settings.py`) and
`PATCH /api/v1/settings` (`app/web/routes/api_v1_settings.py`), so the two
can never disagree about what's allowed.

Bounds on the two timeouts also keep them safely under Celery's own hard
per-task time limits (`app.tasks.jobs._SSH_TASK_TIME_LIMIT_SECONDS` /
`_UPDATE_TASK_TIME_LIMIT_SECONDS`) — see `update_background_checks`'s
docstring.
"""

from __future__ import annotations

# Whole numbers within (minimum, maximum), never empty.
BOUNDED_FIELDS: dict[str, tuple[int, int]] = {
    "ssh_connect_timeout": (1, 300),
    "update_timeout_seconds": (60, 14400),
    "reachability_check_interval_seconds": (5, 86400),
    "facts_refresh_interval_seconds": (60, 604800),
    "monitoring_interval_seconds": (10, 86400),
    "reachability_check_concurrency": (1, 1000),
    "notification_condition_check_interval_seconds": (10, 86400),
    "monitoring_downsample_interval_minutes": (1, 1440),
    # Settings -> Security's sign-in policy (app.auth.session_policy).
    "session_idle_timeout_minutes": (5, 43200),
    "session_absolute_max_hours": (1, 8760),
    "login_max_failed_attempts": (1, 100),
    "login_lockout_minutes": (1, 1440),
}

# Fields whose new value must reach `app.auth.session_policy`'s in-process
# cache at once — the saving handler invalidates it.
SIGN_IN_POLICY_FIELDS: frozenset[str] = frozenset(
    {
        "session_idle_timeout_minutes",
        "session_absolute_max_hours",
        "login_max_failed_attempts",
        "login_lockout_minutes",
    }
)

# A whole number of days >= 0, or `None` for "keep forever"/"disabled".
RETENTION_FIELDS: tuple[str, ...] = (
    "audit_log_retention_days",
    "dashboard_trends_retention_days",
    "machine_update_run_retention_days",
    "notification_log_retention_days",
    "monitoring_history_retention_days",
    "monitoring_downsample_after_days",
)

# A whole number of tokens >= 0, or `None` for unlimited.
TOKEN_LIMIT_FIELDS: tuple[str, ...] = (
    "ai_daily_token_limit",
    "ai_weekly_token_limit",
    "ai_monthly_token_limit",
)

# The audit action the web form that owns each field records — the API
# records the same one, once per form touched.
AUDIT_ACTION_BY_FIELD: dict[str, str] = {
    "ssh_connect_timeout": "settings.background_checks.update",
    "update_timeout_seconds": "settings.background_checks.update",
    "reachability_check_interval_seconds": "settings.background_checks.update",
    "facts_refresh_interval_seconds": "settings.background_checks.update",
    "monitoring_interval_seconds": "settings.background_checks.update",
    "reachability_check_concurrency": "settings.background_checks.update",
    "notification_condition_check_interval_seconds": "settings.background_checks.update",
    "audit_log_retention_days": "settings.audit_retention.update",
    "dashboard_trends_retention_days": "settings.dashboard_trends_retention.update",
    "machine_update_run_retention_days": "settings.machine_update_run_retention.update",
    "notification_log_retention_days": "settings.notification_log_retention.update",
    "monitoring_history_retention_days": "settings.monitoring_retention.update",
    "monitoring_downsample_after_days": "settings.monitoring_downsampling.update",
    "monitoring_downsample_interval_minutes": "settings.monitoring_downsampling.update",
    "ai_daily_token_limit": "settings.ai_limits.update",
    "ai_weekly_token_limit": "settings.ai_limits.update",
    "ai_monthly_token_limit": "settings.ai_limits.update",
    "session_idle_timeout_minutes": "settings.sign_in_policy.update",
    "session_absolute_max_hours": "settings.sign_in_policy.update",
    "login_max_failed_attempts": "settings.sign_in_policy.update",
    "login_lockout_minutes": "settings.sign_in_policy.update",
}

# Read only by Celery Beat at its own start, so a change needs a
# worker/beat restart — reported back by the API, same note the form shows.
NEEDS_RESTART_FIELDS: frozenset[str] = frozenset(
    {
        "reachability_check_interval_seconds",
        "facts_refresh_interval_seconds",
        "monitoring_interval_seconds",
        "notification_condition_check_interval_seconds",
    }
)
