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
    "ssh_connection_reuse_minutes": (0, 1440),
    "update_timeout_seconds": (60, 14400),
    "reachability_check_interval_seconds": (5, 86400),
    "facts_refresh_interval_seconds": (60, 604800),
    "monitoring_interval_seconds": (10, 86400),
    "reachability_check_concurrency": (1, 1000),
    "notification_condition_check_interval_seconds": (10, 86400),
    "monitoring_downsample_interval_minutes": (1, 1440),
    "docker_image_check_interval_hours": (1, 168),
    # Settings -> Security's sign-in policy (app.auth.session_policy).
    "session_idle_timeout_minutes": (5, 43200),
    "session_absolute_max_hours": (1, 8760),
    "login_max_failed_attempts": (1, 100),
    "login_lockout_minutes": (1, 1440),
    # Machine health thresholds (app.services.machine_health).
    "health_cpu_warn_percent": (1, 100),
    "health_cpu_critical_percent": (1, 100),
    "health_memory_warn_percent": (1, 100),
    "health_memory_critical_percent": (1, 100),
    "health_disk_warn_percent": (1, 100),
    "health_disk_critical_percent": (1, 100),
    "health_temperature_warn_celsius": (20, 150),
    "health_temperature_critical_celsius": (20, 150),
    "health_disk_full_warn_days": (1, 365),
    "health_disk_full_critical_days": (0, 365),
    "health_latency_warn_ms": (1, 10000),
    "health_latency_critical_ms": (1, 10000),
}

# (warning, critical) pairs that must stay in order: a percent or a
# temperature warns before it is critical; "days until full" warns at more
# days than it is critical at.
HEALTH_THRESHOLD_PAIRS: tuple[tuple[str, str, bool], ...] = (
    # (warning field, critical field, critical is the higher number)
    ("health_cpu_warn_percent", "health_cpu_critical_percent", True),
    ("health_memory_warn_percent", "health_memory_critical_percent", True),
    ("health_disk_warn_percent", "health_disk_critical_percent", True),
    ("health_temperature_warn_celsius", "health_temperature_critical_celsius", True),
    ("health_disk_full_warn_days", "health_disk_full_critical_days", False),
    ("health_latency_warn_ms", "health_latency_critical_ms", True),
)


def threshold_pairs_out_of_order(values: dict[str, object]) -> list[tuple[str, str, bool]]:
    """The `HEALTH_THRESHOLD_PAIRS` whose warning level is not short of the
    critical one in `values` (the merged old and new settings)."""
    wrong: list[tuple[str, str, bool]] = []
    for warn, critical, critical_higher in HEALTH_THRESHOLD_PAIRS:
        low, high = values.get(warn), values.get(critical)
        if not isinstance(low, int) or not isinstance(high, int):
            continue
        if (critical_higher and low >= high) or (not critical_higher and low <= high):
            wrong.append((warn, critical, critical_higher))
    return wrong


def threshold_pair_errors(values: dict[str, object]) -> list[str]:
    """`threshold_pairs_out_of_order` as English sentences (the API)."""
    return [
        f"{warn} must be {'lower' if higher else 'higher'} than {critical}"
        for warn, critical, higher in threshold_pairs_out_of_order(values)
    ]


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

# On/off switches (true/false).
BOOLEAN_FIELDS: tuple[str, ...] = (
    # Endpoint checks for container web links (app.services.docker_endpoint_checks).
    "docker_endpoint_checks",
    # Connectivity from the machines (app.ssh.connectivity).
    "connectivity_checks_enabled",
)

# A host name or IP address the machines ping or resolve
# (`app.ssh.connectivity.valid_target`).
TARGET_FIELDS: tuple[str, ...] = (
    "connectivity_internet_target",
    "connectivity_dns_name",
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
    "ssh_connection_reuse_minutes": "settings.background_checks.update",
    "update_timeout_seconds": "settings.background_checks.update",
    "reachability_check_interval_seconds": "settings.background_checks.update",
    "facts_refresh_interval_seconds": "settings.background_checks.update",
    "monitoring_interval_seconds": "settings.background_checks.update",
    "reachability_check_concurrency": "settings.background_checks.update",
    "notification_condition_check_interval_seconds": "settings.background_checks.update",
    "docker_image_check_interval_hours": "settings.background_checks.update",
    "docker_endpoint_checks": "settings.background_checks.update",
    "connectivity_checks_enabled": "settings.background_checks.update",
    "connectivity_internet_target": "settings.background_checks.update",
    "connectivity_dns_name": "settings.background_checks.update",
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
    **dict.fromkeys(
        (name for name in BOUNDED_FIELDS if name.startswith("health_")),
        "settings.health_thresholds.update",
    ),
}

# Fields whose change needs a worker/beat restart — none any more: Beat
# re-reads its intervals about once a minute (`app.tasks.celery_app.
# SettingInterval`). Kept (empty) so `PATCH /api/v1/settings` still returns
# its `needs_restart` list for scripts that read it.
NEEDS_RESTART_FIELDS: frozenset[str] = frozenset()
