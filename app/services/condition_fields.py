"""The curated, code-defined set of fields a `NotificationCondition` can
reference — everything debcontrol already knows about a machine, either
from its latest facts snapshot (`Machine`) or its latest monitoring sample
(`MachineMonitoringSample`). See `app.db.models.notification_condition`'s
module docstring for why this is a registry, not an arbitrary-expression
engine.

Adding a field means adding one `ConditionField` entry here — nothing else
needs to change (the evaluation sweep, the rule form, and the YAML
import/export all read this registry rather than hardcoding field names).
"""

from __future__ import annotations

import operator as op
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from app.db.models.machine import Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.services.disk_forecast import soonest_full_days

ValueType = Literal["number", "string", "bool"]


@dataclass(frozen=True)
class ConditionField:
    #: i18n key for the field's label, under `notifications.condition_field.`
    label_key: str
    value_type: ValueType
    #: Reads the current value off a machine (+ its latest monitoring
    #: sample, if any) — None means "unknown," which never matches any
    #: condition on this field (a machine with no sample yet, or a fact
    #: that hasn't been gathered, simply can't trigger a condition on it).
    accessor: Callable[[Machine, MachineMonitoringSample | None, str | None], Any]
    #: Only "monitoring.filesystem_use_percent" needs a mount_point to
    #: disambiguate which filesystem row to read.
    needs_mount: bool = False


def _filesystem_percent(
    filesystems: list[dict[str, Any]] | None, mount_point: str | None
) -> float | None:
    if not filesystems or not mount_point:
        return None
    for entry in filesystems:
        if entry.get("mount") == mount_point:
            value = entry.get("use_percent") if "use_percent" in entry else entry.get("percent")
            return float(value) if value is not None else None
    return None


def _max_temperature(sample: MachineMonitoringSample | None) -> float | None:
    """Hottest sensor in the latest sample — one threshold covers every
    sensor, whatever they're called on this machine."""
    readings = [
        float(t["celsius"])
        for t in (sample.sensor_temps or [] if sample else [])
        if isinstance(t, dict) and isinstance(t.get("celsius"), (int, float))
    ]
    return max(readings) if readings else None


def _smart_failed_count(sample: MachineMonitoringSample | None) -> int | None:
    """Disks whose S.M.A.R.T. overall health said FAILED. None (unknown)
    when the latest sample has no S.M.A.R.T. data at all — a VM, or no
    smartctl access — so a "count > 0" rule can't silently pass there."""
    if sample is None or not sample.smart_disks:
        return None
    return sum(1 for d in sample.smart_disks if isinstance(d, dict) and d.get("healthy") is False)


def _docker_count(machine: Machine, predicate: Callable[[dict[str, Any]], bool]) -> int | None:
    """Containers matching `predicate` in the latest container list. None
    unless Docker was actually readable (`docker_status == "ok"`)."""
    if machine.docker_status != "ok":
        return None
    return sum(1 for c in (machine.docker_containers or []) if isinstance(c, dict) and predicate(c))


def _exited_with_error(container: dict[str, Any]) -> bool:
    status = str(container.get("status") or "")
    return container.get("state") in ("exited", "dead") and not status.startswith("Exited (0)")


CONDITION_FIELDS: dict[str, ConditionField] = {
    "machine.os_id": ConditionField(
        "os_id", "string", lambda m, s, mount: m.os_id
    ),
    "machine.os_version": ConditionField(
        "os_version", "string", lambda m, s, mount: m.os_version
    ),
    "machine.kernel_version": ConditionField(
        "kernel_version", "string", lambda m, s, mount: m.kernel_version
    ),
    "machine.cpu_architecture": ConditionField(
        "cpu_architecture", "string", lambda m, s, mount: m.cpu_architecture
    ),
    "machine.cpu_cores": ConditionField(
        "cpu_cores", "number", lambda m, s, mount: m.cpu_cores
    ),
    "machine.uptime_seconds": ConditionField(
        "uptime_seconds", "number", lambda m, s, mount: m.uptime_seconds
    ),
    "machine.reboot_required": ConditionField(
        "reboot_required", "bool", lambda m, s, mount: m.reboot_required
    ),
    "machine.upgradable_count": ConditionField(
        "upgradable_count", "number", lambda m, s, mount: m.upgradable_count
    ),
    "machine.security_upgradable_count": ConditionField(
        "security_upgradable_count",
        "number",
        lambda m, s, mount: m.security_upgradable_count,
    ),
    "machine.is_reachable": ConditionField(
        "is_reachable", "bool", lambda m, s, mount: m.is_reachable
    ),
    "monitoring.cpu_percent": ConditionField(
        "cpu_percent", "number", lambda m, s, mount: s.cpu_percent if s else None
    ),
    "monitoring.load1": ConditionField(
        "load1", "number", lambda m, s, mount: s.load1 if s else None
    ),
    "monitoring.load5": ConditionField(
        "load5", "number", lambda m, s, mount: s.load5 if s else None
    ),
    "monitoring.load15": ConditionField(
        "load15", "number", lambda m, s, mount: s.load15 if s else None
    ),
    "monitoring.ram_percent": ConditionField(
        "ram_percent",
        "number",
        lambda m, s, mount: (
            (s.ram_used_bytes / s.ram_total_bytes * 100)
            if s and s.ram_used_bytes is not None and s.ram_total_bytes
            else None
        ),
    ),
    "monitoring.filesystem_use_percent": ConditionField(
        "filesystem_use_percent",
        "number",
        lambda m, s, mount: _filesystem_percent(s.filesystems if s else None, mount),
        needs_mount=True,
    ),
    "monitoring.failed_services_count": ConditionField(
        "failed_services_count",
        "number",
        lambda m, s, mount: s.failed_services_count if s else None,
    ),
    # --- Hardware (bare metal only; unknown on a VM, so never matches) ---
    "monitoring.max_temperature_c": ConditionField(
        "max_temperature_c", "number", lambda m, s, mount: _max_temperature(s)
    ),
    "monitoring.smart_failed_count": ConditionField(
        "smart_failed_count", "number", lambda m, s, mount: _smart_failed_count(s)
    ),
    # --- Disk-full forecast (Machine.disk_forecast, recomputed hourly) ---
    "monitoring.disk_full_days": ConditionField(
        "disk_full_days", "number", lambda m, s, mount: soonest_full_days(m.disk_forecast)
    ),
    # --- Docker (latest container list, see Machine.docker_containers) ---
    "docker.unhealthy_count": ConditionField(
        "docker_unhealthy_count",
        "number",
        lambda m, s, mount: _docker_count(m, lambda c: c.get("health") == "unhealthy"),
    ),
    "docker.restarting_count": ConditionField(
        "docker_restarting_count",
        "number",
        lambda m, s, mount: _docker_count(m, lambda c: c.get("state") == "restarting"),
    ),
    "docker.exited_error_count": ConditionField(
        "docker_exited_error_count",
        "number",
        lambda m, s, mount: _docker_count(m, _exited_with_error),
    ),
}


class UnknownOperatorError(ValueError):
    pass


_NUMERIC_OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "gt": op.gt,
    "gte": op.ge,
    "lt": op.lt,
    "lte": op.le,
    "eq": op.eq,
    "ne": op.ne,
}
_STRING_OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": op.eq,
    "ne": op.ne,
    "contains": lambda a, b: b in a,
    "not_contains": lambda a, b: b not in a,
    "in": lambda a, b: a in [v.strip() for v in b.split(",")],
    "not_in": lambda a, b: a not in [v.strip() for v in b.split(",")],
}
_BOOL_OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": op.eq,
    "ne": op.ne,
}

#: Every operator key valid for at least one value type — used by the rule
#: form/YAML validation to reject an unknown operator outright.
ALL_OPERATORS: tuple[str, ...] = (
    "gt",
    "gte",
    "lt",
    "lte",
    "eq",
    "ne",
    "contains",
    "not_contains",
    "in",
    "not_in",
)


def operators_for(value_type: ValueType) -> dict[str, Callable[[Any, Any], bool]]:
    if value_type == "number":
        return _NUMERIC_OPERATORS
    if value_type == "string":
        return _STRING_OPERATORS
    return _BOOL_OPERATORS


def _parse_value(raw: str, value_type: ValueType) -> Any:
    if value_type == "number":
        return float(raw)
    if value_type == "bool":
        return raw.strip().lower() in ("1", "true", "yes", "on")
    return raw


def evaluate_condition(
    field_key: str,
    operator_key: str,
    raw_value: str,
    machine: Machine,
    sample: MachineMonitoringSample | None,
    mount_point: str | None,
) -> bool:
    """`True` only if the field's current value is known *and* the operator
    matches it against `raw_value`. Unknown field/operator or an unparsable
    stored value never matches (never raises) — a bad/legacy condition row
    should silently never fire, not break the whole sweep for every other
    rule/machine (see `app.tasks.jobs.evaluate_notification_conditions`)."""
    condition_field = CONDITION_FIELDS.get(field_key)
    if condition_field is None:
        return False
    operators = operators_for(condition_field.value_type)
    comparator = operators.get(operator_key)
    if comparator is None:
        return False
    actual = condition_field.accessor(machine, sample, mount_point)
    if actual is None:
        return False
    try:
        if condition_field.value_type == "number":
            return bool(comparator(float(actual), _parse_value(raw_value, "number")))
        if condition_field.value_type == "bool":
            return bool(comparator(bool(actual), _parse_value(raw_value, "bool")))
        return bool(comparator(str(actual), raw_value))
    except (TypeError, ValueError):
        return False


def summarize_condition(
    field_key: str, operator_key: str, raw_value: str, mount_point: str | None
) -> str:
    """Human-readable rendering of one condition, e.g. "cpu_percent > 90"
    or "filesystem_use_percent (/var) >= 85" — used to build the
    `{condition_summary}` notification placeholder (see
    `app.services.notifications`'s CONDITION_MATCHED default templates)."""
    field_label = field_key.split(".", 1)[-1]
    if mount_point:
        field_label = f"{field_label} ({mount_point})"
    return f"{field_label} {operator_key} {raw_value}"
