from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from app.db.models.role import Permission
from app.db.models.scheduled_task import ScheduleTargetType
from app.scheduling.actions import (
    ActionRunResult,
    ScheduledActionParam,
    ScheduledActionSpec,
    all_actions,
    get_action,
    register_action,
)
from app.scheduling.builtin_actions import register_builtin_actions
from app.scheduling.cron import compute_next_run, validate_cron_expression
from app.scheduling.targets import decode_target, encode_target


def test_validate_cron_expression_accepts_standard_5_field():
    validate_cron_expression("0 3 * * *")  # must not raise


def test_validate_cron_expression_rejects_garbage():
    with pytest.raises(ValueError, match="not a valid cron expression"):
        validate_cron_expression("not a cron expression")


def test_compute_next_run_is_strictly_after_base():
    base = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
    next_run = compute_next_run("0 3 * * *", after=base)

    assert next_run > base
    assert next_run == datetime(2026, 1, 1, 3, 0, tzinfo=UTC)


def test_compute_next_run_every_six_hours():
    base = datetime(2026, 1, 1, 1, 0, tzinfo=UTC)
    next_run = compute_next_run("0 */6 * * *", after=base)

    assert next_run == datetime(2026, 1, 1, 6, 0, tzinfo=UTC)


def test_encode_decode_target_round_trips_all_machines():
    encoded = encode_target(ScheduleTargetType.ALL_MACHINES, None, None)
    assert encoded == "all"
    assert decode_target(encoded) == (ScheduleTargetType.ALL_MACHINES, None, None)


def test_encode_decode_target_round_trips_machine():
    machine_id = uuid.uuid4()
    encoded = encode_target(ScheduleTargetType.MACHINE, machine_id, None)
    assert decode_target(encoded) == (ScheduleTargetType.MACHINE, machine_id, None)


def test_encode_decode_target_round_trips_group():
    group_id = uuid.uuid4()
    encoded = encode_target(ScheduleTargetType.GROUP, None, group_id)
    assert decode_target(encoded) == (ScheduleTargetType.GROUP, None, group_id)


def test_decode_target_rejects_garbage():
    with pytest.raises(ValueError, match="Invalid target"):
        decode_target("bogus")


def test_register_builtin_actions_is_idempotent():
    register_builtin_actions()
    register_builtin_actions()  # must not raise on the second call

    keys = {action.key for action in all_actions()}
    assert {"system_update", "check_updates", "reboot", "shutdown"} <= keys


def test_builtin_reboot_and_shutdown_are_marked_destructive():
    register_builtin_actions()

    reboot = get_action("reboot")
    shutdown = get_action("shutdown")
    check_updates = get_action("check_updates")
    assert reboot is not None and reboot.destructive is True
    assert shutdown is not None and shutdown.destructive is True
    assert check_updates is not None and check_updates.destructive is False


def test_system_update_action_has_strategy_param():
    register_builtin_actions()

    action = get_action("system_update")
    assert action is not None
    param_keys = {p.key for p in action.params}
    assert param_keys == {"strategy"}


def test_force_facts_refresh_and_monitoring_sample_actions_are_registered():
    """Debug actions for forcing a fleet-wide sweep on demand, instead of
    waiting out its own interval — see app.services.machine_actions.
    trigger_facts_refresh/trigger_monitoring_sample."""
    register_builtin_actions()

    facts_action = get_action("force_facts_refresh")
    monitoring_action = get_action("force_monitoring_sample")
    assert facts_action is not None
    assert monitoring_action is not None
    assert facts_action.destructive is False
    assert monitoring_action.destructive is False
    assert facts_action.extra_permission is None
    assert monitoring_action.extra_permission is None


def test_run_command_action_is_registered_and_gated():
    register_builtin_actions()

    action = get_action("run_command")
    assert action is not None
    assert action.destructive is True
    assert action.extra_permission == Permission.ACTION_TERMINAL
    assert [p.key for p in action.params] == ["command"]
    assert action.params[0].param_type == "text"


def test_scheduled_action_param_defaults_to_select_with_no_choices():
    param = ScheduledActionParam(key="x", label="X", default="")
    assert param.param_type == "select"
    assert param.choices == []


def test_register_action_rejects_duplicate_key():
    async def _run(db, machines, params):  # pragma: no cover - never invoked
        return ActionRunResult(attempted=0, skipped=0)

    spec = ScheduledActionSpec(key="a-test-only-action", label="x", description="x", run=_run)
    register_action(spec)
    try:
        with pytest.raises(ValueError, match="already registered"):
            register_action(spec)
    finally:
        # Don't leak this test-only action into other tests' registry state.
        from app.scheduling import actions as actions_module

        actions_module._REGISTRY.pop("a-test-only-action", None)
