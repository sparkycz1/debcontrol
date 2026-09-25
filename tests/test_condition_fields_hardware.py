"""The hardware/Docker notification condition fields
(`app.services.condition_fields`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.db.models.machine import AuthMethod, Machine
from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.services.condition_fields import CONDITION_FIELDS, evaluate_condition


def _machine(**fields: object) -> Machine:
    machine = Machine(
        name="m", ip_address="10.0.0.1", port=22, username="u", auth_method=AuthMethod.PASSWORD
    )
    for key, value in fields.items():
        setattr(machine, key, value)
    return machine


def _sample(**fields: object) -> MachineMonitoringSample:
    sample = MachineMonitoringSample(
        id=uuid.uuid4(), machine_id=uuid.uuid4(), sampled_at=datetime.now(UTC)
    )
    for key, value in fields.items():
        setattr(sample, key, value)
    return sample


def test_max_temperature_matches_the_hottest_sensor():
    sample = _sample(
        sensor_temps=[{"name": "a", "celsius": 45.0}, {"name": "b", "celsius": 82.5}]
    )

    assert evaluate_condition("monitoring.max_temperature_c", "gt", "80", _machine(), sample, None)
    assert not evaluate_condition(
        "monitoring.max_temperature_c", "gt", "90", _machine(), sample, None
    )


def test_max_temperature_unknown_without_sensors():
    sample = _sample(sensor_temps=[])

    assert not evaluate_condition(
        "monitoring.max_temperature_c", "lt", "1000", _machine(), sample, None
    )


def test_smart_failed_count():
    sample = _sample(
        smart_disks=[{"device": "sda", "healthy": True}, {"device": "sdb", "healthy": False}]
    )

    assert evaluate_condition("monitoring.smart_failed_count", "gt", "0", _machine(), sample, None)


def test_smart_failed_count_unknown_without_data():
    assert not evaluate_condition(
        "monitoring.smart_failed_count", "eq", "0", _machine(), _sample(smart_disks=[]), None
    )


def test_docker_counts():
    machine = _machine(
        docker_status="ok",
        docker_containers=[
            {"name": "a", "state": "running", "health": "unhealthy", "status": "Up"},
            {"name": "b", "state": "restarting", "health": None, "status": "Restarting (1)"},
            {"name": "c", "state": "exited", "health": None, "status": "Exited (137) 1h ago"},
            {"name": "d", "state": "exited", "health": None, "status": "Exited (0) 1h ago"},
        ],
    )

    accessor = {key: CONDITION_FIELDS[key].accessor for key in CONDITION_FIELDS}
    assert accessor["docker.unhealthy_count"](machine, None, None) == 1
    assert accessor["docker.restarting_count"](machine, None, None) == 1
    assert accessor["docker.exited_error_count"](machine, None, None) == 1


def test_docker_counts_unknown_without_docker_access():
    machine = _machine(docker_status="no_access", docker_containers=None)

    assert not evaluate_condition("docker.unhealthy_count", "eq", "0", machine, None, None)
