"""`app.tasks.jobs._service_usage` — per-service CPU%/peak/memory between
two consecutive services snapshots."""

from __future__ import annotations

from app.db.models.machine_service import MachineService
from app.ssh.services import ServiceEntry
from app.tasks.jobs import _service_usage


def _entry(**overrides: object) -> ServiceEntry:
    base: dict[str, object] = {
        "unit": "docker.service",
        "load_state": "loaded",
        "active_state": "active",
        "sub_state": "running",
        "description": "Docker",
        "cpu_usage_nsec": 0,
        "memory_bytes": 100,
        "memory_peak_bytes": None,
        "active_enter_monotonic": 1,
    }
    base.update(overrides)
    return base  # type: ignore[return-value]


def _previous(**fields: object) -> MachineService:
    row = MachineService(
        unit="docker.service", load_state="loaded", active_state="active",
        sub_state="running", description="Docker",
    )
    for key, value in fields.items():
        setattr(row, key, value)
    return row


def test_cpu_percent_is_share_of_the_whole_machine():
    # 60 s of CPU time over 600 s of wall clock on a 4-core machine = 2.5%.
    previous = _previous(cpu_usage_nsec=0, active_enter_monotonic=1, cpu_percent_peak=None)

    usage = _service_usage(_entry(cpu_usage_nsec=60_000_000_000), previous, 600.0, 4)

    assert usage["cpu_percent"] == 2.5
    assert usage["cpu_percent_peak"] == 2.5


def test_peak_carries_over_within_the_same_run():
    previous = _previous(cpu_usage_nsec=0, active_enter_monotonic=1, cpu_percent_peak=9.0)

    usage = _service_usage(_entry(cpu_usage_nsec=6_000_000_000), previous, 600.0, 1)

    assert usage["cpu_percent"] == 1.0
    assert usage["cpu_percent_peak"] == 9.0


def test_restart_resets_cpu_and_peaks():
    previous = _previous(
        cpu_usage_nsec=10, active_enter_monotonic=1, cpu_percent_peak=9.0, memory_peak_bytes=999
    )

    usage = _service_usage(
        _entry(cpu_usage_nsec=50, active_enter_monotonic=2, memory_bytes=100), previous, 600.0, 1
    )

    assert usage["cpu_percent"] is None
    assert usage["cpu_percent_peak"] is None
    assert usage["memory_peak_bytes"] == 100


def test_systemd_memory_peak_wins_when_reported():
    usage = _service_usage(_entry(memory_peak_bytes=5000), None, None, 1)

    assert usage["memory_peak_bytes"] == 5000
    assert usage["cpu_percent"] is None


def test_not_running_unit_has_no_usage():
    usage = _service_usage(
        _entry(cpu_usage_nsec=None, memory_bytes=None, active_enter_monotonic=None), None, 600.0, 2
    )

    assert usage["cpu_percent"] is None
    assert usage["memory_bytes"] is None
    assert usage["memory_peak_bytes"] is None
