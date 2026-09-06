from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.db.models.machine_monitoring_sample import MachineMonitoringSample
from app.db.models.machine_reachability_sample import MachineReachabilitySample
from app.services.monitoring_history import (
    build_availability_history,
    build_monitoring_history,
    time_range_delta,
)

_MACHINE_ID = uuid.uuid4()


def _sample(
    minutes_ago: int,
    *,
    cpu: float | None = 10.0,
    load1: float | None = 0.5,
    ram_used: int | None = 500,
    ram_total: int | None = 1000,
    network_io: list[dict[str, object]] | None = None,
    disk_io: list[dict[str, object]] | None = None,
    filesystems: list[dict[str, object]] | None = None,
    failed: int | None = 0,
) -> MachineMonitoringSample:
    return MachineMonitoringSample(
        id=uuid.uuid4(),
        machine_id=_MACHINE_ID,
        sampled_at=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        cpu_percent=cpu,
        load1=load1,
        load5=load1,
        load15=load1,
        ram_used_bytes=ram_used,
        ram_total_bytes=ram_total,
        network_io=network_io if network_io is not None else [],
        disk_io=disk_io if disk_io is not None else [],
        filesystems=filesystems if filesystems is not None else [],
        failed_services_count=failed,
    )


def test_time_range_delta_known_and_unknown_keys():
    assert time_range_delta("1h") == timedelta(hours=1)
    assert time_range_delta("bogus") == time_range_delta("24h")


def test_build_monitoring_history_empty():
    history = build_monitoring_history([], "24h")

    assert history.sample_count == 0
    assert history.cpu_percent == []
    assert history.latest_sampled_at is None
    assert history.latest_cpu_percent is None
    assert history.network_rate_by_iface == {}
    assert history.disk_rate_by_device == {}
    assert history.filesystem_usage_by_mount == {}
    assert history.latest_filesystems == {}


def test_build_monitoring_history_filesystem_usage_series():
    samples = [
        _sample(
            10,
            filesystems=[
                {"mount": "/", "size_bytes": 1000, "used_bytes": 300, "avail_bytes": 700,
                 "use_percent": 30},
            ],
        ),
        _sample(
            5,
            filesystems=[
                {"mount": "/", "size_bytes": 1000, "used_bytes": 500, "avail_bytes": 500,
                 "use_percent": 50},
                {"mount": "/boot", "size_bytes": 500, "used_bytes": 50, "avail_bytes": 450,
                 "use_percent": 10},
            ],
        ),
    ]

    history = build_monitoring_history(samples, "1h")

    assert history.filesystem_usage_by_mount["/"] == [30, 50]
    # "/boot" wasn't reported in the first sample — a gap, not zero usage.
    assert history.filesystem_usage_by_mount["/boot"] == [None, 10]
    assert history.latest_filesystems["/"]["use_percent"] == 50
    assert history.latest_filesystems["/boot"]["use_percent"] == 10


def test_build_monitoring_history_no_downsampling_needed():
    samples = [_sample(10 - i, cpu=float(i)) for i in range(5)]

    history = build_monitoring_history(samples, "1h")

    assert history.sample_count == 5
    assert history.truncated is False
    assert history.cpu_percent == [0.0, 1.0, 2.0, 3.0, 4.0]
    assert history.ram_percent == [50.0] * 5
    assert history.latest_cpu_percent == 4.0
    assert history.latest_load1 == 0.5


def test_build_monitoring_history_ram_percent_none_when_total_unknown():
    samples = [_sample(0, ram_used=None, ram_total=None)]

    history = build_monitoring_history(samples, "1h")

    assert history.ram_percent == [None]


def test_build_monitoring_history_downsamples_a_large_series():
    samples = [_sample(1000 - i, cpu=float(i % 100)) for i in range(1000)]

    history = build_monitoring_history(samples, "90d")

    assert history.sample_count == 1000
    assert 1 < len(history.cpu_percent) <= 150


def test_network_rate_computed_from_consecutive_cumulative_samples():
    now = datetime.now(UTC)
    samples = [
        MachineMonitoringSample(
            id=uuid.uuid4(),
            machine_id=_MACHINE_ID,
            sampled_at=now - timedelta(seconds=120),
            network_io=[{"iface": "eth0", "rx_bytes": 1000, "tx_bytes": 500}],
            disk_io=[],
        ),
        MachineMonitoringSample(
            id=uuid.uuid4(),
            machine_id=_MACHINE_ID,
            sampled_at=now,
            network_io=[{"iface": "eth0", "rx_bytes": 1000 + 1200, "tx_bytes": 500 + 600}],
            disk_io=[],
        ),
    ]

    history = build_monitoring_history(samples, "1h")

    # First point has no prior sample to diff against.
    assert history.network_rate_by_iface["eth0"][0] is None
    # (1200 + 600) bytes over 120 seconds = 15 bytes/sec combined.
    assert history.network_rate_by_iface["eth0"][1] == 15.0
    assert history.latest_network_io["eth0"] == {
        "iface": "eth0",
        "rx_bytes": 2200,
        "tx_bytes": 1100,
    }


def test_network_rate_gap_on_counter_reset():
    now = datetime.now(UTC)
    samples = [
        MachineMonitoringSample(
            id=uuid.uuid4(),
            machine_id=_MACHINE_ID,
            sampled_at=now - timedelta(seconds=120),
            network_io=[{"iface": "eth0", "rx_bytes": 5000, "tx_bytes": 5000}],
            disk_io=[],
        ),
        MachineMonitoringSample(
            id=uuid.uuid4(),
            machine_id=_MACHINE_ID,
            sampled_at=now,
            # Counter went backwards — e.g. the machine rebooted.
            network_io=[{"iface": "eth0", "rx_bytes": 100, "tx_bytes": 100}],
            disk_io=[],
        ),
    ]

    history = build_monitoring_history(samples, "1h")

    assert history.network_rate_by_iface["eth0"] == [None, None]


def test_disk_rate_tracks_multiple_devices():
    now = datetime.now(UTC)
    samples = [
        MachineMonitoringSample(
            id=uuid.uuid4(),
            machine_id=_MACHINE_ID,
            sampled_at=now - timedelta(seconds=60),
            network_io=[],
            disk_io=[{"device": "sda", "read_bytes": 1000, "write_bytes": 0}],
        ),
        MachineMonitoringSample(
            id=uuid.uuid4(),
            machine_id=_MACHINE_ID,
            sampled_at=now,
            network_io=[],
            disk_io=[
                {"device": "sda", "read_bytes": 1600, "write_bytes": 0},
                {"device": "nvme0n1", "read_bytes": 200, "write_bytes": 100},
            ],
        ),
    ]

    history = build_monitoring_history(samples, "1h")

    assert history.disk_rate_by_device["sda"] == [None, 10.0]  # 600 bytes / 60s
    # "nvme0n1" only appears in the second sample — first point is None too.
    assert history.disk_rate_by_device["nvme0n1"] == [None, None]


def test_bucket_timestamps_align_with_bucketed_values():
    samples = [_sample(1000 - i, cpu=float(i % 100)) for i in range(1000)]

    history = build_monitoring_history(samples, "90d")

    assert len(history.bucket_timestamps) == len(history.cpu_percent)
    # Oldest-first, strictly increasing.
    assert all(
        a < b
        for a, b in zip(history.bucket_timestamps, history.bucket_timestamps[1:], strict=False)
    )


def test_latest_failed_services_count():
    samples = [_sample(1, failed=None), _sample(0, failed=3)]

    history = build_monitoring_history(samples, "1h")

    assert history.latest_failed_services_count == 3


def _reachability_sample(
    minutes_ago: int, *, reachable: bool = True, latency_ms: float | None = 5.0
) -> MachineReachabilitySample:
    return MachineReachabilitySample(
        id=uuid.uuid4(),
        machine_id=_MACHINE_ID,
        checked_at=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        reachable=reachable,
        latency_ms=latency_ms,
    )


def test_build_availability_history_empty():
    history = build_availability_history([], "24h")

    assert history.sample_count == 0
    assert history.uptime_percent == []
    assert history.latest_reachable is None
    assert history.latest_latency_ms is None


def test_build_availability_history_uptime_and_latency():
    from app.services.monitoring_history import build_availability_history

    samples = [
        _reachability_sample(30, reachable=True, latency_ms=4.0),
        _reachability_sample(20, reachable=False, latency_ms=None),
        _reachability_sample(10, reachable=True, latency_ms=6.0),
        _reachability_sample(0, reachable=True, latency_ms=8.0),
    ]

    history = build_availability_history(samples, "1h")

    assert history.sample_count == 4
    # 3 of 4 checks succeeded, all in one bucket (no downsampling at this size).
    assert history.uptime_percent == [100.0, 0.0, 100.0, 100.0]
    # A failed check contributes no latency reading.
    assert history.latency_ms == [4.0, None, 6.0, 8.0]
    assert history.latest_reachable is True
    assert history.latest_latency_ms == 8.0


def test_build_availability_history_downsampled_uptime_is_a_percentage():
    from app.services.monitoring_history import build_availability_history

    # 8 successes, 2 failures, bucketed down to fewer points than raw rows.
    samples = [_reachability_sample(10 - i, reachable=i not in (2, 5)) for i in range(10)]

    history = build_availability_history(samples, "1h")

    assert history.sample_count == 10
    assert all(0.0 <= (p or 0.0) <= 100.0 for p in history.uptime_percent)
    assert sum(p for p in history.uptime_percent if p is not None) / len(
        history.uptime_percent
    ) == 80.0
