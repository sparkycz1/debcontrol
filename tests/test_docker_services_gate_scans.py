"""The Docker tab's vulnerability gate (`app.services.docker_gate`), the
stored image scans and their per-machine summary
(`app.services.docker_scans`), and what notifications and conditions read
from them (`app.services.condition_fields`, `app.services.notifications`)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select

from app.db.models.docker import DockerImageScan
from app.db.models.machine import AuthMethod, Machine
from app.db.models.notification_rule import NotificationEventType
from app.services import docker_scans
from app.services.condition_fields import CONDITION_FIELDS
from app.services.docker_gate import evaluate, normalize_gate
from app.services.notifications import render_template
from app.ssh.docker_scan import ImageScanResult

OLD_ID = "sha256:" + "a" * 64
NEW_ID = "sha256:" + "b" * 64
OTHER_ID = "sha256:" + "c" * 64


def _counts(critical: int = 0, high: int = 0, medium: int = 0) -> dict[str, int]:
    return {"critical": critical, "high": high, "medium": medium, "low": 0, "unknown": 0}


def _machine(**overrides: Any) -> Machine:
    values: dict[str, Any] = {
        "id": uuid.uuid4(),
        "name": "docker1",
        "ip_address": "10.0.0.7",
        "port": 22,
        "username": "root",
        "auth_method": AuthMethod.PASSWORD,
        "host_key_fingerprint": "SHA256:x",
    }
    values.update(overrides)
    return Machine(**values)


# --- The gate -----------------------------------------------------------------


def test_gate_off_lets_everything_through_even_without_a_scan() -> None:
    assert evaluate("off", None, None).allowed
    assert evaluate("off", _counts(critical=9), None).allowed


@pytest.mark.parametrize("gate", ["critical", "high", "worse"])
def test_gate_fails_closed_when_the_new_image_could_not_be_scanned(gate: str) -> None:
    verdict = evaluate(gate, None, _counts())
    assert not verdict.allowed
    assert verdict.reason == "not_scanned"


@pytest.mark.parametrize(
    ("gate", "new", "allowed", "reason"),
    [
        ("critical", _counts(high=5, medium=20), True, "passed"),
        ("critical", _counts(critical=1), False, "critical"),
        ("high", _counts(medium=20), True, "passed"),
        ("high", _counts(high=1), False, "high"),
        ("high", _counts(critical=1), False, "high"),
    ],
)
def test_critical_and_high_gates_judge_the_new_image_alone(
    gate: str, new: dict[str, int], allowed: bool, reason: str
) -> None:
    verdict = evaluate(gate, new, None)
    assert (verdict.allowed, verdict.reason) == (allowed, reason)


def test_worse_gate_compares_critical_plus_high_with_the_running_image() -> None:
    # Same total of serious findings (moved between critical and high): fine.
    assert evaluate("worse", _counts(critical=2, high=1), _counts(critical=1, high=2)).allowed
    # Fewer serious findings, even with more medium ones: fine.
    assert evaluate("worse", _counts(high=1, medium=50), _counts(high=3)).allowed
    worse = evaluate("worse", _counts(critical=1, high=3), _counts(high=3))
    assert (worse.allowed, worse.reason) == (False, "worse")


def test_worse_gate_stops_when_the_running_image_has_no_scan_to_compare_with() -> None:
    verdict = evaluate("worse", _counts(), None)
    assert (verdict.allowed, verdict.reason) == (False, "old_not_scanned")


def test_unknown_gate_values_are_read_as_off() -> None:
    assert normalize_gate("paranoid") == "off"
    assert normalize_gate(None) == "off"
    assert normalize_gate("high") == "high"
    assert evaluate("paranoid", None, None).allowed


def test_verdict_as_dict_carries_both_scans_for_the_job_result() -> None:
    verdict = evaluate("worse", _counts(critical=1), _counts())
    assert verdict.as_dict() == {
        "allowed": False,
        "reason": "worse",
        "new": _counts(critical=1),
        "old": _counts(),
    }


# --- Stored scans ---------------------------------------------------------------


def _result(image: str, counts: dict[str, int] | None) -> ImageScanResult:
    if counts is None:
        return ImageScanResult(image=image, errors={"trivy": "boom", "grype": "boom"})
    return ImageScanResult(
        image=image,
        scanners={"trivy": "0.58.1"},
        counts=counts,
        vulnerabilities=[{"id": "CVE-1", "severity": "critical"}] if counts["critical"] else [],
    )


async def test_store_keeps_scans_by_image_id_and_reports_unscannable_images_as_none(
    db_session_factory: Any,
) -> None:
    async with db_session_factory() as db:
        machine = _machine()
        db.add(machine)
        await db.commit()

        counts = await docker_scans.store(
            db,
            machine.id,
            [_result("nginx:1.27", _counts(critical=1)), _result("redis:7", None)],
            {"nginx:1.27": NEW_ID, "redis:7": OTHER_ID},
        )
        await db.commit()
        rows = (await db.execute(select(DockerImageScan))).scalars().all()

    assert counts == {NEW_ID: _counts(critical=1), OTHER_ID: None}
    # Only the successful scan is stored; a failed one never overwrites it.
    assert [(r.image_id, r.image_ref) for r in rows] == [(NEW_ID, "nginx:1.27")]


async def test_a_failed_rescan_never_replaces_a_stored_scan(db_session_factory: Any) -> None:
    async with db_session_factory() as db:
        machine = _machine()
        db.add(machine)
        await db.commit()
        await docker_scans.store(
            db, machine.id, [_result("nginx:1.27", _counts(high=2))], {"nginx:1.27": NEW_ID}
        )
        await db.commit()

        counts = await docker_scans.store(
            db, machine.id, [_result("nginx:1.27", None)], {"nginx:1.27": NEW_ID}
        )
        await db.commit()
        stored = await docker_scans.get_scan(db, machine.id, NEW_ID)

    assert counts == {NEW_ID: None}
    assert docker_scans.counts_of(stored) == _counts(high=2)


async def test_summary_covers_only_images_in_use_and_forget_missing_drops_gone_images(
    db_session_factory: Any,
) -> None:
    async with db_session_factory() as db:
        machine = _machine()
        db.add(machine)
        await db.commit()
        await docker_scans.store(
            db,
            machine.id,
            [
                _result(OLD_ID, _counts(critical=1, high=2)),
                _result(NEW_ID, _counts(high=1)),
                _result(OTHER_ID, _counts(critical=5)),
            ],
            {},
        )
        await db.commit()

        summary = await docker_scans.summarize(db, machine, {OLD_ID, NEW_ID, "sha256:" + "d" * 64})
        await docker_scans.forget_missing(db, machine.id, {OLD_ID, NEW_ID})
        # An empty "present" set (inventory read nothing) must never wipe every scan.
        await docker_scans.forget_missing(db, machine.id, set())
        await db.commit()
        left = await docker_scans.scans_by_image(db, machine.id)

    assert summary["critical"] == 1
    assert summary["high"] == 3
    assert summary["images"] == 2
    assert summary["unscanned"] == 1
    assert summary["scanned_at"] is not None
    assert machine.docker_vulnerabilities == summary
    assert set(left) == {OLD_ID, NEW_ID}


# --- Conditions -----------------------------------------------------------------


def _field(name: str, machine: Machine) -> Any:
    return CONDITION_FIELDS[name].accessor(machine, None, None)


def test_vulnerability_conditions_are_unknown_before_any_scan() -> None:
    assert _field("docker.critical_vulnerabilities", _machine()) is None
    nothing_scanned = _machine(docker_vulnerabilities={"critical": 0, "images": 0})
    assert _field("docker.critical_vulnerabilities", nothing_scanned) is None


def test_vulnerability_conditions_read_the_summary() -> None:
    machine = _machine(docker_vulnerabilities={"critical": 2, "high": 7, "images": 3})
    assert _field("docker.critical_vulnerabilities", machine) == 2
    assert _field("docker.high_vulnerabilities", machine) == 7


def test_backup_age_condition_counts_hours_since_the_last_good_backup() -> None:
    assert _field("docker.backup_age_hours", _machine()) is None
    # Stored naive (UTC) by SQLite and some drivers: read as UTC.
    naive = (datetime.now(UTC) - timedelta(hours=30)).replace(tzinfo=None)
    assert _field("docker.backup_age_hours", _machine(docker_backup_ok_at=naive)) == 30.0


def test_container_count_conditions_are_unknown_unless_docker_was_readable() -> None:
    containers = [
        {"name": "a", "state": "running", "health": "unhealthy"},
        {"name": "b", "state": "exited", "status": "Exited (1) 2 hours ago"},
        {"name": "c", "state": "exited", "status": "Exited (0) 2 hours ago"},
        {"name": "d", "state": "restarting"},
    ]
    readable = _machine(docker_status="ok", docker_containers=containers)
    no_access = _machine(docker_status="no_access", docker_containers=containers)

    assert _field("docker.unhealthy_count", readable) == 1
    assert _field("docker.exited_error_count", readable) == 1
    assert _field("docker.restarting_count", readable) == 1
    assert _field("docker.unhealthy_count", no_access) is None


# --- Notification templates -------------------------------------------------------


@pytest.mark.parametrize("locale", ["en", "cs"])
@pytest.mark.parametrize(
    ("event", "context_key"),
    [
        (NotificationEventType.DOCKER_UPDATE_SUCCEEDED, "container"),
        (NotificationEventType.DOCKER_UPDATE_FAILED, "container"),
        (NotificationEventType.DOCKER_UPDATE_BLOCKED, "container"),
        (NotificationEventType.DOCKER_STACK_FAILED, "stack"),
        (NotificationEventType.DOCKER_BACKUP_FAILED, "backup"),
    ],
)
def test_docker_notifications_name_what_they_are_about_in_every_locale(
    event: NotificationEventType, context_key: str, locale: str
) -> None:
    context = {
        context_key: "the-target",
        "machine_name": "docker1",
        "machine_ip": "10.0.0.7",
        "timestamp": "2026-10-17T10:00:00Z",
        "details": "the details",
    }
    subject, body = render_template(event, None, context, locale=locale)

    assert "the-target" in subject + body
    assert "docker1" in subject
    assert "{" not in subject + body  # every placeholder is one the job provides
