"""Proxmox Backup Server, Mail Gateway, Proxmox VE cluster/failed tasks and
guest power actions on the Proxmox tab (0.79.0)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from app.db.models.machine import AuthMethod, Machine
from app.services import health_events
from app.ssh import proxmox
from app.ssh.facts import parse_facts_output

_PBS_RAW = (
    "===PBS_VERSION===\n3.2.7-1\n"
    '===PBS_USAGE===\n[{"store":"main","total":1000,"used":950,"avail":50,'
    '"estimated-full-date":1800000000}]\n'
    '===PBS_GC===\n[{"store":"main","last-run-state":"OK","next-run":1800000000}]\n'
    '===PBS_VERIFY===\n[{"id":"v1","store":"main","last-run-state":"verification failed"}]\n'
    "===PBS_SYNC===\n[]\n===PBS_PRUNE===\n[]\n"
    '===PBS_TASKS===\n[{"worker_type":"backup","worker_id":"main:vm/100","starttime":5,'
    '"endtime":9,"status":"OK"}]\n'
    '===PBS_GROUPS===\n@@STORE main\n[{"backup-type":"vm","backup-id":"100",'
    '"last-backup":1700000000,"backup-count":14}]\n'
)
_PMG_RAW = (
    "===PMG_VERSION===\npmg/8.1.4/abcdef (running kernel: 6.8.12-1-pve)\n"
    '===PMG_STATS===\n{"count":120,"count_in":100,"count_out":20,"spamcount_in":30,'
    '"viruscount_in":1,"rbl_rejects":40,"pregreet_rejects":5}\n'
    '===PMG_QUEUE===\n@@OK\n{"queue_name":"deferred"}\n{"queue_name":"deferred"}\n'
    '===PMG_CLAMAV===\n[{"type":"daily","version":"27400","nsigs":2000000,'
    '"build_time":"Sat Sep 27 08:20:00 2026"}]\n'
)


def test_backup_server_facts():
    facts = parse_facts_output(_PBS_RAW)
    assert facts["pbs_version"] == "3.2.7"
    data = facts["pbs_data"]
    assert data is not None
    assert data["datastores"][0]["used_percent"] == 95.0
    assert data["groups"]["main"][0] == {
        "type": "vm", "id": "100", "last_backup": 1700000000, "count": 14, "comment": ""
    }
    assert proxmox.pbs_failures(data) == ["verify v1: verification failed"]


def test_mail_gateway_facts():
    facts = parse_facts_output(_PMG_RAW)
    assert facts["pmg_version"] == "8.1.4"
    data = facts["pmg_data"]
    assert data is not None and data["stats"] is not None
    assert data["stats"]["spamcount_in"] == 30
    assert data["queue"] == {"active": 0, "deferred": 2, "hold": 0, "incoming": 0}
    assert data["clamav"][0]["signatures"] == 2000000
    # postqueue that couldn't run is "unknown", an empty one is zero.
    empty = parse_facts_output("===PMG_VERSION===\npmg/8.1.4/x\n===PMG_QUEUE===\n@@OK\n")
    assert empty["pmg_data"] is not None and empty["pmg_data"]["queue"]["deferred"] == 0
    unknown = parse_facts_output("===PMG_VERSION===\npmg/8.1.4/x\n===PMG_QUEUE===\n")
    assert unknown["pmg_data"] is not None and unknown["pmg_data"]["queue"] is None


def test_cluster_and_product_labels():
    cluster = proxmox.parse_cluster(
        '[{"type":"cluster","name":"home","quorate":0},'
        '{"type":"node","name":"b","online":0},{"type":"node","name":"a","online":1,"local":1}]'
    )
    assert cluster is not None and cluster["quorate"] is False
    assert [n["name"] for n in cluster["nodes"]] == ["a", "b"]
    machine = Machine(os_version="Debian GNU/Linux 12", pbs_version="3.2.7")
    assert machine.os_display == "Proxmox Backup Server 3.2.7 (Debian GNU/Linux 12)"
    assert machine.has_proxmox_tab


def test_health_events_for_backup_server_mail_and_cluster():
    good = {"verify": [{"id": "v1", "ok": True, "last_state": "OK"}]}
    bad = {"verify": [{"id": "v1", "ok": False, "last_state": "failed"}]}
    assert health_events.new_pbs_failures(good, bad) == ["verify v1: failed"]
    assert health_events.new_pbs_failures(bad, bad) == []
    assert health_events.new_pbs_failures(None, bad) == []
    quiet = {"queue": {"deferred": 3}}
    busy = {"queue": {"deferred": 70, "hold": 1}}
    assert health_events.mail_queue_crossed(quiet, busy) == 71
    assert health_events.mail_queue_crossed(busy, busy) == 0
    assert health_events.lost_quorum({"quorate": True}, {"quorate": False})
    assert not health_events.lost_quorum(None, {"quorate": False})


@pytest.mark.parametrize(
    ("guest", "action", "ok"),
    [
        ({"vmid": 100, "type": "qemu", "node": "pve1"}, "shutdown", True),
        ({"vmid": 100, "type": "lxc", "node": "pve1"}, "start", True),
        ({"vmid": 100, "type": "qemu", "node": "pve1"}, "destroy", False),
        ({"vmid": 100, "type": "qemu", "node": "pve1; rm -rf /"}, "start", False),
        ({"vmid": "100", "type": "qemu", "node": "pve1"}, "start", False),
    ],
)
def test_guest_action_command_is_strictly_built(guest, action, ok):
    if ok:
        command = proxmox.build_guest_action_command(guest, action)
        assert command == (
            f"sudo -n pvesh create /nodes/pve1/{guest['type']}/100/status/{action} 2>&1"
        )
    else:
        with pytest.raises(ValueError):
            proxmox.build_guest_action_command(guest, action)


async def _pve_machine(db_session_factory: Any, **extra: Any) -> uuid.UUID:
    async with db_session_factory() as db:
        machine = Machine(
            name="pve1",
            ip_address="10.0.0.9",
            port=22,
            username="root",
            auth_method=AuthMethod.PASSWORD,
            host_key_fingerprint="SHA256:x",
            pve_version="9.0.6",
            pve_guests=proxmox.parse_guests(
                '[{"vmid":100,"name":"web","type":"qemu","node":"pve1","status":"running"}]'
            ),
            **extra,
        )
        db.add(machine)
        await db.commit()
        return machine.id


async def test_guest_action_route_runs_the_task_and_audits(
    client, db_session_factory, celery_calls
):
    machine_id = await _pve_machine(db_session_factory)
    await client.get(f"/machines/{machine_id}/proxmox")
    celery_calls.result_for["app.tasks.jobs.run_proxmox_guest_action"] = {"ok": True}
    response = await client.post(
        f"/machines/{machine_id}/proxmox/guests/100",
        data={"csrf_token": client.cookies.get("csrftoken"), "action": "shutdown"},
        follow_redirects=False,
    )
    assert response.status_code == 303 and "guest_notice=" in response.headers["location"]
    assert ("app.tasks.jobs.run_proxmox_guest_action", (str(machine_id), 100, "shutdown"), {}) in [
        tuple(c) for c in celery_calls
    ]
    unknown = await client.post(
        f"/machines/{machine_id}/proxmox/guests/999",
        data={"csrf_token": client.cookies.get("csrftoken"), "action": "start"},
        follow_redirects=False,
    )
    assert "guest_error=" in unknown.headers["location"]


async def test_backup_server_and_mail_gateway_sections(client, db_session_factory):
    pbs = parse_facts_output(_PBS_RAW)
    pmg = parse_facts_output(_PMG_RAW)
    machine_id = await _pve_machine(
        db_session_factory,
        pbs_version=pbs["pbs_version"],
        pbs_data=pbs["pbs_data"],
        pmg_version=pmg["pmg_version"],
        pmg_data=pmg["pmg_data"],
    )
    page = await client.get(f"/machines/{machine_id}/proxmox")
    assert page.status_code == 200
    for text in ("Datastores", "verification failed", "vm/100", "27400", "Mail queue"):
        assert text in page.text
