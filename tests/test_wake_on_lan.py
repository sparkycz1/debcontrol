"""Wake-on-LAN (`app.services.wake_on_lan`): the packet is sent by another
managed machine on the same network, and only where that is possible."""

from __future__ import annotations

import socket
import subprocess
import sys
import uuid
from typing import Any

import pytest
from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import Machine
from app.scheduling.actions import get_action
from app.scheduling.builtin_actions import register_builtin_actions
from app.services import wake_on_lan
from app.ssh.facts import parse_facts_output
from app.tasks import jobs
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token

MAC = "aa:bb:cc:dd:ee:01"


def test_only_real_card_addresses_are_kept() -> None:
    facts = parse_facts_output(
        "===MACS===\n"
        "eno1 AA:BB:CC:DD:EE:01\n"
        "eno2 aa:bb:cc:dd:ee:01\n"
        "lo 00:00:00:00:00:00\n"
        "bad;name aa:bb:cc:dd:ee:02\n"
        "eth9 not-a-mac\n"
    )

    assert facts["mac_addresses"] == [{"interface": "eno1", "mac": MAC}]


class _M:
    def __init__(self, name: str, ip: str, **kw: Any) -> None:
        self.id = uuid.uuid4()
        self.name = name
        self.ip_address = ip
        self.is_reachable = kw.get("reachable", True)
        self.host_key_fingerprint = kw.get("key", "SHA256:x")
        self.network_interfaces = kw.get("nets", [{"interface": "eth0", "address": f"{ip}/24"}])
        self.mac_addresses = kw.get("macs", [])


def test_the_relay_is_a_reachable_machine_on_the_same_network() -> None:
    target = _M("nas", "192.168.1.50", reachable=False, macs=[{"interface": "eno1", "mac": MAC}])
    other_net = _M("cloud", "10.0.0.5")
    down = _M("alpha", "192.168.1.2", reachable=False)
    unconfirmed = _M("beta", "192.168.1.3", key=None)
    good = _M("gamma", "192.168.1.4")

    plan = wake_on_lan.choose_relay(target, [other_net, down, unconfirmed, good, target])

    assert plan is not None
    assert (plan.relay_name, plan.macs) == ("gamma", (MAC,))
    assert plan.broadcasts == ("255.255.255.255", "192.168.1.255")
    assert wake_on_lan.choose_relay(target, [other_net, down, unconfirmed]) is None
    # Never seen running: nothing to address the packet to.
    assert wake_on_lan.choose_relay(_M("new", "192.168.1.60"), [good]) is None


def test_the_command_refuses_anything_but_addresses() -> None:
    plan = wake_on_lan.WakePlan(uuid.uuid4(), "gamma", (MAC,), ("192.168.1.255",))

    command = wake_on_lan.build_command(plan)

    assert MAC in command and "192.168.1.255" in command
    for bad in (("aa:bb; reboot",), ("$(id)",)):
        with pytest.raises(ValueError):
            wake_on_lan.build_command(
                wake_on_lan.WakePlan(uuid.uuid4(), "gamma", bad, ("192.168.1.255",))
            )
    with pytest.raises(ValueError):
        wake_on_lan.build_command(wake_on_lan.WakePlan(uuid.uuid4(), "g", (MAC,), ("host; id",)))


def test_the_sender_emits_a_real_magic_packet() -> None:
    """The script the relay runs, run here against a local socket."""
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    receiver.settimeout(5)
    port = receiver.getsockname()[1]
    script = wake_on_lan._SENDER.replace("(9,7)", f"({port},)")

    subprocess.run(  # noqa: S603 - our own script, fixed arguments
        [sys.executable, "-c", script, MAC, "127.0.0.1"], check=True, timeout=20
    )
    packet, _sender = receiver.recvfrom(200)
    receiver.close()

    assert packet == b"\xff" * 6 + bytes.fromhex(MAC.replace(":", "")) * 16


async def test_waking_from_the_page_the_api_and_a_schedule(
    client: AsyncClient, db_session_factory: Any, celery_calls: Any, monkeypatch: Any
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    nas = await _add_machine(
        db_session_factory,
        name="nas",
        ip_address="192.168.1.50",
        is_reachable=False,
        mac_addresses=[{"interface": "eno1", "mac": MAC}],
    )
    await _add_machine(
        db_session_factory,
        name="relay1",
        ip_address="192.168.1.4",
        is_reachable=True,
        network_interfaces=[{"interface": "eth0", "address": "192.168.1.4/24"}],
    )
    lonely = await _add_machine(
        db_session_factory, name="lonely", ip_address="172.16.9.9", is_reachable=False
    )
    ran: list[tuple[str, str]] = []

    async def fake_run(machine: Any, _secret: Any, command: str, *_args: Any) -> Any:
        ran.append((machine.name, command))

        class _Result:
            exit_status = 0
            output = ""

        return _Result()

    monkeypatch.setattr(jobs, "run_command", fake_run)

    page = await client.get(f"/machines/{nas}")
    no_way = await client.get(f"/machines/{lonely}")
    sent = await jobs._wake_machine(str(nas))
    refused = await jobs._wake_machine(str(lonely))
    csrf = client.cookies.get("csrftoken")
    posted = await client.post(
        f"/machines/{nas}/wake", data={"csrf_token": csrf}, follow_redirects=False
    )
    headers = await _api_token(client)
    api = await client.post(f"/api/v1/machines/{nas}/wake", headers=headers)

    assert "Wake up" in page.text and "through relay1" in page.text
    assert f'action="/machines/{lonely}/wake"' not in no_way.text
    assert sent == {"ok": True, "relay": "relay1"}
    assert ran[0][0] == "relay1" and MAC in ran[0][1]
    assert refused["ok"] is False and "No way to wake" in refused["error"]
    assert posted.status_code == 303 and "wake_notice=" in posted.headers["location"]
    assert api.status_code == 200
    assert celery_calls.names.count("app.tasks.jobs.wake_machine") == 2
    async with db_session_factory() as db:
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
        machines = list((await db.execute(select(Machine))).scalars().all())
        register_builtin_actions()
        action = get_action("wake")
        assert action is not None
        result = await action.run(db, machines, {})
    assert actions.count("machine.power.wake") == 2
    # Only the machine that is down and has a known card gets a packet.
    assert (result.attempted, result.skipped) == (1, 2)
