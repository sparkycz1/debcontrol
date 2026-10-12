"""The machine debcontrol runs on goes last in a batch
(`app.services.self_host`), Proxmox guests are paired with managed machines
(`app.services.proxmox_guest_links`), templates are not "not backed up" and
old failed tasks age out."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.machine import Machine
from app.db.models.machine_update_run import MachineUpdateRun, UpdateRunStatus, UpgradeStrategy
from app.services import proxmox_guest_links, self_host
from app.services.machine_actions import trigger_updates
from app.ssh import proxmox
from app.ssh.facts import parse_facts_output
from app.tasks import jobs
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token

BOOT_ID = "0b0f1c2d-3e4f-4a5b-8c6d-7e8f9a0b1c2d"
GUESTS = (
    '[{"vmid":111,"name":"dc","type":"qemu","status":"running","node":"pve1"},'
    '{"vmid":112,"name":"web1","type":"lxc","status":"stopped","node":"pve1"},'
    '{"vmid":9000,"name":"tpl","type":"qemu","status":"stopped","template":1}]'
)


@pytest.fixture
def own_boot_id(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(self_host, "own_boot_id", lambda: BOOT_ID)
    return BOOT_ID


async def _fleet(db_session_factory: Any) -> dict[str, uuid.UUID]:
    """A Proxmox host, the VM debcontrol runs on, and two ordinary machines."""
    return {
        "pve1": await _add_machine(
            db_session_factory,
            name="pve1",
            ip_address="10.0.2.1",
            is_physical=True,
            pve_version="8.3.1",
            pve_guests=proxmox.parse_guests(GUESTS),
        ),
        "dc": await _add_machine(
            db_session_factory,
            name="dc",
            ip_address="10.0.2.2",
            is_physical=False,
            boot_id=BOOT_ID,
        ),
        "web1": await _add_machine(
            db_session_factory,
            name="Web one",
            discovered_hostname="web1.example.com",
            ip_address="10.0.2.3",
            is_physical=False,
        ),
        "app1": await _add_machine(db_session_factory, name="app1", ip_address="10.0.2.4"),
    }


def test_boot_id_is_read_from_the_facts() -> None:
    assert parse_facts_output(f"===BOOT_ID===\n{BOOT_ID.upper()}\n")["boot_id"] == BOOT_ID
    assert parse_facts_output("===BOOT_ID===\nnot an id\n")["boot_id"] is None
    assert parse_facts_output("===HOSTNAME===\nx\n")["boot_id"] is None


async def test_guests_are_paired_with_machines_both_ways(db_session_factory: Any) -> None:
    ids = await _fleet(db_session_factory)
    async with db_session_factory() as db:
        machines = {m.name: m for m in (await db.execute(select(Machine))).scalars().all()}
        host = await proxmox_guest_links.host_of(db, machines["Web one"])
        nothing = await proxmox_guest_links.host_of(db, machines["app1"])
        bare_metal = await proxmox_guest_links.host_of(db, machines["pve1"])

    paired = proxmox_guest_links.pair_guests(
        ids["pve1"], machines["pve1"].pve_guests, machines.values()
    )

    assert host is not None
    assert (host.machine_id, host.vmid, host.type, host.status) == (
        ids["pve1"],
        112,
        "lxc",
        "stopped",
    )
    assert nothing is None and bare_metal is None
    assert {vmid: m.name for vmid, m in paired.items()} == {111: "dc", 112: "Web one"}


def test_an_ambiguous_name_pairs_nothing() -> None:
    class _M:
        def __init__(self, name: str) -> None:
            self.id = uuid.uuid4()
            self.name = name
            self.discovered_hostname: str | None = None

    host, twin_a, twin_b = _M("pve1"), _M("web1"), _M("web1.lan")
    guests = proxmox.parse_guests(GUESTS)
    two_guests = proxmox.parse_guests(
        '[{"vmid":1,"name":"web1","type":"qemu"},{"vmid":2,"name":"web1","type":"lxc"}]'
    )

    assert proxmox_guest_links.pair_guests(host.id, guests, [host, twin_a, twin_b]) == {}
    assert proxmox_guest_links.pair_guests(host.id, two_guests, [host, twin_a]) == {}
    assert proxmox_guest_links.find_host(twin_a, [(host, two_guests)]) is None
    # A template is never a running machine.
    assert proxmox_guest_links.find_host(_M("tpl"), [(host, guests)]) is None


async def test_a_parallel_batch_holds_debcontrols_own_machines_back(
    db_session_factory: Any, celery_calls: Any, monkeypatch: Any, own_boot_id: str
) -> None:
    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    ids = await _fleet(db_session_factory)
    async with db_session_factory() as db:
        machines = list((await db.execute(select(Machine))).scalars().all())
        batch_id, _skipped = await trigger_updates(db, machines, UpgradeStrategy.FULL_UPGRADE)
        runs = {
            r.machine_id: r
            for r in (await db.execute(select(MachineUpdateRun))).scalars().all()
        }

    def started() -> list[str]:
        return [c[1][0] for c in celery_calls if c[0] == "app.tasks.jobs.run_machine_update"]

    assert runs[ids["dc"]].hold_order == self_host.HOLD_HOST
    assert runs[ids["pve1"]].hold_order == self_host.HOLD_HYPERVISOR
    assert runs[ids["app1"]].hold_order is None
    assert sorted(started()) == sorted(str(runs[ids[n]].id) for n in ("web1", "app1"))

    # While anything else is open, nothing is released.
    assert await jobs._release_held_runs(str(batch_id)) is None

    async def finish(name: str) -> None:
        async with db_session_factory() as db:
            run = await db.get(MachineUpdateRun, runs[ids[name]].id)
            assert run is not None
            run.status = UpdateRunStatus.FAILED if name == "app1" else UpdateRunStatus.SUCCEEDED
            await db.commit()

    await finish("web1")
    await finish("app1")
    first = await jobs._release_held_runs(str(batch_id))
    again = await jobs._release_held_runs(str(batch_id))
    await finish("dc")
    last = await jobs._release_held_runs(str(batch_id))

    # The host first, the hypervisor under it after; never the same run twice.
    assert first == str(runs[ids["dc"]].id)
    assert again is None
    assert last == str(runs[ids["pve1"]].id)
    assert started()[-2:] == [first, last]


async def test_a_rolling_batch_orders_them_last_and_a_lone_one_starts(
    db_session_factory: Any, celery_calls: Any, own_boot_id: str
) -> None:
    ids = await _fleet(db_session_factory)
    async with db_session_factory() as db:
        machines = list((await db.execute(select(Machine))).scalars().all())
        await trigger_updates(db, machines, UpgradeStrategy.UPGRADE, rolling=True)
        rolling = {
            r.machine_id: r.rollout_position
            for r in (await db.execute(select(MachineUpdateRun))).scalars().all()
        }
        only = [m for m in machines if m.id == ids["dc"]]
        lone_batch, _ = await trigger_updates(db, only, UpgradeStrategy.UPGRADE)

    assert rolling[ids["dc"]] == 2 and rolling[ids["pve1"]] == 3
    released = [c[1][0] for c in celery_calls if c[0] == "app.tasks.jobs.release_held_runs"]
    assert released == [str(lone_batch)]


async def test_without_a_matching_boot_id_nothing_changes(
    db_session_factory: Any, celery_calls: Any
) -> None:
    await _fleet(db_session_factory)
    async with db_session_factory() as db:
        machines = list((await db.execute(select(Machine))).scalars().all())
        await trigger_updates(db, machines, UpgradeStrategy.UPGRADE)
        runs = list((await db.execute(select(MachineUpdateRun))).scalars().all())
        own = await self_host.find(db)

    assert own == self_host.NONE
    assert all(r.hold_order is None for r in runs)
    assert len([c for c in celery_calls if c[0] == "app.tasks.jobs.run_machine_update"]) == 4


async def test_pages_say_where_debcontrol_runs(
    client: AsyncClient, db_session_factory: Any, own_boot_id: str
) -> None:
    ids = await _fleet(db_session_factory)

    host_page = await client.get(f"/machines/{ids['dc']}")
    hypervisor_page = await client.get(f"/machines/{ids['pve1']}/proxmox")
    guest_page = await client.get(f"/machines/{ids['web1']}")
    listing = await client.get("/machines")
    power = await client.get(f"/machines/{ids['dc']}/power/reboot")

    assert "debcontrol itself runs on this machine." in host_page.text
    assert f'href="/machines/{ids["pve1"]}/proxmox">pve1</a>' in host_page.text
    assert "Runs as VM 111 on" in host_page.text
    assert "Runs as container 112 on" in guest_page.text
    assert "debcontrol itself runs on" not in guest_page.text
    # The guest rows link to the machines they are.
    assert f'<a href="/machines/{ids["dc"]}"' in hypervisor_page.text
    assert f'<a href="/machines/{ids["web1"]}"' in hypervisor_page.text
    assert "debcontrol depends on: dc, pve1." in listing.text
    assert "debcontrol itself runs on this machine. Updating or restarting" in power.text


async def test_api_reports_the_host_and_the_role(
    client: AsyncClient, db_session_factory: Any, own_boot_id: str
) -> None:
    ids = await _fleet(db_session_factory)
    headers = await _api_token(client)

    dc = (await client.get(f"/api/v1/machines/{ids['dc']}", headers=headers)).json()
    pve = (await client.get(f"/api/v1/machines/{ids['pve1']}", headers=headers)).json()
    app1 = (await client.get(f"/api/v1/machines/{ids['app1']}", headers=headers)).json()
    tab = (await client.get(f"/api/v1/machines/{ids['pve1']}/proxmox", headers=headers)).json()

    assert dc["debcontrol_role"] == "host"
    assert dc["runs_on"] == {
        "machine_id": str(ids["pve1"]),
        "machine_name": "pve1",
        "vmid": 111,
        "type": "qemu",
        "status": "running",
    }
    assert pve["debcontrol_role"] == "hypervisor" and pve["runs_on"] is None
    assert app1["debcontrol_role"] is None and app1["runs_on"] is None
    assert tab["guest_machines"] == {"111": str(ids["dc"]), "112": str(ids["web1"])}


def test_templates_are_not_reported_as_not_backed_up() -> None:
    backups = proxmox.parse_backups(
        "[]",
        "[]",
        '[{"vmid":112,"name":"web1","type":"lxc"},{"vmid":9000,"name":"tpl","type":"qemu"}]',
    )

    uncovered, signed_off = proxmox.split_not_backed_up(
        backups, [9000], proxmox.parse_guests(GUESTS)
    )

    assert [g["vmid"] for g in uncovered] == [112]
    assert signed_off == []


def test_failed_tasks_older_than_two_weeks_are_left_out() -> None:
    now = 1_800_000_000
    tasks: list[dict[str, Any]] = [
        {"id": "a", "started_at": now - 3600},
        {"id": "b", "started_at": now - 13 * 86400},
        {"id": "c", "started_at": now - 15 * 86400},
        {"id": "d", "started_at": None},
    ]

    recent = proxmox.recent_failed_tasks(tasks, now)

    assert [t["id"] for t in recent] == ["a", "b", "d"]
    assert proxmox.recent_failed_tasks(None, now) == []
