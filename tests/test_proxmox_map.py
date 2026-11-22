"""Proxmox VE guests in depth, node capacity, a machine's network picture
and the Map pages (`app.ssh.proxmox`, `app.services.proxmox_capacity`,
`app.services.network_topology`, `app.services.fleet_map`): parsing,
the over-commit check, where a guest fits, the pages and the REST API."""

from __future__ import annotations

import json
import shlex
import subprocess
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import AuthMethod, Machine
from app.services import fleet_map, machine_health, network_topology, proxmox_capacity
from app.services.proxmox_guest_links import pair_guests
from app.ssh import proxmox
from tests.test_api_v1_extended import _api_token

GIB = 1024**3

_RESOURCES = json.dumps(
    [
        {"type": "node", "node": "pve1", "status": "online", "cpu": 0.25, "maxcpu": 8,
         "mem": 20 * GIB, "maxmem": 32 * GIB, "disk": 10, "maxdisk": 100, "uptime": 99},
        {"type": "node", "node": "pve2", "status": "online", "cpu": 0.05, "maxcpu": 4,
         "mem": 4 * GIB, "maxmem": 16 * GIB},
        {"type": "storage", "node": "pve1", "storage": "local-lvm", "plugintype": "lvmthin",
         "content": "rootdir,images", "disk": 100 * GIB, "maxdisk": 400 * GIB,
         "status": "available", "shared": 0},
        {"type": "storage", "node": "pve1", "storage": "local", "plugintype": "dir",
         "content": "iso,backup", "disk": 1, "maxdisk": 2, "status": "available"},
        {"type": "storage", "node": "pve2", "storage": "local-lvm", "plugintype": "lvmthin",
         "content": "images", "disk": 10 * GIB, "maxdisk": 50 * GIB, "status": "available"},
        {"type": "qemu", "vmid": 101, "name": "web1", "node": "pve1", "status": "running",
         "cpu": 0.1, "maxcpu": 4, "mem": 2 * GIB, "maxmem": 24 * GIB, "maxdisk": 32 * GIB,
         "diskread": 1000, "diskwrite": 2000, "netin": 3000, "netout": 4000, "uptime": 50},
        {"type": "lxc", "vmid": 200, "name": "ct1", "node": "pve1", "status": "running",
         "maxcpu": 2, "mem": GIB, "maxmem": 12 * GIB},
        {"type": "qemu", "vmid": 300, "name": "off", "node": "pve2", "status": "stopped",
         "maxcpu": 2, "maxmem": 8 * GIB},
        {"type": "sdn", "node": "pve1", "sdn": "localnetwork"},
    ]
)

_VM_CONF = (
    "#Web server\n#owner%3A ops\nagent: 1\ncores: 2\nsockets: 2\nmemory: 4096\nname: web1\n"
    "net0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1,tag=10\n"
    "scsi0: local-lvm:vm-101-disk-0,size=32G\nide2: none,media=cdrom\nonboot: 1\n"
    "\n[snap1]\nmemory: 1\n"
)
_CT_CONF = (
    "hostname: ct1\nmemory: 512\ncores: 1\nrootfs: local-lvm:subvol-200-disk-0,size=8G\n"
    "mp0: /tank/data,mp=/data,backup=1\nunprivileged: 1\n"
    "net0: name=eth0,bridge=vmbr0,hwaddr=BC:24:11:00:11:22,ip=dhcp,type=veth\n"
)
_AGENT = json.dumps(
    {"result": [
        {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1"}]},
        {"name": "eth0", "ip-addresses": [
            {"ip-address": "192.168.1.21"}, {"ip-address": "fe80::1"},
            {"ip-address": "2001:db8::21"},
        ]},
    ]}
)


def _details_section() -> str:
    return (
        f"@@GUEST qemu 101\n{_VM_CONF}\n@@IPS\n{_AGENT}\n\n"
        f"@@GUEST lxc 200\n{_CT_CONF}\n@@IPS\n192.168.1.30\nfe80::2\n\n"
        "@@GUEST lxc x9\nbad\n@@IPS\n"
    )


def test_resources_and_guests_from_one_call() -> None:
    guests = proxmox.parse_guests(_RESOURCES)
    assert guests is not None and [g["vmid"] for g in guests] == [101, 200, 300]
    web = guests[0]
    assert web["cores"] == 4 and web["disk_write_bytes"] == 2000 and web["net_out_bytes"] == 4000
    resources = proxmox.parse_resources(_RESOURCES)
    assert resources is not None
    assert [n["node"] for n in resources["nodes"]] == ["pve1", "pve2"]
    assert resources["nodes"][0]["cores"] == 8
    assert {(s["node"], s["storage"]) for s in resources["storages"]} == {
        ("pve1", "local-lvm"), ("pve1", "local"), ("pve2", "local-lvm"),
    }
    assert proxmox.parse_resources("") is None and proxmox.parse_resources("nope") is None


def test_guest_rates_between_samples() -> None:
    before = proxmox.parse_guests(_RESOURCES)
    after = proxmox.parse_guests(_RESOURCES)
    assert before is not None and after is not None
    after[0]["disk_read_bytes"] = 1000 + 600
    after[0]["net_in_bytes"] = 100  # restarted: counter went down
    rated = proxmox.with_guest_rates(before, after, 60)
    assert rated is not None
    assert rated[0]["disk_read_bps"] == 10.0 and rated[0]["net_in_bps"] is None
    assert rated[2]["disk_read_bps"] is None  # stopped
    first = proxmox.with_guest_rates(None, proxmox.parse_guests(_RESOURCES), None)
    assert first is not None and first[0]["disk_read_bps"] is None


def test_guest_details_parse_config_and_addresses() -> None:
    details = proxmox.parse_guest_details(_details_section())
    assert details is not None and set(details) == {"101", "200"}
    vm = details["101"]
    assert vm["notes"] == "Web server\nowner: ops" and vm["cores"] == 4 and vm["onboot"]
    assert vm["agent"] and vm["memory_mb"] == 4096
    assert vm["disks"] == [{"key": "scsi0", "volume": "local-lvm:vm-101-disk-0", "size": "32G"}]
    assert vm["nets"][0]["bridge"] == "vmbr0" and vm["nets"][0]["vlan"] == "10"
    assert vm["nets"][0]["mac"] == "bc:24:11:aa:bb:cc" and vm["nets"][0]["model"] == "virtio"
    assert vm["ips"] == ["192.168.1.21", "2001:db8::21"]
    ct = details["200"]
    assert [m["key"] for m in ct["mounts"]] == ["rootfs", "mp0"]
    assert ct["mounts"][1]["path"] == "/data" and ct["unprivileged"] is True
    assert ct["ips"] == ["192.168.1.30"]
    assert proxmox.parse_guest_details("") is None
    assert proxmox.parse_guest_details("nothing here\n") == {}


def test_guest_details_script_reads_config_files(tmp_path: Path) -> None:
    """The shell loop itself, against a fake /etc/pve."""
    (tmp_path / "qemu-server").mkdir()
    (tmp_path / "lxc").mkdir()
    (tmp_path / "qemu-server" / "101.conf").write_text(_VM_CONF)
    (tmp_path / "lxc" / "200.conf").write_text(_CT_CONF)
    (tmp_path / "lxc" / "evil;rm.conf").write_text("hostname: x\n")
    script = proxmox._GUEST_DETAILS_SCRIPT.replace("/etc/pve/", f"{tmp_path}/")
    output = subprocess.run(["sh", "-c", script], capture_output=True, text=True, check=False)  # noqa: S603, S607
    details = proxmox.parse_guest_details(output.stdout)
    assert details is not None and set(details) == {"101", "200"}
    assert details["101"]["name"] == "web1" and details["200"]["mounts"][0]["size"] == "8G"


def test_notes_and_console_commands() -> None:
    guest = {"vmid": 101, "type": "qemu", "node": "pve1"}
    notes = "it's; $(rm -rf /)\nline two"
    command = proxmox.build_guest_notes_command(guest, notes)
    assert command.endswith(f"--description {shlex.quote(notes)} 2>&1")
    assert "--delete description" in proxmox.build_guest_notes_command(guest, "  ")
    assert proxmox.clean_notes("a\r\nb\x00\x1b[31m\tc") == "a\nb[31m\tc"
    assert proxmox.build_guest_console_command(guest) == "sudo -n qm terminal 101"
    assert proxmox.build_guest_console_command({**guest, "type": "lxc"}) == "sudo -n pct enter 101"
    for bad in ({**guest, "node": "pve1; reboot"}, {**guest, "type": "x"}):
        try:
            proxmox.build_guest_notes_command(bad, "x")
        except ValueError:
            continue
        raise AssertionError("accepted a bad guest")


def _machine(name: str = "pve1", **kwargs: Any) -> Machine:
    return Machine(
        id=kwargs.pop("id", uuid.uuid4()),
        name=name,
        ip_address=kwargs.pop("ip_address", "10.0.0.5"),
        port=22,
        username="root",
        auth_method=AuthMethod.PASSWORD,
        host_key_fingerprint="SHA256:abc",
        is_active=True,
        **kwargs,
    )


def _pve(name: str = "pve1", **kwargs: Any) -> Machine:
    return _machine(
        name,
        pve_version="8.2.4",
        pve_guests=proxmox.parse_guests(_RESOURCES),
        pve_resources=proxmox.parse_resources(_RESOURCES),
        pve_cluster={"name": "lab", "quorate": True, "nodes": [
            {"name": "pve1", "online": True, "local": name == "pve1", "ip": ""},
            {"name": "pve2", "online": True, "local": name == "pve2", "ip": ""},
        ]},
        pve_guest_details=proxmox.parse_guest_details(_details_section()),
        **kwargs,
    )


def test_capacity_and_overcommit() -> None:
    host = _pve()
    node = proxmox_capacity.local_capacity(host)
    assert node is not None and node.node == "pve1"
    # 24 + 12 GiB given to running guests on a 32 GiB node.
    assert node.mem_running_bytes == 36 * GIB and node.overcommitted
    assert node.vcpus_running == 6 and node.vcpu_ratio == 0.75
    assert [s.name for s in node.storages] == ["local-lvm"]
    assert node.storage_free_bytes == 300 * GIB
    findings = machine_health._memory(host, None, machine_health.Thresholds())
    assert [(f.key, f.message) for f in findings] == [("memory.overcommit", "memory_overcommitted")]
    assert findings[0].params == {"given": "36", "total": "32"}

    other = _pve("pve2")
    nodes = proxmox_capacity.fleet_nodes([host, other])
    assert [(n.cluster, n.node) for n in nodes] == [("lab", "pve1"), ("lab", "pve2")]
    assert nodes[1].machine_name == "pve2" and nodes[1].mem_running_bytes == 0
    fits = proxmox_capacity.fits(nodes, 2, 8 * GIB, 20 * GIB)
    assert fits[0].node.node == "pve2" and fits[0].fits
    assert fits[1].reasons == ("memory",)
    too_big = proxmox_capacity.fits(nodes, 16, 0, 0)
    assert not any(f.fits for f in too_big) and too_big[0].reasons == ("cores",)


def _link(name: str, kind: str, master: str | None = None, rate: float | None = None,
          **extra: Any) -> dict[str, Any]:
    return {"name": name, "kind": kind, "master": master, "rx": rate, "tx": rate,
            "state": extra.pop("state", "up"), "addresses": extra.pop("addresses", []),
            "speed_mbps": 1000, **extra}


def test_topology_from_interfaces() -> None:
    links = [
        _link("eno1", "physical", "bond0", 1e6), _link("eno2", "physical", "bond0", 0.0),
        _link("bond0", "bond", "vmbr0", 1e6), _link("vmbr0", "bridge", addresses=["10.0.0.5/24"]),
        _link("tap101i0", "virtual", "fwbr101i0", 5e5), _link("fwbr101i0", "bridge"),
        _link("fwpr101p0", "virtual", "vmbr0"), _link("fwln101i0", "virtual", "fwbr101i0"),
        _link("veth200i0", "virtual", "vmbr0", 10.0), _link("docker0", "bridge"),
        _link("veth1a2b3c", "virtual", "docker0", 1.0), _link("veth4d5e6f", "virtual", "docker0"),
        _link("wg0", "virtual"),
    ]
    topo = network_topology.build(
        links, [{"vmid": 101, "name": "web1", "type": "qemu"}], guest_href="/g/{vmid}"
    )
    assert topo is not None
    by_id = {n.id: n for n in topo.nodes}
    assert "fwbr101i0" not in by_id and "wg0" not in by_id
    assert by_id["guest:101:vmbr0"].label == "web1" and by_id["guest:101:vmbr0"].href == "/g/101"
    assert by_id["guest:200:vmbr0"].detail == "CT 200"
    assert by_id["docker:docker0"].detail == "2"
    edges = {(e.source, e.target): e for e in topo.edges}
    assert ("eno1", "bond0") in edges and ("bond0", "vmbr0") in edges
    assert edges[("guest:101:vmbr0", "vmbr0")].width > edges[("guest:200:vmbr0", "vmbr0")].width
    assert all(e.path.startswith("M") for e in topo.edges)
    assert network_topology.build([_link("eth0", "physical")]) is None


def test_guests_pair_by_address() -> None:
    host = _pve()
    by_ip = _machine("something-else", ip_address="192.168.1.30")
    paired = pair_guests(host.id, host.pve_guests, [host, by_ip], host.pve_guest_details)
    assert paired == {200: by_ip}


async def _seed(db_session_factory: Any) -> dict[str, Any]:
    async with db_session_factory() as db:
        host = _pve(network_interfaces=[{"interface": "vmbr0", "address": "10.0.0.5/24"}],
                    default_gateway="10.0.0.1")
        guest = _machine("web1", ip_address="10.0.0.21",
                         network_interfaces=[{"interface": "eth0", "address": "10.0.0.21/24"},
                                             {"interface": "docker0", "address": "172.17.0.1/16"}],
                         default_gateway="10.0.0.1",
                         docker_status="ok",
                         docker_containers=[
                             {"name": "app", "state": "running", "image": "nginx:1",
                              "compose_project": "site", "ports": "", "link_labels": {
                                  "debcontrol.url": "https://site.example.com"}},
                         ])
        lone = _machine("nas", ip_address="10.0.0.40")
        db.add_all([host, guest, lone])
        await db.commit()
        return {"host": host.id, "guest": guest.id, "lone": lone.id}


async def test_where_and_networks(db_session_factory: Any) -> None:
    await _seed(db_session_factory)
    async with db_session_factory() as db:
        machines = list((await db.execute(select(Machine))).scalars().all())
    entries = fleet_map.where(machines)
    assert [e.machine.name for e in entries] == ["pve1", "nas"]
    web = next(g for g in entries[0].guests if g.vmid == 101)
    assert web.machine is not None and web.machine.machine.name == "web1"
    stack = web.machine.stacks[0]
    assert stack.name == "site" and stack.containers[0].links[0].url == "https://site.example.com"
    assert [g.vmid for g in entries[0].guests] == [101, 200]  # 300 runs on pve2
    assert [e.machine.name for e in fleet_map.where(machines, "nginx")] == ["pve1"]
    networks, unknown = fleet_map.networks(machines)
    assert [n.cidr for n in networks] == ["10.0.0.0/24"]
    assert networks[0].gateways == ["10.0.0.1"]
    assert [m.machine.name for m in networks[0].members] == ["pve1", "web1"]
    assert [m.name for m in unknown] == ["nas"]


async def test_map_pages(client: Any, db_session_factory: Any) -> None:
    await _seed(db_session_factory)
    where = await client.get("/map")
    assert where.status_code == 200 and "web1" in where.text
    assert 'href="https://site.example.com"' in where.text
    networks = await client.get("/map/networks")
    assert networks.status_code == 200 and "10.0.0.0/24" in networks.text
    capacity = await client.get("/map/capacity?cores=2&memory_gb=8&disk_gb=20")
    assert capacity.status_code == 200 and "Best fit: pve2" in capacity.text
    assert "over-committed" in capacity.text
    for page in (where, networks, capacity):
        assert "style=" not in page.text and "<style" not in page.text


async def test_guest_page_notes_and_console(
    client: Any, db_session_factory: Any, celery_calls: Any
) -> None:
    ids = await _seed(db_session_factory)
    host = ids["host"]
    tab = await client.get(f"/machines/{host}/proxmox")
    assert tab.status_code == 200
    assert f"/machines/{host}/proxmox/guests/101" in tab.text and "192.168.1.21" in tab.text
    page = await client.get(f"/machines/{host}/proxmox/guests/101")
    assert page.status_code == 200
    assert "Web server" in page.text and "local-lvm:vm-101-disk-0" in page.text
    assert f"/machines/{host}/proxmox/guests/101/console" in page.text
    ct = await client.get(f"/machines/{host}/proxmox/guests/200")
    assert "/data" in ct.text
    assert (await client.get(f"/machines/{host}/proxmox/guests/999")).status_code == 404

    celery_calls.result_for["app.tasks.jobs.set_proxmox_guest_notes"] = {"ok": True}
    saved = await client.post(
        f"/machines/{host}/proxmox/guests/101/notes",
        data={"csrf_token": client.cookies.get("csrftoken"), "notes": "New notes"},
        follow_redirects=False,
    )
    assert saved.status_code == 303 and "guest_notice=" in saved.headers["location"]
    assert ("app.tasks.jobs.set_proxmox_guest_notes", (str(host), 101, "New notes"), {}) in [
        tuple(c) for c in celery_calls
    ]
    async with db_session_factory() as db:
        actions = (await db.execute(select(AuditLogEntry.action))).scalars().all()
    assert "machine.guest.notes" in actions

    console = await client.get(f"/machines/{host}/proxmox/guests/200/console")
    assert console.status_code == 200 and "terminal/ws?guest=200" in console.text
    # VM 300 runs on the other node: no console from here.
    assert (await client.get(f"/machines/{host}/proxmox/guests/300/console")).status_code == 404


async def test_map_and_guest_api(client: Any, db_session_factory: Any, celery_calls: Any) -> None:
    ids = await _seed(db_session_factory)
    headers = await _api_token(client)
    where = (await client.get("/api/v1/map/where", headers=headers)).json()
    assert where[0]["name"] == "pve1"
    assert where[0]["guests"][0]["machine"]["stacks"][0]["name"] == "site"
    nets = (await client.get("/api/v1/map/networks", headers=headers)).json()
    assert nets["networks"][0]["cidr"] == "10.0.0.0/24" and nets["unknown"][0]["name"] == "nas"
    capacity = (await client.get("/api/v1/proxmox/capacity?memory_gb=8", headers=headers)).json()
    assert capacity["nodes"][0]["overcommitted"] is True
    assert capacity["fits"][0] == {
        "cluster": "lab", "node": "pve2", "fits": True, "reasons": [],
        "memory_left_bytes": 8 * GIB,
    }
    guest = (await client.get(f"/api/v1/machines/{ids['host']}/proxmox/guests/101",
                              headers=headers)).json()
    assert guest["details"]["ips"] == ["192.168.1.21", "2001:db8::21"]
    tab = (await client.get(f"/api/v1/machines/{ids['host']}/proxmox", headers=headers)).json()
    assert tab["resources"]["nodes"][0]["node"] == "pve1" and "101" in tab["guest_details"]
    topo = await client.get(f"/api/v1/machines/{ids['host']}/network/topology", headers=headers)
    assert topo.status_code == 200 and topo.json() is None  # no interfaces sampled
    celery_calls.result_for["app.tasks.jobs.set_proxmox_guest_notes"] = {"ok": True}
    notes = await client.put(f"/api/v1/machines/{ids['host']}/proxmox/guests/101/notes",
                             json={"notes": "via API"}, headers=headers)
    assert notes.status_code == 200 and notes.json() == {"notes": "via API"}
    celery_calls.result_for["app.tasks.jobs.set_proxmox_guest_notes"] = {
        "ok": False, "error": "permission denied"}
    failed = await client.put(f"/api/v1/machines/{ids['host']}/proxmox/guests/101/notes",
                              json={"notes": "x"}, headers=headers)
    assert failed.status_code == 502


async def test_set_notes_task_keeps_them(db_session_factory: Any, monkeypatch: Any) -> None:
    from app.tasks import jobs

    ids = await _seed(db_session_factory)
    seen: list[str] = []

    async def fake_run(machine: Any, secret: Any, guest: Any, notes: str, timeout: int) -> Any:  # noqa: ASYNC109
        seen.append(proxmox.build_guest_notes_command(guest, notes))
        return 0, ""

    async def no_secret(machine: Any, db: Any) -> None:
        return None

    monkeypatch.setattr("app.db.session.AsyncSessionLocal", db_session_factory)
    monkeypatch.setattr(jobs, "run_guest_notes", fake_run)
    monkeypatch.setattr(jobs, "resolve_machine_credential", no_secret)
    result = await jobs._set_proxmox_guest_notes(str(ids["host"]), 101, "Line\r\nTwo\x00")
    assert result == {"ok": True, "notes": "Line\nTwo"}
    assert "pvesh set /nodes/pve1/qemu/101/config --description" in seen[0]
    async with db_session_factory() as db:
        host = await db.get(Machine, ids["host"])
        assert host is not None and host.pve_guest_details["101"]["notes"] == "Line\nTwo"
