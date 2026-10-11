"""Proxmox guests marked as deliberately not backed up
(`app.services.proxmox_backup_exempt`): they leave the "not in any backup
job" warning on the Proxmox tab and the Overview, and can be put back."""

from __future__ import annotations

import re
from typing import Any

from httpx2 import AsyncClient
from sqlalchemy import select

from app.db.models.audit_log import AuditLogEntry
from app.db.models.machine import Machine
from app.ssh import proxmox
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token

_NOT_BACKED_UP = (
    '[{"vmid":105,"name":"web","type":"lxc"},'
    '{"vmid":9000,"name":"tpl-debian","type":"qemu"},'
    '{"vmid":9001,"name":"test","type":"qemu"}]'
)


async def _pve_machine(db_session_factory: Any) -> Any:
    return await _add_machine(
        db_session_factory,
        pve_version="8.3.1",
        pve_guests=proxmox.parse_guests(
            '[{"vmid":105,"name":"web","type":"lxc","status":"running","cpu":0.1}]'
        ),
        pve_backups=proxmox.parse_backups("[]", "[]", _NOT_BACKED_UP),
    )


def test_split_keeps_only_guests_proxmox_still_reports() -> None:
    backups = proxmox.parse_backups("[]", "[]", _NOT_BACKED_UP)

    uncovered, signed_off = proxmox.split_not_backed_up(backups, [9000, 4242])

    assert [g["vmid"] for g in uncovered] == [105, 9001]
    assert [g["vmid"] for g in signed_off] == [9000]
    assert proxmox.split_not_backed_up(None, [1]) == ([], [])
    assert proxmox.with_backup_exempt([9000], [105, 9000], exempt=True) == [105, 9000]
    assert proxmox.with_backup_exempt([105, 9000], [105], exempt=False) == [9000]


async def _csrf(client: AsyncClient, url: str) -> str:
    page = await client.get(url)
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match is not None
    return match.group(1)


async def test_marking_a_guest_removes_it_from_the_warning(
    client: AsyncClient, db_session_factory: Any
) -> None:
    machine_id = await _pve_machine(db_session_factory)
    base = f"/machines/{machine_id}/proxmox"
    csrf = await _csrf(client, base)

    before = await client.get(f"/machines/{machine_id}")
    marked = await client.post(
        f"{base}/backup-exempt",
        data={"csrf_token": csrf, "vmid": "9000", "exempt": "1"},
        follow_redirects=False,
    )
    page = await client.get(base)
    overview = await client.get(f"/machines/{machine_id}")

    assert "3 guests without a backup job" in before.text
    assert marked.status_code == 303 and marked.headers["location"].endswith("/proxmox#backups")
    assert "2 guests aren&#39;t in any backup job:" in page.text
    assert "Deliberately not backed up (1):" in page.text
    assert "2 guests without a backup job" in overview.text
    async with db_session_factory() as db:
        assert (await db.get(Machine, machine_id)).pve_backup_exempt == [9000]
        actions = list((await db.execute(select(AuditLogEntry.action))).scalars().all())
    assert actions.count("machine.proxmox.backup_exempt.add") == 1


async def test_mark_all_then_warn_again(client: AsyncClient, db_session_factory: Any) -> None:
    machine_id = await _pve_machine(db_session_factory)
    base = f"/machines/{machine_id}/proxmox"
    csrf = await _csrf(client, base)

    await client.post(f"{base}/backup-exempt", data={"csrf_token": csrf, "vmid": "all"})
    quiet = await client.get(base)
    overview = await client.get(f"/machines/{machine_id}")
    await client.post(
        f"{base}/backup-exempt", data={"csrf_token": csrf, "vmid": "105", "exempt": "0"}
    )
    again = await client.get(base)
    unknown = await client.post(
        f"{base}/backup-exempt", data={"csrf_token": csrf, "vmid": "4242", "exempt": "1"}
    )

    assert "in any backup job" not in quiet.text
    assert "Deliberately not backed up (3):" in quiet.text
    assert "without a backup job" not in overview.text
    assert "1 guest isn&#39;t in any backup job:" in again.text
    assert unknown.status_code == 404
    async with db_session_factory() as db:
        assert (await db.get(Machine, machine_id)).pve_backup_exempt == [9000, 9001]


async def test_api_marks_and_unmarks(client: AsyncClient, db_session_factory: Any) -> None:
    machine_id = await _pve_machine(db_session_factory)
    headers = await _api_token(client)
    base = f"/api/v1/machines/{machine_id}/proxmox"

    marked = await client.put(f"{base}/backup-exempt/9000", headers=headers)
    unknown = await client.put(f"{base}/backup-exempt/4242", headers=headers)
    listing = await client.get(base, headers=headers)
    unmarked = await client.delete(f"{base}/backup-exempt/9000", headers=headers)
    again = await client.delete(f"{base}/backup-exempt/9000", headers=headers)

    assert marked.status_code == 200 and marked.json() == {"backup_exempt": [9000]}
    assert unknown.status_code == 404
    assert listing.json()["backup_exempt"] == [9000]
    assert len(listing.json()["backups"]["not_backed_up"]) == 3
    assert unmarked.json() == {"backup_exempt": []}
    assert again.status_code == 404
