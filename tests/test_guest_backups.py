"""When each Proxmox guest was last backed up (`app.ssh.proxmox`): read
from the node's backup storages, shown per guest, usable in a rule."""

from __future__ import annotations

from typing import Any

from httpx2 import AsyncClient

from app.services.condition_fields import CONDITION_FIELDS
from app.ssh import proxmox
from app.ssh.facts import parse_facts_output
from tests.test_homelab_round import _add_machine
from tests.test_update_history import _api_token

NOW = 1_790_100_000
DAY = 86400
GUESTS = proxmox.parse_guests(
    '[{"vmid":111,"name":"web","type":"qemu","status":"running"},'
    '{"vmid":112,"name":"db","type":"lxc","status":"running"},'
    '{"vmid":113,"name":"scratch","type":"qemu","status":"stopped"},'
    '{"vmid":114,"name":"new","type":"qemu","status":"running"},'
    '{"vmid":9000,"name":"tpl","type":"qemu","status":"stopped","template":1}]'
)
SECTION = f"listed\n111 {NOW - 3600} 7\n112 {NOW - 9 * DAY} 2\nnot a line\n"


def test_backups_are_read_per_guest() -> None:
    backups = proxmox.parse_guest_backups(SECTION)

    assert backups == {
        "111": {"last": NOW - 3600, "count": 7},
        "112": {"last": NOW - 9 * DAY, "count": 2},
    }
    # Listed and empty is not the same as never listed.
    assert proxmox.parse_guest_backups("listed\n") == {}
    assert proxmox.parse_guest_backups("") is None
    facts = parse_facts_output(f"===PVE_GUEST_BACKUPS===\n{SECTION}")
    assert facts["pve_guest_backups"] == backups


def test_a_template_and_an_exempt_guest_are_not_expected_to_have_one() -> None:
    backups = proxmox.parse_guest_backups(SECTION)

    rows = proxmox.guest_backup_rows(GUESTS, backups, [113], NOW)

    assert rows[111]["age_days"] == 0 and rows[111]["count"] == 7
    assert rows[112]["age_days"] == 9
    assert rows[113] == {"last": None, "count": 0, "age_days": None, "expected": False}
    assert rows[114]["expected"] is True and rows[114]["last"] is None
    assert rows[9000]["expected"] is False
    assert proxmox.oldest_guest_backup_days(GUESTS, backups, [113], NOW) == 9
    assert proxmox.guests_without_backup(GUESTS, backups, [113]) == 1
    assert proxmox.guest_backup_rows(GUESTS, None, None, NOW) == {}
    assert proxmox.oldest_guest_backup_days(GUESTS, None, None, NOW) is None
    assert proxmox.guests_without_backup(GUESTS, None, None) is None


async def test_proxmox_tab_and_api_show_the_last_backup(
    client: AsyncClient, db_session_factory: Any
) -> None:
    import time

    now = int(time.time())
    backups = {"111": {"last": now - 3600, "count": 7}, "112": {"last": now - 9 * DAY, "count": 2}}
    machine_id = await _add_machine(
        db_session_factory,
        pve_version="8.3.1",
        pve_guests=GUESTS,
        pve_guest_backups=backups,
        pve_backup_exempt=[113],
    )
    old_host = await _add_machine(
        db_session_factory,
        name="old",
        ip_address="10.9.9.9",
        pve_version="8.3.1",
        pve_guests=GUESTS,
    )
    headers = await _api_token(client)

    page = await client.get(f"/machines/{machine_id}/proxmox")
    before_upgrade = await client.get(f"/machines/{old_host}/proxmox")
    api = (await client.get(f"/api/v1/machines/{machine_id}/proxmox", headers=headers)).json()

    assert "Last backup" in page.text
    assert "today" in page.text and "7 kept" in page.text
    assert "9 d ago" in page.text and "2 kept" in page.text
    # Only the new guest is missing one it should have.
    assert page.text.count('<span class="badge badge-warn">none</span>') == 1
    assert "Last backup" not in before_upgrade.text
    assert api["guest_backups"] == backups


def test_rules_can_watch_the_age_of_the_stalest_backup() -> None:
    class _Host:
        def __init__(self) -> None:
            self.pve_guests = GUESTS
            self.pve_backup_exempt = [113]
            self.pve_guest_backups: dict[str, dict[str, int]] | None = {
                "111": {"last": 0, "count": 1}
            }

    host: Any = _Host()
    age = CONDITION_FIELDS["proxmox.oldest_guest_backup_days"].accessor(host, None, None)
    missing = CONDITION_FIELDS["proxmox.guests_without_backup_count"].accessor(host, None, None)
    host.pve_guest_backups = None
    unknown = CONDITION_FIELDS["proxmox.oldest_guest_backup_days"].accessor(host, None, None)

    assert isinstance(age, int) and age > 20000
    assert missing == 2
    assert unknown is None
