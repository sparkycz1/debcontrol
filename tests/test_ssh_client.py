from __future__ import annotations

import pytest

from app.db.models.machine import AuthMethod, Machine
from app.ssh.client import open_connection
from app.ssh.exceptions import UnknownHostKeyError


async def test_open_connection_refuses_without_pinned_fingerprint():
    """No connection may be attempted at all without a confirmed key fingerprint."""
    machine = Machine(
        hostname="unpinned.example.com",
        port=22,
        username="admin",
        auth_method=AuthMethod.PASSWORD,
        host_key_fingerprint=None,
    )

    with pytest.raises(UnknownHostKeyError):
        await open_connection(machine, secret="whatever", timeout_seconds=1)
