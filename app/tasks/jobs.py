"""Úlohy zpracovávané na pozadí přes arq (fronta v Redisu).

Zatím jen jedna ukázková úloha, která ověří dostupnost stroje — slouží
jako základ pro budoucí hromadné/dlouho běžící operace na více strojích.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from app.core.config import get_settings
from app.core.security import decrypt_secret
from app.db.session import AsyncSessionLocal
from app.ssh.client import test_connection
from app.ssh.exceptions import SSHConnectionError

logger = logging.getLogger(__name__)


async def ping_machine(ctx: dict[str, Any], machine_id: str) -> dict[str, Any]:
    """Zkusí se připojit na stroj a vrátit výstup `uname -a`."""
    from app.db.models.machine import Machine

    settings = get_settings()

    async with AsyncSessionLocal() as session:
        machine = await session.get(Machine, uuid.UUID(machine_id))
        if machine is None:
            return {"ok": False, "error": "Stroj nenalezen."}

        secret = decrypt_secret(machine.secret_encrypted) if machine.secret_encrypted else None

        try:
            output = await test_connection(machine, secret, settings.ssh_connect_timeout)
        except SSHConnectionError as exc:
            logger.warning("ping_machine selhal pro %s: %s", machine.hostname, exc)
            return {"ok": False, "error": str(exc)}

        return {"ok": True, "output": output}
