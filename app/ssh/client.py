"""Tenká vrstva nad AsyncSSH pro připojování na spravované Debian stroje.

Bezpečnostní princip — žádné "trust on first use" naslepo:

1. `discover_host_key_fingerprint()` se strojem naváže spojení POUZE za
   účelem zjištění otisku jeho SSH host klíče a spojení vždy záměrně
   ukončí bez autentizace. Otisk se zobrazí obsluze, která ho musí ověřit
   mimo tuto aplikaci (např. přes konzoli poskytovatele serveru, `ssh-keygen
   -lf` na samotném stroji apod.) a teprve pak explicitně potvrdit.
2. Až po tomto lidském potvrzení se otisk uloží k danému stroji
   (`Machine.host_key_fingerprint`).
3. Všechna další spojení (`open_connection`) pak ověřují prezentovaný klíč
   striktně proti tomuto uloženému otisku — neshoda okamžitě ukončí spojení
   jako možný Man-in-the-Middle útok, nikdy se tiše neignoruje.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING

import asyncssh

from app.ssh.exceptions import HostKeyMismatchError, SSHConnectionError, UnknownHostKeyError

if TYPE_CHECKING:
    from app.db.models.machine import Machine

FINGERPRINT_HASH = "sha256"


class _DiscoverySSHClient(asyncssh.SSHClient):
    """Zjistí otisk klíče serveru a spojení vždy odmítne — nikdy neautentizuje."""

    def __init__(self) -> None:
        self.discovered_fingerprint: str | None = None

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey
    ) -> bool:
        self.discovered_fingerprint = key.get_fingerprint(FINGERPRINT_HASH)
        return False


class _PinnedSSHClient(asyncssh.SSHClient):
    """Přijme spojení jen pokud klíč serveru odpovídá připnutému otisku."""

    def __init__(self, expected_fingerprint: str) -> None:
        self._expected_fingerprint = expected_fingerprint
        self.presented_fingerprint: str | None = None

    def validate_host_public_key(
        self, host: str, addr: str, port: int, key: asyncssh.SSHKey
    ) -> bool:
        self.presented_fingerprint = key.get_fingerprint(FINGERPRINT_HASH)
        return self.presented_fingerprint == self._expected_fingerprint


async def discover_host_key_fingerprint(hostname: str, port: int, timeout_seconds: int) -> str:
    """Zjistí SHA256 otisk host klíče serveru, aniž by se s ním kdy autentizovala.

    Vrací otisk k lidskému ověření. Nikdy sama o sobě nic "nedůvěřuje".
    """
    holder: dict[str, _DiscoverySSHClient] = {}

    def factory() -> _DiscoverySSHClient:
        client = _DiscoverySSHClient()
        holder["client"] = client
        return client

    try:
        async with asyncio.timeout(timeout_seconds):
            await asyncssh.connect(
                hostname,
                port=port,
                known_hosts=None,
                client_factory=factory,
                username="debcontrol-key-discovery",
            )
    except (asyncssh.Error, OSError, TimeoutError):
        pass  # očekávané: factory záměrně odmítá každé spojení

    client = holder.get("client")
    if client is None or client.discovered_fingerprint is None:
        raise SSHConnectionError(
            f"Nepodařilo se zjistit otisk SSH klíče serveru {hostname}:{port}."
        )
    return client.discovered_fingerprint


def _build_connect_kwargs(
    machine: Machine,
    secret: str | None,
    client_factory: Callable[[], asyncssh.SSHClient],
) -> dict[str, object]:
    from app.db.models.machine import AuthMethod  # lokální import kvůli TYPE_CHECKING výše

    kwargs: dict[str, object] = {
        "host": machine.hostname,
        "port": machine.port,
        "username": machine.username,
        "known_hosts": None,
        "client_factory": client_factory,
        "client_keys": [],
    }
    if machine.auth_method == AuthMethod.PASSWORD:
        kwargs["password"] = secret
    else:
        if not secret:
            raise SSHConnectionError("Chybí privátní klíč pro autentizaci.")
        kwargs["client_keys"] = [asyncssh.import_private_key(secret)]
    return kwargs


async def open_connection(
    machine: Machine, secret: str | None, timeout_seconds: int
) -> asyncssh.SSHClientConnection:
    """Otevře SSH spojení na stroj se striktním ověřením připnutého host klíče."""
    if not machine.host_key_fingerprint:
        raise UnknownHostKeyError(
            f"Stroj {machine.hostname} nemá připnutý otisk SSH klíče serveru — "
            "nejdřív ho zjisti a potvrď."
        )

    holder: dict[str, _PinnedSSHClient] = {}

    def factory() -> _PinnedSSHClient:
        client = _PinnedSSHClient(machine.host_key_fingerprint)  # type: ignore[arg-type]
        holder["client"] = client
        return client

    connect_kwargs = _build_connect_kwargs(machine, secret, factory)

    try:
        async with asyncio.timeout(timeout_seconds):
            return await asyncssh.connect(**connect_kwargs)
    except (asyncssh.Error, OSError, TimeoutError) as exc:
        client = holder.get("client")
        presented = client.presented_fingerprint if client else None
        if presented and presented != machine.host_key_fingerprint:
            raise HostKeyMismatchError(
                f"Server {machine.hostname}:{machine.port} prezentoval jiný otisk klíče "
                f"({presented}) než je připnutý ({machine.host_key_fingerprint}). "
                "Spojení bylo odmítnuto — může jít o útok typu Man-in-the-Middle."
            ) from exc
        raise SSHConnectionError(
            f"Spojení na {machine.hostname}:{machine.port} selhalo: {exc}"
        ) from exc


async def test_connection(machine: Machine, secret: str | None, timeout_seconds: int) -> str:
    """Ověří dostupnost stroje a vrátí výstup jednoduchého diagnostického příkazu."""
    async with await open_connection(machine, secret, timeout_seconds) as conn:
        result = await conn.run("uname -a", check=False, timeout=timeout_seconds)

    stdout = result.stdout
    if not stdout:
        return ""
    return (stdout if isinstance(stdout, str) else stdout.decode()).strip()
