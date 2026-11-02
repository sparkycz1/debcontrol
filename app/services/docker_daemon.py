"""Fleet-wide Docker Engine settings (Docker → Settings): the keys of
`/etc/docker/daemon.json` debcontrol keeps the same on every machine in
scope, and the defaults it gives containers and stacks it sees for the
first time.

**What debcontrol manages in daemon.json** — only these keys, and only
the ones an admin filled in (an empty field leaves the machine's own
value alone):

- `log-driver` and, for `json-file`/`local`, `log-opts.max-size` and
  `log-opts.max-file` (other `log-opts` stay);
- `live-restore`;
- `default-address-pools`;
- `registry-mirrors`;
- `dns`;
- `no-new-privileges`;
- `builder.gc.defaultKeepStorage` (with `builder.gc.enabled`).

Everything else in the file is kept as it is. Applying
(`DockerJobKind.DAEMON_CONFIG`, `app.ssh.docker_daemon`) backs the file
up, lets `dockerd --validate` check the result where it can, and writes
it; the Docker daemon only reads it when it restarts, which happens on a
separate button (`DockerJobKind.DAEMON_RESTART`), never by itself. A
restart that leaves Docker down puts the backup back and restarts again.

**Defaults for new containers and stacks**: the update policy (automatic
updates on, limited to patch / minor / any version), the vulnerability
gate and autoheal. A container gets them the first time a monitoring
sample shows it (not when an existing one is recreated); a stack when it
is added. Existing settings are never changed by them.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.app_settings import AppSettings
from app.db.models.docker import (
    DockerContainerSetting,
    DockerJob,
    DockerJobKind,
    VulnerabilityGate,
)
from app.db.models.machine import Machine
from app.db.models.user import User
from app.services.access_scope import machines_visible_to

LOG_DRIVERS = ("json-file", "local", "journald")
ROTATING_DRIVERS = ("json-file", "local")
UPDATE_POLICIES = ("patch", "minor", "any")
GATES = tuple(g.value for g in VulnerabilityGate if g is not VulnerabilityGate.OFF)
MAX_POOLS = 10
MAX_MIRRORS = 5
MAX_DNS = 4

_SIZE_RE = re.compile(r"^[1-9][0-9]{0,4}[kmg]$")
_KEEP_RE = re.compile(r"^[1-9][0-9]{0,4}(MB|GB|TB)$")

# The daemon.json keys this module may change, in the order the page
# shows them.
FIELDS = (
    "log_driver",
    "log_max_size",
    "log_max_file",
    "live_restore",
    "address_pools",
    "registry_mirrors",
    "dns",
    "no_new_privileges",
    "builder_keep_storage",
)


class DaemonSettingsError(ValueError):
    """A value the form or API sent is not valid; `key` is an i18n key,
    `field` the setting it is about."""

    def __init__(self, field_name: str, key: str) -> None:
        super().__init__(f"{field_name}: {key}")
        self.field = field_name
        self.key = key


def _tristate(value: Any, name: str) -> bool | None:
    if value in (None, "", "keep"):
        return None
    if value in (True, "on", "true", "1"):
        return True
    if value in (False, "off", "false", "0"):
        return False
    raise DaemonSettingsError(name, "docker.settings.error.choice")


def _lines(value: Any) -> list[str]:
    if value is None:
        return []
    items = [str(v) for v in value] if isinstance(value, list) else re.split(r"[\s,]+", str(value))
    return [item.strip() for item in items if item.strip()]


def _pool(item: Any) -> dict[str, Any]:
    """`10.200.0.0/16 24`, `10.200.0.0/16:24` or {"base", "size"}."""
    if isinstance(item, dict):
        base, size = str(item.get("base") or ""), item.get("size")
    else:
        parts = re.split(r"[\s:]+", str(item).strip())
        if len(parts) != 2:
            raise DaemonSettingsError("address_pools", "docker.settings.error.pool")
        base, size = parts
    try:
        network = ipaddress.ip_network(base, strict=True)
        size_int = int(str(size))
    except ValueError:
        raise DaemonSettingsError("address_pools", "docker.settings.error.pool") from None
    if (
        network.version != 4
        or not network.is_private
        or not 8 <= network.prefixlen <= size_int <= 29
    ):
        raise DaemonSettingsError("address_pools", "docker.settings.error.pool")
    return {"base": str(network), "size": size_int}


def _mirror(url: str) -> str:
    parts = urlsplit(url)
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or len(url) > 255
    ):
        raise DaemonSettingsError("registry_mirrors", "docker.settings.error.mirror")
    return url.rstrip("/")


def _dns(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise DaemonSettingsError("dns", "docker.settings.error.dns") from None


def clean(raw: dict[str, Any]) -> dict[str, Any]:
    """The settings as stored (`AppSettings.docker_daemon_config`): only
    the filled-in ones, validated. Raises `DaemonSettingsError`."""
    out: dict[str, Any] = {}
    driver = str(raw.get("log_driver") or "").strip()
    if driver:
        if driver not in LOG_DRIVERS:
            raise DaemonSettingsError("log_driver", "docker.settings.error.choice")
        out["log_driver"] = driver
    size = str(raw.get("log_max_size") or "").strip().lower()
    if size:
        if not _SIZE_RE.match(size):
            raise DaemonSettingsError("log_max_size", "docker.settings.error.size")
        out["log_max_size"] = size
    files = str(raw.get("log_max_file") or "").strip()
    if files:
        if not files.isdecimal() or not 1 <= int(files) <= 100:
            raise DaemonSettingsError("log_max_file", "docker.settings.error.files")
        out["log_max_file"] = int(files)
    if (size or files) and driver not in ("", *ROTATING_DRIVERS):
        raise DaemonSettingsError("log_max_size", "docker.settings.error.rotation_driver")
    for name in ("live_restore", "no_new_privileges"):
        value = _tristate(raw.get(name), name)
        if value is not None:
            out[name] = value
    pools = raw.get("address_pools")
    pool_items = pools if isinstance(pools, list) else [
        line for line in str(pools or "").splitlines() if line.strip()
    ]
    if pool_items:
        if len(pool_items) > MAX_POOLS:
            raise DaemonSettingsError("address_pools", "docker.settings.error.too_many")
        out["address_pools"] = [_pool(item) for item in pool_items]
    mirrors = _lines(raw.get("registry_mirrors"))
    if mirrors:
        if len(mirrors) > MAX_MIRRORS:
            raise DaemonSettingsError("registry_mirrors", "docker.settings.error.too_many")
        out["registry_mirrors"] = [_mirror(m) for m in mirrors]
    servers = _lines(raw.get("dns"))
    if servers:
        if len(servers) > MAX_DNS:
            raise DaemonSettingsError("dns", "docker.settings.error.too_many")
        out["dns"] = [_dns(s) for s in servers]
    keep = str(raw.get("builder_keep_storage") or "").strip().upper()
    if keep:
        if not _KEEP_RE.match(keep):
            raise DaemonSettingsError("builder_keep_storage", "docker.settings.error.keep")
        out["builder_keep_storage"] = keep
    return out


def form_values(config: dict[str, Any] | None) -> dict[str, str]:
    """The stored settings as the form shows them."""
    config = config or {}
    values = dict.fromkeys(FIELDS, "")
    for name in ("log_driver", "log_max_size", "builder_keep_storage"):
        values[name] = str(config.get(name) or "")
    if config.get("log_max_file"):
        values["log_max_file"] = str(config["log_max_file"])
    for name in ("live_restore", "no_new_privileges"):
        if name in config:
            values[name] = "on" if config[name] else "off"
    values["address_pools"] = "\n".join(
        f"{p['base']} {p['size']}" for p in config.get("address_pools") or []
    )
    values["registry_mirrors"] = "\n".join(config.get("registry_mirrors") or [])
    values["dns"] = " ".join(config.get("dns") or [])
    return values


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def merge(daemon: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """`daemon` (the machine's daemon.json) with the managed keys set from
    `config`; every other key is kept."""
    out: dict[str, Any] = json.loads(json.dumps(daemon))
    if "log_driver" in config:
        out["log-driver"] = config["log_driver"]
    if "log_max_size" in config or "log_max_file" in config:
        opts = _dict(out.get("log-opts"))
        if "log_max_size" in config:
            opts["max-size"] = config["log_max_size"]
        if "log_max_file" in config:
            opts["max-file"] = str(config["log_max_file"])
        out["log-opts"] = opts
    if "live_restore" in config:
        out["live-restore"] = bool(config["live_restore"])
    if "address_pools" in config:
        out["default-address-pools"] = [dict(p) for p in config["address_pools"]]
    if "registry_mirrors" in config:
        out["registry-mirrors"] = list(config["registry_mirrors"])
    if "dns" in config:
        out["dns"] = list(config["dns"])
    if "no_new_privileges" in config:
        out["no-new-privileges"] = bool(config["no_new_privileges"])
    if "builder_keep_storage" in config:
        builder = _dict(out.get("builder"))
        gc = _dict(builder.get("gc"))
        gc["enabled"] = True
        gc["defaultKeepStorage"] = config["builder_keep_storage"]
        builder["gc"] = gc
        out["builder"] = builder
    return out


def managed_view(daemon: dict[str, Any] | None) -> dict[str, Any]:
    """The managed keys as a machine's daemon.json has them, in the stored
    settings' shape (for comparing; stored with the host check)."""
    daemon = _dict(daemon)
    view: dict[str, Any] = {}
    if daemon.get("log-driver"):
        view["log_driver"] = str(daemon["log-driver"])[:40]
    opts = _dict(daemon.get("log-opts"))
    if opts.get("max-size"):
        view["log_max_size"] = str(opts["max-size"]).lower()[:20]
    if str(opts.get("max-file") or "").isdecimal():
        view["log_max_file"] = int(str(opts["max-file"]))
    for key, name in (("live-restore", "live_restore"), ("no-new-privileges", "no_new_privileges")):
        if isinstance(daemon.get(key), bool):
            view[name] = daemon[key]
    pools = daemon.get("default-address-pools")
    if isinstance(pools, list):
        view["address_pools"] = [
            {"base": str(p.get("base"))[:50], "size": p.get("size")}
            for p in pools[:MAX_POOLS * 2]
            if isinstance(p, dict)
        ]
    for key, name in (("registry-mirrors", "registry_mirrors"), ("dns", "dns")):
        if isinstance(daemon.get(key), list):
            view[name] = [str(v).rstrip("/")[:255] for v in daemon[key][:20]]
    gc = _dict(_dict(daemon.get("builder")).get("gc"))
    if gc.get("defaultKeepStorage"):
        view["builder_keep_storage"] = str(gc["defaultKeepStorage"]).upper()[:20]
    return view


@dataclass
class Difference:
    field: str
    current: Any
    wanted: Any


def differences(config: dict[str, Any] | None, current: dict[str, Any] | None) -> list[Difference]:
    """Where a machine's daemon.json differs from the fleet settings (only
    the keys the settings manage)."""
    current = current or {}
    return [
        Difference(name, current.get(name), wanted)
        for name, wanted in (config or {}).items()
        if name in FIELDS and current.get(name) != wanted
    ]


def config_hash(config: dict[str, Any] | None) -> str:
    return hashlib.sha256(
        json.dumps(config or {}, sort_keys=True).encode()
    ).hexdigest()[:16]


@dataclass
class Scope:
    """Which machines the daemon settings are for: every machine with
    Docker, or only those in `group_ids`."""

    group_ids: list[uuid.UUID] = field(default_factory=list)

    def covers(self, machine: Machine) -> bool:
        return not self.group_ids or machine.group_id in self.group_ids


def scope_of(settings: AppSettings) -> Scope:
    ids: list[uuid.UUID] = []
    for raw in settings.docker_daemon_group_ids or []:
        try:
            ids.append(uuid.UUID(str(raw)))
        except ValueError:
            continue
    return Scope(ids)


def machine_status(machine: Machine, settings: AppSettings) -> dict[str, Any]:
    """For a machine's Docker → Host page and the API: whether the fleet
    settings apply to it, what differs, and whether a Docker restart is
    waiting."""
    config = settings.docker_daemon_config or {}
    state = machine.docker_daemon_state or {}
    facts = (machine.docker_host_check or {}).get("facts") or {}
    in_scope = bool(config) and scope_of(settings).covers(machine)
    current = facts.get("daemon_config")
    diffs = differences(config, current) if in_scope and current is not None else []
    return {
        "in_scope": in_scope,
        "configured": bool(config),
        "checked": current is not None,
        "differences": [
            {"field": d.field, "current": d.current, "wanted": d.wanted} for d in diffs
        ],
        "restart_pending": bool(state.get("restart_pending")),
        "applied_at": state.get("applied_at"),
        "error": state.get("error"),
    }


# --- Defaults for new containers -------------------------------------------


def container_defaults(settings: AppSettings) -> dict[str, Any] | None:
    """The values a newly seen container's settings start with, or None
    when every default is Docker's own (nothing to store)."""
    policy = settings.docker_default_update_policy
    gate = settings.docker_default_vulnerability_gate
    autoheal = bool(settings.docker_default_autoheal)
    if policy not in UPDATE_POLICIES and gate not in GATES and not autoheal:
        return None
    return {
        "auto_update": policy in UPDATE_POLICIES,
        "update_policy": policy if policy in UPDATE_POLICIES else "any",
        "vulnerability_gate": gate if gate in GATES else "off",
        "autoheal": autoheal,
    }


async def apply_container_defaults(
    db: AsyncSession,
    machine: Machine,
    previous: list[Any] | None,
    settings: AppSettings,
    *,
    protected_project: str | None,
) -> list[str]:
    """Give each container that this sample shows for the first time (not
    in `previous`, the machine's container list before it) the default
    settings — unless it already has its own, or is one of debcontrol's.
    Autoheal only for a container with a health check. Returns the names."""
    defaults = container_defaults(settings)
    if defaults is None or previous is None:
        return []
    before = {str(c.get("name")) for c in previous if isinstance(c, dict)}
    new = [
        c
        for c in machine.docker_containers or []
        if isinstance(c, dict)
        and c.get("name")
        and str(c["name"]) not in before
        and not (protected_project and c.get("compose_project") == protected_project)
    ]
    if not new:
        return []
    names = [str(c["name"])[:255] for c in new]
    existing = set(
        (
            await db.execute(
                select(DockerContainerSetting.name).where(
                    DockerContainerSetting.machine_id == machine.id,
                    DockerContainerSetting.name.in_(names),
                )
            )
        ).scalars()
    )
    added: list[str] = []
    for container, name in zip(new, names, strict=True):
        if name in existing:
            continue
        db.add(
            DockerContainerSetting(
                machine_id=machine.id,
                name=name,
                auto_update=defaults["auto_update"],
                update_policy=defaults["update_policy"],
                vulnerability_gate=defaults["vulnerability_gate"],
                autoheal=defaults["autoheal"] and bool(container.get("health")),
                updated_by="default settings",
            )
        )
        added.append(name)
    return added


# --- Applying -----------------------------------------------------------------


async def target_machines(db: AsyncSession, user: User, settings: AppSettings) -> list[Machine]:
    """The machines "Apply to machines" writes to: visible to `user`, with
    Docker readable at the last sample, a confirmed host key, and in the
    settings' scope."""
    scope = scope_of(settings)
    query = (await machines_visible_to(db, user)).where(
        Machine.docker_status == "ok", Machine.host_key_fingerprint.is_not(None)
    )
    if scope.group_ids:
        query = query.where(Machine.group_id.in_(scope.group_ids))
    result = await db.execute(query.order_by(Machine.name))
    return list(result.scalars().all())


async def pending_restart(db: AsyncSession, user: User) -> list[Machine]:
    """Visible machines whose daemon.json was written but whose Docker
    has not been restarted since."""
    query = (await machines_visible_to(db, user)).where(
        Machine.docker_daemon_state.is_not(None), Machine.host_key_fingerprint.is_not(None)
    )
    result = await db.execute(query.order_by(Machine.name))
    return [
        m for m in result.scalars().all() if (m.docker_daemon_state or {}).get("restart_pending")
    ]


async def queue_apply(db: AsyncSession, machine: Machine, *, actor: str) -> DockerJob | None:
    # Imported here: docker_actions → tasks.docker_jobs → this module.
    from app.services.docker_actions import queue_job

    return await queue_job(
        db, machine, DockerJobKind.DAEMON_CONFIG, "daemon.json", started_by=actor
    )


async def queue_restart(db: AsyncSession, machine: Machine, *, actor: str) -> DockerJob | None:
    from app.services.docker_actions import queue_job

    return await queue_job(db, machine, DockerJobKind.DAEMON_RESTART, "docker", started_by=actor)
