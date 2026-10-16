"""debcontrol's own security checks, run next to Lynis by every security
audit (`app.ssh.lynis.run_audit`): the checks of vps-audit
(https://github.com/nuver-labs/vps-audit, MIT license), reimplemented in
`scripts/security_checks.sh` rather than downloaded and run.

**Why not run vps-audit itself.** It is one bash script on GitHub: running
it means running whatever that repository holds at the time, as root, on
every machine; it also writes a report file into the current directory and
asks a public web service for the machine's IP address. The script here is
part of debcontrol (reviewed and versioned with it), only reads, and talks
to nothing. vps-audit's disk, memory and CPU checks are left out:
debcontrol's monitoring already covers them.

**Root.** The script runs as the SSH account. Connected as root it sees
everything; through the scoped `debcontrol` account the checks that need
root (the firewall rules, sudo's own configuration, the full journal)
report `skip` rather than guess.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SCRIPT = (Path(__file__).parent / "scripts" / "security_checks.sh").read_text(encoding="utf-8")

CHECK_MARKER = "DEBCONTROL_CHECK|"

# Every check, in the order a page lists them. Each has a title, an
# explanation and a fix in the locale files
# (`security_audit.check.<id>.title` / `.why` / `.fix`).
CHECK_IDS: tuple[str, ...] = (
    "firewall",
    "ssh_root_login",
    "ssh_password_auth",
    "intrusion_prevention",
    "fail2ban_ssh_port",
    "pending_updates",
    "auto_updates",
    "reboot_required",
    "failed_logins",
    "listening_ports",
    "suid_files",
    "sudo_logging",
    "password_policy",
    "ssh_port",
    "running_services",
)

# pass/info are fine, skip could not be checked; warn and fail are findings.
STATUSES = ("fail", "warn", "pass", "info", "skip")
FINDING_STATUSES = ("fail", "warn")

_MAX_VALUE = 400


@dataclass(frozen=True)
class Check:
    id: str
    status: str
    value: str

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "status": self.status, "value": self.value}


def parse_output(text: str) -> list[dict[str, str]]:
    """The script's `DEBCONTROL_CHECK|id|status|value` lines → one dict per
    known check, in `CHECK_IDS` order. Anything else is ignored."""
    found: dict[str, Check] = {}
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if not line.startswith(CHECK_MARKER):
            continue
        parts = line[len(CHECK_MARKER) :].split("|", 2)
        if len(parts) < 2:
            continue
        check_id, status = parts[0].strip(), parts[1].strip()
        if check_id not in CHECK_IDS or status not in STATUSES or check_id in found:
            continue
        value = parts[2].strip() if len(parts) > 2 else ""
        found[check_id] = Check(check_id, status, value[:_MAX_VALUE])
    return [found[i].as_dict() for i in CHECK_IDS if i in found]
