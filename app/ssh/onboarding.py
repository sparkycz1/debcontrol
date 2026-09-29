"""Builds the shell script that prepares a fresh, not-yet-managed Debian/
Ubuntu machine for debcontrol — the same steps
`ansible/debcontrol-onboard.yml` automates for someone who'd rather run
Ansible from their own machine, run here instead directly over SSH (see
`app.tasks.jobs._run_machine_onboarding`, the only caller):

1. Create a dedicated `debcontrol` user (idempotent — `id -u` first).
2. Install this app's own SSH public key into that user's
   `authorized_keys` (idempotent — `grep -qxF` first, same convention as
   `app.tasks.jobs._push_pending_ssh_key`).
3. Grant it passwordless sudo, scoped to exactly what debcontrol needs
   (`SUDO_COMMANDS`, plus `flatpak`/`snap`/`docker` if present) —
   the exact sudoers line documented in
   wiki/Machine-Requirements.
4. Best-effort install `ncurses-term`, so the web Terminal tab gets colors
   and box-drawing (see that same wiki page) without a separate manual
   step. Its failure (no network, offline apt cache) must never fail
   onboarding itself — only steps 1-3 are load-bearing.

Deliberately **not** an actual `ansible-playbook` invocation: that would
need Ansible (and its own dependency tree) added to the worker image just
for this, plus a dynamically generated inventory file, for no behavioral
difference over running the same handful of idempotent shell commands
through the SSH connection machinery this app already has everywhere else.

Requires connecting as root (or an account that already behaves like
root) — that one-time credential is the whole point of onboarding a
machine that has nothing configured for debcontrol yet, so there is
deliberately no `sudo` escalation anywhere in this script to fall back on
if the connecting account isn't already root.
"""

from __future__ import annotations

import shlex

# The account debcontrol connects as afterwards — matches
# `debcontrol_user` in ansible/debcontrol-onboard.yml.
ONBOARD_USERNAME = "debcontrol"

# Everything the `debcontrol` account may run as root — the one list both
# this script's sudoers file and the machine edit page's manual snippet use.
# smartctl (smartmontools) — S.M.A.R.T. health for physical disks, part of
# the hardware-monitoring round trip (app.ssh.monitoring, gated on
# Machine.is_physical); `sensors` and the RAPL powercap files need no root.
# apt-mark — holding a package back (0.78.0+); pvesh — guests/storage/
# backups on Proxmox VE; the Proxmox Backup Server / Mail Gateway read-outs
# (app.ssh.proxmox, 0.79.0+), under both bin directories since the packages
# differ. A path that doesn't exist on a machine is simply unused (sudoers
# accepts it), and a grant missing on a machine onboarded before it existed
# is harmless — `sudo -n ...` just fails and that one reading is skipped.
SUDO_COMMANDS: tuple[str, ...] = (
    "/usr/bin/apt-get",
    "/usr/sbin/shutdown",
    "/usr/sbin/dmidecode",
    "/usr/sbin/smartctl",
    "/usr/bin/apt-mark",
    "/usr/bin/pvesh",
    "/usr/bin/proxmox-backup-debug",
    "/usr/sbin/proxmox-backup-debug",
    "/usr/bin/proxmox-backup-manager",
    "/usr/sbin/proxmox-backup-manager",
    "/usr/bin/pmgsh",
    "/usr/sbin/postqueue",
)
SUDO_COMMAND_LIST = ", ".join(SUDO_COMMANDS)

# Printed as the script's last line on success, so a caller can tell "ran
# to completion" apart from "produced some output but got cut off partway"
# without relying on exit status alone.
ONBOARD_SUCCESS_MARKER = "DEBCONTROL_ONBOARD_OK"


def build_onboarding_command(public_key: str) -> str:
    """Returns one `set -e` shell script — a single exec, not several round
    trips, same reasoning `app.ssh.updates.build_update_command` documents
    for bundling apt/flatpak/snap into one script. Safe to re-run (e.g.
    after a partial failure on an earlier attempt) without duplicating the
    `authorized_keys` line or fighting its own sudoers files.
    """
    quoted_key = shlex.quote(public_key.strip())
    user = ONBOARD_USERNAME
    return (
        "set -e; "
        f"id -u {user} >/dev/null 2>&1 || useradd -m -s /bin/bash {user}; "
        f'home="$(getent passwd {user} | cut -d: -f6)"; '
        f'install -d -m 700 -o {user} -g {user} "$home/.ssh"; '
        f'touch "$home/.ssh/authorized_keys"; '
        f'grep -qxF {quoted_key} "$home/.ssh/authorized_keys" 2>/dev/null || '
        f'echo {quoted_key} >> "$home/.ssh/authorized_keys"; '
        f'chmod 600 "$home/.ssh/authorized_keys"; '
        f'chown {user}:{user} "$home/.ssh/authorized_keys"; '
        f"cat > /etc/sudoers.d/{user} <<'DEBCONTROL_SUDOERS_APT'\n"
        f"{user} ALL=(root) NOPASSWD: {SUDO_COMMAND_LIST}\n"
        "DEBCONTROL_SUDOERS_APT\n"
        f"chmod 440 /etc/sudoers.d/{user}; "
        f"visudo -cf /etc/sudoers.d/{user}; "
        "if command -v flatpak >/dev/null 2>&1 || command -v snap >/dev/null 2>&1; then "
        f"cat > /etc/sudoers.d/{user}-flatpak-snap <<'DEBCONTROL_SUDOERS_FS'\n"
        f"{user} ALL=(root) NOPASSWD: /usr/bin/flatpak, /usr/bin/snap\n"
        "DEBCONTROL_SUDOERS_FS\n"
        f"chmod 440 /etc/sudoers.d/{user}-flatpak-snap; "
        f"visudo -cf /etc/sudoers.d/{user}-flatpak-snap; "
        "fi; "
        # Docker — container monitoring and container logs
        # (app.ssh.monitoring / app.ssh.logs) try plain `docker`, then
        # `sudo -n <docker path>`. Granted only when Docker is installed,
        # for whatever path this machine's `docker` actually lives at. Note
        # this is root-equivalent (anyone who can start a container can
        # mount the host filesystem) — deliberate, the account already has
        # apt-get as root; see wiki/Machine-Requirements.
        'DP="$(command -v docker 2>/dev/null || true)"; '
        'if [ -n "$DP" ]; then '
        f"printf '%s ALL=(root) NOPASSWD: %s\\n' {user} \"$DP\" > /etc/sudoers.d/{user}-docker; "
        f"chmod 440 /etc/sudoers.d/{user}-docker; "
        f"visudo -cf /etc/sudoers.d/{user}-docker; "
        "fi; "
        "(apt-get update -q >/dev/null 2>&1 && "
        "apt-get install -y ncurses-term >/dev/null 2>&1) || true; "
        f"echo {ONBOARD_SUCCESS_MARKER}"
    )
