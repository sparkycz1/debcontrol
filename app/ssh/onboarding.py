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
   (`apt-get`, `shutdown`, and `flatpak`/`snap` if either is present) —
   the exact sudoers line documented in
   wiki/Machine-Requirements.md.
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
        f"{user} ALL=(root) NOPASSWD: /usr/bin/apt-get, /usr/sbin/shutdown, "
        # smartctl (smartmontools) — S.M.A.R.T. health status for physical
        # disks, part of the hardware-monitoring round trip
        # (app.ssh.monitoring), gated on Machine.is_physical. `sensors`
        # (lm-sensors) and the RAPL powercap sysfs files it also reads
        # need no root at all, unlike this one. Missing entirely on an
        # already-onboarded machine from before this grant existed is
        # harmless and self-healing, same as the dmidecode grant above —
        # `sudo -n smartctl ...` just fails and that disk's health simply
        # isn't reported, never a crash.
        # apt-mark — holding a package back from updates (0.78.0+);
        # pvesh — reading guests/storage/backups on Proxmox VE (the path
        # simply doesn't exist elsewhere, which sudoers accepts).
        "/usr/sbin/dmidecode, /usr/sbin/smartctl, /usr/bin/apt-mark, /usr/bin/pvesh\n"
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
        # apt-get as root; see wiki/Machine-Requirements.md.
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
