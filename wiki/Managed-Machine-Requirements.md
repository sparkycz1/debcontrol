# Managed machine requirements

What a machine needs — network-wise, account-wise, and package-wise — to
be added to and managed by debcontrol. Short version: a stock Debian
install already satisfies almost all of this. Doing all of it by hand is
the point of this page; see [Ansible Onboarding](Ansible-Onboarding.md)
for a playbook that does it for you.

## Network

- Reachable from the debcontrol host over TCP, on whatever port its SSH
  daemon listens on (default 22).
- If there's a firewall on the machine (`nftables`, `ufw`, a cloud
  provider security group, ...), allow inbound SSH from the debcontrol
  host's IP.
- No inbound connectivity is required *to* debcontrol, except when using
  the optional self-registration flow (see below), which is initiated
  *from* the machine.

## OS

- **Officially supported: Debian and its derivatives (e.g. Ubuntu), for as
  long as each is supported by its own upstream/developer.** debcontrol
  deliberately doesn't pin a fixed list of version numbers here — that
  would just go stale — the policy is "any currently-supported deb-based
  release." Nothing in debcontrol is Debian-version-specific: everything
  it runs (`dpkg`, `apt`, `systemd`'s `shutdown`, and optionally `flatpak`/
  `snap`) is standard tooling any Debian-based distribution ships or can
  install, so a derivative needs nothing extra beyond what its own vendor
  already supports.
- `sshd` (the `openssh-server` package) installed and running. This is
  included by default on most Debian installation profiles (it's an
  explicit checkbox in the graphical installer, ticked by default when
  "SSH server" is selected) but is worth double-checking on a minimal /
  debootstrap-based image:
  ```bash
  sudo apt install openssh-server
  sudo systemctl enable --now ssh
  ```

## Account

- A user for debcontrol to connect as. Using a dedicated non-root user
  with passwordless sudo scoped to `apt-get` (see "System updates" below)
  is recommended over connecting as `root` directly — least privilege,
  and it keeps what debcontrol can do on a machine visible in one sudoers
  line instead of "everything."
- **SSH key auth (recommended):** append the public key shown on
  debcontrol's **Settings** page to that user's
  `~/.ssh/authorized_keys`:
  ```bash
  echo 'ssh-ed25519 AAAA... debcontrol' >> ~/.ssh/authorized_keys
  chmod 600 ~/.ssh/authorized_keys
  ```
  This is a manual step today — see
  [Architecture](Architecture.md#one-shared-ssh-identity-not-one-key-per-machine)
  for why debcontrol works this way instead of a key per machine.
- **Password auth:** supported as a fallback (the UI marks it as not
  recommended). Make sure `PasswordAuthentication yes` is set in
  `/etc/ssh/sshd_config` if you go this route — many hardened Debian
  images disable it by default.

## Fact gathering — no agent, no extra packages

When a host key fingerprint is confirmed, and then periodically after
that, debcontrol runs one shell command over SSH to collect facts. It
deliberately only uses tools present on a stock Debian install — see
`app/ssh/facts.py` for the exact command:

| Fact | Command | Package (already on a default install) |
|---|---|---|
| Hostname | `hostname` | `hostname` |
| OS version | `/etc/os-release` | `base-files` |
| Kernel version | `uname -r` | `coreutils` |
| Latest installed kernel (for reboot-required) | `dpkg --list 'linux-image-*'` | `dpkg` |
| CPU architecture | `uname -m` | `coreutils` |
| CPU cores | `nproc` | `coreutils` |
| RAM | `/proc/meminfo` via `awk` | kernel + `mawk` (Debian's default `awk`) |
| Disks | `lsblk` | `util-linux` |
| Uptime | `/proc/uptime` via `awk` | kernel + `mawk` |
| Process count | `ls /proc/[0-9]*` | `coreutils` (no `procps`/`ps` needed) |
| Filesystem usage (used/free/%) | `df -B1 --output=...` | `coreutils` |
| Network interfaces + IPv4 addresses | `ip -4 -o addr show` | `iproute2` |

None of these need root — including "reboot required," which is worked
out by comparing the running kernel (`uname -r`) against the newest
`linux-image-*` package `dpkg` knows is installed; if they differ, a
reboot would pick up the newer one. If a command is missing (e.g. a
container-like minimal rootfs without `util-linux` or `iproute2`), that
one fact is simply left empty/unknown rather than failing the whole
refresh. Filesystem usage excludes pseudo-filesystems (`tmpfs`,
`devtmpfs`, `squashfs`, `overlay`) — only real, sized mounts are shown.

## Installed packages — also no agent, no root

**Machines → a machine → Installed packages** lists every apt package,
plus every flatpak app and snap if either is installed, each with its
version — refreshed on the same schedule as facts above, and again right
after any update run on that machine. Also no root needed:

| Source | Command | Notes |
|---|---|---|
| apt | `dpkg-query -W -f='${Package}\t${Version}\n'` | always present on Debian |
| flatpak | `flatpak list --app --columns=application,version` | skipped if `flatpak` isn't installed |
| snap | `snap list` | skipped if `snap` isn't installed |
| apt held/pinned | `apt-mark showhold` | marks matching apt entries above |

Neither flatpak nor snap is required — most Debian/Ubuntu server installs
have neither by default — each is simply omitted from the list (and from
"System updates" below) when absent. See `app/ssh/packages.py`.

A package apt has been told to hold (`apt-mark hold <package>`, e.g. to
pin a kernel version or work around a known-bad release) shows a "held"
badge in the list — held packages are still installed and listed
normally, they're just excluded from `dist-upgrade`/`full-upgrade` until
unheld, which is worth knowing when a machine's upgrade count doesn't
match your expectations.

**Fleet-wide search**: **Machines → Package search** looks across every
machine's most recent package snapshot at once — useful after a CVE
announcement to find every machine still running a vulnerable version of
something, without opening each machine individually.

## System updates and power actions — require root

Running updates (**Machines → a machine → System updates**: `apt-get
update`, then `dist-upgrade` or `full-upgrade`, then
`autoremove`/`autoclean`, then `flatpak update` and `snap refresh` if
installed) and reboot/shutdown (**Machines → a machine → Power**,
`shutdown -r now` / `shutdown -h now`) always need root. Checking what's
available without installing anything (the same panel's "Check for
updates now") needs root only for the apt part (`apt-get update`) —
flatpak's `flatpak remote-ls --updates` and snap's `snap refresh --list`
are both read-only and don't. See `app/ssh/updates.py` and
`app/ssh/power.py` for the exact commands. Two ways to satisfy the root
requirement:

- Connect as `root` directly (simplest, least isolated — many hardened
  Debian images disable direct root SSH login by policy, so this may not
  even be available).
- **(Recommended)** Connect as a non-root user with passwordless sudo
  scoped to just what's needed:
  ```
  # /etc/sudoers.d/debcontrol — install with: visudo -cf /etc/sudoers.d/debcontrol
  debcontrol ALL=(root) NOPASSWD: /usr/bin/apt-get, /usr/sbin/shutdown
  # Add these two only if flatpak/snap are installed and you want debcontrol
  # to keep them updated too:
  debcontrol ALL=(root) NOPASSWD: /usr/bin/flatpak, /usr/bin/snap
  ```
  (replace `debcontrol` with whatever username you configured; on a
  pre-usrmerge system the paths are `/sbin/shutdown` instead — check with
  `which shutdown`). debcontrol always calls sudo as `sudo -n ...`
  (non-interactive) — if passwordless sudo isn't set up correctly, the
  action fails immediately with a clear error instead of hanging forever
  waiting for a password that can never arrive over a non-interactive SSH
  command. Without the flatpak/snap sudoers lines, the apt part of an
  update run still succeeds — the flatpak/snap steps just fail
  individually (visible in the run's stored output) rather than blocking
  the rest.

Reboot and shutdown are double-confirmed in the UI (a dedicated warning
page, then typing the machine's — or group's — name exactly) precisely
because there's no undo once sent. All three actions — update, check for
updates, reboot/shutdown — can also be put on a cron schedule (see
**Scheduling** in the nav); a schedule someone deliberately created doesn't
get a second confirmation prompt each time it fires, but destructive
actions are clearly flagged when setting one up. There's no scheduled
"power on" — the app has no way to turn on a machine that's already off.

All three can also be triggered against an ad-hoc selection right from
the **Machines** list — tick the checkboxes you want (a "select all" box
in the header ticks every visible row) and use the action bar below the
table — without first having to put those machines in a group. Power
still requires typing a fixed confirmation phrase (`SELECTED MACHINES`),
same double-confirmation as everywhere else. This is on top of, not
instead of, the existing group and "All machines" versions of the same
actions.

Config-file conflicts during an upgrade are resolved automatically in
favor of keeping your existing config (`--force-confdef --force-confold`)
rather than prompting — the standard safe default for unattended Debian
upgrades. A run's full output (stdout+stderr combined) is stored and
shown in the UI so you can review exactly what happened.

### Which packages, not just how many

The update-availability panel also shows *which* apt packages, flatpak
apps, and snaps are pending (name and version, under a "Which ... ?"
disclosure) — not just the counts. This comes from whichever "check for
updates" run happened most recently for that machine: the automatic
periodic sweep (same cadence as facts), the "Check for updates now"
button, or a **scheduled task** using the "check_updates" action (see
**Scheduling** in the nav). There's no separate history — if you want a
fresh, specific answer to "what's pending on this machine right now,"
either click the button or create a schedule for it; whatever ran last is
what's shown.

## Interactive terminal — nothing extra needed

**Machines → a machine → Terminal** (if your role has been granted the
`action.terminal` permission) needs nothing beyond ordinary SSH access —
the same account and key/password auth already set up above, and a shell
configured for that account (true of any normal Debian account by
default). It doesn't need root, sudo, or any extra package: whatever the
connecting account can normally do at an interactive SSH prompt is exactly
what the browser terminal can do too, since it's the same shell.

## Self-registration (optional, for future automation)

A machine can announce itself to debcontrol during first boot /
provisioning by POSTing to `/api/inform` with a shared bearer token
(`INFORM_TOKEN`, set in debcontrol's `.env`). This only creates a
*pending* entry for a human to review in the **Machines** tab — it grants
no access on its own (see
[Architecture](Architecture.md#self-registration-is-not-the-same-as-trust)).

The shell script below is the manual, minimal version of this. If you'd
rather not write it yourself — and want the account/sudo/SSH-key setup
above done at the same time — see
[Ansible Onboarding](Ansible-Onboarding.md) for a playbook that does all
of it, including this POST, in one run.

This needs `curl` (or an equivalent HTTP client), which — unlike the
fact-gathering tools above — is **not** always present on a minimal
Debian install:

```bash
sudo apt install curl
```

Example first-boot script (e.g. as a cloud-init `runcmd`, or a systemd
oneshot unit):

```bash
#!/bin/sh
set -e

DEBCONTROL_URL="https://debcontrol.example.com"
DEBCONTROL_INFORM_TOKEN="paste-the-INFORM_TOKEN-value-here"

RAM_BYTES=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) * 1024 ))
OS_VERSION=$(grep -m1 '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '"')

curl -sf -X POST "$DEBCONTROL_URL/api/inform" \
  -H "Authorization: Bearer $DEBCONTROL_INFORM_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"hostname\": \"$(hostname)\",
    \"os_version\": \"$OS_VERSION\",
    \"kernel_version\": \"$(uname -r)\",
    \"cpu_cores\": $(nproc),
    \"ram_bytes\": $RAM_BYTES
  }"
```

Treat `DEBCONTROL_INFORM_TOKEN` like a password: anyone who has it can
create pending entries (though, again, not manage anything). Bake it into
a golden image or secrets-injected cloud-init template rather than a
shell history.

## Summary checklist

Everything below is what [Ansible Onboarding](Ansible-Onboarding.md)'s
playbook automates — do it by hand, or run that instead.

- [ ] `openssh-server` installed and `sshd` running
- [ ] Reachable on the SSH port from the debcontrol host
- [ ] A user account for debcontrol to connect as
- [ ] debcontrol's public key added to that user's `authorized_keys`
      (or password auth explicitly enabled, if you're using that instead)
- [ ] *(for System updates and Power)* passwordless sudo for `apt-get`
      and `shutdown` configured for that user (or it's `root`)
- [ ] *(optional)* passwordless sudo for `flatpak`/`snap` too, if either is
      installed and you want debcontrol to keep it updated
- [ ] *(optional)* `curl` installed, if using self-registration
