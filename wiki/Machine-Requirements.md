# 🖥️ Machine requirements

*Good news: a stock Debian install is already 90% of the way there.*

What a **managed machine** — the Debian/Ubuntu box debcontrol SSHes into,
not debcontrol's own host — needs network/account/package-wise. Doing it
by hand is the point of this page; [Ansible Onboarding](Ansible-Onboarding.md)
automates it. For debcontrol's *own* host, see [Host Requirements](Host-Requirements.md).

## 🌐 Network

- Reachable from the debcontrol host over TCP, on whatever port its SSH
  daemon listens on (default 22).
- If there's a firewall on the machine (`nftables`, `ufw`, a cloud
  provider security group, ...), allow inbound SSH from the debcontrol
  host's IP.
- No inbound connectivity is required *to* debcontrol, except when using
  the optional self-registration flow (see below), which is initiated
  *from* the machine.

## OS

- **Officially supported: Debian and its derivatives (e.g. Ubuntu), for
  as long as each is supported upstream** — any currently-supported
  deb-based release, not a fixed version list. Nothing here is
  Debian-version-specific: `dpkg`, `apt`, `systemd`'s `shutdown`, and
  optionally `flatpak`/`snap` are all standard tooling.
- `sshd` (`openssh-server`) installed and running — on by default in
  most installer profiles, worth double-checking on a minimal/debootstrap image:
  ```bash
  sudo apt install openssh-server
  sudo systemctl enable --now ssh
  ```

## 👤 Account

- A user for debcontrol to connect as — dedicated, non-root, scoped
  passwordless sudo (see "System updates" below), rather than raw `root`.
- **SSH key auth (recommended):** append the public key from
  debcontrol's **Settings** page:
  ```bash
  echo 'ssh-ed25519 AAAA... debcontrol' >> ~/.ssh/authorized_keys
  chmod 600 ~/.ssh/authorized_keys
  ```
  Manual today — debcontrol uses
  [one shared SSH identity](Machine-Management.md#one-shared-ssh-identity-not-one-key-per-machine),
  not a key per machine.
- **Password auth:** a supported fallback (marked not-recommended in the
  UI). Needs `PasswordAuthentication yes` in `/etc/ssh/sshd_config` —
  many hardened images disable it by default.

## 🔍 Fact gathering — no agent, no extra packages

When a host key fingerprint is confirmed, and then periodically after
that, debcontrol runs one shell command over SSH to collect facts, using
only tools present on a stock Debian install — see `app/ssh/facts.py` for
the exact command:

| Fact | Command | Package (already on a default install) |
|---|---|---|
| Hostname | `hostname` | `hostname` |
| OS version | `/etc/os-release` | `base-files` |
| Kernel version | `uname -r` | `coreutils` |
| Latest installed kernel (for reboot-required) | `dpkg --list 'linux-image-*'` | `dpkg` |
| CPU architecture | `uname -m` | `coreutils` |
| CPU cores | `nproc` | `coreutils` |
| CPU model | `lscpu` (`Model name:`), falls back to `/proc/cpuinfo` (`model name`) if `lscpu` is missing | `util-linux` |
| RAM | `/proc/meminfo` via `awk` | kernel + `mawk` (Debian's default `awk`) |
| RAM speed (MHz) | `dmidecode -t 17` | `dmidecode` — **needs root**, see below |
| Disks | `lsblk` | `util-linux` |
| Uptime | `/proc/uptime` via `awk` | kernel + `mawk` |
| Process count | `ls /proc/[0-9]*` | `coreutils` (no `procps`/`ps` needed) |
| Filesystem usage (used/free/%) | `df -B1 --output=...` | `coreutils` |
| Network interfaces + IPv4 addresses | `ip -4 -o addr show` | `iproute2` |

None of these need root — including "reboot required" (compares running
kernel vs. the newest `linux-image-*` `dpkg` knows about) — **except RAM
speed**, the one fact genuinely unreadable without it (only SMBIOS type
17 via `dmidecode` has it; no `/proc`/`/sys` entry exists). Tries
`sudo -n dmidecode -t 17`, falls back to plain `dmidecode -t 17` for a
root-connected account, leaves `ram_speed_mhz` unknown if neither works
— optional, not worth broader root access for. **Machines onboarded
through this app already have this** (bundled into the same sudoers file
"System updates" below describes) — add it by hand only for a
pre-existing or externally-provisioned machine; **Overview** flags
what's missing with an in-app fix, so manual `visudo` is rarely needed:

```
# /etc/sudoers.d/debcontrol
debcontrol ALL=(root) NOPASSWD: /usr/sbin/dmidecode
```

Missing command (e.g. a minimal rootfs without `util-linux`/`iproute2`)?
That one fact is left empty, not a failed refresh. Filesystem usage
excludes pseudo-filesystems (`tmpfs`, `devtmpfs`, `squashfs`, `overlay`).

## 🌡️ Hardware monitoring — physical machines only, optional packages

One extra fact, `is_physical` (`systemd-detect-virt`, standard on any
systemd host), decides whether the Monitoring tab's hardware cards
appear at all — a VM never runs the probes below, since a virtual
disk's S.M.A.R.T. status is meaningless and there's usually no real
sensor/RAPL data to read.

On a physical machine, every reading below is best-effort — a missing
package just means that one reading is empty, not a failed sample:

| Reading | Command | Package | Root? |
|---|---|---|---|
| Temperatures + fan speeds | `sensors -j` | `lm-sensors` (run `sensors-detect` once after install) | No |
| S.M.A.R.T. health (every sample) and full detail (with facts) | `smartctl -H` / `smartctl -a -j` per disk | `smartmontools` | **Yes**, see below |
| CPU power | `/sys/class/powercap/*-rapl:*/energy_uj` | kernel (Intel or AMD RAPL — a CPU with neither has no reading) | No |
| GPU utilization, VRAM, power (per card) | `nvidia-smi` (NVIDIA); `/sys/class/drm/card*/device/` sysfs (AMD; Intel exposes only power, on newer kernels) | NVIDIA driver / kernel; `pciutils` (`lspci`) for the card's name | No |

S.M.A.R.T. is the one exception needing root, added to the same sudoers
line as `dmidecode` — **machines onboarded through this app already have
it**; a pre-existing/externally-provisioned machine needs the line added
by hand (or simply re-onboarded):

```
# /etc/sudoers.d/debcontrol
debcontrol ALL=(root) NOPASSWD: /usr/sbin/dmidecode, /usr/sbin/smartctl
```

Every reading is gathered fresh on each monitoring sample, so a sensor,
fan, or disk that's physically added or removed between samples is
picked up automatically — nothing to reconcile by hand.

## 🐳 Docker containers — optional, needs Docker access

On any machine (VMs included) with a `docker` CLI, each monitoring sample
also reads `docker ps -a` and `docker stats --no-stream` — per-container
CPU/memory/network charts and a container table on the Monitoring tab.
Talking to the Docker daemon needs one of:

- the connecting account in the `docker` group
  (`sudo usermod -aG docker debcontrol`), or
- a sudoers rule for exactly the docker binary:
  ```
  # /etc/sudoers.d/debcontrol
  debcontrol ALL=(root) NOPASSWD: /usr/bin/docker
  ```

**Machines onboarded through this app get the sudoers rule
automatically** when Docker is already installed (a separate
`/etc/sudoers.d/debcontrol-docker`, pointing at wherever `docker` lives on
that machine). Installed Docker later, or onboarded before this existed?
Re-run onboarding, or add the line above by hand. Either option is
effectively root on that machine (anyone who can start a container can
mount the host's filesystem) — the same trust level the `apt-get` grant
already implies. Without it, the Monitoring tab just says Docker is
present but not accessible. No Docker installed at all → the Docker cards
simply don't appear.

## 📦 Installed packages — also no agent, no root

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

Neither flatpak nor snap is required — simply omitted when absent. See
`app/ssh/packages.py`.

A held package (`apt-mark hold`) shows a "held" badge — still listed
normally, just excluded from `dist-upgrade`/`full-upgrade` until unheld
(worth knowing when an upgrade count looks off).

**Fleet-wide search**: **Security → Package search** checks every
machine's latest snapshot at once — handy right after a CVE announcement.

## ⚡ System updates and power actions — require root

`apt-mark` (holding a package back) and, on Proxmox VE, `pvesh` (guests,
storage, backups) are in the same line since 0.78.0 — a machine
onboarded earlier simply lacks those two until the line is updated.
An account connecting **as root** needs none of it: debcontrol never
calls `sudo` as root.

Running updates (`apt-get update` → the upgrade strategy →
`autoremove`/`autoclean` → `flatpak update`/`snap refresh` if present)
and reboot/shutdown always need root. "Check for updates now" needs root
only for the apt part — flatpak/snap listing is read-only. See
`app/ssh/updates.py` / `app/ssh/power.py`. Two ways to get root:

- Connect as `root` directly (simplest, least isolated — often disabled
  by policy on hardened images).
- **(Recommended)** Non-root user, scoped passwordless sudo:
  ```
  # /etc/sudoers.d/debcontrol — install with: visudo -cf /etc/sudoers.d/debcontrol
  debcontrol ALL=(root) NOPASSWD: /usr/bin/apt-get, /usr/sbin/shutdown, /usr/sbin/dmidecode, /usr/sbin/smartctl, /usr/bin/apt-mark, /usr/bin/pvesh
  # Only if flatpak/snap are installed and you want them kept updated too:
  debcontrol ALL=(root) NOPASSWD: /usr/bin/flatpak, /usr/bin/snap
  ```
  (pre-usrmerge: `/sbin/shutdown` — check `which shutdown`). Always
  `sudo -n` (non-interactive) — broken sudo fails fast and clearly rather
  than hanging on a password prompt. Missing the flatpak/snap lines just
  fails those two steps individually, doesn't block apt.

Root directly needs none of the above — every privileged command tries
`sudo -n` first, falls straight through if that fails. A root-connected
machine's readiness check only ever flags `ncurses-term`, fixable with
one click (no password prompt — nothing left to escalate).

Reboot/shutdown are double-confirmed (a warning page, then typing the
machine/group name exactly) — no undo. All three actions can be put on a
cron schedule (**Scheduling**) — a deliberately-created schedule skips
the per-fire confirmation, but destructive ones are flagged clearly at
setup time. No scheduled "power on" exists — can't turn on what's already off.

All three also work against an ad-hoc selection straight from the
**Machines** list (checkboxes + action bar), no group required — Power
still needs the typed confirmation phrase (`SELECTED MACHINES`). On top
of, not instead of, the group/"All machines" versions.

Config-file conflicts during an upgrade resolve in favor of your
existing config (`--force-confdef --force-confold`), the standard
unattended-Debian-upgrade default. Full stdout+stderr is stored and shown.

### Which packages, not just how many

The availability panel also shows *which* packages are pending (name +
version), from whichever "check for updates" ran most recently —
periodic sweep, the manual button, or a scheduled `check_updates` task.
No separate history; whatever ran last is what's shown.

## 🖧 Interactive terminal

**Terminal** (needs `action.terminal`) needs nothing beyond ordinary SSH
access — same account, no extra root/sudo/package. Whatever that account
can do at a shell prompt is exactly what the browser terminal can do.

**Full 256-color (htop, less, vim, ...)**: xterm.js negotiates
`TERM=xterm-256color`, needing the `ncurses-term` terminfo entry (not in
a minimal install by default — only base entries are guaranteed).
Missing it doesn't error, it just silently degrades to a near-blank,
flat rendering. **This app's own onboarding installs it automatically**;
anything onboarded another way needs:
```sh
sudo apt-get install -y ncurses-term
```
Also requests `LANG`/`LC_ALL=C.UTF-8` for proper Unicode box-drawing
(minimal servers often default to the POSIX "C" locale) — best-effort,
works as long as sshd's `AcceptEnv`/`SetEnv` allows it (Debian/Ubuntu's default).

**Copy/paste** — system clipboard both ways (Ctrl/Cmd+Shift+C/V, or
right-click), PuTTY-style. Entirely browser-side (Clipboard API), needs a
secure context (HTTPS or `localhost`) — see the reverse-proxy pages if
that's not yet true for you. Nothing needed on the machine's side.

## 📜 Logs

Gated behind the same `action.terminal` permission — reading logs is a
materially different trust level than a plain fact, even without root.

- **Journal** (default view) needs no root — `journalctl` is readable by
  the `systemd-journal`/`adm` group (covers the default onboarding
  account). Can't read it? The tab says so plainly, doesn't just go blank.
- **A specific file** is restricted to a configurable allowlist
  (`LOG_FILE_ALLOWED_PATHS`, default `/var/log,/var/lib/docker/containers`)
  — an app-side scope guardrail, not an SSH permission; shows whatever
  that account could already `tail`/`grep` at a prompt anyway.
- **A Docker container's logs** need the same Docker access as container
  monitoring (see *Docker containers* above) — no extra setup beyond that.

## Self-registration (optional, for future automation)

A machine can announce itself during first boot by POSTing to
`/api/inform` with a shared bearer token (`INFORM_TOKEN` in `.env`) — a
*pending* entry only, no access granted (see
[Architecture](Machine-Management.md#self-registration-is-not-the-same-as-trust)).

The script below is the manual, minimal version. Want the
account/sudo/key setup done at the same time? See
[Ansible Onboarding](Ansible-Onboarding.md) — one playbook, one run.

Needs `curl` — unlike the fact-gathering tools above, **not** guaranteed
on a minimal Debian install:

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

Treat `DEBCONTROL_INFORM_TOKEN` like a password — anyone with it can
create pending entries (not manage anything). Bake it into a golden
image or secrets-injected cloud-init template, not shell history.

## ✅ Summary checklist

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
- [ ] *(optional, bare metal)* `lm-sensors` and `smartmontools` for
      temperatures/fans and S.M.A.R.T. (smartctl via the sudoers line above)
- [ ] *(optional)* `docker` group membership or a sudoers rule for
      `/usr/bin/docker`, for container monitoring
- [ ] *(optional)* `ncurses-term` installed, for 256-color depth
      specifically in the Terminal tab (colors/box-drawing already work
      without it)
