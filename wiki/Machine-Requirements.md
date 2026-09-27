# 🖥️ Machine requirements

*A stock Debian install is already 90 % of the way there.*

What a **managed machine** needs. [Ansible Onboarding](Ansible-Onboarding.md)
— or the app's own *Run initial setup* — automates all of it. For
debcontrol's own host see [Host Requirements](Host-Requirements.md).

## 🌐 Network

- Reachable from the debcontrol host on its SSH port (default 22); allow
  it in any firewall or security group.
- Nothing needs to reach debcontrol, except the optional
  [self-registration](#self-registration-optional-for-future-automation).

## OS

- **Debian and its derivatives (Ubuntu, Proxmox VE, Proxmox Backup Server,
  Proxmox Mail Gateway), for as long as each is supported upstream.**
  Only standard tooling is used (`dpkg`, `apt`, systemd, optionally
  flatpak/snap).
- `openssh-server` installed and running:
  ```bash
  sudo apt install openssh-server
  sudo systemctl enable --now ssh
  ```

## 👤 Account

- A dedicated, non-root account with scoped passwordless sudo (below) is
  recommended; connecting as `root` also works (debcontrol then never
  calls `sudo`).
- **SSH key** (recommended): add the public key from **Settings** to
  `~/.ssh/authorized_keys` (`chmod 600`). debcontrol uses
  [one shared SSH identity](Machine-Management.md#one-shared-ssh-identity-not-one-key-per-machine).
- **Password**: a fallback; needs `PasswordAuthentication yes` in sshd.

## 🔐 Root access: the sudoers line

Updates, power actions and a few readings need root. For a non-root
account, one scoped sudoers file covers everything (onboarding writes it;
the machine's edit page shows the exact current line):

```
# /etc/sudoers.d/debcontrol — check with: visudo -cf /etc/sudoers.d/debcontrol
debcontrol ALL=(root) NOPASSWD: /usr/bin/apt-get, /usr/sbin/shutdown, /usr/sbin/dmidecode, /usr/sbin/smartctl, /usr/bin/apt-mark, /usr/bin/pvesh, /usr/bin/proxmox-backup-debug, /usr/sbin/proxmox-backup-debug, /usr/bin/proxmox-backup-manager, /usr/sbin/proxmox-backup-manager, /usr/bin/pmgsh, /usr/sbin/postqueue
# Only if flatpak/snap are installed and should be updated:
debcontrol ALL=(root) NOPASSWD: /usr/bin/flatpak, /usr/bin/snap
# Only for Docker monitoring, container actions and logs:
debcontrol ALL=(root) NOPASSWD: /usr/bin/docker
```

| Command | Used for |
|---|---|
| `apt-get`, `shutdown` | updates, reboot/shutdown (required for those features) |
| `dmidecode` | RAM speed |
| `smartctl` | S.M.A.R.T. health and detail (bare metal) |
| `apt-mark` | holding packages back (0.78.0+) |
| `pvesh` | Proxmox VE guests, storage, backups, cluster, guest actions (0.78.0+) |
| `proxmox-backup-debug`, `proxmox-backup-manager` | Proxmox Backup Server data (0.79.0+) |
| `pmgsh`, `postqueue` | Proxmox Mail Gateway statistics and queue (0.79.0+) |
| `docker` | containers — root-equivalent, like `apt-get` (or add the account to the `docker` group instead) |

Everything uses `sudo -n`, so a missing grant fails fast and only that one
feature is affected. A machine onboarded before a grant existed simply
lacks that reading until the line is updated (re-run onboarding, or the
readiness banner's *Fix it*). On older, non-usrmerged systems
`shutdown` may be `/sbin/shutdown`.

## 🔍 What debcontrol reads — no agent

| Area | Commands | Root? |
|---|---|---|
| Facts | `hostname`, `/etc/os-release`, `uname`, `nproc`, `lscpu`, `/proc/meminfo`, `lsblk`, `df`, `ip`, `ss`, `/etc/passwd`/`/etc/group`, `systemd-detect-virt` | no (RAM speed via `dmidecode`: yes) |
| Packages | `dpkg-query`, `flatpak list`, `snap list`, `apt-mark showhold` | no |
| Services | `systemctl list-units`, `systemctl show` | no |
| Update check | `apt-get update` + `apt list --upgradable`, `apt-get changelog` (CVEs) | `apt-get update`: yes |
| Monitoring | `/proc`, `df`, network/disk counters | no |
| Hardware (bare metal) | `sensors -j` (`lm-sensors`), `smartctl`, RAPL sysfs, `nvidia-smi` / DRM sysfs, `lspci` | `smartctl`: yes |
| Docker | `docker ps`, `docker stats`, `docker buildx imagetools inspect` | docker access |
| Proxmox | `pveversion`, `pvesh`, `zpool`, `proxmox-backup-debug`, `pmgsh`, `postqueue` | yes (except `zpool`) |
| Logs | `journalctl` (`adm`/`systemd-journal` group), `tail`/`grep` on allowed paths, `docker logs` | no |

A missing tool leaves that one value empty; it never fails a refresh.
Optional packages worth installing on bare metal: `lm-sensors` (run
`sensors-detect` once) and `smartmontools`.

## ⚡ Updates and power

Updates run `apt-get update` → the chosen upgrade → `autoremove` /
`autoclean` → `flatpak update` / `snap refresh`, keeping existing config
files on conflicts (`--force-confdef --force-confold`). Reboot and
shutdown are confirmed by typing the name. Both can be scheduled.

## 🖧 Terminal

Needs nothing beyond SSH access; it can do whatever the account can. For
full 256-color rendering install `ncurses-term` (onboarding does). The
terminal requests `LANG=C.UTF-8` (works with Debian's default
`AcceptEnv`). Clipboard needs HTTPS in the browser.

## Self-registration (optional, for future automation)

A machine can announce itself at first boot with `POST /api/inform` and
the shared `INFORM_TOKEN` (or a user's API token). It only creates a
*pending* entry
([why](Machine-Management.md#self-registration-is-not-the-same-as-trust)).
Needs `curl`:

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

Treat the token like a password (it can only create pending entries);
keep it in an image or secret-injected cloud-init, not shell history.

## ✅ Checklist

- [ ] `openssh-server` running and reachable from debcontrol
- [ ] an account with debcontrol's public key (or password auth)
- [ ] the sudoers line above (or connect as `root`)
- [ ] *(optional)* flatpak/snap and Docker grants
- [ ] *(optional, bare metal)* `lm-sensors`, `smartmontools`
- [ ] *(optional)* `ncurses-term`, `curl` for self-registration
