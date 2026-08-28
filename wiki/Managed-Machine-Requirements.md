# Managed machine requirements

What a Debian machine needs — network-wise, account-wise, and
package-wise — to be added to and managed by debcontrol. Short version:
a stock Debian install already satisfies almost all of this.

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

- Debian (any reasonably current release). Nothing here is
  Debian-version-specific, but debcontrol is not tested against other
  distributions.
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
| CPU cores | `nproc` | `coreutils` |
| RAM | `/proc/meminfo` via `awk` | kernel + `mawk` (Debian's default `awk`) |
| Disks | `lsblk` | `util-linux` |

None of these need root. If a command is missing (e.g. a container-like
minimal rootfs without `util-linux`), that one fact is simply left empty
rather than failing the whole refresh.

## System updates — requires root

Unlike fact gathering, running updates (**Machines → a machine → System
updates**) always needs root: it runs `apt-get update`, then `dist-upgrade`
or `full-upgrade` (your choice), then `autoremove` and `autoclean`
unconditionally — see `app/ssh/updates.py` for the exact commands. Two
ways to satisfy that:

- Connect as `root` directly (simplest, least isolated — many hardened
  Debian images disable direct root SSH login by policy, so this may not
  even be available).
- **(Recommended)** Connect as a non-root user with passwordless sudo
  scoped to just `apt-get`:
  ```
  # /etc/sudoers.d/debcontrol — install with: visudo -cf /etc/sudoers.d/debcontrol
  debcontrol ALL=(root) NOPASSWD: /usr/bin/apt-get
  ```
  (replace `debcontrol` with whatever username you configured). debcontrol
  always calls sudo as `sudo -n ...` (non-interactive) — if passwordless
  sudo isn't set up correctly, the update fails immediately with a clear
  error instead of hanging forever waiting for a password that can never
  arrive over a non-interactive SSH command.

Config-file conflicts during an upgrade are resolved automatically in
favor of keeping your existing config (`--force-confdef --force-confold`)
rather than prompting — the standard safe default for unattended Debian
upgrades. A run's full output (stdout+stderr combined) is stored and
shown in the UI so you can review exactly what happened.

## Self-registration (optional, for future automation)

A machine can announce itself to debcontrol during first boot /
provisioning by POSTing to `/api/inform` with a shared bearer token
(`INFORM_TOKEN`, set in debcontrol's `.env`). This only creates a
*pending* entry for a human to review in the **Machines** tab — it grants
no access on its own (see
[Architecture](Architecture.md#self-registration-is-not-the-same-as-trust)).

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

- [ ] `openssh-server` installed and `sshd` running
- [ ] Reachable on the SSH port from the debcontrol host
- [ ] A user account for debcontrol to connect as
- [ ] debcontrol's public key added to that user's `authorized_keys`
      (or password auth explicitly enabled, if you're using that instead)
- [ ] *(for System updates)* passwordless sudo for `apt-get` configured
      for that user (or it's `root`)
- [ ] *(optional)* `curl` installed, if using self-registration
