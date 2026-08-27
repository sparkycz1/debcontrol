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
  (rather than `root` directly) is recommended, even though nothing in
  the current feature set requires root — none of the commands
  debcontrol runs today (see "Fact gathering" below) need elevated
  privileges.
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
- [ ] *(optional)* `curl` installed, if using self-registration
