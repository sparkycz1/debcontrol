# 🤖 Ansible onboarding

Everything in [Managed Machine Requirements](Managed-Machine-Requirements.md)
done by hand, in one playbook run: installs/enables `sshd`, creates a
dedicated non-root user with debcontrol's SSH public key, grants that user
passwordless sudo scoped to exactly what debcontrol needs, and
self-registers the machine so it shows up as **pending** in the
**Machines** tab. Lives in [`ansible/`](../ansible/) at the repo root:

- [`debcontrol-onboard.yml`](../ansible/debcontrol-onboard.yml) — the playbook
- [`inventory.example.ini`](../ansible/inventory.example.ini) — copy to `inventory.ini`
- [`group_vars/all.yml.example`](../ansible/group_vars/all.yml.example) — copy to `group_vars/all.yml`

It's safe to re-run — every task is idempotent (Ansible's
`apt`/`user`/`copy`/`authorized_key` modules all are).

**It never creates a manageable machine by itself.** The playbook's last
step is the same `POST /api/inform` self-registration described in
[Managed Machine Requirements](Managed-Machine-Requirements.md#self-registration-optional-for-future-automation) —
it only creates a *pending* entry. Approving it (pinning the host key
fingerprint, confirming it's really the machine you meant) is still a
separate, deliberate step a human does in the **Machines** tab. See
[Architecture](Architecture.md#self-registration-is-not-the-same-as-trust).

## ✅ Requirements

- Ansible on the machine you run the playbook from (not on the target) —
  `ansible-core` plus the `ansible.posix` collection for the
  `authorized_key` module (bundled if you installed the full `ansible`
  package; otherwise `ansible-galaxy collection install ansible.posix`).
- SSH access to the target *before* running this — your own key or a cloud
  image's default account, since this playbook is what installs
  debcontrol's own key. Set `ansible_user` (and `ansible_ssh_private_key_file`
  if needed) in the inventory for that account.
- `become: true` is set in the playbook — the account Ansible connects as
  needs to become root (directly, or via passwordless/interactive sudo,
  whichever your `ansible.cfg`/inventory already assumes for this host).
  This is separate from — and only needed once, up front — the
  passwordless sudo the playbook then sets up *for debcontrol's own user*.

## ⚙️ Setup

1. Copy the two example files and fill them in:
   ```bash
   cd ansible
   cp inventory.example.ini inventory.ini
   cp group_vars/all.yml.example group_vars/all.yml
   ```
   Both `inventory.ini` and `group_vars/all.yml` are gitignored — the
   inventory can list real internal hostnames and the vars file holds a
   bearer token. Prefer `--extra-vars` or `ansible-vault` over
   `group_vars/all.yml` for the token if several people share this
   checkout.

2. Fill in `inventory.ini` with the machine(s) to onboard, and whichever
   account Ansible should connect as *initially* (see Requirements above).

3. Fill in `group_vars/all.yml`:
   - `debcontrol_ssh_public_key` — debcontrol's **Settings** page, "SSH
     identity" panel. Paste it exactly as shown, one line, quoted.
   - `debcontrol_url` — your debcontrol instance's base URL, no trailing
     slash (e.g. `https://debcontrol.example.com`).
   - `debcontrol_inform_token` — either the shared `INFORM_TOKEN` from
     debcontrol's `.env`, or (recommended, since it's attributable and
     individually revocable) a per-user API token from **My account**,
     created by a user whose role has "Manage machines". See
     [Architecture](Architecture.md#per-user-api-tokens-gated-by-a-separate-account-level-flag-inheriting-the-role-live)
     for how these tokens work.

4. Run it:
   ```bash
   ansible-playbook -i inventory.ini debcontrol-onboard.yml
   ```

5. Go to debcontrol's **Machines** tab — the machine is now listed under
   **Pending**. Review it, then add it properly (confirm/pin its SSH host
   key fingerprint — still a manual, deliberate step; see
   [SSH Host Key Verification](SSH-Host-Key-Verification.md)).

## 🧭 What it does, and what it deliberately doesn't

| Step | Does | Doesn't |
|---|---|---|
| `sshd` | Installs `openssh-server` if missing, enables + starts it | Doesn't touch `sshd_config` (e.g. `PermitRootLogin`, `PasswordAuthentication`) — your existing hardening stays as-is |
| User | Creates `debcontrol_user` (default `debcontrol`) with a home dir | Doesn't set a password — key-only, matching debcontrol's recommended auth method |
| SSH key | Appends debcontrol's public key to that user's `authorized_keys` | Doesn't remove any other keys already there |
| sudo | Two `/etc/sudoers.d/` files, `apt-get`/`shutdown` always, `flatpak`/`snap` only if either is found installed | Scoped to exactly those binaries — never a blanket `NOPASSWD: ALL` |
| Self-registration | Posts hostname/OS/kernel/CPU/RAM to `/api/inform` | Doesn't send credentials, a host key, or anything else — see the self-registration payload in `app/schemas/inform.py` |

## 🗂️ Variables reference

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `debcontrol_ssh_public_key` | yes | — | debcontrol's SSH public key (Settings page) |
| `debcontrol_url` | yes | — | debcontrol's base URL |
| `debcontrol_inform_token` | yes | — | `INFORM_TOKEN` or a per-user API token |
| `debcontrol_user` | no | `debcontrol` | the dedicated account created on each machine |
| `debcontrol_enable_flatpak_snap_sudo` | no | `true` | set `false` to skip the flatpak/snap sudoers file even if either is installed |

## 🔧 Extending it

Adding this playbook to your own machine-provisioning pipeline (cloud-init,
Packer, an existing site-wide Ansible repo) is the intended use: it's a
single, dependency-light playbook rather than a role, so it can be
`import_playbook`'d or copied into an existing one.
