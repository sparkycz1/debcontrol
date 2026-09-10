# 🤖 Ansible onboarding

*Machine Requirements, but you never had to type any of it yourself.*

Everything in [Machine Requirements](Machine-Requirements.md) done by
hand, in one playbook run: installs/enables `sshd`, creates a dedicated
non-root user with debcontrol's SSH public key, grants scoped
passwordless sudo, self-registers the machine as **pending**. Lives in
[`ansible/`](../ansible/):

- [`debcontrol-onboard.yml`](../ansible/debcontrol-onboard.yml) — the playbook
- [`inventory.example.ini`](../ansible/inventory.example.ini) — copy to `inventory.ini`
- [`group_vars/all.yml.example`](../ansible/group_vars/all.yml.example) — copy to `group_vars/all.yml`

Safe to re-run — every task is idempotent.

> [!TIP]
> **No Ansible? No problem.** debcontrol does the equivalent itself, from
> the web UI, over the one-time root credential you'd otherwise hand to
> this playbook: add the machine (**Machines → Add machine**), confirm
> its host key, then **Run initial setup** on Settings. Same dedicated
> user, same key, same scoped sudo — direct over the connection this app
> already has, no Ansible dependency needed. Only difference: no
> self-register-as-pending step, since the machine already exists. See
> `app/ssh/onboarding.py`.

**It never creates a manageable machine by itself.** The last step is
the same `POST /api/inform` self-registration
[Machine Requirements](Machine-Requirements.md#self-registration-optional-for-future-automation)
describes — a *pending* entry only. Pinning the host key and confirming
it's really your machine is still a deliberate human step in
**Machines**. See [Architecture](Architecture.md#self-registration-is-not-the-same-as-trust).

## ✅ Requirements

- Ansible on the machine you run *from* (not the target) —
  `ansible-core` + the `ansible.posix` collection for `authorized_key`
  (`ansible-galaxy collection install ansible.posix` if not bundled).
- SSH access to the target *before* running this (your own key, or a
  cloud image's default account) — this playbook is what installs
  debcontrol's key. Set `ansible_user`
  (+`ansible_ssh_private_key_file` if needed) in the inventory.
- `become: true` — the connecting account needs root, once, up front.
  Separate from the passwordless sudo the playbook then sets up *for
  debcontrol's own user*.

## ⚙️ Setup

1. Copy the two example files (both gitignored — the inventory can hold
   real hostnames, the vars file a bearer token; prefer `--extra-vars`/
   `ansible-vault` over the file if several people share this checkout):
   ```bash
   cd ansible
   cp inventory.example.ini inventory.ini
   cp group_vars/all.yml.example group_vars/all.yml
   ```
2. Fill `inventory.ini`: the machine(s), and the account to connect as
   *initially* (see Requirements).
3. Fill `group_vars/all.yml`:
   - `debcontrol_ssh_public_key` — **Settings** → SSH identity, pasted exactly.
   - `debcontrol_url` — base URL, no trailing slash.
   - `debcontrol_inform_token` — the shared `INFORM_TOKEN`, or
     (recommended — attributable, individually revocable) a per-user API
     token from **My account** (role needs "Manage machines"). See
     [Architecture](Architecture.md#per-user-api-tokens-gated-by-a-separate-account-level-flag-inheriting-the-role-live).
4. Run it:
   ```bash
   ansible-playbook -i inventory.ini debcontrol-onboard.yml
   ```
5. **Machines** tab → **Pending**. Review, then confirm/pin its host key
   fingerprint — still a manual step; see
   [SSH Host Key Verification](SSH-Host-Key-Verification.md).

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
