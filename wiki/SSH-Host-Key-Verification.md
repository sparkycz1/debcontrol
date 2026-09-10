# 🔑 SSH host key verification

*Paranoid by design — a stranger with a keyboard between you and your server never gets the benefit of the doubt.*

## ⚠️ No trust on first use

Most SSH tooling trusts whatever host key a server presents the first time
you connect (TOFU — "trust on first use"), which leaves that first
connection unauthenticated at the transport level: an attacker who can
intercept it can present their own key and silently man-in-the-middle every
session from then on.

> [!IMPORTANT]
> **debcontrol never trusts on first use.** A machine's host key fingerprint
> must be explicitly discovered and **confirmed by a human** before any real
> connection is attempted. There is no setting that turns this off.

## 🖱️ The flow in the UI

1. Add a machine (**Machines → Add machine**). At this point it has no
   pinned fingerprint, and the **Test connection** button is disabled.
2. Its detail page runs discovery automatically as soon as it loads — no
   click needed to kick it off; a **Discover key fingerprint** /
   **Retry discovery** button stays available too, for whenever it needs
   to run again (the machine wasn't reachable yet, its IP changed, ...).
   Either way, the app connects just far enough to read the server's host
   key, computes its SHA256 fingerprint, and **always aborts before
   authenticating** — no credentials are ever sent at this stage, and
   nothing is trusted yet.
3. The fingerprint is displayed with a warning: **verify it through a
   channel *other than this application*** before confirming — for example:
   - your hosting provider's console/control panel, which often shows the
     host key fingerprint for a freshly-provisioned VM;
   - running `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` (or
     whichever host key type is in use) directly on the machine via a
     console session;
   - a fingerprint you recorded yourself when you first provisioned the
     machine.
4. Only if it matches, click **Confirm, fingerprint matches**. The
   fingerprint is now stored on the machine record
   (`Machine.host_key_fingerprint`), and this is the point where the app
   first gathers facts (OS/kernel/hostname/CPU/RAM/disks — see
   `app/ssh/facts.py`), since that requires a real, authenticated
   connection. (The online/offline status badge is different: it's a plain
   TCP connect with no authentication at all, so it runs for every active
   machine regardless of whether a fingerprint is pinned yet.)
5. From then on, **Test connection** (and every background job that
   connects over SSH: facts refresh, package refresh, updates, power) verifies the presented key
   against this stored fingerprint on every single connection. A mismatch
   immediately aborts with an explicit "possible Man-in-the-Middle" error —
   it is never silently accepted, and the stored fingerprint is never
   auto-updated.

## 🤔 Not `~/.ssh/known_hosts`

The fingerprint is stored per-machine in the database, set only through an
explicit human confirmation step, so the trust decision stays visible and
auditable in the UI rather than buried in a dotfile populated by a TOFU
prompt.

## 🔧 Implementation notes

The logic lives in `app/ssh/client.py`:

- `discover_host_key_fingerprint()` uses AsyncSSH's own
  `get_server_host_key()` helper, which stops right after key exchange and
  never proceeds to authentication at all — no username, no credentials,
  nothing sent past the point of learning the key.
- `open_connection()` refuses outright (`UnknownHostKeyError`) if
  `Machine.host_key_fingerprint` is empty — it never even attempts a
  connection.
- Otherwise it connects with a custom `SSHClient` subclass whose
  `validate_host_public_key()` compares the presented key's fingerprint
  against the stored one, byte for byte. A mismatch raises
  `HostKeyMismatchError`, which the UI surfaces distinctly from a generic
  connection failure.

> [!CAUTION]
> **A sharp edge worth knowing about if you ever touch this file.**
> That comparison callback is only consulted at all if the `known_hosts=`
> option passed to `asyncssh.connect()` is anything other than the literal
> sentinel `None`. Passing `known_hosts=None` means "there are no trusted
> keys to compare against, so don't bother calling the callback either" —
> AsyncSSH then accepts whatever key the server presents, silently. An
> earlier version of this file did exactly that, so the pinned fingerprint
> was never actually checked.

`open_connection()` passes `known_hosts=([], [], [])` — an explicit "empty
sets, and don't touch any known_hosts file" tuple in AsyncSSH's own
accepted `known_hosts` formats — which keeps an empty (not `None`)
trusted-key set and *does* make AsyncSSH fall through to the callback for
every key. See `app/ssh/client.py`'s module docstring, and
`tests/test_ssh_client.py` for a regression test that opens a real local
SSH server and asserts a mismatched pinned fingerprint is rejected.

> [!WARNING]
> If you're extending this code (e.g. adding a "re-discover fingerprint"
> flow, or bulk machine import), **keep this property intact**: nothing
> should be able to establish a real, authenticated connection to a machine
> without a fingerprint a human explicitly confirmed through this app's UI.
> And if you change anything about how host keys are validated, **verify it
> against a real SSH server in a test**, not just by reading the code — the
> earlier bug above read as correct and passed every test that existed.
