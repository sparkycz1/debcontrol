# 🔑 SSH host key verification

*Paranoid by design — a stranger with a keyboard between you and your server never gets the benefit of the doubt.*

## ⚠️ No trust on first use

Most SSH tooling trusts whatever host key a server presents the first
connection (TOFU — "trust on first use"), leaving that first connection
unauthenticated at the transport level: an attacker who intercepts it can
present their own key and silently MITM every session after.

> [!IMPORTANT]
> **debcontrol never trusts on first use.** A machine's host key fingerprint
> must be explicitly discovered and **confirmed by a human** before any real
> connection is attempted. There is no setting that turns this off.

## 🖱️ The flow in the UI

1. Add a machine. No pinned fingerprint yet → **Test connection** is disabled.
2. Its page auto-runs discovery on load (a **Discover**/**Retry** button
   re-triggers it). Connects just far enough to read the host key, hashes
   it (SHA256), and **always aborts before authenticating** — no
   credentials sent, nothing trusted yet.
3. Fingerprint shown with a warning: **verify it through a channel other
   than this app** — your hosting provider's console, `ssh-keygen -lf`
   run directly on the box, or one you recorded at provision time.
4. Matches? **Confirm, fingerprint matches** stores it
   (`Machine.host_key_fingerprint`) — and only now does the app gather
   facts for the first time, since that needs a real authenticated
   connection. (Online/offline is different: a plain unauthenticated TCP
   connect, runs regardless of whether a fingerprint is pinned.)
5. From then on, every SSH connection (Test connection, facts/package
   refresh, updates, power) checks the presented key against the stored
   fingerprint. A mismatch aborts hard with an explicit MITM warning —
   never silently accepted, never auto-updated.

## 🤔 Not `~/.ssh/known_hosts`

Stored per-machine in the database, set only through an explicit human
confirmation — the trust decision stays visible and auditable in the UI,
not buried in a dotfile a TOFU prompt quietly populated.

## 🔧 Implementation notes

The logic lives in `app/ssh/client.py`:

- `discover_host_key_fingerprint()` uses AsyncSSH's `get_server_host_key()`,
  which stops right after key exchange — no username, no credentials,
  nothing sent past learning the key.
- `open_connection()` refuses outright (`UnknownHostKeyError`) with no
  pinned fingerprint — never even attempts a connection.
- Otherwise a custom `SSHClient` subclass's `validate_host_public_key()`
  compares the presented fingerprint byte-for-byte. A mismatch raises
  `HostKeyMismatchError`, surfaced distinctly in the UI from a generic
  connection failure.

> [!CAUTION]
> **A sharp edge if you ever touch this file.** The comparison callback
> only gets consulted if `known_hosts=` passed to `asyncssh.connect()` is
> anything other than the literal sentinel `None`. `known_hosts=None`
> means "no trusted keys to compare, don't bother calling the callback" —
> AsyncSSH then silently accepts whatever key the server presents. An
> earlier version of this file did exactly that: the pinned fingerprint
> was never actually checked, and it looked correct on a read-through.

`open_connection()` passes `known_hosts=([], [], [])` instead — an empty
(not `None`) trusted-key set, which *does* make AsyncSSH consult the
callback for every key. See `tests/test_ssh_client.py` for the regression
test: a real local SSH server, asserting a mismatched pinned fingerprint
is rejected.

> [!WARNING]
> Extending this (re-discover flow, bulk import)? **Keep this property
> intact**: nothing should reach a real authenticated connection without
> a human-confirmed fingerprint. And **verify any change against a real
> SSH server in a test**, not just by reading the code — the bug above
> read as correct and passed every existing test.
