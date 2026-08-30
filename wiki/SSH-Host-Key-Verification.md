# SSH host key verification

## The problem with "trust on first use"

Most SSH tooling, by default, trusts whatever host key a server presents
the first time you connect to it (TOFU — "trust on first use"), then
remembers it for next time. That's convenient, but it means the very first
connection to a machine is unauthenticated at the transport level: if an
attacker can intercept that first connection (a compromised network,
DNS spoofing, a rogue DHCP server, etc.), they can present their own key
and silently man-in-the-middle every session from then on.

debcontrol never does this automatically. A machine's host key fingerprint
must be explicitly discovered and confirmed by a human before any real
connection is attempted.

## The flow in the UI

1. Add a machine (**Machines → Add machine**). At this point it has no
   pinned fingerprint, and the **Test connection** button is disabled.
2. Its detail page runs discovery automatically as soon as it loads — no
   click needed to kick it off; a **Discover key fingerprint** /
   **Retry discovery** button stays available too, for whenever it needs
   to run again (the machine wasn't reachable yet, its IP changed, ...).
   Either way, the app connects just far enough to read the server's host
   key, computes its SHA256 fingerprint, and **always aborts before
   authenticating** — no credentials are ever sent at this stage, and
   nothing is trusted yet. Automating *this* step is safe precisely
   because it still can't establish a real connection or trust anything
   on its own — see step 4.
3. The fingerprint is displayed with a warning: verify it through a
   channel *other than this application* before confirming — for example:
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
   connects over SSH: facts refresh, etc.) verifies the presented key
   against this stored fingerprint on every single connection. A mismatch
   immediately aborts with an explicit "possible Man-in-the-Middle" error —
   it is never silently accepted, and the stored fingerprint is never
   auto-updated.

## Why not just use `~/.ssh/known_hosts`?

A conventional `known_hosts` file conflates "I've seen this key before"
with "I trust this key," and typically gets populated via the same TOFU
prompt that this design deliberately avoids. Storing a fingerprint
per-machine in the database, set only through an explicit human
confirmation step, keeps that trust decision visible and auditable in the
UI rather than buried in a dotfile.

## Implementation notes

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

**A sharp edge worth knowing about if you ever touch this file**: that
comparison callback only gets consulted at all if the `known_hosts=`
option passed to `asyncssh.connect()` is anything other than the literal
sentinel `None`. Passing `known_hosts=None` doesn't mean "no known_hosts
file, ask my callback for every key" — it means "there are no trusted keys
to compare against, so don't bother calling the callback either," and
AsyncSSH accepts whatever key the server presents, silently. An earlier
version of this file did exactly that, for both `open_connection()` and
the (now-replaced) hand-rolled discovery client — which meant the pinned
fingerprint was never actually checked against anything, ever, on real
Postgres-backed deployments; `validate_host_public_key()` never ran, and a
different key than the one pinned would have gone through as if nothing
were wrong. `open_connection()` now passes `known_hosts=([], [], [])`
instead — an explicit "empty sets, and don't touch any known_hosts file"
tuple in AsyncSSH's own accepted `known_hosts` formats — which keeps an
empty (not `None`) trusted-key set and *does* make AsyncSSH fall through
to the callback for every key. See `app/ssh/client.py`'s module docstring
for the full explanation, and `tests/test_ssh_client.py` for a regression
test that opens a real local SSH server and asserts a mismatched pinned
fingerprint is actually rejected — the earlier bug looked correct on
inspection and passed every existing test, since nothing exercised it
against a real AsyncSSH connection.

If you're extending this code (e.g. adding a "re-discover fingerprint"
flow, or bulk machine import), keep this property intact: nothing should
be able to establish a real, authenticated connection to a machine without
a fingerprint that a human explicitly confirmed through this app's UI —
and if you change anything about how host keys are validated, verify it
against a real SSH server in a test, not just by reading the code.
