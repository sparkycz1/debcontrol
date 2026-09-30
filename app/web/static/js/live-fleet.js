// The machine list's half of app/services/live_updates.py: one WebSocket to
// the fleet channel (app/web/routes/live_ws.py's `/machines/live/ws`), and
// on each "something changed" message a quiet re-fetch of this same page
// whose `#machine-results` block replaces the one on screen — so a bulk
// "check for updates" (or a machine going up/down) shows up without a
// reload. The message says only *what kind* of thing changed, never which
// machine; the re-fetch is the ordinary, permission- and scope-checked
// page load.
//
// Keeps what the viewer is doing: ticked checkboxes (by value) and the
// "select all" box survive the swap, and the bulk-action bar outside the
// block is left alone. Bursts are coalesced (a bulk check finishes one
// machine at a time), a backgrounded tab refreshes once when it's shown
// again, and a viewer mid-way through something inside the list (focus in
// it) is waited for.
//
// No-op on a page without a `[data-live-fleet]` element.
(() => {
  "use strict";

  const RESULTS_ID = "machine-results";
  if (!document.querySelector("[data-live-fleet]")) return;

  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const url = `${scheme}://${window.location.host}/machines/live/ws`;

  const QUIET_MS = 1500; // wait this long after the last message of a burst
  const MIN_GAP_MS = 5000; // and never refresh more often than this
  let timer = null;
  let lastRefresh = 0;
  let pendingWhileHidden = false;
  let inFlight = false;

  function schedule(delay) {
    if (timer !== null) window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      timer = null;
      refresh();
    }, delay);
  }

  function onChange() {
    if (document.visibilityState === "hidden") {
      pendingWhileHidden = true;
      return;
    }
    const sinceLast = Date.now() - lastRefresh;
    schedule(Math.max(QUIET_MS, MIN_GAP_MS - sinceLast));
  }

  async function refresh() {
    const current = document.getElementById(RESULTS_ID);
    if (!current || inFlight) return;
    const active = document.activeElement;
    if (active && active !== document.body && current.contains(active)) {
      schedule(QUIET_MS); // the viewer is using the list — try again shortly
      return;
    }
    inFlight = true;
    lastRefresh = Date.now();
    try {
      const response = await fetch(window.location.href, {
        credentials: "same-origin",
        headers: { Accept: "text/html" },
      });
      if (!response.ok || response.redirected) return; // logged out, say
      const doc = new DOMParser().parseFromString(await response.text(), "text/html");
      const fresh = doc.getElementById(RESULTS_ID);
      if (!fresh) return; // the list emptied or changed shape — leave it
      const ticked = new Set(
        [...current.querySelectorAll("input[type=checkbox][value]:checked")].map((box) => box.value),
      );
      const allTicked = [...current.querySelectorAll("input[data-select-all]:checked")].map(
        (box) => box.getAttribute("data-select-all"),
      );
      current.replaceChildren(...[...fresh.childNodes].map((node) => document.importNode(node, true)));
      for (const box of current.querySelectorAll("input[type=checkbox][value]")) {
        box.checked = ticked.has(box.value);
      }
      for (const name of allTicked) {
        const box = current.querySelector(`input[data-select-all="${name}"]`);
        if (box) box.checked = true;
      }
      // bulk-select.js recounts the ticked boxes on any "change".
      current.dispatchEvent(new Event("change", { bubbles: true }));
    } catch {
      // Network hiccup — the next message (or a reload) catches up.
    } finally {
      inFlight = false;
    }
  }

  const INITIAL_RETRY_MS = 1000;
  const MAX_RETRY_MS = 30000;
  let retryDelayMs = INITIAL_RETRY_MS;
  let retryTimer = null;

  function scheduleReconnect() {
    if (retryTimer !== null) return;
    retryTimer = window.setTimeout(() => {
      retryTimer = null;
      connect();
    }, retryDelayMs);
    retryDelayMs = Math.min(retryDelayMs * 2, MAX_RETRY_MS);
  }

  function connect() {
    let socket;
    try {
      socket = new WebSocket(url);
    } catch {
      scheduleReconnect();
      return;
    }
    socket.addEventListener("open", () => {
      retryDelayMs = INITIAL_RETRY_MS;
    });
    socket.addEventListener("message", onChange);
    socket.addEventListener("close", scheduleReconnect);
    socket.addEventListener("error", () => socket.close());
  }

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && pendingWhileHidden) {
      pendingWhileHidden = false;
      onChange();
    }
  });

  connect();
})();
