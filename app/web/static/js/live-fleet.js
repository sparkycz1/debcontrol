// The fleet half of app/services/live_updates.py: one WebSocket to the
// fleet channel (app/web/routes/live_ws.py's `/machines/live/ws`), and on
// each "something changed" message a quiet re-fetch of every
// `[data-live-fleet]` block on the page, which replaces the one on screen.
// The machine list, the dashboard's fleet grid, Docker -> Containers and
// Docker -> Settings use it, so a bulk "check for updates", a machine going
// up/down or a finished Docker job shows up without a reload. The message
// says only *what kind* of thing changed, never which machine; the re-fetch
// is the ordinary, permission- and scope-checked page load.
//
// Each block needs an `id`. Optional attributes:
// - `data-live-kinds="status,updates"`: only these kinds refresh it;
// - `data-live-url="/fleet/cards"`: fetch this instead of the page itself
//   (the block with the same id is taken from the answer).
//
// Keeps what the viewer is doing: ticked checkboxes (by value) and the
// "select all" box survive the swap, and anything outside the block (the
// bulk-action bar) is left alone. Bursts are coalesced (a bulk check
// finishes one machine at a time), a backgrounded tab refreshes once when
// it's shown again, and a viewer mid-way through something inside a block
// (focus in it, an open menu) is waited for.
//
// No-op on a page without a `[data-live-fleet]` element.
(() => {
  "use strict";

  if (!document.querySelector("[data-live-fleet]")) return;

  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const url = `${scheme}://${window.location.host}/machines/live/ws`;

  const QUIET_MS = 1500; // wait this long after the last message of a burst
  const MIN_GAP_MS = 5000; // and never refresh more often than this
  let timer = null;
  let lastRefresh = 0;
  let pendingWhileHidden = false;
  let inFlight = false;
  const pendingKinds = new Set();

  function schedule(delay) {
    if (timer !== null) window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      timer = null;
      refresh();
    }, delay);
  }

  function onMessage(event) {
    let kind = "";
    try {
      kind = String(JSON.parse(event.data).kind || "");
    } catch {
      // Not JSON: treat as "something changed".
    }
    pendingKinds.add(kind);
    onChange();
  }

  function wants(block) {
    const kinds = block.getAttribute("data-live-kinds");
    if (!kinds || pendingKinds.has("")) return true;
    return kinds.split(",").some((kind) => pendingKinds.has(kind.trim()));
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
    if (inFlight) return;
    const blocks = [...document.querySelectorAll("[data-live-fleet][id]")].filter(wants);
    if (!blocks.length) {
      pendingKinds.clear();
      return;
    }
    const active = document.activeElement;
    const busy = blocks.some(
      (block) =>
        (active && active !== document.body && block.contains(active)) ||
        block.querySelector(":popover-open"),
    );
    if (busy) {
      schedule(QUIET_MS); // the viewer is using it — try again shortly
      return;
    }
    pendingKinds.clear();
    inFlight = true;
    lastRefresh = Date.now();
    try {
      const pages = new Map();
      for (const block of blocks) {
        const source = block.getAttribute("data-live-url") || window.location.href;
        if (!pages.has(source)) pages.set(source, load(source));
        const doc = await pages.get(source);
        const fresh = doc && doc.getElementById(block.id);
        if (fresh) swap(block, fresh); // missing: the page changed shape — leave it
      }
    } catch {
      // Network hiccup — the next message (or a reload) catches up.
    } finally {
      inFlight = false;
    }
  }

  async function load(source) {
    const response = await fetch(source, {
      credentials: "same-origin",
      headers: { Accept: "text/html" },
    });
    if (!response.ok || response.redirected) return null; // logged out, say
    return new DOMParser().parseFromString(await response.text(), "text/html");
  }

  function swap(current, fresh) {
    const ticked = new Set(
      [...current.querySelectorAll("input[type=checkbox][value]:checked")].map((box) => box.value),
    );
    const allTicked = [...current.querySelectorAll("input[data-select-all]:checked")].map((box) =>
      box.getAttribute("data-select-all"),
    );
    current.replaceChildren(...[...fresh.childNodes].map((node) => document.importNode(node, true)));
    for (const box of current.querySelectorAll("input[type=checkbox][value]")) {
      box.checked = ticked.has(box.value);
    }
    for (const name of allTicked) {
      const box = current.querySelector(`input[data-select-all="${name}"]`);
      if (box) box.checked = true;
    }
    if (window.htmx) window.htmx.process(current);
    // bulk-select.js recounts the ticked boxes on any "change"; others
    // (fleet.js's name filter) re-apply on "live:swapped".
    current.dispatchEvent(new Event("change", { bubbles: true }));
    current.dispatchEvent(new CustomEvent("live:swapped", { bubbles: true }));
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
    socket.addEventListener("message", onMessage);
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
