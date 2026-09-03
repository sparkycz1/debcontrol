// "Something changed, go check" — the browser half of app/services/
// live_updates.py and app/web/routes/live_ws.py. Opens one WebSocket per
// machine page (Overview, Monitoring, Updates — anywhere with a
// `[data-live-machine-id]` element) and turns each `{"kind": "..."}`
// message it receives into a plain DOM event (`live-<kind>`) dispatched on
// `document.body`. Every htmx panel that used to poll on a fixed interval
// now also listens for its matching event (`hx-trigger="every 60s,
// live-facts from:body"`, say) — the interval stays only as a fallback for
// a missed/dropped push, so panels update within roughly a second of a
// background job finishing instead of waiting out the old ~20s poll.
//
// No-ops entirely on a page with no `[data-live-machine-id]` anchor —
// nothing loads this unconditionally, each machine-scoped page opts in by
// including it (see machines/detail.html, monitoring.html,
// update_history.html).
(() => {
  "use strict";

  const anchor = document.querySelector("[data-live-machine-id]");
  const machineId = anchor && anchor.getAttribute("data-live-machine-id");
  if (!machineId) return;

  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  const url = `${scheme}://${window.location.host}/machines/${encodeURIComponent(machineId)}/live/ws`;

  const INITIAL_RETRY_MS = 1000;
  const MAX_RETRY_MS = 30000;
  let retryDelayMs = INITIAL_RETRY_MS;
  let retryTimer = null;

  function scheduleReconnect() {
    if (retryTimer !== null) return; // already scheduled
    retryTimer = window.setTimeout(() => {
      retryTimer = null;
      connect();
    }, retryDelayMs);
    retryDelayMs = Math.min(retryDelayMs * 2, MAX_RETRY_MS);
  }

  function handleMessage(event) {
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch {
      return; // not JSON — ignore rather than crash the socket handler
    }
    if (!payload || typeof payload.kind !== "string") return;
    document.body.dispatchEvent(new Event(`live-${payload.kind}`));
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
      retryDelayMs = INITIAL_RETRY_MS; // a successful connection resets backoff
    });
    socket.addEventListener("message", handleMessage);
    socket.addEventListener("close", scheduleReconnect);
    // A socket that errors also fires "close" right after — closing it
    // explicitly here just avoids waiting on the browser's own timeout.
    socket.addEventListener("error", () => socket.close());
  }

  connect();

  // A backgrounded tab's WebSocket can go stale (some browsers/proxies
  // silently drop long-idle connections without ever firing "close") —
  // reconnecting on visibility is cheap insurance, not a fix for anything
  // observed, and the server-side idle cap is the real backstop either way.
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      retryDelayMs = INITIAL_RETRY_MS;
    }
  });
})();
