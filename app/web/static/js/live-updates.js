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
// Also offers a browser Notification for the same event when this tab is
// backgrounded (`document.visibilityState === "hidden"`) and the viewer
// opted in via the toggle button this script injects next to the page
// heading — see `notifyIfBackgrounded`/`buildToggle` below. Deliberately
// the plain Notification API, not the Push API: no service worker, no
// server-side subscription storage, nothing that would still fire with
// the tab fully closed. It only ever surfaces something this same open
// tab already received over the WebSocket above.
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
  const machineName = anchor.getAttribute("data-live-machine-name") || "This machine";

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
    notifyIfBackgrounded(payload.kind);
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

  // --- Browser notifications ------------------------------------------

  const NOTIFY_PREF_KEY = "debcontrol:notifications-enabled";

  const KIND_MESSAGES = {
    status: "Reachability status changed",
    facts: "Facts refreshed",
    packages: "Installed packages refreshed",
    services: "Services refreshed",
    updates: "Update availability changed",
  };

  function notificationsWanted() {
    try {
      return window.localStorage.getItem(NOTIFY_PREF_KEY) === "1";
    } catch {
      return false; // private browsing / storage blocked — just skip it
    }
  }

  function setNotificationsWanted(value) {
    try {
      window.localStorage.setItem(NOTIFY_PREF_KEY, value ? "1" : "0");
    } catch {
      // Nothing to persist to — the toggle still reflects the in-memory
      // choice for the rest of this page view, it just won't survive a
      // reload. Not worth surfacing an error for.
    }
  }

  function notifyIfBackgrounded(kind) {
    if (!("Notification" in window)) return;
    if (Notification.permission !== "granted") return;
    if (!notificationsWanted()) return;
    if (document.visibilityState !== "hidden") return; // tab is frontmost — the DOM update is enough
    const body = KIND_MESSAGES[kind] || "Something changed";
    let notification;
    try {
      notification = new Notification(machineName, { body, tag: `debcontrol-${machineId}` });
    } catch {
      return; // some browsers throw if constructed from a background/service context
    }
    notification.onclick = () => {
      window.focus();
      notification.close();
    };
  }

  // --- The toggle button, injected next to the page heading rather than
  // duplicated in three separate templates. ---

  function buildToggle() {
    if (!("Notification" in window)) return; // unsupported browser — nothing to offer

    const button = document.createElement("button");
    button.type = "button";
    button.className = "link-button live-notify-toggle";

    function render() {
      if (Notification.permission === "denied") {
        button.textContent = "🔕 Notifications blocked";
        button.disabled = true;
        button.title = "Blocked in this browser's site settings.";
        return;
      }
      if (Notification.permission === "granted" && notificationsWanted()) {
        button.textContent = "🔔 Notifications on";
        button.title = "Click to turn off background notifications for this machine's page.";
      } else {
        button.textContent = "🔔 Enable notifications";
        button.title = "Get a browser notification when this page updates while backgrounded.";
      }
    }

    button.addEventListener("click", async () => {
      if (Notification.permission === "default") {
        let permission;
        try {
          permission = await Notification.requestPermission();
        } catch {
          return;
        }
        if (permission === "granted") setNotificationsWanted(true);
        render();
        return;
      }
      if (Notification.permission === "granted") {
        setNotificationsWanted(!notificationsWanted());
        render();
      }
    });

    render();
    anchor.appendChild(button);
  }

  buildToggle();
})();
