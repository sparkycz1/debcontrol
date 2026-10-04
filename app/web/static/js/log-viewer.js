// Logs tab viewer (logs.html, shared with the sister app): start scrolled to the newest line
// (logs show the *last* N lines, so the interesting end is the bottom), a
// "Wrap lines" toggle, a "Jump to bottom" button and "Follow live", which
// streams new lines over a WebSocket (app/web/routes/logs_ws.py). No
// inline handlers, per the CSP.

(function () {
  // Same severity guess as app/web/log_lines.py, so streamed lines are
  // colored like the server-rendered ones.
  const LEVELS = [
    ["error", /\b(error|err|fail(ed|ure)?|fatal|crit(ical)?|panic|emerg|alert|exception|traceback|denied|segfault)\b/i],
    ["warn", /\b(warn(ing)?|deprecated)\b/i],
    ["debug", /\b(debug|trace)\b/i],
  ];
  // Keep the page responsive on a chatty log.
  const MAX_LINES = 5000;

  function levelOf(text) {
    for (const [level, pattern] of LEVELS) {
      if (pattern.test(text)) return level;
    }
    return null;
  }

  // Built with text nodes only — log content is never trusted as markup.
  function renderLine(text, search) {
    const li = document.createElement("li");
    li.className = "log-line";
    const level = levelOf(text);
    if (level) li.classList.add("log-" + level);
    if (!search) {
      li.textContent = text;
      return li;
    }
    let start = 0;
    let index;
    while ((index = text.indexOf(search, start)) !== -1) {
      if (index > start) li.append(text.slice(start, index));
      const mark = document.createElement("mark");
      mark.textContent = search;
      li.append(mark);
      start = index + search.length;
    }
    if (start < text.length) li.append(text.slice(start));
    return li;
  }

  function setupFollow(viewer, body) {
    const button = viewer.querySelector("[data-log-follow]");
    const url = viewer.dataset.followUrl;
    if (!button || !url) return;
    const status = viewer.querySelector("[data-log-follow-status]");
    const count = viewer.querySelector("[data-log-count]");
    const empty = viewer.querySelector("[data-log-empty]");
    const search = (viewer.dataset.search || "").trim();
    const labels = viewer.dataset;
    let socket = null;

    function setStatus(text, live) {
      if (!status) return;
      status.textContent = text;
      status.classList.toggle("is-live", Boolean(live));
    }

    function setFollowing(on) {
      button.setAttribute("aria-pressed", on ? "true" : "false");
      button.textContent = on ? labels.labelStop : labels.labelFollow;
    }

    function stop(message) {
      if (socket) {
        const s = socket;
        socket = null;
        s.close();
      }
      setFollowing(false);
      setStatus(message || labels.statusEnded, false);
    }

    function start() {
      const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
      socket = new WebSocket(scheme + "//" + window.location.host + url);
      const current = socket;
      setFollowing(true);
      setStatus(labels.statusConnecting, false);
      // The stream starts with the last lines again, so replace the snapshot.
      body.replaceChildren();
      if (empty) empty.hidden = true;
      if (count) count.hidden = true;

      current.addEventListener("open", () => {
        if (socket === current) setStatus(labels.statusLive, true);
      });
      current.addEventListener("message", (event) => {
        if (socket !== current) return;
        let message;
        try {
          message = JSON.parse(event.data);
        } catch {
          return;
        }
        if (message.t === "line") {
          const atBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 40;
          body.append(renderLine(String(message.v), search));
          while (body.childElementCount > MAX_LINES) body.firstElementChild.remove();
          if (atBottom) body.scrollTop = body.scrollHeight;
        } else if (message.t === "error" || message.t === "end") {
          stop(String(message.v));
        }
      });
      current.addEventListener("close", (event) => {
        if (socket !== current) return;
        stop(event.reason || labels.statusEnded);
      });
    }

    button.addEventListener("click", () => {
      if (socket) stop();
      else start();
    });
    window.addEventListener("pagehide", () => {
      if (socket) socket.close();
    });
  }

  document.querySelectorAll("[data-log-viewer]").forEach((viewer) => {
    const body = viewer.querySelector("[data-log-body]");
    if (!body) return;
    body.scrollTop = body.scrollHeight;

    const wrap = viewer.querySelector("[data-log-wrap]");
    if (wrap) {
      wrap.addEventListener("click", () => {
        const wrapped = body.classList.toggle("is-wrapped");
        wrap.setAttribute("aria-pressed", wrapped ? "true" : "false");
      });
    }

    const bottom = viewer.querySelector("[data-log-bottom]");
    if (bottom) {
      bottom.addEventListener("click", () => {
        body.scrollTop = body.scrollHeight;
      });
    }

    setupFollow(viewer, body);
  });
})();
