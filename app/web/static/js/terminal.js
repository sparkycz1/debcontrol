// Wires xterm.js up to the terminal WebSocket endpoint
// (app/web/routes/terminal_ws.py). Protocol: binary WebSocket frames carry
// raw terminal bytes in both directions; text frames carry JSON control
// messages (a client-sent "resize", a server-sent "error"). CSP-safe: no
// inline scripts — vendored xterm.js 6 + addon-fit/addon-webgl load before this file (see
// partials/terminal.html), and this is loaded as its own external file,
// same convention as htmx/confirm.js/bulk-select.js.
//
// Clipboard: copying is Ctrl/Cmd+C *when there's a selection* (falls
// through to the shell as a normal SIGINT otherwise, same as any terminal)
// or Ctrl/Cmd+Shift+C unconditionally, both via `navigator.clipboard.
// writeText` — well-supported everywhere. Pasting is deliberately left to
// the browser's own native paste (a real Ctrl+V/Cmd+V, or "Paste" from the
// right-click menu) wherever possible, rather than this app's own
// `clipboard.readText()`: that API needs a user-gesture-scoped permission
// that not every browser grants the same way (Firefox disables it outright
// by default), where native paste needs nothing extra — xterm.js's own
// hidden textarea already turns a real paste event into terminal input.
// Right-click only intercepts the browser's context menu when there's a
// selection to copy; otherwise it's left alone so its native "Paste" still
// works. Ctrl/Cmd+Shift+V is a best-effort `readText()` paste on top of
// that, for browsers where it works — `navigator.clipboard.readText` being
// entirely absent (Firefox) degrades to a status-bar hint pointing at
// native paste instead of a silent no-op.
//
// Several terminals on one page (the Terminals page, /terminals) each get
// their own `DebcontrolTerminal.create(pane)`; a page with one terminal
// marks its pane `data-terminal-auto` (partials/terminal.html).
//
// Reconnect: a session that drops without being ended (network gone,
// laptop asleep, debcontrol restarted, the machine rebooting) reconnects
// by itself, with growing pauses, and right away when the tab becomes
// visible again or the network comes back; a hidden tab waits until it is
// looked at. A session that ended (exit, the time limit) or was refused
// (permission, host key) does not; its Reconnect button starts a new one.
// A new session is a new shell: what ran in the old one is gone.
//
// Key bar: Esc, Tab, arrows, Home/End, PgUp/PgDn, a few symbols and a
// sticky Ctrl/Alt for a phone's keyboard; shown on touch screens, and on
// any screen with the Keys button.
(function () {
  "use strict";

  // Translated strings from partials/terminal.html (English fallback).
  let i18n = {};
  try {
    i18n = JSON.parse(document.getElementById("js-i18n").textContent);
  } catch {
    i18n = {};
  }
  const tr = (key, fallback) => i18n[key] || fallback;

  const POLICY_VIOLATION = 1008;
  const NORMAL = 1000;
  const MAX_ATTEMPTS = 8;
  const MAX_DELAY_MS = 30000;

  // Full 16-color ANSI palette, so `ls --color`, htop and vim get every
  // color they ask for; always dark, whatever the site's theme, like the
  // terminals people already use.
  const THEME = {
    background: "#0b0f16",
    foreground: "#d8dee9",
    cursor: "#d8dee9",
    selectionBackground: "#3b4a6b",
    black: "#1a1f2b",
    red: "#e0685f",
    green: "#5fbf8f",
    yellow: "#e0ab4a",
    blue: "#5b8fff",
    magenta: "#b98fe0",
    cyan: "#5fbfd8",
    white: "#d8dee9",
    brightBlack: "#5c6577",
    brightRed: "#f0857a",
    brightGreen: "#7fd8a8",
    brightYellow: "#f0c46a",
    brightBlue: "#7ba6ff",
    brightMagenta: "#d0aef0",
    brightCyan: "#7fd8ea",
    brightWhite: "#f4f6fa",
  };

  const encoder = new TextEncoder();

  function wsUrlFor(path) {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    return protocol + "//" + window.location.host + path;
  }

  function sequenceFor(term, key) {
    const app = term.modes && term.modes.applicationCursorKeysMode;
    const cursor = (letter) => (app ? "\x1bO" : "\x1b[") + letter;
    switch (key) {
      case "esc": return "\x1b";
      case "tab": return "\t";
      case "up": return cursor("A");
      case "down": return cursor("B");
      case "right": return cursor("C");
      case "left": return cursor("D");
      case "home": return cursor("H");
      case "end": return cursor("F");
      case "pgup": return "\x1b[5~";
      case "pgdn": return "\x1b[6~";
      case "ctrl-c": return "\x03";
      default: return "";
    }
  }

  // Ctrl+<key> as the byte a terminal sends: a-z and @[\]^_ to 0-31,
  // ? to DEL; anything else is sent unchanged.
  function withCtrl(data) {
    if (data.length !== 1) return data;
    const code = data.toUpperCase().charCodeAt(0);
    if (code >= 64 && code <= 95) return String.fromCharCode(code - 64);
    if (data === "?") return "\x7f";
    if (data === " ") return "\x00";
    return data;
  }

  function create(pane, options) {
    const opts = options || {};
    const container = pane.querySelector("[data-terminal-screen]");
    const statusEl = pane.querySelector("[data-terminal-status]");
    const reconnectButton = pane.querySelector("[data-terminal-reconnect]");
    const keysEl = pane.querySelector("[data-terminal-keys]");
    const keysToggle = pane.querySelector("[data-terminal-keys-toggle]");
    const wsPath = opts.wsPath || pane.dataset.wsPath;
    if (!container || !wsPath) return null;

    function setStatus(text) {
      if (statusEl) statusEl.textContent = text;
    }

    const term = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontSize: 14,
      fontFamily: '"SFMono-Regular", Consolas, monospace',
      scrollback: 5000,
      theme: THEME,
    });
    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(container);

    // xterm.js's default DOM renderer styles cells by injecting <style>
    // elements, which this app's CSP (`style-src 'self'`) blocks. The WebGL
    // addon draws on a <canvas> instead; without WebGL2 (or after a lost
    // context) the DOM renderer falls back on css/xterm-csp.css.
    if (typeof WebglAddon !== "undefined") {
      try {
        const webgl = new WebglAddon.WebglAddon();
        webgl.onContextLoss(() => webgl.dispose());
        term.loadAddon(webgl);
      } catch (err) {
        // No WebGL2 here: the DOM renderer + xterm-csp.css take over.
      }
    }

    let socket = null;
    let disposed = false;
    let attempts = 0;
    let timer = null;
    let autoReconnect = false; // set while a dropped session may come back by itself
    let everConnected = false;
    let ctrlArmed = false;
    let altArmed = false;

    function sendResize() {
      if (!socket || socket.readyState !== WebSocket.OPEN) return;
      socket.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
    }

    function refit() {
      // A hidden pane (another tab on the Terminals page) has no size.
      if (!container.offsetWidth || !container.offsetHeight) return;
      fitAddon.fit();
      sendResize();
    }

    function showReconnect(show) {
      if (reconnectButton) reconnectButton.hidden = !show;
    }

    function connect() {
      if (disposed) return;
      clearTimeout(timer);
      timer = null;
      showReconnect(false);
      setStatus(tr("terminal.status.connecting", "Connecting…"));
      const ws = new WebSocket(wsUrlFor(wsPath));
      ws.binaryType = "arraybuffer";
      socket = ws;

      ws.addEventListener("open", () => {
        if (everConnected) {
          term.write("\r\n\x1b[90m[" + tr("terminal.status.new_session", "Reconnected: this is a new session.") + "]\x1b[0m\r\n");
        }
        everConnected = true;
        attempts = 0;
        autoReconnect = true;
        setStatus(tr("terminal.status.connected", "Connected."));
        refit();
        sendResize();
      });

      ws.addEventListener("message", (event) => {
        if (typeof event.data === "string") {
          let msg;
          try {
            msg = JSON.parse(event.data);
          } catch (err) {
            return;
          }
          if (msg && msg.type === "error") {
            setStatus(tr("terminal.status.error", "Error: ") + msg.message);
            term.write("\r\n\x1b[31m[" + msg.message + "]\x1b[0m\r\n");
          }
          return;
        }
        term.write(new Uint8Array(event.data));
      });

      ws.addEventListener("close", (event) => {
        if (ws !== socket || disposed) return;
        socket = null;
        const reason = event.reason
          ? tr("terminal.status.disconnected_reason", "Disconnected: ") + event.reason
          : tr("terminal.status.disconnected", "Disconnected.");
        setStatus(reason);
        showReconnect(true);
        // Ended on purpose, or refused: only the button starts a new one.
        if (event.code === NORMAL || event.code === POLICY_VIOLATION) {
          autoReconnect = false;
          return;
        }
        // The first try failed (SSH refused, the machine rebooting): keep
        // trying too, within the same limit.
        if (!everConnected && attempts === 0) autoReconnect = true;
        scheduleReconnect();
      });

      ws.addEventListener("error", () => {
        if (ws === socket) setStatus(tr("terminal.status.connection_error", "Connection error."));
      });
    }

    function scheduleReconnect() {
      if (!autoReconnect || disposed) return;
      if (attempts >= MAX_ATTEMPTS) {
        autoReconnect = false;
        setStatus(tr("terminal.status.gave_up", "Disconnected. The connection did not come back."));
        return;
      }
      if (document.visibilityState === "hidden") {
        setStatus(tr("terminal.status.waiting_visible", "Disconnected. Reconnects when you come back to this tab."));
        return; // visibilitychange picks it up
      }
      const delay = Math.min(MAX_DELAY_MS, 1000 * Math.pow(2, attempts));
      attempts += 1;
      setStatus(tr("terminal.status.reconnecting", "Disconnected. Reconnecting in {seconds} s…").replace("{seconds}", String(Math.round(delay / 1000))));
      timer = setTimeout(connect, delay);
    }

    function reconnectNow() {
      if (disposed || socket) return;
      if (!autoReconnect) return;
      attempts = 0;
      connect();
    }

    function onVisible() {
      if (document.visibilityState === "visible") reconnectNow();
    }
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("online", reconnectNow);

    if (reconnectButton) {
      reconnectButton.addEventListener("click", () => {
        attempts = 0;
        autoReconnect = true;
        connect();
        term.focus();
      });
    }

    // --- Input, with the key bar's sticky Ctrl/Alt -------------------------

    function send(data) {
      if (socket && socket.readyState === WebSocket.OPEN) socket.send(encoder.encode(data));
    }

    function setModifier(name, on) {
      if (name === "ctrl") ctrlArmed = on;
      if (name === "alt") altArmed = on;
      if (!keysEl) return;
      const button = keysEl.querySelector('[data-mod="' + name + '"]');
      if (button) button.setAttribute("aria-pressed", on ? "true" : "false");
    }

    function sendWithModifiers(data) {
      let out = data;
      if (ctrlArmed) out = withCtrl(out);
      if (altArmed) out = "\x1b" + out;
      setModifier("ctrl", false);
      setModifier("alt", false);
      send(out);
    }

    term.onData((data) => {
      if (ctrlArmed || altArmed) {
        sendWithModifiers(data);
        return;
      }
      send(data);
    });

    if (keysEl) {
      // Keep the focus (and a phone's keyboard) in the terminal.
      keysEl.addEventListener("pointerdown", (event) => {
        if (event.target.closest("button")) event.preventDefault();
      });
      keysEl.addEventListener("click", (event) => {
        const button = event.target.closest("button");
        if (!button) return;
        if (button.dataset.mod) {
          const armed = button.dataset.mod === "ctrl" ? ctrlArmed : altArmed;
          setModifier(button.dataset.mod, !armed);
        } else if (button.dataset.key) {
          sendWithModifiers(sequenceFor(term, button.dataset.key));
        } else if (button.dataset.text) {
          sendWithModifiers(button.dataset.text);
        }
        term.focus();
      });
    }
    function showKeys(on) {
      pane.classList.toggle("terminal-keys-shown", on);
      if (keysToggle) keysToggle.setAttribute("aria-pressed", on ? "true" : "false");
    }
    // A touch screen has no Esc, Tab or arrows: the bar starts shown there.
    const touch =
      navigator.maxTouchPoints > 0 ||
      (window.matchMedia && window.matchMedia("(pointer: coarse)").matches);
    showKeys(Boolean(touch));
    if (keysToggle) {
      keysToggle.addEventListener("click", () => {
        showKeys(!pane.classList.contains("terminal-keys-shown"));
        refit();
        term.focus();
      });
    }

    // --- Clipboard ---------------------------------------------------------

    // `navigator.clipboard` is undefined outside a secure context (HTTPS or
    // http://localhost), common for a self-hosted instance on a LAN: say so
    // instead of failing silently.
    function clipboardUnavailableReason() {
      if (navigator.clipboard) return null;
      if (!window.isSecureContext) {
        return tr("terminal.clipboard.need_https", "Clipboard access needs HTTPS (or http://localhost) — this page is loaded over plain HTTP. Put debcontrol behind a reverse proxy with TLS (see the wiki's Installation page), or use Ctrl+Shift+C/V manually via the terminal's own keyboard shortcuts once it is.");
      }
      return tr("terminal.clipboard.unsupported", "This browser doesn't support clipboard access.");
    }

    function copySelection() {
      const text = term.getSelection();
      if (!text) return false;
      const reason = clipboardUnavailableReason();
      if (reason) {
        setStatus(reason);
        return false;
      }
      navigator.clipboard.writeText(text).catch(() => {
        setStatus(tr("terminal.clipboard.copy_failed", "Couldn't copy — clipboard access needs HTTPS (or localhost)."));
      });
      return true;
    }

    function pasteFromClipboard() {
      const reason = clipboardUnavailableReason();
      if (reason) {
        setStatus(reason);
        return;
      }
      if (!navigator.clipboard.readText) {
        setStatus(tr("terminal.clipboard.use_ctrl_v", "Use Ctrl+V (or right-click → Paste) — this browser doesn't allow reading the clipboard programmatically."));
        return;
      }
      navigator.clipboard
        .readText()
        .then((text) => {
          if (text) term.paste(text);
        })
        .catch(() => {
          setStatus(tr("terminal.clipboard.read_failed", "Couldn't read the clipboard — use Ctrl+V instead."));
        });
    }

    // Ctrl/Cmd+C copies when there is a selection (else it is a normal
    // SIGINT), Ctrl/Cmd+Shift+C always; plain Ctrl+V is the browser's own
    // paste, Ctrl/Cmd+Shift+V a best-effort clipboard read.
    term.attachCustomKeyEventHandler((event) => {
      if (event.type !== "keydown") return true;
      const key = event.key.toLowerCase();
      const modified = event.ctrlKey || event.metaKey;
      if (modified && key === "c" && (event.shiftKey || term.hasSelection())) {
        if (copySelection()) return false;
      }
      if (modified && event.shiftKey && key === "v") {
        pasteFromClipboard();
        return false;
      }
      return true;
    });

    // Right-click only takes over when there is a selection to copy, so
    // the browser's own "Paste" stays available.
    container.addEventListener("contextmenu", (event) => {
      if (copySelection()) event.preventDefault();
    });

    // --- Size ----------------------------------------------------------------

    window.addEventListener("resize", refit);
    let observer = null;
    if (typeof ResizeObserver !== "undefined") {
      observer = new ResizeObserver(refit);
      observer.observe(container);
    }

    function dispose() {
      if (disposed) return;
      disposed = true;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("online", reconnectNow);
      window.removeEventListener("resize", refit);
      if (observer) observer.disconnect();
      if (socket) socket.close(NORMAL, "Page closed.");
      socket = null;
      term.dispose();
    }

    window.addEventListener("beforeunload", () => {
      disposed = true;
      if (socket) socket.close(NORMAL, "Page closed.");
    });

    refit();
    connect();
    if (opts.focus !== false) term.focus();
    return { term: term, focus: () => term.focus(), refit: refit, dispose: dispose };
  }

  window.DebcontrolTerminal = { create: create };

  document.querySelectorAll(".terminal-pane[data-terminal-auto]").forEach((pane) => create(pane));
})();
