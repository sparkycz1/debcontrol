// Wires xterm.js up to the terminal WebSocket endpoint
// (app/web/routes/terminal_ws.py). Protocol: binary WebSocket frames carry
// raw terminal bytes in both directions; text frames carry JSON control
// messages (a client-sent "resize", a server-sent "error"). CSP-safe: no
// inline scripts — vendored xterm.js/addon-fit load before this file (see
// machines/terminal.html), and this is loaded as its own external file,
// same convention as htmx/confirm.js/bulk-select.js.
//
// Clipboard: xterm.js's own hidden-textarea handling already covers plain
// Ctrl+V/Cmd+V paste in most browsers, but that's brittle (loses focus
// easily, differs across browsers) — this adds explicit, reliable paths on
// top of it via the Clipboard API: Ctrl/Cmd+Shift+C copies the current
// selection, Ctrl/Cmd+Shift+V pastes, and right-click does whichever makes
// sense (copy if there's a selection, otherwise paste) — the same
// convention PuTTY/most native terminals use. `navigator.clipboard` needs a
// secure context (HTTPS, or localhost) and, for reading, a user gesture —
// both are true here (a keypress or click is exactly a user gesture) except
// when the app is reached over plain HTTP through a misconfigured reverse
// proxy, which fails visibly (a status-bar message) rather than silently.
(function () {
  "use strict";

  const container = document.getElementById("terminal-container");
  const statusEl = document.getElementById("terminal-status");
  if (!container) return;

  function setStatus(text) {
    if (statusEl) statusEl.textContent = text;
  }

  // Full 16-color ANSI palette (not just a background override) so
  // `ls --color`, `htop`, `vim`, etc. render every color they ask for
  // instead of falling back to xterm.js's own built-in palette, which
  // this app has no control over matching visually. Deliberately always
  // dark regardless of the site's own light/dark theme — a light-on-dark
  // terminal is the near-universal convention this app's own users will
  // already expect from every other terminal they use.
  const term = new Terminal({
    cursorBlink: true,
    convertEol: true,
    fontSize: 14,
    fontFamily: '"SFMono-Regular", Consolas, monospace',
    scrollback: 5000,
    theme: {
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
    },
  });
  const fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(container);
  fitAddon.fit();
  term.focus();

  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = protocol + "//" + window.location.host + container.dataset.wsPath;
  const socket = new WebSocket(wsUrl);
  socket.binaryType = "arraybuffer";

  const encoder = new TextEncoder();

  function sendResize() {
    if (socket.readyState !== WebSocket.OPEN) return;
    socket.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
  }

  setStatus("Connecting…");

  socket.addEventListener("open", () => {
    setStatus("Connected.");
    sendResize();
  });

  socket.addEventListener("message", (event) => {
    if (typeof event.data === "string") {
      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch (err) {
        return;
      }
      if (msg && msg.type === "error") {
        setStatus("Error: " + msg.message);
        term.write("\r\n\x1b[31m[" + msg.message + "]\x1b[0m\r\n");
      }
      return;
    }
    term.write(new Uint8Array(event.data));
  });

  socket.addEventListener("close", (event) => {
    setStatus(event.reason ? "Disconnected: " + event.reason : "Disconnected.");
  });

  socket.addEventListener("error", () => {
    setStatus("Connection error.");
  });

  term.onData((data) => {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(encoder.encode(data));
    }
  });

  // --- Clipboard -------------------------------------------------------

  function copySelection() {
    const text = term.getSelection();
    if (!text || !navigator.clipboard) return false;
    navigator.clipboard.writeText(text).catch(() => {
      setStatus("Couldn't copy — clipboard access needs HTTPS (or localhost).");
    });
    return true;
  }

  function pasteFromClipboard() {
    if (!navigator.clipboard) {
      setStatus("Couldn't paste — clipboard access needs HTTPS (or localhost).");
      return;
    }
    navigator.clipboard
      .readText()
      .then((text) => {
        if (text) term.paste(text);
      })
      .catch(() => {
        setStatus("Couldn't paste — grant this page clipboard access and try again.");
      });
  }

  term.attachCustomKeyEventHandler((event) => {
    if (event.type !== "keydown") return true;
    const combo = (event.ctrlKey || event.metaKey) && event.shiftKey;
    if (combo && event.key.toLowerCase() === "c") {
      if (copySelection()) return false; // handled — don't also send Ctrl+C to the shell
    }
    if (combo && event.key.toLowerCase() === "v") {
      pasteFromClipboard();
      return false;
    }
    return true;
  });

  // Right-click: copy the selection if there is one, otherwise paste —
  // same convention PuTTY and most native terminal emulators use. Always
  // suppresses the browser's own context menu, which has nothing useful
  // to offer over a canvas-rendered terminal anyway.
  container.addEventListener("contextmenu", (event) => {
    event.preventDefault();
    if (!copySelection()) pasteFromClipboard();
  });

  // --- Resize ------------------------------------------------------------

  function refit() {
    fitAddon.fit();
    sendResize();
  }

  window.addEventListener("resize", refit);
  // Covers layout changes that don't fire a window resize event (e.g. a
  // sidebar/panel toggling elsewhere on the page changing this container's
  // own size) — window resize alone missed those.
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(refit).observe(container);
  }

  window.addEventListener("beforeunload", () => {
    socket.close(1000, "Page closed.");
  });
})();
