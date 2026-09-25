// Wires xterm.js up to the terminal WebSocket endpoint
// (app/web/routes/terminal_ws.py). Protocol: binary WebSocket frames carry
// raw terminal bytes in both directions; text frames carry JSON control
// messages (a client-sent "resize", a server-sent "error"). CSP-safe: no
// inline scripts — vendored xterm.js 6 + addon-fit/addon-webgl load before this file (see
// machines/terminal.html), and this is loaded as its own external file,
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

  // xterm.js's default DOM renderer styles cells by injecting <style>
  // elements (palette, cursor, selection, span layout) — this app's CSP
  // (`style-src 'self'`, no `unsafe-inline`) silently blocks those. The
  // WebGL addon draws glyphs and colors on a <canvas> instead, which CSP's
  // style-src has no say over (xterm.js 6 dropped the older canvas addon
  // that used to fill this role). When WebGL2 isn't available, or its
  // context is lost later (GPU reset, driver update), the terminal falls
  // back to the DOM renderer, kept usable by the static rules in
  // css/xterm-csp.css — everything but 24-bit truecolor.
  if (typeof WebglAddon !== "undefined") {
    try {
      const webgl = new WebglAddon.WebglAddon();
      webgl.onContextLoss(() => webgl.dispose());
      term.loadAddon(webgl);
    } catch (err) {
      // No WebGL2 here — the DOM renderer + xterm-csp.css take over.
    }
  }

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

  // `navigator.clipboard` is entirely undefined — not just permission-
  // denied — outside a "secure context" (HTTPS, or http://localhost). A
  // self-hosted instance reached over plain HTTP on a LAN IP/hostname (a
  // very common setup for this app) hits exactly this, and previously got
  // no feedback at all: `copySelection`/`pasteFromClipboard` bailed out
  // silently before ever reaching the code that explains why. This gives
  // the actionable reason instead, same diagnosis webauthn.js's passkey
  // buttons make for the same underlying cause.
  function clipboardUnavailableReason() {
    if (navigator.clipboard) return null;
    if (!window.isSecureContext) {
      return "Clipboard access needs HTTPS (or http://localhost) — this page is loaded over plain HTTP. Put debcontrol behind a reverse proxy with TLS (see the wiki's Installation page), or use Ctrl+Shift+C/V manually via the terminal's own keyboard shortcuts once it is.";
    }
    return "This browser doesn't support clipboard access.";
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
      setStatus("Couldn't copy — clipboard access needs HTTPS (or localhost).");
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
      setStatus("Use Ctrl+V (or right-click → Paste) — this browser doesn't allow reading the clipboard programmatically.");
      return;
    }
    navigator.clipboard
      .readText()
      .then((text) => {
        if (text) term.paste(text);
      })
      .catch(() => {
        setStatus("Couldn't read the clipboard — use Ctrl+V instead.");
      });
  }

  term.attachCustomKeyEventHandler((event) => {
    if (event.type !== "keydown") return true;
    const key = event.key.toLowerCase();
    const modified = event.ctrlKey || event.metaKey;
    if (modified && key === "c" && (event.shiftKey || term.hasSelection())) {
      if (copySelection()) return false; // handled — don't also send Ctrl+C to the shell
    }
    if (modified && event.shiftKey && key === "v") {
      pasteFromClipboard();
      return false;
    }
    return true; // includes plain Ctrl+V — left to xterm.js's own native paste handling
  });

  // Right-click only handles the copy side — only intercepted (and the
  // browser's own context menu suppressed) when there's a selection to
  // copy; otherwise the native menu is left alone so its own "Paste" still
  // works everywhere, no clipboard-read permission needed for it.
  container.addEventListener("contextmenu", (event) => {
    if (copySelection()) event.preventDefault();
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
