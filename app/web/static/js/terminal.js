// Wires xterm.js up to the terminal WebSocket endpoint
// (app/web/routes/terminal_ws.py). Protocol: binary WebSocket frames carry
// raw terminal bytes in both directions; text frames carry JSON control
// messages (a client-sent "resize", a server-sent "error"). CSP-safe: no
// inline scripts — vendored xterm.js/addon-fit load before this file (see
// machines/terminal.html), and this is loaded as its own external file,
// same convention as htmx/confirm.js/bulk-select.js.
(function () {
  "use strict";

  const container = document.getElementById("terminal-container");
  const statusEl = document.getElementById("terminal-status");
  if (!container) return;

  function setStatus(text) {
    if (statusEl) statusEl.textContent = text;
  }

  const term = new Terminal({
    cursorBlink: true,
    convertEol: true,
    fontSize: 14,
    theme: { background: "#000000" },
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

  window.addEventListener("resize", () => {
    fitAddon.fit();
    sendResize();
  });

  window.addEventListener("beforeunload", () => {
    socket.close(1000, "Page closed.");
  });
})();
