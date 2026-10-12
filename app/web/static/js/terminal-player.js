// Replays a recorded terminal session (Audit -> Terminal recordings) in the
// same vendored xterm.js the live terminal uses. The recording comes from
// the page's own `data-cast-url` as `{cols, rows, events: [[seconds, kind,
// data], ...]}`, where kind "o" is output and "r" a resize ("COLSxROWS").
// Nothing is ever sent anywhere: this is playback only.
(() => {
  "use strict";

  const container = document.getElementById("terminal-player");
  if (!container || typeof window.Terminal === "undefined") return;

  const status = document.getElementById("player-status");
  const playButton = document.getElementById("player-play");
  const restartButton = document.getElementById("player-restart");
  const speedSelect = document.getElementById("player-speed");
  const position = document.getElementById("player-position");
  const labels = container.dataset;

  // A long pause in the session (someone reading, a coffee) is shortened to
  // this, so a two-hour session does not take two hours to watch.
  const MAX_GAP_SECONDS = 2;

  let term = null;
  let events = [];
  let index = 0;
  let timer = null;
  let playing = false;

  function setStatus(text) {
    if (status) status.textContent = text;
  }

  function formatTime(seconds) {
    const total = Math.max(0, Math.floor(seconds));
    const minutes = Math.floor(total / 60);
    const rest = String(total % 60).padStart(2, "0");
    return `${minutes}:${rest}`;
  }

  function showPosition() {
    if (!position || events.length === 0) return;
    const now = index > 0 ? events[index - 1][0] : 0;
    const end = events[events.length - 1][0];
    position.textContent = `${formatTime(now)} / ${formatTime(end)}`;
  }

  function apply(event) {
    if (event[1] === "o") {
      term.write(event[2]);
    } else if (event[1] === "r") {
      const [cols, rows] = event[2].split("x").map((value) => parseInt(value, 10));
      if (cols > 0 && rows > 0) term.resize(cols, rows);
    }
  }

  function setPlaying(value) {
    playing = value;
    if (playButton) {
      playButton.textContent = value ? labels.labelPause : labels.labelPlay;
    }
    if (!value && timer !== null) {
      window.clearTimeout(timer);
      timer = null;
    }
  }

  function step() {
    timer = null;
    if (!playing) return;
    if (index >= events.length) {
      setPlaying(false);
      setStatus(labels.labelEnded);
      return;
    }
    apply(events[index]);
    index += 1;
    showPosition();
    if (index >= events.length) {
      setPlaying(false);
      setStatus(labels.labelEnded);
      return;
    }
    const gap = Math.min(events[index][0] - events[index - 1][0], MAX_GAP_SECONDS);
    const speed = speedSelect ? parseFloat(speedSelect.value) || 1 : 1;
    timer = window.setTimeout(step, Math.max(0, (gap * 1000) / speed));
  }

  function restart() {
    setPlaying(false);
    term.reset();
    index = 0;
    showPosition();
    setStatus("");
  }

  async function load() {
    setStatus(labels.labelLoading);
    let cast;
    try {
      const response = await fetch(container.dataset.castUrl, { credentials: "same-origin" });
      if (!response.ok) throw new Error(String(response.status));
      cast = await response.json();
    } catch {
      setStatus(labels.labelFailed);
      return;
    }
    events = Array.isArray(cast.events) ? cast.events : [];
    term = new window.Terminal({
      cols: cast.cols || 80,
      rows: cast.rows || 24,
      disableStdin: true,
      cursorBlink: false,
      convertEol: false,
      scrollback: 5000,
    });
    term.open(container);
    // Same as the live terminal (terminal.js): xterm's default DOM renderer
    // styles cells with injected <style> elements, which this app's CSP
    // blocks. The WebGL addon draws on a <canvas> instead; without WebGL2
    // the DOM renderer and css/xterm-csp.css take over.
    if (typeof window.WebglAddon !== "undefined") {
      try {
        const webgl = new window.WebglAddon.WebglAddon();
        webgl.onContextLoss(() => webgl.dispose());
        term.loadAddon(webgl);
      } catch {
        // No WebGL2 here.
      }
    }
    showPosition();
    setStatus(events.length === 0 ? labels.labelEmpty : "");
    if (playButton) {
      playButton.disabled = events.length === 0;
      playButton.addEventListener("click", () => {
        if (playing) {
          setPlaying(false);
          return;
        }
        if (index >= events.length) restart();
        setStatus("");
        setPlaying(true);
        step();
      });
    }
    if (restartButton) restartButton.addEventListener("click", restart);
  }

  load();
})();
