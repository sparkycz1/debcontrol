// Logs tab viewer (machines/logs.html): start scrolled to the newest line
// (logs show the *last* N lines, so the interesting end is the bottom), a
// "Wrap lines" toggle and a "Jump to bottom" button. No inline handlers,
// per the CSP.

(function () {
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
  });
})();
