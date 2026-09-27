// Update run page: the apt output is a fixed-height scroll box. While the
// run is live, the whole status panel is re-fetched every 3 s
// (partials/update_run_status.html), which would reset the box to the
// top each time. This keeps following the end of the output while you're
// at the bottom, and keeps your place once you scroll up to read.
(function () {
  let atBottom = true;
  let scrollTop = 0;

  function box() {
    return document.querySelector("[data-run-output]");
  }

  function remember() {
    const el = box();
    if (!el) return;
    atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    scrollTop = el.scrollTop;
  }

  function restore() {
    const el = box();
    if (!el) return;
    el.scrollTop = atBottom ? el.scrollHeight : scrollTop;
  }

  document.addEventListener("htmx:beforeSwap", (event) => {
    if (event.target && event.target.id === "update-run-status") remember();
  });
  document.addEventListener("htmx:afterSettle", restore);
  restore();
})();
