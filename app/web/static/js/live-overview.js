// The machine Overview's popovers (machines/detail.html). A popover with
// `data-clear-on-close="<selector>"` puts that element back to its
// "Loading…" text when it closes — for the top processes this removes the
// element that asks again every few seconds, so nothing keeps polling the
// machine once the list is out of sight.
(() => {
  "use strict";

  document.querySelectorAll("[popover][data-clear-on-close]").forEach((popover) => {
    const target = document.querySelector(popover.dataset.clearOnClose);
    if (!target) return;
    const placeholder = target.innerHTML;
    popover.addEventListener("toggle", (event) => {
      if (event.newState === "closed") target.innerHTML = placeholder;
    });
  });
})();
