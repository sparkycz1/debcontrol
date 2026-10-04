// "/" anywhere on the page puts the cursor in the header's search box —
// unless something that takes text already has it.
(function () {
  "use strict";

  document.addEventListener("keydown", function (event) {
    if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey) return;
    var target = event.target;
    if (
      target instanceof HTMLElement &&
      (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName))
    ) {
      return;
    }
    // The terminal and other widgets that read keys themselves.
    if (target instanceof HTMLElement && target.closest(".xterm, [data-keys-own]")) return;
    var box = document.querySelector("[data-global-search]");
    if (!box) return;
    event.preventDefault();
    box.focus();
    box.select();
  });
})();
