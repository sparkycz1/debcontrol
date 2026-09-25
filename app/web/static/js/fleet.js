// Fleet page (fleet/index.html): the name filter box, re-applied after
// the grid's own 60 s htmx refresh swaps in fresh cards.
(function () {
  const box = document.querySelector("[data-fleet-filter]");
  if (!box) return;

  function apply() {
    const q = box.value.trim().toLowerCase();
    document.querySelectorAll("[data-fleet-name]").forEach((card) => {
      card.hidden = q !== "" && !card.dataset.fleetName.includes(q);
    });
  }

  box.addEventListener("input", apply);
  document.addEventListener("htmx:afterSwap", apply);
})();
