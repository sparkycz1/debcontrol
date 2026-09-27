// Shows only the chosen delivery channel's fields on the Notifications
// rule form (app/web/templates/notifications/rule_form.html): every
// `[data-delivery-for]` lists the channels it belongs to. The server
// already renders the other channels' fields hidden; this only re-syncs
// them as the select changes (the server reads just the fields the chosen
// channel uses either way).
(function () {
  function sync(select) {
    const form = select.closest("form");
    if (!form) return;
    form.querySelectorAll("[data-delivery-for]").forEach((el) => {
      el.hidden = !el.dataset.deliveryFor.split(" ").includes(select.value);
    });
  }

  document.addEventListener("change", (event) => {
    const select = event.target;
    if (select instanceof HTMLSelectElement && select.matches("[data-delivery-channel-select]")) {
      sync(select);
    }
  });
  document.querySelectorAll("[data-delivery-channel-select]").forEach(sync);
})();
