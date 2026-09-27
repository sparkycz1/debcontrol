// Scheduled task form: show only the selected action's description and
// options (everything is visible without JavaScript). A hidden option is
// also disabled, so it isn't submitted — the server ignores options of
// other actions anyway (`_action_params_from_form`).
(function () {
  const select = document.querySelector("[data-schedule-action]");
  if (!select) return;
  const form = select.closest("form");

  function sync() {
    form.querySelectorAll("[data-for-action]").forEach((el) => {
      const active = el.dataset.forAction === select.value;
      el.hidden = !active;
      el.querySelectorAll("input, select, textarea").forEach((field) => {
        field.disabled = !active;
      });
    });
    form.querySelectorAll(".schedule-param-owner").forEach((el) => {
      el.hidden = true;
    });
  }

  select.addEventListener("change", sync);
  sync();
})();
