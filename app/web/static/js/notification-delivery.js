// Shows/hides the webhook URL field on the Notifications rule form
// (app/web/templates/notifications/rule_form.html) based on the selected
// delivery channel — progressive enhancement only: with JS disabled, the
// field just stays visible and unused when "Email" is selected, which is
// harmless (the server only reads it for a "webhook" rule).
document.addEventListener("change", (event) => {
  const select = event.target;
  if (!(select instanceof HTMLSelectElement) || !select.matches("[data-delivery-channel-select]")) {
    return;
  }
  const field = select.closest("form")?.querySelector("[data-delivery-webhook-field]");
  if (field instanceof HTMLElement) {
    field.hidden = select.value !== "webhook";
  }
});
