// Add/remove condition rows on the Notifications rule form
// (app/web/templates/notifications/rule_form.html) without a page reload.
// Progressive enhancement only — with JS disabled, a rule can still be
// saved with whatever rows it already has, and more conditions can be
// added by pasting YAML into the "…or as YAML" box below the rows (see
// wiki/Notifications.md's "Condition-based rules" section); nothing here
// is required to submit the form.
//
// Markup contract: a `[data-condition-add]` button and a `<template
// data-condition-row-template>` both live inside the same
// `[data-condition-rows]` wrapper as the row list `[data-condition-row-list]`
// and an optional `[data-condition-empty]` "no conditions yet" hint; each
// row carries `data-condition-row` and its own remove button carries
// `data-condition-remove`.
document.addEventListener("click", (event) => {
  const addButton = event.target.closest("[data-condition-add]");
  if (addButton) {
    event.preventDefault();
    const wrapper = addButton.closest("[data-condition-rows]");
    const list = wrapper && wrapper.querySelector("[data-condition-row-list]");
    const rowTemplate = wrapper && wrapper.querySelector("template[data-condition-row-template]");
    if (list && rowTemplate) {
      list.appendChild(rowTemplate.content.cloneNode(true));
    }
    const emptyHint = wrapper && wrapper.querySelector("[data-condition-empty]");
    if (emptyHint) emptyHint.hidden = true;
    return;
  }
  const removeButton = event.target.closest("[data-condition-remove]");
  if (removeButton) {
    event.preventDefault();
    const row = removeButton.closest("[data-condition-row]");
    if (row) row.remove();
  }
});
