// "Select all" checkbox for bulk-action tables (the machine list, the user
// list, ...): toggles every other checkbox inside the same <form> — not
// tied to one specific `name`, so the same script covers any bulk-actions
// form's own selection checkboxes. Kept as an external script, not an
// inline handler — the CSP here has no 'unsafe-inline' for script-src.
document.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || !target.matches("[data-select-all]")) return;
  const form = target.closest("form");
  if (!form) return;
  for (const checkbox of form.querySelectorAll('input[type="checkbox"]:not([data-select-all])')) {
    checkbox.checked = target.checked;
  }
});
