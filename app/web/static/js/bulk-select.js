// "Select all" checkbox for bulk-action tables (e.g. the machine list):
// toggles every `machine_ids` checkbox inside the same <form>. Kept as an
// external script, not an inline handler — the CSP here has no
// 'unsafe-inline' for script-src.
document.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || !target.matches("[data-select-all]")) return;
  const form = target.closest("form");
  if (!form) return;
  for (const checkbox of form.querySelectorAll('input[name="machine_ids"]')) {
    checkbox.checked = target.checked;
  }
});
