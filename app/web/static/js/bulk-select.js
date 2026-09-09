// "Select all" checkbox for bulk-action tables (the machine list, the user
// list, ...): toggles every same-named checkbox inside the same <form>.
// The name to toggle comes from the checkbox's own `data-select-all`
// value (e.g. `data-select-all="user_ids"`), not a hardcoded/heuristic
// selector, so the same script works for any bulk-select table this app
// adds without risking one page's "select all" also grabbing an unrelated
// checkbox that happens to share its form (a plain `:not([data-select-
// all])` selector would). Kept as an external script, not an inline
// handler — the CSP here has no 'unsafe-inline' for script-src.
document.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || !target.matches("[data-select-all]")) return;
  const form = target.closest("form");
  if (!form) return;
  const name = target.getAttribute("data-select-all");
  if (!name) return;
  for (const checkbox of form.querySelectorAll(`input[name="${name}"]`)) {
    checkbox.checked = target.checked;
  }
});
