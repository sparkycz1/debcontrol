// Live-filters a "Choose models" modal's checkbox list as you type — CSP-safe
// (no inline script/onXXX), same event-delegation convention as
// bulk-select.js. One search box per provider (data-model-search names the
// id of *that* provider's own model-list container), so filtering one
// provider's modal never touches another's.
document.addEventListener("input", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || !target.matches("[data-model-search]")) return;
  const list = document.getElementById(target.dataset.modelSearch);
  if (!list) return;
  const needle = target.value.trim().toLowerCase();
  for (const row of list.querySelectorAll("[data-model-row]")) {
    const label = row.dataset.modelRow || "";
    row.hidden = needle !== "" && !label.includes(needle);
  }
});
