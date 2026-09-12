// A live text filter above a long checkbox list — Notifications' user/role/
// machine/machine-group pickers (app/web/templates/notifications/rule_form.html)
// can each have hundreds of options at fleet scale, and scrolling a plain
// checkbox grid to find one isn't workable at that size.
//
// Markup contract: a search <input data-checklist-filter> immediately
// followed (anywhere inside the same `.checklist-filter-group` wrapper) by
// the checkbox grid, each option wrapped in a <label> that also carries the
// filterable text as its own content — nothing fancier needed since a
// <label>'s textContent already includes its checkbox's visible name.
// Hidden items use the `hidden` attribute (not inline `style`), same
// convention as everywhere else CSS depends on it.
document.addEventListener("input", (event) => {
  const field = event.target;
  if (!field || !field.dataset || !("checklistFilter" in field.dataset)) return;
  const group = field.closest(".checklist-filter-group");
  if (!group) return;
  const query = field.value.trim().toLowerCase();
  const labels = group.querySelectorAll("[data-checklist-items] label");
  let visibleCount = 0;
  labels.forEach((label) => {
    const matches = !query || label.textContent.toLowerCase().includes(query);
    label.hidden = !matches;
    if (matches) visibleCount += 1;
  });
  const emptyHint = group.querySelector("[data-checklist-empty]");
  if (emptyHint) emptyHint.hidden = visibleCount !== 0;
});
