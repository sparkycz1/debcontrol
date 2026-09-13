// "Select all" checkbox for bulk-action tables (the machine list, the user
// list, ...): toggles every same-named checkbox belonging to the same
// <form>. The name to toggle comes from the checkbox's own
// `data-select-all` value (e.g. `data-select-all="user_ids"`), not a
// hardcoded/heuristic selector, so the same script works for any
// bulk-select table this app adds without risking one page's "select
// all" also grabbing an unrelated checkbox that happens to share its
// form (a plain `:not([data-select-all])` selector would). Kept as an
// external script, not an inline handler — the CSP here has no
// 'unsafe-inline' for script-src.
//
// `.form` (the IDL property), not `.closest("form")`: a table that sits
// as a *sibling* of its <form> — associated via each control's own
// `form="<id>"` attribute rather than DOM nesting (see users/list.html's
// own comment on why: an actual per-row <form> for a different action
// needs to live inside the same table cell, and HTML forbids nesting a
// <form> inside another <form>) — has no ancestor <form> for `closest`
// to find, but `.form` resolves the same explicit attribute the browser
// already uses to decide what this checkbox submits with. For a
// checkbox that's genuinely still a DOM descendant of its <form> (no
// `form=` attribute set), `.form` falls back to exactly what
// `closest("form")` would have found, so this covers both cases.
document.addEventListener("change", (event) => {
  const target = event.target;
  if (!(target instanceof HTMLInputElement) || !target.matches("[data-select-all]")) return;
  const form = target.form;
  if (!form) return;
  const name = target.getAttribute("data-select-all");
  if (!name) return;
  // `document.querySelectorAll`, not `form.querySelectorAll` — the same
  // `form="<id>"` association above means a matching checkbox need not be
  // a DOM descendant of `form` either, so a form-scoped selector could
  // miss it. `.form === form` re-applies that same scoping check per
  // checkbox instead, so this still only ever touches this one form's
  // own checkboxes, not an unrelated same-named one elsewhere on the page.
  for (const checkbox of document.querySelectorAll(`input[name="${name}"]`)) {
    if (checkbox.form === form) checkbox.checked = target.checked;
  }
});
