// Auto-submit a form when one of its fields changes, without an inline
// `onchange="..."` attribute (the CSP here has no 'unsafe-inline' for
// script-src, so that attribute is silently ignored by the browser — same
// issue confirm.js documents for `onsubmit`). Add `data-autosubmit` to any
// <select>/<input> whose <form> should submit as soon as its value changes
// (e.g. the Monitoring tab's time-range picker) instead.
document.addEventListener("change", (event) => {
  const field = event.target;
  if (!field || !field.dataset || !("autosubmit" in field.dataset)) return;
  if (field.form) field.form.submit();
});
