// Confirmation dialog for destructive forms, without inline event handlers
// (the CSP here has no 'unsafe-inline' for script-src, so `onsubmit="..."`
// attributes are silently ignored by the browser — this is the CSP-safe
// equivalent: add `data-confirm="Some question?"` to a <form>).
document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  const message = form.dataset.confirm;
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});
