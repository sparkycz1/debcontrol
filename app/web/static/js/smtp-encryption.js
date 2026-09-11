// Fills in the conventional port for the newly-selected SMTP encryption
// mode (25/none, 587/STARTTLS, 465/SSL-TLS) as soon as it's changed — still
// a plain number input the admin can overwrite afterward, this just saves
// looking the default up. CSP-safe (no inline script/onXXX), same
// event-delegation + data-attribute convention as model-picker.js:
// `data-smtp-encryption` names the port `<input>`'s id, and
// `data-port-defaults` carries the {encryption: port} map as JSON so this
// stays generic rather than hardcoding SMTP specifics here.
document.addEventListener("change", (event) => {
  const select = event.target;
  if (!(select instanceof HTMLSelectElement) || !select.matches("[data-smtp-encryption]")) return;
  const portField = document.getElementById(select.dataset.smtpEncryption);
  if (!(portField instanceof HTMLInputElement)) return;
  let defaults;
  try {
    defaults = JSON.parse(select.dataset.portDefaults || "{}");
  } catch {
    return;
  }
  const port = defaults[select.value];
  if (port !== undefined) portField.value = String(port);
});
