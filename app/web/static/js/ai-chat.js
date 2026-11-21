// The AI chat page (ai/conversation.html): newest message at the bottom
// and kept in view, the compose box below it, Enter to send.
//
// - Scroll: the chat scrolls inside `[data-ai-chat-scroll]`. On load it
//   jumps to the newest message. When the self-polling panel inside it
//   (partials/ai_messages_panel.html) is swapped, it follows the new
//   content only if the reader was already at (or near) the bottom, so
//   scrolling up to read something older is never yanked away.
// - Compose: disabled while a reply is coming (the panel's
//   `data-awaiting`), re-enabled by the swap that brings the reply. Enter
//   sends, Shift+Enter is a new line.
// - Copy buttons: `data-copy-text` (a proposed command) to the clipboard.
// - Pictures: the compose box's file input (`data-ai-attach`) lists the
//   chosen files; a picture pasted into the message box is added to it.
//   The server checks type and size again (app/services/ai_attachments.py).
//
// No inline script or style anywhere (CSP), only these listeners.

const NEAR_BOTTOM_PX = 120;
let followBottom = true;

function scrollBox() {
  return document.querySelector("[data-ai-chat-scroll]");
}

function toBottom(box) {
  box.scrollTop = box.scrollHeight;
}

function syncCompose() {
  const panel = document.querySelector("[data-ai-panel]");
  const form = document.querySelector("[data-ai-compose]");
  if (!panel || !form) return;
  const awaiting = panel.dataset.awaiting === "true";
  for (const field of form.querySelectorAll("textarea, button[type=submit], input[type=file]")) {
    field.disabled = awaiting;
  }
  const hint = form.querySelector("[data-ai-compose-hint]");
  if (hint) hint.textContent = awaiting ? hint.dataset.waiting : hint.dataset.idle;
}

document.addEventListener("DOMContentLoaded", () => {
  const box = scrollBox();
  if (!box) return;
  toBottom(box);
  box.addEventListener("scroll", () => {
    followBottom = box.scrollHeight - box.scrollTop - box.clientHeight < NEAR_BOTTOM_PX;
  });
  const textarea = document.querySelector("[data-ai-compose] textarea");
  if (textarea && !textarea.disabled) textarea.focus({ preventScroll: true });
});

document.addEventListener("htmx:afterSwap", (event) => {
  const box = scrollBox();
  if (!box || !box.contains(event.target)) return;
  if (followBottom) toBottom(box);
  syncCompose();
});

document.addEventListener("keydown", (event) => {
  const field = event.target;
  if (!(field instanceof HTMLTextAreaElement) || !field.closest("[data-ai-compose]")) return;
  if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
  event.preventDefault();
  const files = field.form.querySelector("[data-ai-attach]");
  const hasFiles = files && files.files && files.files.length > 0;
  if ((field.value.trim() || hasFiles) && !field.disabled) field.form.requestSubmit();
});

function showChosen(input) {
  const names = input.form && input.form.querySelector("[data-ai-attach-names]");
  if (!names) return;
  if (!names.dataset.idle) names.dataset.idle = names.textContent;
  const chosen = Array.from(input.files || []).map((file) => file.name || "image");
  names.textContent = chosen.length
    ? `${input.dataset.chosenLabel || ""} ${chosen.join(", ")}`.trim()
    : names.dataset.idle;
}

function setFiles(input, files) {
  const max = Number(input.dataset.max) || files.length;
  const transfer = new DataTransfer();
  for (const file of files.slice(0, max)) transfer.items.add(file);
  input.files = transfer.files;
  showChosen(input);
}

document.addEventListener("change", (event) => {
  const input = event.target;
  if (!(input instanceof HTMLInputElement) || !input.matches("[data-ai-attach]")) return;
  const max = Number(input.dataset.max) || 0;
  if (max && input.files.length > max) setFiles(input, Array.from(input.files));
  else showChosen(input);
});

document.addEventListener("paste", (event) => {
  const field = event.target;
  if (!(field instanceof HTMLTextAreaElement) || !field.closest("[data-ai-compose]")) return;
  const input = field.form.querySelector("[data-ai-attach]");
  const pasted = Array.from(event.clipboardData ? event.clipboardData.files : []).filter(
    (file) => file.type.startsWith("image/"),
  );
  if (!input || input.disabled || pasted.length === 0) return;
  event.preventDefault();
  setFiles(input, [...Array.from(input.files || []), ...pasted]);
});

document.addEventListener("submit", (event) => {
  // Disable the button once the message is on its way (no double send).
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.matches("[data-ai-compose]")) return;
  if (event.defaultPrevented) return;
  const button = form.querySelector("button[type=submit]");
  if (button) setTimeout(() => { button.disabled = true; }, 0);
});

document.addEventListener("click", async (event) => {
  const button = event.target instanceof Element ? event.target.closest("[data-copy-text]") : null;
  if (!button) return;
  try {
    await navigator.clipboard.writeText(button.dataset.copyText);
    const label = button.textContent;
    button.textContent = button.dataset.copiedLabel || label;
    setTimeout(() => { button.textContent = label; }, 1500);
  } catch {
    // No clipboard access (plain http): the command is selectable text.
  }
});
