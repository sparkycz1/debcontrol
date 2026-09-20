// "Auto-confirm further commands in this conversation" — see
// partials/ai_messages_panel.html's own comment for why this exists and
// its safety scoping (only ever offered after a human has already
// confirmed one command here by hand).
//
// Purely client-side and per-browser-tab: `sessionStorage`, namespaced by
// conversation id, so it never survives closing the tab and never leaks
// into a different conversation. Turning this on never changes anything
// server-side or weakens the confirm route itself
// (app/web/routes/ai.py's confirm_action, the one place a proposed
// command actually runs) — it only means this script submits the exact
// same "Confirm and run" form (CSRF token included) a human would
// otherwise click, the moment a new pending action shows up while the
// toggle is on. Switching it off — or just closing the tab, or opening a
// different conversation — stops that immediately; nothing here is a
// persisted account setting.
const STORAGE_PREFIX = "ai-auto-confirm:";

function storageKey(conversationId) {
  return STORAGE_PREFIX + conversationId;
}

function isEnabled(conversationId) {
  try {
    return sessionStorage.getItem(storageKey(conversationId)) === "1";
  } catch {
    return false;
  }
}

function setEnabled(conversationId, enabled) {
  try {
    if (enabled) {
      sessionStorage.setItem(storageKey(conversationId), "1");
    } else {
      sessionStorage.removeItem(storageKey(conversationId));
    }
  } catch {
    // Storage unavailable (private browsing, etc.) — the toggle just
    // won't persist across a poll; every sync() call re-applies it from
    // whatever state a later call *can* read, so this fails safe (stays
    // off, never silently "on" with nothing to show for it).
  }
}

// The confirm form also carries `data-confirm="..."` (confirm.js's own
// native window.confirm() safety dialog, for a *manual* click) — a real
// DOM `submit` (including `form.requestSubmit()`) would still trigger
// that popup even here, defeating the entire point of "auto". A plain
// `fetch()` POST never dispatches a `submit` event at all, so confirm.js
// never sees it; the explicit, persistently-visible red banner above is
// this path's own, deliberately different consent gate instead.
async function autoConfirm(root, form) {
  const conversationId = root.dataset.conversationId;
  try {
    await fetch(form.action, { method: "POST", body: new FormData(form) });
  } catch {
    // Network hiccup — harmless: the next poll's sync() call finds the
    // same still-pending action and tries again.
    return;
  }
  window.location.href = `/ai/conversations/${conversationId}`;
}

function sync(root) {
  const conversationId = root.dataset.conversationId;
  if (!conversationId) return;
  const enabled = isEnabled(conversationId);

  const toggle = root.querySelector("[data-ai-auto-confirm-toggle]");
  if (toggle) toggle.checked = enabled;
  if (!enabled) return;

  // Only the *first* still-pending confirm form ever needs submitting:
  // confirm_action redirects the whole page on success, so there's never
  // a second one left in the same DOM to also submit in this same pass.
  const form = root.querySelector("[data-ai-confirm-form]");
  if (form instanceof HTMLFormElement) autoConfirm(root, form);
}

document.addEventListener("change", (event) => {
  const toggle = event.target;
  if (!(toggle instanceof HTMLInputElement) || !("aiAutoConfirmToggle" in toggle.dataset)) return;
  const root = toggle.closest("[data-ai-auto-confirm-root]");
  if (!root) return;
  setEnabled(root.dataset.conversationId, toggle.checked);
  sync(root);
});

function syncAll() {
  for (const root of document.querySelectorAll("[data-ai-auto-confirm-root]")) {
    sync(root);
  }
}

// Re-run on every htmx swap rather than trying to pin down exactly which
// DOM node `htmx:afterSwap` hands back — an `outerHTML` swap replaces
// `#ai-messages-panel` wholesale, and there's only ever the one
// auto-confirm root on this page anyway.
document.addEventListener("htmx:afterSwap", syncAll);

syncAll();
