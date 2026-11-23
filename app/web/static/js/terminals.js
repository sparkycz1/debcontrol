// The Terminals page (/terminals, app/web/routes/terminals.py): several
// machines' terminals at once, as tabs or a grid. Each pane is a clone of
// partials/terminal.html's pane, wired up by terminal.js's
// `DebcontrolTerminal.create`. Adding or closing a pane never reloads the
// page, so the other sessions keep running; the address keeps the panes
// (`?m=<id>&m=<id>&layout=grid`) so a reload or a bookmark opens them again.
(function () {
  "use strict";

  const board = document.getElementById("terminals-board");
  const tabs = document.getElementById("terminals-tabs");
  const template = document.getElementById("terminals-pane-template");
  const empty = document.getElementById("terminals-empty");
  const select = document.getElementById("terminals-machine");
  const addButton = document.getElementById("terminals-add");
  if (!board || !template || !window.DebcontrolTerminal) return;

  let i18n = {};
  try {
    i18n = JSON.parse(document.getElementById("js-i18n").textContent);
  } catch {
    i18n = {};
  }
  const tr = (key, fallback) => i18n[key] || fallback;

  const max = parseInt(board.dataset.max || "8", 10);
  const panes = []; // {id, machineId, name, el, tab, terminal}
  let counter = 0;
  let active = null;

  function layout() {
    return board.classList.contains("is-grid") ? "grid" : "tabs";
  }

  function saveAddress() {
    const params = new URLSearchParams();
    panes.forEach((p) => params.append("m", p.machineId));
    params.set("layout", layout());
    history.replaceState(null, "", window.location.pathname + "?" + params.toString());
  }

  function refresh() {
    empty.hidden = panes.length > 0;
    tabs.hidden = layout() !== "tabs" || panes.length === 0;
    if (addButton) addButton.disabled = panes.length >= max;
    panes.forEach((p) => {
      const on = p === active;
      p.el.classList.toggle("is-active", on);
      p.tab.setAttribute("aria-selected", on ? "true" : "false");
      p.tab.tabIndex = on ? 0 : -1;
    });
  }

  function activate(pane) {
    active = pane;
    refresh();
    if (pane) {
      pane.terminal.refit();
      pane.terminal.focus();
    }
  }

  function label(name) {
    // The same machine twice gets "web1 (2)".
    const same = panes.filter((p) => p.name === name).length;
    return same ? name + " (" + (same + 1) + ")" : name;
  }

  function closePane(pane) {
    const index = panes.indexOf(pane);
    if (index < 0) return;
    pane.terminal.dispose();
    pane.el.remove();
    pane.tab.remove();
    panes.splice(index, 1);
    if (active === pane) active = panes[Math.min(index, panes.length - 1)] || null;
    activate(active);
    saveAddress();
  }

  function addPane(machineId, name) {
    if (panes.length >= max) return;
    counter += 1;
    const fragment = template.content.cloneNode(true);
    const el = fragment.querySelector(".terminal-pane");
    const id = "terminal-pane-" + counter;
    const title = label(name);
    el.id = id;
    el.setAttribute("role", "tabpanel");
    el.querySelector("[data-terminal-title]").textContent = title;

    const close = document.createElement("button");
    close.type = "button";
    close.className = "button button-secondary log-small-button";
    close.textContent = tr("terminals.close", "Close");
    el.querySelector(".terminal-pane-bar").appendChild(close);

    const tab = document.createElement("button");
    tab.type = "button";
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-controls", id);
    tab.textContent = title;
    tabs.appendChild(tab);
    board.appendChild(fragment);

    const pane = { machineId: machineId, name: name, el: el, tab: tab, terminal: null };
    panes.push(pane);
    active = pane;
    refresh(); // visible before xterm.js measures it
    pane.terminal = window.DebcontrolTerminal.create(el, {
      wsPath: "/machines/" + encodeURIComponent(machineId) + "/terminal/ws",
    });
    tab.addEventListener("click", () => activate(pane));
    close.addEventListener("click", () => closePane(pane));
    activate(pane);
    saveAddress();
  }

  function setLayout(value) {
    board.classList.toggle("is-grid", value === "grid");
    board.classList.toggle("is-tabs", value !== "grid");
    document.querySelectorAll("[data-layout]").forEach((b) => {
      b.setAttribute("aria-pressed", b.dataset.layout === value ? "true" : "false");
    });
    refresh();
    panes.forEach((p) => p.terminal.refit());
    saveAddress();
  }

  document.querySelectorAll("[data-layout]").forEach((b) => {
    b.addEventListener("click", () => setLayout(b.dataset.layout));
  });

  if (addButton && select) {
    addButton.addEventListener("click", () => {
      const option = select.options[select.selectedIndex];
      if (option) addPane(option.value, option.textContent);
    });
  }

  // Arrow keys move between tabs (WAI-ARIA tabs pattern).
  tabs.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    const index = panes.indexOf(active);
    if (index < 0) return;
    const next = panes[(index + (event.key === "ArrowRight" ? 1 : panes.length - 1)) % panes.length];
    activate(next);
    next.tab.focus();
    event.preventDefault();
  });

  let initial = [];
  try {
    initial = JSON.parse(document.getElementById("terminals-initial").textContent) || [];
  } catch {
    initial = [];
  }
  initial.forEach((m) => addPane(m.id, m.name));
  if (panes.length) activate(panes[0]);
  refresh();
})();
