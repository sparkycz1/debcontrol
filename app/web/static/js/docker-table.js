// The Docker tab's tables (CSP-safe, no inline handlers):
//
//  - state tiles (`[data-state-tiles="<table id>"]`): a click picks the
//    state group to show and sets the table's `[data-row-state-filter]`
//    select, which monitoring-chart.js already filters by;
//  - a submit button's own `data-confirm` (several buttons share one
//    form under the containers table, each with its own question);
//  - `table[data-remember="<key>"]`: the filter text, the state picked and
//    the sorted column are kept in this browser (localStorage) and put
//    back on the next visit, and after an htmx panel re-renders;
//  - `table.table-cards`: each cell gets its column's name as
//    `data-label` (unless the template set one), which style.css shows
//    in front of the value when a narrow screen turns rows into cards.
//
// Storage is a convenience only: when the browser refuses it, the table
// simply starts unfiltered.

(function () {
  const PREFIX = "debcontrol.table.";

  function load(key) {
    try {
      const raw = window.localStorage.getItem(PREFIX + key);
      const value = raw ? JSON.parse(raw) : null;
      return value && typeof value === "object" ? value : {};
    } catch {
      return {};
    }
  }

  function save(key, patch) {
    try {
      const value = Object.assign(load(key), patch);
      window.localStorage.setItem(PREFIX + key, JSON.stringify(value));
    } catch {
      // Private window or storage turned off: nothing to keep.
    }
  }

  function rememberKey(tableId) {
    const table = document.getElementById(tableId);
    return table ? table.dataset.remember || null : null;
  }

  // --- State tiles ---
  function markTiles(group, state) {
    group.querySelectorAll("[data-state]").forEach((tile) => {
      tile.setAttribute("aria-pressed", tile.dataset.state === state ? "true" : "false");
    });
  }

  function setState(tableId, state) {
    const select = document.querySelector(`[data-row-state-filter="${tableId}"]`);
    if (select) {
      select.value = state;
      select.dispatchEvent(new Event("change", { bubbles: true }));
    }
    const group = document.querySelector(`[data-state-tiles="${tableId}"]`);
    if (group) markTiles(group, state);
  }

  document.addEventListener("click", (event) => {
    const tile = event.target.closest("[data-state-tiles] [data-state]");
    if (!tile) return;
    const group = tile.closest("[data-state-tiles]");
    const tableId = group.dataset.stateTiles;
    const state = tile.dataset.state || "";
    setState(tableId, state);
    const key = rememberKey(tableId);
    if (key) save(key, { state });
  });

  // --- A submit button's own confirmation ---
  document.addEventListener("submit", (event) => {
    const button = event.submitter;
    if (!button || !button.dataset || !button.dataset.confirm) return;
    if (!window.confirm(button.dataset.confirm)) event.preventDefault();
  });

  // --- Remembering filter, state and sort ---
  document.addEventListener("input", (event) => {
    const box = event.target.closest("[data-table-filter]");
    if (!box) return;
    const key = rememberKey(box.dataset.tableFilter);
    if (key) save(key, { filter: box.value });
  });

  document.addEventListener("click", (event) => {
    const th = event.target.closest("th[data-sort]");
    if (!th) return;
    const table = th.closest("table[data-remember]");
    if (!table) return;
    // monitoring-chart.js sorts in its own click handler; read the
    // outcome once it has run.
    window.setTimeout(() => {
      const index = Array.from(th.parentElement.children).indexOf(th);
      save(table.dataset.remember, {
        sort: index,
        dir: th.getAttribute("aria-sort") === "descending" ? "desc" : "asc",
      });
    }, 0);
  });

  function restore(table) {
    if (!table.id || table.dataset.restored === "1") return;
    table.dataset.restored = "1";
    const saved = load(table.dataset.remember);
    const box = document.querySelector(`[data-table-filter="${table.id}"]`);
    if (box && typeof saved.filter === "string" && saved.filter && !box.value) {
      box.value = saved.filter;
      box.dispatchEvent(new Event("input", { bubbles: true }));
    }
    if (typeof saved.state === "string" && saved.state) {
      const tile = document.querySelector(
        `[data-state-tiles="${table.id}"] [data-state="${CSS.escape(saved.state)}"]`,
      );
      // A state with no container any more has no tile: show everything.
      setState(table.id, tile ? saved.state : "");
    }
    if (Number.isInteger(saved.sort)) {
      const th = table.tHead && table.tHead.rows[0] && table.tHead.rows[0].children[saved.sort];
      if (th && th.matches("[data-sort]")) {
        th.click();
        if (saved.dir === "desc") th.click();
      }
    }
  }

  function labelCells(table) {
    const head = table.tHead && table.tHead.rows[0];
    if (!head) return;
    const labels = Array.from(head.children).map((th) => th.textContent.trim());
    Array.from(table.tBodies).forEach((body) => {
      Array.from(body.rows).forEach((tr) => {
        Array.from(tr.children).forEach((cell, index) => {
          if (!cell.hasAttribute("data-label") && labels[index]) {
            cell.setAttribute("data-label", labels[index]);
          }
        });
      });
    });
  }

  function restoreAll(root) {
    root.querySelectorAll("table.table-cards").forEach(labelCells);
    root.querySelectorAll("table[data-remember]").forEach(restore);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => restoreAll(document));
  } else {
    restoreAll(document);
  }
  document.body.addEventListener("htmx:afterSwap", (event) => {
    const target = event.target;
    if (target && typeof target.querySelectorAll === "function") restoreAll(target);
  });
})();
