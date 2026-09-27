// Interactivity for the Monitoring tab's charts (markup from
// macros/charts.html's `render_chart`, geometry from app/web/charts.py).
// Each `.chart[data-chart]` carries JSON: {fmt, stacked, t: [time labels],
// s: [{label, color, v: [values or null]}]}.
//
//  - hover: a cursor line plus a tooltip listing every visible series'
//    value at that point (highest first), built with textContent — labels
//    are sensor/container names reported by the managed machine;
//  - legend buttons toggle a series on/off;
//  - a card's `[data-chart-filter]` box shows only series whose label
//    contains the typed text.
//
// Also: `[data-table-filter]` / `th[data-sort]` for the Monitoring tab's
// tables (services, containers, S.M.A.R.T.) — client-side, since the whole
// table is already on the page.

(function () {
  const UNITS = ["B", "KB", "MB", "GB", "TB"];

  function trim(value, decimals) {
    let text = value.toFixed(decimals);
    if (text.includes(".")) text = text.replace(/0+$/, "").replace(/\.$/, "");
    return text || "0";
  }

  function number(value) {
    const m = Math.abs(value);
    if (m >= 100) return trim(value, 0);
    if (m >= 10) return trim(value, 1);
    if (m >= 1) return trim(value, 2);
    return trim(value, 3);
  }

  function bytes(value, suffix) {
    let v = value;
    let i = 0;
    while (Math.abs(v) >= 1024 && i < UNITS.length - 1) {
      v /= 1024;
      i += 1;
    }
    return `${number(v)} ${UNITS[i]}${suffix}`;
  }

  function formatValue(value, fmt) {
    if (value === null || value === undefined) return "—";
    switch (fmt) {
      case "percent": return `${number(value)}%`;
      case "bytes": return bytes(value, "");
      case "bytes_rate": return bytes(value, "/s");
      case "celsius": return `${number(value)} °C`;
      case "watts": return `${number(value)} W`;
      case "rpm": return trim(value, 0);
      case "ms": return `${number(value)} ms`;
      default: return number(value);
    }
  }

  function setUpChart(el) {
    let data;
    try {
      data = JSON.parse(el.dataset.chart || "{}");
    } catch {
      return;
    }
    const times = data.t || [];
    const series = data.s || [];
    if (times.length === 0) return;

    const svg = el.querySelector(".chart-svg");
    const cursor = el.querySelector(".chart-cursor");
    const tooltip = el.querySelector(".chart-tooltip");
    if (!svg || !cursor || !tooltip) return;
    // Series the server marked as noise start switched off (`h`).
    const defaultHidden = new Set(data.h || []);
    const hidden = new Set(defaultHidden);

    function applyVisibility() {
      el.querySelectorAll(".chart-series").forEach((g) => {
        g.classList.toggle("is-hidden", hidden.has(Number(g.dataset.series)));
      });
      el.querySelectorAll("[data-series-toggle]").forEach((btn) => {
        const off = hidden.has(Number(btn.dataset.seriesToggle));
        btn.classList.toggle("is-off", off);
        btn.setAttribute("aria-pressed", off ? "false" : "true");
      });
    }

    el.addEventListener("click", (event) => {
      const all = event.target.closest("[data-series-show-all]");
      if (all && el.contains(all)) {
        const showing = all.getAttribute("aria-pressed") === "true";
        hidden.clear();
        if (showing) defaultHidden.forEach((i) => hidden.add(i));
        all.setAttribute("aria-pressed", showing ? "false" : "true");
        all.textContent = showing ? all.dataset.labelShow : all.dataset.labelHide;
        applyVisibility();
        return;
      }
      const btn = event.target.closest("[data-series-toggle]");
      if (!btn || !el.contains(btn)) return;
      const idx = Number(btn.dataset.seriesToggle);
      if (hidden.has(idx)) hidden.delete(idx);
      else hidden.add(idx);
      applyVisibility();
    });

    el.chartFilter = (query) => {
      const q = query.trim().toLowerCase();
      hidden.clear();
      if (q) {
        series.forEach((s, i) => {
          if (!String(s.label).toLowerCase().includes(q)) hidden.add(i);
        });
      } else {
        defaultHidden.forEach((i) => hidden.add(i));
      }
      applyVisibility();
    };

    applyVisibility();

    function indexAt(clientX) {
      const rect = svg.getBoundingClientRect();
      if (rect.width <= 0 || times.length === 1) return 0;
      const fraction = Math.min(Math.max((clientX - rect.left) / rect.width, 0), 1);
      return Math.round(fraction * (times.length - 1));
    }

    function show(idx) {
      const x = times.length === 1 ? 500 : (idx * 1000) / (times.length - 1);
      cursor.setAttribute("x1", String(x));
      cursor.setAttribute("x2", String(x));
      cursor.hidden = false;

      const rows = series
        .map((s, i) => ({ s, i, v: s.v[idx] }))
        .filter((row) => !hidden.has(row.i) && row.v !== null && row.v !== undefined);
      if (!data.stacked) rows.sort((a, b) => b.v - a.v);

      tooltip.replaceChildren();
      const head = document.createElement("div");
      head.className = "chart-tooltip-time";
      head.textContent = times[idx];
      tooltip.appendChild(head);
      rows.forEach(({ s, v }) => {
        const row = document.createElement("div");
        row.className = "chart-tooltip-row";
        const swatch = document.createElement("span");
        swatch.className = "chart-tooltip-swatch";
        swatch.style.background = s.color;
        const label = document.createElement("span");
        label.className = "chart-tooltip-label";
        label.textContent = s.label;
        const value = document.createElement("span");
        value.className = "chart-tooltip-value";
        value.textContent = formatValue(v, data.fmt);
        row.append(swatch, label, value);
        tooltip.appendChild(row);
      });
      if (rows.length === 0) {
        const none = document.createElement("div");
        none.textContent = "—";
        tooltip.appendChild(none);
      }
      tooltip.hidden = false;

      const fraction = times.length > 1 ? idx / (times.length - 1) : 0.5;
      if (fraction > 0.55) {
        tooltip.style.left = "auto";
        tooltip.style.right = `${(1 - fraction) * 100 + 1}%`;
      } else {
        tooltip.style.right = "auto";
        tooltip.style.left = `${fraction * 100 + 1}%`;
      }
    }

    function hide() {
      cursor.hidden = true;
      tooltip.hidden = true;
    }

    svg.addEventListener("pointermove", (event) => show(indexAt(event.clientX)));
    svg.addEventListener("pointerleave", hide);
  }

  document.querySelectorAll(".chart[data-chart]").forEach(setUpChart);

  document.addEventListener("input", (event) => {
    const box = event.target.closest("[data-chart-filter]");
    if (!box) return;
    const card = box.closest(".chart-card");
    if (!card) return;
    card.querySelectorAll(".chart[data-chart]").forEach((el) => {
      if (typeof el.chartFilter === "function") el.chartFilter(box.value);
    });
  });

  // --- Tables: filter box, row-state select, sortable headers ---
  // A row is shown when it contains the typed text *and* its
  // `data-row-state` is one of the select's space-separated values (an
  // empty value = every state). Rows without a state ignore the select.
  function filterTable(id) {
    const table = document.getElementById(id);
    if (!table) return;
    const box = document.querySelector(`[data-table-filter="${id}"]`);
    const select = document.querySelector(`[data-row-state-filter="${id}"]`);
    const q = box ? box.value.trim().toLowerCase() : "";
    const states = select && select.value ? select.value.split(" ") : null;
    table.querySelectorAll("tbody tr").forEach((tr) => {
      const textOk = q === "" || tr.textContent.toLowerCase().includes(q);
      const state = tr.dataset.rowState;
      const stateOk = !states || !state || states.includes(state);
      tr.hidden = !(textOk && stateOk);
    });
  }

  document.addEventListener("input", (event) => {
    const box = event.target.closest("[data-table-filter]");
    if (box) filterTable(box.dataset.tableFilter);
  });
  document.addEventListener("change", (event) => {
    const select = event.target.closest("[data-row-state-filter]");
    if (select) filterTable(select.dataset.rowStateFilter);
  });

  document.addEventListener("click", (event) => {
    const th = event.target.closest("th[data-sort]");
    if (!th) return;
    const table = th.closest("table");
    const tbody = table && table.tBodies[0];
    if (!tbody) return;
    const index = Array.from(th.parentElement.children).indexOf(th);
    const numeric = th.dataset.sort === "number";
    const ascending = th.getAttribute("aria-sort") !== "ascending";
    table.querySelectorAll("th[data-sort]").forEach((h) => h.removeAttribute("aria-sort"));
    th.setAttribute("aria-sort", ascending ? "ascending" : "descending");
    const key = (tr) => {
      const cell = tr.children[index];
      const raw = cell ? cell.dataset.sortValue ?? cell.textContent.trim() : "";
      if (!numeric) return raw.toLowerCase();
      const n = Number.parseFloat(raw);
      return Number.isNaN(n) ? -Infinity : n;
    };
    const rows = Array.from(tbody.rows);
    rows.sort((a, b) => {
      const ka = key(a);
      const kb = key(b);
      if (ka < kb) return ascending ? -1 : 1;
      if (ka > kb) return ascending ? 1 : -1;
      return 0;
    });
    tbody.append(...rows);
  });
})();
