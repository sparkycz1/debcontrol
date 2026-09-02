// Hover/scrub interactivity for the Monitoring tab's charts (see
// macros/charts.html's `trend_chart` macro, which renders the actual SVG
// and just embeds the data this reads via `data-*` attributes — no
// framework, no chart library, consistent with the rest of this app's
// dependency-free front end).
//
// Each `[data-chart]` wrapper carries:
//   data-timestamps  JSON array of ISO datetime strings, oldest first
//   data-series      JSON array of arrays (one per line), each the same
//                     length as data-timestamps; entries may be `null`
//   data-labels      JSON array of series labels, same order as data-series
//   data-unit        display suffix appended after each formatted number
//   data-bytes-rate  "true" if values are bytes/sec and should be
//                     formatted as KB/s-MB/s-GB/s rather than a raw number
//
// On pointer move over the chart, this finds the nearest sample by X
// position, draws a vertical guide line (the pre-existing but `hidden`
// `.trend-chart-cursor` line in the SVG) at that sample's X, and fills in
// the `.trend-chart-tooltip` div with its timestamp and each series'
// value. Touch works the same way via `pointermove`, which fires for both.

(function () {
  function formatBytesRate(value) {
    if (value === null || value === undefined) return "—";
    const units = ["B/s", "KB/s", "MB/s", "GB/s"];
    let v = value;
    let i = 0;
    while (Math.abs(v) >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function formatValue(value, unit, bytesRate) {
    if (value === null || value === undefined) return "—";
    if (bytesRate) return formatBytesRate(value);
    const rounded = Math.abs(value) >= 10 ? value.toFixed(0) : value.toFixed(1);
    return `${rounded}${unit}`;
  }

  function formatTimestamp(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  function setUp(wrap) {
    const svg = wrap.querySelector(".trend-chart-svg");
    const cursor = wrap.querySelector(".trend-chart-cursor");
    const tooltip = wrap.querySelector(".trend-chart-tooltip");
    if (!svg || !cursor || !tooltip) return;

    let timestamps, series, labels;
    try {
      timestamps = JSON.parse(wrap.dataset.timestamps || "[]");
      series = JSON.parse(wrap.dataset.series || "[]");
      labels = JSON.parse(wrap.dataset.labels || "[]");
    } catch {
      return; // malformed data — leave the static chart as-is, no crash
    }
    if (timestamps.length === 0) return;
    const unit = wrap.dataset.unit || "";
    const bytesRate = wrap.dataset.bytesRate === "true";

    const viewBox = svg.viewBox.baseVal;
    const [vbX, , vbWidth] = [viewBox.x, viewBox.y, viewBox.width];
    const pad = 14; // must match the macro's own default `pad`
    const step = timestamps.length > 1 ? (vbWidth - 2 * pad) / (timestamps.length - 1) : 0;

    function indexForClientX(clientX) {
      const rect = svg.getBoundingClientRect();
      const fraction = rect.width > 0 ? (clientX - rect.left) / rect.width : 0;
      const svgX = vbX + fraction * vbWidth;
      if (step === 0) return 0;
      const idx = Math.round((svgX - pad) / step);
      return Math.min(Math.max(idx, 0), timestamps.length - 1);
    }

    function showAt(idx) {
      const x = pad + idx * step;
      cursor.setAttribute("x1", String(x));
      cursor.setAttribute("x2", String(x));
      cursor.hidden = false;

      const lines = [`<strong>${formatTimestamp(timestamps[idx])}</strong>`];
      series.forEach((values, i) => {
        const label = labels[i] ? `${labels[i]}: ` : "";
        lines.push(`${label}${formatValue(values[idx], unit, bytesRate)}`);
      });
      tooltip.innerHTML = lines.join("<br>");
      tooltip.hidden = false;

      // Keep the tooltip inside the chart's own box — flip to the left of
      // the cursor once past the halfway point, rather than letting it
      // overflow the wrapper.
      const fraction = timestamps.length > 1 ? idx / (timestamps.length - 1) : 0;
      tooltip.style.left = fraction > 0.6 ? "auto" : `${fraction * 100}%`;
      tooltip.style.right = fraction > 0.6 ? `${(1 - fraction) * 100}%` : "auto";
    }

    function hide() {
      cursor.hidden = true;
      tooltip.hidden = true;
    }

    svg.addEventListener("pointermove", (event) => {
      showAt(indexForClientX(event.clientX));
    });
    svg.addEventListener("pointerleave", hide);
  }

  document.querySelectorAll("[data-chart]").forEach(setUp);
})();
