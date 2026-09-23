"""Server-side geometry for the Monitoring tab's charts — smooth (monotone
cubic) lines, filled or stacked areas, "nice" Y-axis ticks and evenly
spaced time labels. The template (`macros/charts.html`) only lays the
result out; `static/js/monitoring-chart.js` adds hover, legend toggling
and the series filter on top.

The SVG uses a fixed 1000x100 viewBox stretched to its box
(`preserveAspectRatio="none"`, strokes kept crisp with
`vector-effect="non-scaling-stroke"`), so no text lives inside it — axis
labels are plain HTML laid out by flexbox (`space-between` over evenly
spaced ticks lines them up with the grid exactly, with no inline style the
CSP would block).
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

VIEW_WIDTH = 1000.0
VIEW_HEIGHT = 100.0

PALETTE = (
    "#5b8fff",
    "#46bf8a",
    "#f0a33c",
    "#f0685f",
    "#a970ff",
    "#38bdf8",
    "#f472b6",
    "#facc15",
    "#2dd4bf",
    "#a3e635",
    "#fb7185",
    "#818cf8",
)

# Every value format the charts (and their tooltips, see
# monitoring-chart.js's formatValue, which mirrors this) understand.
FORMATS = ("percent", "bytes", "bytes_rate", "celsius", "watts", "rpm", "ms", "number")

_BYTE_UNITS = ("B", "KB", "MB", "GB", "TB")


def _trim(value: float, decimals: int) -> str:
    text = f"{value:.{decimals}f}"
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def _number(value: float) -> str:
    magnitude = abs(value)
    if magnitude >= 100:
        return _trim(value, 0)
    if magnitude >= 10:
        return _trim(value, 1)
    if magnitude >= 1:
        return _trim(value, 2)
    return _trim(value, 3)


def format_bytes(value: float | None, suffix: str = "") -> str:
    if value is None:
        return "—"
    v = float(value)
    unit = 0
    while abs(v) >= 1024 and unit < len(_BYTE_UNITS) - 1:
        v /= 1024
        unit += 1
    return f"{_number(v)} {_BYTE_UNITS[unit]}{suffix}"


def format_value(value: float | None, fmt: str) -> str:
    """One number the way its chart's axis/tooltip shows it."""
    if value is None:
        return "—"
    if fmt == "percent":
        return f"{_number(value)}%"
    if fmt == "bytes":
        return format_bytes(value)
    if fmt == "bytes_rate":
        return format_bytes(value, "/s")
    if fmt == "celsius":
        return f"{_number(value)} °C"
    if fmt == "watts":
        return f"{_number(value)} W"
    if fmt == "rpm":
        return _trim(value, 0)
    if fmt == "ms":
        return f"{_number(value)} ms"
    return _number(value)


def _nice_step(raw_step: float) -> float:
    if raw_step <= 0:
        return 1.0
    magnitude = 10.0 ** math.floor(math.log10(raw_step))
    for multiplier in (1, 2, 2.5, 5, 10):
        if multiplier * magnitude >= raw_step:
            return multiplier * magnitude
    return 10 * magnitude


def nice_range(lo: float, hi: float, fmt: str, *, intervals: int = 4) -> tuple[float, float, float]:
    """`(axis_min, axis_max, step)` covering `[lo, hi]` with round numbers —
    on a 1024-based scale for byte formats, so ticks land on "256 MB",
    not "268.4 MB"."""
    if hi <= lo:
        if fmt in ("bytes", "bytes_rate"):
            pad = abs(hi) * 0.1 or 1024.0
        else:
            pad = max(abs(hi) * 0.001, 1.0)
        lo, hi = (lo - pad if lo != 0 else 0.0), hi + pad
    scale = 1.0
    if fmt in ("bytes", "bytes_rate") and hi > 0:
        scale = 1024 ** min(math.floor(math.log(max(hi, 1), 1024)), len(_BYTE_UNITS) - 1)
    step = _nice_step((hi - lo) / scale / intervals) * scale
    axis_min = math.floor(lo / step) * step
    axis_max = math.ceil(hi / step) * step
    if axis_max <= axis_min:
        axis_max = axis_min + step
    return axis_min, axis_max, step


Point = tuple[float, float]
Segment = tuple[Point, Point, Point, Point]


def _monotone_segments(points: Sequence[Point]) -> list[Segment]:
    """Fritsch-Carlson monotone cubic interpolation as Bézier segments —
    smooth like the reference design, but never overshooting past a data
    point (a spike to 50% never draws a curve dipping below 0%)."""
    n = len(points)
    if n < 2:
        return []
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    dx = [xs[i + 1] - xs[i] for i in range(n - 1)]
    slopes = [(ys[i + 1] - ys[i]) / dx[i] if dx[i] else 0.0 for i in range(n - 1)]
    tangents = [0.0] * n
    tangents[0] = slopes[0]
    tangents[-1] = slopes[-1]
    for i in range(1, n - 1):
        if slopes[i - 1] * slopes[i] <= 0:
            tangents[i] = 0.0
        else:
            tangents[i] = (slopes[i - 1] + slopes[i]) / 2
    for i in range(n - 1):
        if slopes[i] == 0:
            tangents[i] = tangents[i + 1] = 0.0
            continue
        a, b = tangents[i] / slopes[i], tangents[i + 1] / slopes[i]
        h = a * a + b * b
        if h > 9:
            t = 3 / math.sqrt(h)
            tangents[i] = t * a * slopes[i]
            tangents[i + 1] = t * b * slopes[i]
    segments: list[Segment] = []
    for i in range(n - 1):
        third = dx[i] / 3
        segments.append(
            (
                points[i],
                (xs[i] + third, ys[i] + tangents[i] * third),
                (xs[i + 1] - third, ys[i + 1] - tangents[i + 1] * third),
                points[i + 1],
            )
        )
    return segments


def _p(point: Point) -> str:
    return f"{point[0]:.1f} {point[1]:.2f}"


def _curve(points: Sequence[Point], *, move: bool = True) -> str:
    if len(points) == 1:
        (x, y) = points[0]
        start = f"M {_p((x - 3, y))}" if move else f"L {_p((x - 3, y))}"
        return f"{start} L {_p((x + 3, y))}"
    parts = [f"M {_p(points[0])}" if move else f"L {_p(points[0])}"]
    for _p0, c1, c2, p1 in _monotone_segments(points):
        parts.append(f"C {_p(c1)} {_p(c2)} {_p(p1)}")
    return " ".join(parts)


def _runs(defined: Sequence[bool]) -> list[range]:
    runs: list[range] = []
    start: int | None = None
    for i, ok in enumerate(defined):
        if ok and start is None:
            start = i
        elif not ok and start is not None:
            runs.append(range(start, i))
            start = None
    if start is not None:
        runs.append(range(start, len(defined)))
    return runs


@dataclass
class ChartSeries:
    label: str
    color: str
    values: list[float | None]
    line_paths: list[str] = field(default_factory=list)
    area_paths: list[str] = field(default_factory=list)


@dataclass
class Chart:
    series: list[ChartSeries]
    fmt: str
    # Top → bottom, one per horizontal grid line.
    y_ticks: list[str]
    grid_y: list[float]
    # Left → right, evenly spaced across the plot.
    x_ticks: list[str]
    threshold_y: float | None
    threshold_label: str | None
    stacked: bool
    area: bool
    # Everything monitoring-chart.js needs for hover/filtering.
    data: dict[str, Any]

    @property
    def empty(self) -> bool:
        return not any(v is not None for s in self.series for v in s.values)


def _round_for_json(value: float | None) -> float | None:
    if value is None:
        return None
    if value == 0:
        return 0.0
    digits = max(0, 3 - math.floor(math.log10(abs(value))))
    return round(value, digits)


def build_chart(
    series: Sequence[tuple[str, Sequence[float | None]]],
    timestamps: Sequence[datetime],
    *,
    fmt: str = "number",
    fixed_max: float | None = None,
    zero_based: bool = True,
    stacked: bool = False,
    area: bool | None = None,
    threshold: float | None = None,
    threshold_label: str | None = None,
    colors: Sequence[str] | None = None,
    time_format: str = "%H:%M",
    time_label: Callable[[datetime, str], str] | None = None,
    x_tick_count: int = 6,
) -> Chart:
    """`series` is `[(label, values), ...]`, every `values` the same length
    as `timestamps` (a `None` is a gap). `fixed_max` pins the axis top
    (percent charts); `zero_based=False` fits the axis to the data instead
    of starting at 0 (temperatures, fan speeds — a flat 1409 RPM line
    should be readable, not pressed against the top of a 0-1500 axis).
    `stacked` stacks areas (per-container CPU/memory); `area` defaults to
    filled for stacked charts or up to three series, plain lines above
    that (twenty overlapping temperature fills would be mud)."""
    labels_fn = time_label or (lambda dt, f: dt.strftime(f))
    palette = list(colors) if colors else list(PALETTE)
    n = len(timestamps)
    prepared = [
        ChartSeries(
            label=label,
            color=palette[i % len(palette)],
            values=[None if v is None else float(v) for v in list(values)[:n]]
            + [None] * max(0, n - len(values)),
        )
        for i, (label, values) in enumerate(series)
    ]
    # A fill only means something down to a zero baseline — under a fitted
    # axis (temperatures, fans) it would just shade an arbitrary band.
    use_area = area if area is not None else (stacked or (zero_based and len(prepared) <= 3))

    # Stacked charts plot running totals; everything else plots raw values.
    if stacked:
        cumulative: list[list[float | None]] = []
        running = [0.0] * n
        defined_any = [any(s.values[i] is not None for s in prepared) for i in range(n)]
        for s in prepared:
            level: list[float | None] = []
            for i in range(n):
                if not defined_any[i]:
                    level.append(None)
                    continue
                running[i] += s.values[i] or 0.0
                level.append(running[i])
            cumulative.append(level)
        plotted = cumulative
    else:
        plotted = [s.values for s in prepared]

    finite = [v for values in plotted for v in values if v is not None]
    data_hi = max(finite) if finite else 1.0
    data_lo = min(finite) if finite else 0.0
    if threshold is not None:
        data_hi = max(data_hi, threshold)
        data_lo = min(data_lo, threshold)
    if fixed_max is not None:
        lo, hi = 0.0, float(fixed_max)
        step = hi / 4
    elif zero_based:
        lo, hi, step = nice_range(min(0.0, data_lo), max(data_hi, 0.0), fmt)
        if fmt == "percent" and hi > 100 >= data_hi:
            lo, hi, step = 0.0, 100.0, 25.0
    else:
        lo, hi, step = nice_range(data_lo, data_hi, fmt)
    span = (hi - lo) or 1.0

    def y_of(value: float) -> float:
        return VIEW_HEIGHT - (min(max(value, lo), hi) - lo) / span * VIEW_HEIGHT

    def x_of(index: int) -> float:
        return VIEW_WIDTH / 2 if n <= 1 else index * VIEW_WIDTH / (n - 1)

    previous_level: list[float | None] | None = None
    for s, values in zip(prepared, plotted, strict=True):
        for run in _runs([v is not None for v in values]):
            points = [(x_of(i), y_of(values[i] or 0.0)) for i in run]
            s.line_paths.append(_curve(points))
            if not use_area:
                continue
            if stacked and previous_level is not None:
                lower = [(x_of(i), y_of(previous_level[i] or 0.0)) for i in run]
                s.area_paths.append(
                    f"{_curve(points)} {_curve(list(reversed(lower)), move=False)} Z"
                )
            else:
                baseline = y_of(max(lo, 0.0) if lo <= 0 <= hi else lo)
                s.area_paths.append(
                    f"{_curve(points)} L {points[-1][0]:.1f} {baseline:.2f} "
                    f"L {points[0][0]:.1f} {baseline:.2f} Z"
                )
        previous_level = values

    tick_values: list[float] = []
    tick = hi
    while tick >= lo - step / 1000:
        tick_values.append(tick)
        tick -= step
    y_ticks = [format_value(round(v, 10), fmt) for v in tick_values]
    grid_y = [round(y_of(v), 2) for v in tick_values]

    x_ticks: list[str] = []
    if n >= 2:
        count = min(x_tick_count, n)
        indices = [round(i * (n - 1) / (count - 1)) for i in range(count)]
        x_ticks = [labels_fn(timestamps[i], time_format) for i in indices]
    elif n == 1:
        x_ticks = [labels_fn(timestamps[0], time_format)]

    threshold_y = y_of(threshold) if threshold is not None and lo <= threshold <= hi else None

    return Chart(
        series=prepared,
        fmt=fmt,
        y_ticks=y_ticks,
        grid_y=grid_y,
        x_ticks=x_ticks,
        threshold_y=threshold_y,
        threshold_label=threshold_label if threshold_y is not None else None,
        stacked=stacked,
        area=use_area,
        data={
            "fmt": fmt,
            "stacked": stacked,
            "t": [labels_fn(ts, "%d.%m. %H:%M") for ts in timestamps],
            "s": [
                {
                    "label": s.label,
                    "color": s.color,
                    "v": [_round_for_json(v) for v in s.values],
                }
                for s in prepared
            ],
        },
    )
