from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.web.charts import build_chart, format_value, nice_range

_TS = [datetime(2026, 9, 23, 19, 30, tzinfo=UTC) + timedelta(minutes=2 * i) for i in range(10)]


def test_format_value_per_format():
    assert format_value(3.456, "percent") == "3.46%"
    assert format_value(1536, "bytes") == "1.5 KB"
    assert format_value(12 * 1024, "bytes_rate") == "12 KB/s"
    assert format_value(44.0, "celsius") == "44 °C"
    assert format_value(3.2, "watts") == "3.2 W"
    assert format_value(1409.4, "rpm") == "1409"
    assert format_value(None, "percent") == "—"


def test_nice_range_rounds_to_friendly_ticks():
    assert nice_range(0, 3.3, "percent") == (0.0, 4.0, 1.0)
    lo, hi, step = nice_range(0, 900 * 1024**2, "bytes")
    assert (lo, hi, step) == (0.0, 1000 * 1024**2, 250 * 1024**2)


def test_percent_axis_autoscales_but_never_past_100():
    low = build_chart([("cpu", [1.0, 3.2] * 5)], _TS, fmt="percent")
    high = build_chart([("cpu", [90.0, 99.0] * 5)], _TS, fmt="percent")

    assert low.y_ticks[0] == "4%"
    assert high.y_ticks[0] == "100%"
    assert low.y_ticks[-1] == high.y_ticks[-1] == "0%"


def test_flat_series_without_zero_base_gets_a_readable_axis():
    chart = build_chart([("fan1", [1409.0] * 10)], _TS, fmt="rpm", zero_based=False)

    assert chart.y_ticks == ["1411", "1410", "1409", "1408", "1407"]


def test_gaps_split_a_series_into_separate_paths():
    values = [1.0, 2.0, None, None, 3.0, 4.0, 5.0, None, 1.0, 2.0]

    chart = build_chart([("x", values)], _TS, fmt="number")

    assert len(chart.series[0].line_paths) == 3
    assert chart.series[0].values[2] is None


def test_stacked_areas_sit_on_top_of_each_other():
    chart = build_chart(
        [("a", [1.0] * 10), ("b", [2.0] * 10)], _TS, fmt="number", stacked=True
    )

    # The axis covers the stacked total (3), not the largest single series (2).
    assert chart.y_ticks[0] == "3"
    assert chart.stacked and chart.area
    assert len(chart.series[1].area_paths) == 1
    assert chart.series[1].area_paths[0].endswith("Z")
    # Tooltip data keeps each series' own value, not the running total.
    assert chart.data["s"][1]["v"][0] == 2.0


def test_many_series_are_lines_not_areas_by_default():
    chart = build_chart([(f"s{i}", [float(i)] * 10) for i in range(5)], _TS, fmt="celsius")

    assert not chart.area
    assert all(not s.area_paths for s in chart.series)


def test_threshold_outside_the_axis_is_dropped():
    inside = build_chart([("cpu", [10.0] * 10)], _TS, fmt="percent", fixed_max=100, threshold=90)
    outside = build_chart([("cpu", [10.0] * 10)], _TS, fmt="percent", fixed_max=100, threshold=150)

    assert inside.threshold_y is not None
    assert outside.threshold_y is None


def test_x_ticks_are_evenly_spread_time_labels():
    chart = build_chart(
        [("x", [1.0] * 10)], _TS, fmt="number", time_label=lambda dt, f: dt.strftime(f)
    )

    assert chart.x_ticks[0] == "19:30"
    assert chart.x_ticks[-1] == "19:48"
    assert len(chart.x_ticks) == 6


def test_empty_chart():
    chart = build_chart([("x", [None] * 10)], _TS, fmt="number")

    assert chart.empty
