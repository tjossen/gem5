#!/usr/bin/env python3
"""
Plot gem5 crypto multisim statistics.

The script uses crypto_prefetcher_sweep.csv as the experiment index and reads
the detailed metric values from each simulation's stats.txt. This makes it
easy to compare cache-level prefetcher configurations over hint trace lookback
distances.

Examples:
  python3 configs/crypto_multisim/plot_prefetch_stats.py \
      --benchmark sha256 \
      --metric ipc --metric l1d_misses --metric l1d_pf_useful \
      --l1d hint --l2 hint --l3 none \
      --trace-lookbacks 1-30 \
      --output plots/sha256_l1d_l2.svg

  python3 configs/crypto_multisim/plot_prefetch_stats.py \
      --benchmark sha256 \
      --metric l1d_accuracy --metric l1d_coverage \
      --config l1i-none_l1d-hint_l2-none_l3-none \
      --config l1i-none_l1d-hint_l2-hint_l3-none \
      --trace-lookbacks 5,10,20,30 \
      --kind bar \
      --output plots/sha256_accuracy_coverage.svg
"""

from __future__ import annotations

import argparse
import csv
import html
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
GEM5_ROOT = SCRIPT_DIR.parent.parent
M5OUT_ROOT = GEM5_ROOT / "m5out"
DEFAULT_SWEEP_CSV = M5OUT_ROOT / "crypto_prefetcher_sweep.csv"

PREFETCHER_LEVELS = ("l1i", "l1d", "l2", "l3")
CACHE_OBJECTS = {
    "l1i": "l1i_cache_0",
    "l1d": "l1d_cache_0",
    "l2": "l2_cache_0",
    "l3": "l3_cache",
}

TRACE_BENCHMARK_RE = re.compile(r"^(?P<benchmark>.+)_trace(?P<lookback>\d+)$")


def _build_metric_aliases() -> dict[str, str]:
    aliases = {
        "ipc": "summary:ipc",
        "sim_seconds": "simSeconds",
        "sim_ticks": "simTicks",
        "sim_insts": "simInsts",
        "sim_ops": "simOps",
        "sim_cycles": "summary:sim_cycles",
        "summary_sim_seconds": "summary:sim_seconds",
        "summary_sim_insts": "summary:sim_insts",
    }

    cache_stat_templates = {
        "hits": "overallHits::total",
        "misses": "overallMisses::total",
        "accesses": "overallAccesses::total",
        "miss_rate": "overallMissRate::total",
        "mshr_hits": "demandMshrHits::total",
        "mshr_misses": "demandMshrMisses::total",
        "mshr_miss_rate": "demandMshrMissRate::total",
        "avg_miss_latency": "overallAvgMissLatency::total",
        "replacements": "replacements",
    }
    prefetcher_stats = {
        "demand_mshr_misses": "demandMshrMisses",
        "pf_issued": "pfIssued",
        "pf_unused": "pfUnused",
        "pf_useful": "pfUseful",
        "pf_useful_but_miss": "pfUsefulButMiss",
        "accuracy": "accuracy",
        "coverage": "coverage",
        "pf_late": "pfLate",
        "pf_identified": "pfIdentified",
        "pf_buffer_hit": "pfBufferHit",
        "pf_in_cache": "pfInCache",
        "pf_removed_demand": "pfRemovedDemand",
        "pf_removed_full": "pfRemovedFull",
        "hint_segments_generated": "hintSegmentsGenerated",
        "hint_segments_queued": "hintSegmentsQueued",
        "hint_segments_dropped_queue_full": "hintSegmentsDroppedQueueFull",
        "hint_segments_skipped_redundant": "hintSegmentsSkippedRedundant",
        "hints_matched": "hintsMatched",
        "hints_skipped_by_sampling": "hintsSkippedBySampling",
        "retired_pcs_observed": "retiredPCsObserved",
        "retired_pcs_skipped": "retiredPCsSkipped",
        "hints_loaded": "hintsLoaded",
        "csv_parse_errors": "csvParseErrors",
    }

    for level, cache_object in CACHE_OBJECTS.items():
        cache_prefix = f"board.cache_hierarchy.{cache_object}"
        for short_name, stat_suffix in cache_stat_templates.items():
            aliases[f"{level}_{short_name}"] = f"{cache_prefix}.{stat_suffix}"
        for short_name, stat_suffix in prefetcher_stats.items():
            aliases[f"{level}_{short_name}"] = (
                f"{cache_prefix}.prefetcher.{stat_suffix}"
            )

    return aliases


METRIC_ALIASES = _build_metric_aliases()


@dataclass(frozen=True)
class Experiment:
    simulation_id: str
    benchmark: str
    trace_lookback: int | None
    l1i_prefetcher: str
    l1d_prefetcher: str
    l2_prefetcher: str
    l3_prefetcher: str
    stats_path: Path
    summary_values: dict[str, str]

    @property
    def cache_config(self) -> str:
        return "_".join(
            f"{level}-{getattr(self, f'{level}_prefetcher')}"
            for level in PREFETCHER_LEVELS
        )

    @property
    def trace_label(self) -> str:
        if self.trace_lookback is None:
            return "baseline"
        return f"trace{self.trace_lookback}"

    @property
    def plot_label(self) -> str:
        return f"{self.benchmark} {self.cache_config}"


def _parse_numeric(raw: str) -> float:
    raw = raw.strip()
    lower = raw.lower()
    if lower == "nan":
        return math.nan
    if lower == "inf":
        return math.inf
    if lower == "-inf":
        return -math.inf
    return float(raw)


def parse_stats_file(stats_path: Path) -> dict[str, float]:
    stats: dict[str, float] = {}
    with stats_path.open("r", encoding="utf-8") as stats_file:
        for line in stats_file:
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith("#")
                or stripped.startswith("-")
            ):
                continue
            payload = stripped.split("#", 1)[0].strip()
            fields = payload.split()
            if len(fields) < 2:
                continue
            try:
                stats[fields[0]] = _parse_numeric(fields[1])
            except ValueError:
                continue
    return stats


def _split_benchmark_and_lookback(benchmark_label: str) -> tuple[str, int | None]:
    match = TRACE_BENCHMARK_RE.match(benchmark_label)
    if match is None:
        return benchmark_label, None
    return match.group("benchmark"), int(match.group("lookback"))


def load_experiments(sweep_csv: Path, m5out_root: Path) -> list[Experiment]:
    experiments: list[Experiment] = []
    with sweep_csv.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        required = {
            "simulation_id",
            "benchmark",
            "l1i_prefetcher",
            "l1d_prefetcher",
            "l2_prefetcher",
            "l3_prefetcher",
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"{sweep_csv} is missing required columns: "
                + ", ".join(sorted(missing))
            )

        for row in reader:
            simulation_id = (row.get("simulation_id") or "").strip()
            benchmark_label = (row.get("benchmark") or "").strip()
            if not simulation_id or not benchmark_label:
                continue
            benchmark, trace_lookback = _split_benchmark_and_lookback(
                benchmark_label
            )
            stats_path = m5out_root / simulation_id / "stats.txt"
            experiments.append(
                Experiment(
                    simulation_id=simulation_id,
                    benchmark=benchmark,
                    trace_lookback=trace_lookback,
                    l1i_prefetcher=(row.get("l1i_prefetcher") or "none"),
                    l1d_prefetcher=(row.get("l1d_prefetcher") or "none"),
                    l2_prefetcher=(row.get("l2_prefetcher") or "none"),
                    l3_prefetcher=(row.get("l3_prefetcher") or "none"),
                    stats_path=stats_path,
                    summary_values=dict(row),
                )
            )
    return experiments


def parse_csv_set(values: list[str] | None) -> set[str] | None:
    if not values:
        return None
    parsed: set[str] = set()
    for value in values:
        parsed.update(part.strip() for part in value.split(",") if part.strip())
    return parsed or None


def parse_lookback_set(raw: str | None) -> set[int] | None:
    if raw is None or raw.strip().lower() in {"", "all"}:
        return None
    lookbacks: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_raw, end_raw = part.split("-", 1)
            start = int(start_raw)
            end = int(end_raw)
            if end < start:
                raise ValueError(f"Invalid lookback range {part!r}")
            lookbacks.update(range(start, end + 1))
        else:
            lookbacks.add(int(part))
    return lookbacks


def _allowed(value: str, allowed_values: set[str] | None) -> bool:
    return (
        allowed_values is None
        or "any" in allowed_values
        or value in allowed_values
    )


def filter_experiments(
    experiments: Iterable[Experiment],
    benchmarks: set[str] | None,
    configs: set[str] | None,
    level_filters: dict[str, set[str] | None],
    trace_lookbacks: set[int] | None,
    include_baseline: bool,
) -> list[Experiment]:
    filtered: list[Experiment] = []
    for experiment in experiments:
        if benchmarks is not None and experiment.benchmark not in benchmarks:
            continue
        if configs is not None and experiment.cache_config not in configs:
            continue
        if not all(
            _allowed(getattr(experiment, f"{level}_prefetcher"), allowed)
            for level, allowed in level_filters.items()
        ):
            continue
        if experiment.trace_lookback is None:
            if not include_baseline:
                continue
        elif (
            trace_lookbacks is not None
            and experiment.trace_lookback not in trace_lookbacks
        ):
            continue
        filtered.append(experiment)
    return filtered


def resolve_metric(metric: str) -> str:
    return METRIC_ALIASES.get(metric, metric)


def metric_label(metric: str) -> str:
    resolved = resolve_metric(metric)
    if resolved == metric:
        return metric
    return metric.replace("_", " ")


def get_metric_value(
    experiment: Experiment,
    metric: str,
    stats_cache: dict[Path, dict[str, float]],
) -> float | None:
    resolved = resolve_metric(metric)
    if resolved.startswith("summary:"):
        column = resolved.split(":", 1)[1]
        raw = experiment.summary_values.get(column)
        if raw in (None, ""):
            return None
        return _parse_numeric(raw)

    stats = stats_cache.get(experiment.stats_path)
    if stats is None:
        if not experiment.stats_path.is_file():
            return None
        stats = parse_stats_file(experiment.stats_path)
        stats_cache[experiment.stats_path] = stats
    return stats.get(resolved)


def collect_metric_rows(
    experiments: list[Experiment],
    metrics: list[str],
) -> tuple[list[dict[str, object]], list[str]]:
    rows: list[dict[str, object]] = []
    missing: set[str] = set()
    stats_cache: dict[Path, dict[str, float]] = {}
    for experiment in experiments:
        values: dict[str, float] = {}
        for metric in metrics:
            value = get_metric_value(experiment, metric, stats_cache)
            if value is None:
                missing.add(f"{experiment.simulation_id}: {metric}")
                continue
            values[metric] = value
        if values:
            row: dict[str, object] = {
                "experiment": experiment,
                "values": values,
            }
            rows.append(row)
    return rows, sorted(missing)


def dump_table(rows: list[dict[str, object]], metrics: list[str]) -> None:
    header = [
        "benchmark",
        "trace_lookback",
        "cache_config",
        "simulation_id",
        *metrics,
    ]
    print(",".join(header))
    for row in rows:
        experiment = row["experiment"]
        assert isinstance(experiment, Experiment)
        values = row["values"]
        assert isinstance(values, dict)
        lookback = (
            ""
            if experiment.trace_lookback is None
            else str(experiment.trace_lookback)
        )
        fields = [
            experiment.benchmark,
            lookback,
            experiment.cache_config,
            experiment.simulation_id,
        ]
        for metric in metrics:
            value = values.get(metric)
            fields.append("" if value is None else f"{value:g}")
        print(",".join(fields))


def _default_group_label(experiments: list[Experiment], experiment: Experiment) -> str:
    multi_benchmark = len({item.benchmark for item in experiments}) > 1
    if multi_benchmark:
        return experiment.plot_label
    return experiment.cache_config


def _record_sort_key(row: dict[str, object]) -> tuple[str, int, str]:
    experiment = row["experiment"]
    assert isinstance(experiment, Experiment)
    lookback = -1 if experiment.trace_lookback is None else experiment.trace_lookback
    return (experiment.benchmark, lookback, experiment.cache_config)


def _finite_values(values: Iterable[float]) -> list[float]:
    return [value for value in values if math.isfinite(value)]


def _nice_range(values: list[float]) -> tuple[float, float]:
    finite = _finite_values(values)
    if not finite:
        return 0.0, 1.0
    low = min(finite)
    high = max(finite)
    if low == high:
        if low == 0:
            return 0.0, 1.0
        pad = abs(low) * 0.1
        return low - pad, high + pad
    pad = (high - low) * 0.08
    return low - pad, high + pad


def _format_tick(value: float) -> str:
    if abs(value) >= 10000 or (0 < abs(value) < 0.001):
        return f"{value:.2e}"
    if abs(value - round(value)) < 1e-9:
        return str(int(round(value)))
    return f"{value:.4g}"


def _line_groups(
    rows: list[dict[str, object]], metric: str
) -> dict[str, list[tuple[int, float]]]:
    experiments = [
        row["experiment"]
        for row in rows
        if isinstance(row["experiment"], Experiment)
    ]
    groups: dict[str, list[tuple[int, float]]] = {}
    for row in rows:
        experiment = row["experiment"]
        values = row["values"]
        assert isinstance(experiment, Experiment)
        assert isinstance(values, dict)
        if experiment.trace_lookback is None or metric not in values:
            continue
        value = float(values[metric])
        if not math.isfinite(value):
            continue
        label = _default_group_label(experiments, experiment)
        groups.setdefault(label, []).append((experiment.trace_lookback, value))
    return {label: sorted(points) for label, points in groups.items()}


def render_svg_plot(
    rows: list[dict[str, object]],
    metrics: list[str],
    *,
    kind: str,
    title: str | None,
    output: Path,
) -> None:
    palette = [
        "#1f77b4",
        "#d62728",
        "#2ca02c",
        "#9467bd",
        "#ff7f0e",
        "#17becf",
        "#8c564b",
        "#7f7f7f",
        "#bcbd22",
        "#e377c2",
    ]
    rows = sorted(rows, key=_record_sort_key)
    left = 95
    right = 260 if kind == "line" else 35
    top = 55
    panel_height = 290
    gap = 45
    bottom = 90 if kind == "bar" else 60
    width = 1200
    if kind == "bar":
        width = max(width, 120 + len(rows) * 85)
    height = top + len(metrics) * panel_height + (len(metrics) - 1) * gap + bottom
    plot_width = width - left - right

    svg: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
            f'height="{height}" viewBox="0 0 {width} {height}">'
        ),
        '<rect width="100%" height="100%" fill="white"/>',
        (
            '<style>'
            'text{font-family:Inter,Arial,sans-serif;fill:#222}'
            '.title{font-size:22px;font-weight:700}'
            '.label{font-size:13px}'
            '.tick{font-size:11px;fill:#444}'
            '.legend{font-size:12px}'
            '.grid{stroke:#d6dde5;stroke-width:1}'
            '.axis{stroke:#222;stroke-width:1.4}'
            '</style>'
        ),
    ]
    if title:
        svg.append(
            f'<text class="title" x="{width / 2:.1f}" y="30" '
            f'text-anchor="middle">{html.escape(title)}</text>'
        )

    for axis_index, metric in enumerate(metrics):
        y0 = top + axis_index * (panel_height + gap)
        plot_height = panel_height - 45
        x_axis_y = y0 + plot_height
        metric_title_y = y0 - 12 if axis_index == 0 and not title else y0 - 8
        svg.append(
            f'<text class="label" x="{left}" y="{metric_title_y}" '
            f'font-weight="700">{html.escape(metric_label(metric))}</text>'
        )

        if kind == "line":
            groups = _line_groups(rows, metric)
            all_points = [point for points in groups.values() for point in points]
            if not all_points:
                continue
            x_values = [point[0] for point in all_points]
            y_values = [point[1] for point in all_points]
            x_min = min(x_values)
            x_max = max(x_values)
            y_min, y_max = _nice_range(y_values)
            if x_min == x_max:
                x_min -= 1
                x_max += 1

            def sx(value: float) -> float:
                return left + (value - x_min) / (x_max - x_min) * plot_width

            def sy(value: float) -> float:
                return y0 + (y_max - value) / (y_max - y_min) * plot_height

            for tick_index in range(6):
                frac = tick_index / 5
                tick_value = y_min + frac * (y_max - y_min)
                y = sy(tick_value)
                svg.append(
                    f'<line class="grid" x1="{left}" y1="{y:.1f}" '
                    f'x2="{left + plot_width}" y2="{y:.1f}"/>'
                )
                svg.append(
                    f'<text class="tick" x="{left - 8}" y="{y + 4:.1f}" '
                    f'text-anchor="end">{html.escape(_format_tick(tick_value))}</text>'
                )
            unique_x = sorted(set(x_values))
            x_tick_step = max(1, math.ceil(len(unique_x) / 12))
            for value in unique_x[::x_tick_step]:
                x = sx(value)
                svg.append(
                    f'<line class="grid" x1="{x:.1f}" y1="{y0}" '
                    f'x2="{x:.1f}" y2="{x_axis_y}"/>'
                )
                svg.append(
                    f'<text class="tick" x="{x:.1f}" y="{x_axis_y + 18}" '
                    f'text-anchor="middle">{value}</text>'
                )
            svg.append(
                f'<line class="axis" x1="{left}" y1="{x_axis_y}" '
                f'x2="{left + plot_width}" y2="{x_axis_y}"/>'
            )
            svg.append(
                f'<line class="axis" x1="{left}" y1="{y0}" '
                f'x2="{left}" y2="{x_axis_y}"/>'
            )

            for group_index, (label, points) in enumerate(sorted(groups.items())):
                color = palette[group_index % len(palette)]
                polyline = " ".join(
                    f"{sx(x):.1f},{sy(y):.1f}" for x, y in points
                )
                svg.append(
                    f'<polyline fill="none" stroke="{color}" stroke-width="2.2" '
                    f'points="{polyline}"/>'
                )
                for x_value, y_value in points:
                    svg.append(
                        f'<circle cx="{sx(x_value):.1f}" cy="{sy(y_value):.1f}" '
                        f'r="3.6" fill="{color}"/>'
                    )
                legend_y = y0 + 18 + group_index * 18
                legend_x = left + plot_width + 22
                svg.append(
                    f'<line x1="{legend_x}" y1="{legend_y - 4}" '
                    f'x2="{legend_x + 20}" y2="{legend_y - 4}" '
                    f'stroke="{color}" stroke-width="2.2"/>'
                )
                svg.append(
                    f'<text class="legend" x="{legend_x + 28}" y="{legend_y}">'
                    f'{html.escape(label)}</text>'
                )
            svg.append(
                f'<text class="label" x="{left + plot_width / 2:.1f}" '
                f'y="{x_axis_y + 42}" text-anchor="middle">Trace lookback</text>'
            )
        else:
            values: list[float] = []
            labels: list[str] = []
            for row in rows:
                experiment = row["experiment"]
                metric_values = row["values"]
                assert isinstance(experiment, Experiment)
                assert isinstance(metric_values, dict)
                if metric not in metric_values:
                    continue
                value = float(metric_values[metric])
                if not math.isfinite(value):
                    continue
                values.append(value)
                labels.append(
                    f"{experiment.benchmark} {experiment.trace_label} "
                    f"{experiment.cache_config}"
                )
            if not values:
                continue
            y_min, y_max = _nice_range(values + [0.0])
            y_min = min(y_min, 0.0)

            def sy(value: float) -> float:
                return y0 + (y_max - value) / (y_max - y_min) * plot_height

            bar_gap = 8
            bar_width = max(
                8, (plot_width - bar_gap * (len(values) + 1)) / len(values)
            )
            for tick_index in range(6):
                frac = tick_index / 5
                tick_value = y_min + frac * (y_max - y_min)
                y = sy(tick_value)
                svg.append(
                    f'<line class="grid" x1="{left}" y1="{y:.1f}" '
                    f'x2="{left + plot_width}" y2="{y:.1f}"/>'
                )
                svg.append(
                    f'<text class="tick" x="{left - 8}" y="{y + 4:.1f}" '
                    f'text-anchor="end">{html.escape(_format_tick(tick_value))}</text>'
                )
            svg.append(
                f'<line class="axis" x1="{left}" y1="{x_axis_y}" '
                f'x2="{left + plot_width}" y2="{x_axis_y}"/>'
            )
            svg.append(
                f'<line class="axis" x1="{left}" y1="{y0}" '
                f'x2="{left}" y2="{x_axis_y}"/>'
            )
            for index, (label, value) in enumerate(zip(labels, values, strict=True)):
                x = left + bar_gap + index * (bar_width + bar_gap)
                y = sy(max(value, 0.0))
                baseline_y = sy(0.0)
                height_value = abs(baseline_y - sy(value))
                svg.append(
                    f'<rect x="{x:.1f}" y="{min(y, baseline_y):.1f}" '
                    f'width="{bar_width:.1f}" height="{height_value:.1f}" '
                    f'fill="{palette[index % len(palette)]}"/>'
                )
                svg.append(
                    f'<text class="tick" transform="translate({x + bar_width / 2:.1f},'
                    f'{x_axis_y + 16}) rotate(45)" text-anchor="start">'
                    f'{html.escape(label)}</text>'
                )

    svg.append("</svg>")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(svg) + "\n", encoding="utf-8")
    print(f"Wrote {output}")


def plot_metrics(
    rows: list[dict[str, object]],
    metrics: list[str],
    *,
    kind: str,
    title: str | None,
    output: Path,
    dpi: int,
) -> None:
    if output.suffix.lower() == ".svg":
        render_svg_plot(
            rows,
            metrics,
            kind=kind,
            title=title,
            output=output,
        )
        return

    try:
        import matplotlib.pyplot as plt
    except ImportError as error:
        raise SystemExit(
            "matplotlib is required for non-SVG output. Install it, choose an "
            ".svg output path, or use --print-table to inspect the selected "
            "data without plotting."
        ) from error

    rows = sorted(rows, key=_record_sort_key)
    figure_height = max(3.0, 2.8 * len(metrics))
    fig, axes = plt.subplots(
        len(metrics),
        1,
        figsize=(11, figure_height),
        squeeze=False,
        constrained_layout=True,
    )

    for axis_index, metric in enumerate(metrics):
        axis = axes[axis_index][0]
        if kind == "line":
            groups = _line_groups(rows, metric)
            for label, points in sorted(groups.items()):
                axis.plot(
                    [point[0] for point in points],
                    [point[1] for point in points],
                    marker="o",
                    linewidth=1.8,
                    markersize=4,
                    label=label,
                )
            axis.set_xlabel("Trace lookback")
        else:
            labels: list[str] = []
            values_to_plot: list[float] = []
            for row in rows:
                experiment = row["experiment"]
                values = row["values"]
                assert isinstance(experiment, Experiment)
                assert isinstance(values, dict)
                if metric not in values:
                    continue
                labels.append(
                    f"{experiment.benchmark}\n{experiment.trace_label}\n"
                    f"{experiment.cache_config}"
                )
                values_to_plot.append(float(values[metric]))
            axis.bar(range(len(values_to_plot)), values_to_plot)
            axis.set_xticks(range(len(labels)))
            axis.set_xticklabels(labels, rotation=45, ha="right")

        axis.set_ylabel(metric_label(metric))
        axis.grid(True, axis="y", alpha=0.3)
        if kind == "line":
            axis.legend(fontsize="small", loc="best")

    if title:
        fig.suptitle(title)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=dpi)
    print(f"Wrote {output}")


def list_metrics() -> None:
    for alias in sorted(METRIC_ALIASES):
        print(f"{alias:40} {METRIC_ALIASES[alias]}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Plot crypto multisim stats.txt counters filtered by benchmark, "
            "cache prefetcher configuration, and trace lookback."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--m5out",
        type=Path,
        default=M5OUT_ROOT,
        help=f"m5out root directory (default: {M5OUT_ROOT})",
    )
    parser.add_argument(
        "--sweep-csv",
        type=Path,
        default=DEFAULT_SWEEP_CSV,
        help=f"summary CSV path (default: {DEFAULT_SWEEP_CSV})",
    )
    parser.add_argument(
        "--benchmark",
        "--benchmarks",
        action="append",
        help="Benchmark filter, comma-separated or repeated, e.g. sha256,chacha20",
    )
    parser.add_argument(
        "--config",
        action="append",
        help=(
            "Exact cache configuration filter, repeated or comma-separated. "
            "Example: l1i-none_l1d-hint_l2-hint_l3-none"
        ),
    )
    for level in PREFETCHER_LEVELS:
        parser.add_argument(
            f"--{level}",
            action="append",
            help=(
                f"{level} prefetcher filter, comma-separated or repeated. "
                "Use any, none, hint, indirect, IMPv2, stride, tagged, ampm, bop, stems."
            ),
        )
    parser.add_argument(
        "--trace-lookbacks",
        default="all",
        help="Trace lookbacks to include, e.g. all, 20, 1,5,10, or 1-30.",
    )
    parser.add_argument(
        "--include-baseline",
        action="store_true",
        help="Include non-hint baseline rows with no trace lookback.",
    )
    parser.add_argument(
        "--metric",
        "--stat",
        action="append",
        dest="metrics",
        help=(
            "Metric alias or exact stats.txt counter. Repeat for subplots. "
            "Use --list-metrics for aliases."
        ),
    )
    parser.add_argument(
        "--list-metrics",
        action="store_true",
        help="Print available metric aliases and exit.",
    )
    parser.add_argument(
        "--kind",
        choices=("line", "bar"),
        default="line",
        help="Plot type. line uses trace lookback on the x-axis.",
    )
    parser.add_argument(
        "--title",
        help="Optional plot title.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("prefetch_stats.svg"),
        help="Output image path.",
    )
    parser.add_argument(
        "--dpi",
        type=int,
        default=160,
        help="Output image DPI.",
    )
    parser.add_argument(
        "--print-table",
        action="store_true",
        help="Print selected data as CSV before plotting.",
    )
    parser.add_argument(
        "--no-plot",
        action="store_true",
        help="Only print/filter data; do not create an image.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_metrics:
        list_metrics()
        return 0

    metrics = args.metrics or ["ipc", "sim_seconds", "l1d_misses"]
    if not args.sweep_csv.is_file():
        parser.error(f"summary CSV not found: {args.sweep_csv}")

    benchmarks = parse_csv_set(args.benchmark)
    configs = parse_csv_set(args.config)
    level_filters = {
        level: parse_csv_set(getattr(args, level))
        for level in PREFETCHER_LEVELS
    }
    try:
        trace_lookbacks = parse_lookback_set(args.trace_lookbacks)
    except ValueError as error:
        parser.error(str(error))

    experiments = load_experiments(args.sweep_csv, args.m5out)
    experiments = filter_experiments(
        experiments,
        benchmarks,
        configs,
        level_filters,
        trace_lookbacks,
        args.include_baseline,
    )
    if not experiments:
        parser.error("no experiments matched the selected filters")

    rows, missing = collect_metric_rows(experiments, metrics)
    if missing:
        print(
            f"Warning: {len(missing)} selected metric values were missing.",
            file=sys.stderr,
        )
        for item in missing[:20]:
            print(f"  {item}", file=sys.stderr)
        if len(missing) > 20:
            print(f"  ... {len(missing) - 20} more", file=sys.stderr)
    if not rows:
        parser.error("no metric values were found for the selected experiments")

    if args.print_table or args.no_plot:
        dump_table(rows, metrics)
    if not args.no_plot:
        plot_metrics(
            rows,
            metrics,
            kind=args.kind,
            title=args.title,
            output=args.output,
            dpi=args.dpi,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
