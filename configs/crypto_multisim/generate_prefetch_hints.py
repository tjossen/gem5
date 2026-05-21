#!/usr/bin/env python3
"""
Generate chronological prefetch hints from SimpleMemTrace commit traces.

Examples:
  python3 configs/crypto_multisim/generate_prefetch_hints.py sha256
  python3 configs/crypto_multisim/generate_prefetch_hints.py sha256 \
      --trace-lookback 5
  python3 configs/crypto_multisim/generate_prefetch_hints.py \
      --trace /path/to/commit_rw_trace.csv --output /path/to/hints_trace5.csv
"""

import argparse
import csv
import os
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from inspect_commit_rw_trace import find_trace_file


SCRIPT_DIR = Path(__file__).resolve().parent
GEM5_ROOT = SCRIPT_DIR.parent.parent

DEFAULT_TRACE_LINE_LOOKBACK = 5


@dataclass(frozen=True)
class HintGenerationStats:
    rows_read: int = 0
    hints_written: int = 0
    skipped_cache_hits: int = 0
    skipped_missing_pc: int = 0
    skipped_early_pc: int = 0
    malformed_rows: int = 0


@dataclass(frozen=True)
class HintGenerationJob:
    trace_path: Path
    output_path: Path
    trace_lookback: int


@dataclass(frozen=True)
class HintGenerationResult:
    trace_lookback: int
    output_path: Path
    stats: HintGenerationStats


def _format_hex(value: int) -> str:
    return f"0x{value:x}"


def generate_hints_from_trace(
    trace_path: Path,
    output_path: Path,
    trace_lookback: int = DEFAULT_TRACE_LINE_LOOKBACK,
) -> HintGenerationStats:
    if trace_lookback < 0:
        raise ValueError("trace_lookback must be non-negative")

    prior_pcs: deque[int | None] = deque(maxlen=max(trace_lookback, 1))
    rows_read = 0
    hints_written = 0
    skipped_cache_hits = 0
    skipped_missing_pc = 0
    skipped_early_pc = 0
    malformed_rows = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with trace_path.open("r", encoding="utf-8", newline="") as trace_file, (
        output_path.open("w", encoding="utf-8", newline="")
    ) as output_file:
        reader = csv.DictReader(trace_file)
        writer = csv.writer(output_file)
        writer.writerow(["pc", "address", "size"])

        for row in reader:
            rows_read += 1
            try:
                pc = int(row["instruction_pointer"], 0)
                address = int(row["memory_address"], 0)
                size = int(row["access_size"], 0)
                cache_hit = int(row["cache_hit"], 0)
            except (KeyError, TypeError, ValueError):
                malformed_rows += 1
                prior_pcs.append(None)
                continue

            if cache_hit != 0:
                skipped_cache_hits += 1
                prior_pcs.append(pc)
                continue

            if trace_lookback == 0:
                hint_pc = pc
            elif len(prior_pcs) < trace_lookback:
                skipped_early_pc += 1
                prior_pcs.append(pc)
                continue
            else:
                hint_pc = prior_pcs[0]
                if hint_pc is None:
                    skipped_missing_pc += 1
                    prior_pcs.append(pc)
                    continue

            writer.writerow([_format_hex(hint_pc), _format_hex(address), size])
            hints_written += 1
            prior_pcs.append(pc)

    return HintGenerationStats(
        rows_read=rows_read,
        hints_written=hints_written,
        skipped_cache_hits=skipped_cache_hits,
        skipped_missing_pc=skipped_missing_pc,
        skipped_early_pc=skipped_early_pc,
        malformed_rows=malformed_rows,
    )


def default_output_path(
    trace_path: Path,
    trace_lookback: int = DEFAULT_TRACE_LINE_LOOKBACK,
) -> Path:
    return trace_path.parent / f"hints_trace{trace_lookback}.csv"


def _generate_hints_for_lookback_job(
    job: HintGenerationJob,
) -> HintGenerationResult:
    stats = generate_hints_from_trace(
        trace_path=job.trace_path,
        output_path=job.output_path,
        trace_lookback=job.trace_lookback,
    )
    return HintGenerationResult(
        trace_lookback=job.trace_lookback,
        output_path=job.output_path,
        stats=stats,
    )


def _default_parallelism(job_count: int) -> int:
    return max(1, min(job_count, os.cpu_count() or 1))


def generate_hints_for_lookbacks_from_trace(
    trace_path: Path,
    trace_lookbacks: Iterable[int],
    output_path_for_lookback: Callable[[int], Path] | None = None,
    max_workers: int | None = None,
    executor_class=ProcessPoolExecutor,
) -> list[HintGenerationResult]:
    lookbacks = list(trace_lookbacks)
    if any(lookback < 0 for lookback in lookbacks):
        raise ValueError("trace_lookbacks must be non-negative")
    if not lookbacks:
        return []

    def output_path(lookback: int) -> Path:
        if output_path_for_lookback is not None:
            return output_path_for_lookback(lookback)
        return default_output_path(trace_path, lookback)

    jobs = [
        HintGenerationJob(
            trace_path=trace_path,
            output_path=output_path(lookback),
            trace_lookback=lookback,
        )
        for lookback in lookbacks
    ]
    worker_count = (
        _default_parallelism(len(jobs))
        if max_workers is None
        else max(1, min(max_workers, len(jobs)))
    )

    if worker_count == 1:
        return [_generate_hints_for_lookback_job(job) for job in jobs]

    with executor_class(max_workers=worker_count) as executor:
        return list(executor.map(_generate_hints_for_lookback_job, jobs))


def _resolve_inputs(args: argparse.Namespace) -> tuple[Path, Path]:
    if args.trace is not None:
        trace_path = args.trace.resolve()
    elif args.target is not None:
        trace_path = find_trace_file(args.target).resolve()
    else:
        raise ValueError("Provide a benchmark target or --trace.")

    output_path = (
        args.output.resolve()
        if args.output is not None
        else default_output_path(trace_path, args.trace_lookback)
    )
    return trace_path, output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate chronological pc,address,size prefetch hints"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Benchmark name matching configs/crypto_multisim, e.g. sha256",
    )
    parser.add_argument("--trace", type=Path, help="Explicit trace CSV path")
    parser.add_argument("--output", type=Path, help="Output hint CSV path")
    parser.add_argument(
        "--trace-lookback",
        type=int,
        default=DEFAULT_TRACE_LINE_LOOKBACK,
        help="Number of prior trace CSV rows to look back",
    )
    args = parser.parse_args()

    if args.trace_lookback < 0:
        raise ValueError("--trace-lookback must be non-negative")

    trace_path, output_path = _resolve_inputs(args)
    stats = generate_hints_from_trace(
        trace_path=trace_path,
        output_path=output_path,
        trace_lookback=args.trace_lookback,
    )

    print(f"Trace: {trace_path}")
    print(f"Output: {output_path}")
    print(f"Trace-line lookback: fixed {args.trace_lookback}")
    print(f"Rows read: {stats.rows_read}")
    print(f"Hints written: {stats.hints_written}")
    print(f"Skipped cache hits: {stats.skipped_cache_hits}")
    print(f"Skipped missing PCs: {stats.skipped_missing_pc}")
    print(f"Skipped early PCs: {stats.skipped_early_pc}")
    print(f"Malformed rows: {stats.malformed_rows}")


if __name__ == "__main__":
    main()
