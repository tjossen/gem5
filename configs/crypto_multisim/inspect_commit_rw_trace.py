#!/usr/bin/env python3
"""
Inspect joined committed-memory read/write CSV traces.

Usage:
  python3 inspect_commit_rw_trace.py kyber768 --records 20
  python3 inspect_commit_rw_trace.py /path/to/trace.csv
"""

import argparse
import csv
from pathlib import Path

GEM5_ROOT = Path(__file__).resolve().parent.parent.parent
M5OUT_ROOT = GEM5_ROOT / "m5out"


def trace_output_dir(benchmark_name: str) -> Path:
    commit_trace_dir = M5OUT_ROOT / f"crypto_{benchmark_name}_commit_trace"
    if commit_trace_dir.exists():
        return commit_trace_dir
    legacy_dir = M5OUT_ROOT / f"crypto_{benchmark_name}_etrace"
    return legacy_dir


def find_trace_file(path_or_benchmark: str) -> Path:
    candidate = Path(path_or_benchmark)
    if candidate.exists():
        return candidate

    trace_dir = trace_output_dir(path_or_benchmark)
    joined_trace = trace_dir / "commit_rw_trace.csv"
    if joined_trace.exists():
        return joined_trace

    l1d_matches = sorted(trace_dir.glob("*l1d_cache*commit_rw_trace.csv"))
    if l1d_matches:
        return l1d_matches[0]

    cpu_matches = sorted(
        trace_dir.glob("*processor*traceListener*commit_rw_trace.csv")
    )
    if cpu_matches:
        return cpu_matches[0]

    matches = sorted(trace_dir.glob("*commit_rw_trace.csv"))
    if matches:
        return matches[0]

    raise FileNotFoundError(
        f"Could not find a commit RW trace for {path_or_benchmark!r} in {trace_dir}"
    )


def inspect_trace(trace_file: Path, max_records: int) -> None:
    with trace_file.open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        print(f"TRACE: {trace_file}")
        print(f"HEADER: {', '.join(reader.fieldnames or [])}")
        print()
        print(f"First {max_records} rows:")

        for index, row in enumerate(reader):
            if index >= max_records:
                break
            print(
                f"{index:<5} {row.get('thread_id', '-'):<8} "
                f"{row.get('instruction_pointer', '-'):<18} "
                f"{row.get('access_type', '-'):<4} "
                f"{row.get('memory_address', '-'):<18} "
                f"{row.get('access_size', '-'):<6} "
                f"{row.get('cache_hit', '-')}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect joined commit RW CSV traces"
    )
    parser.add_argument("target", help="Benchmark name or trace file path")
    parser.add_argument(
        "--records", type=int, default=10, help="Rows to display"
    )
    args = parser.parse_args()

    inspect_trace(find_trace_file(args.target), args.records)


if __name__ == "__main__":
    main()
