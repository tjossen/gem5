#!/usr/bin/env python3

import csv
import sys
import tempfile
import unittest
from pathlib import Path


GEM5_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(GEM5_ROOT / "configs" / "crypto_multisim"))

from generate_prefetch_hints import (
    generate_hints_for_lookbacks_from_trace,
    generate_hints_from_trace,
)


TRACE_FIELDS = [
    "thread_id",
    "instruction_pointer",
    "access_type",
    "memory_address",
    "access_size",
    "cache_hit",
]


def _write_trace(path, rows):
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=TRACE_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _trace_row(pc, address, cache_hit="1", size="8", access_type="R"):
    return {
        "thread_id": "0",
        "instruction_pointer": pc,
        "access_type": access_type,
        "memory_address": address,
        "access_size": size,
        "cache_hit": cache_hit,
    }


class GeneratePrefetchHintsTest(unittest.TestCase):
    def test_generate_hints_uses_full_trace_row_lookback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            trace_path = temp_path / "commit_rw_trace.csv"
            output_path = temp_path / "hints_trace5.csv"

            _write_trace(
                trace_path,
                [
                    _trace_row("0x1000", "0xaaa0", cache_hit="0"),
                    _trace_row("0x1001", "0xbbb0", cache_hit="1"),
                    _trace_row("0x1002", "0xccc0", cache_hit="1"),
                    _trace_row("0x1003", "0xddd0", cache_hit="1"),
                    _trace_row("0x1004", "0xeee0", cache_hit="1"),
                    _trace_row("0x1005", "0xfff0", cache_hit="0"),
                    _trace_row("0x1006", "0x1110", cache_hit="1"),
                    _trace_row("0x1007", "0x2220", cache_hit="1"),
                    _trace_row("0x1008", "0x3330", cache_hit="1"),
                    _trace_row("0x1009", "0x4440", cache_hit="1"),
                    _trace_row("0x100a", "0x5550", cache_hit="0", size="16"),
                ],
            )

            stats = generate_hints_from_trace(
                trace_path=trace_path,
                output_path=output_path,
                trace_lookback=5,
            )

            self.assertEqual(stats.rows_read, 11)
            self.assertEqual(stats.hints_written, 2)
            self.assertEqual(stats.skipped_cache_hits, 8)
            self.assertEqual(stats.skipped_missing_pc, 0)
            self.assertEqual(stats.skipped_early_pc, 1)
            self.assertEqual(stats.malformed_rows, 0)

            with output_path.open("r", encoding="utf-8", newline="") as file:
                rows = list(csv.reader(file))

            self.assertEqual(
                rows,
                [
                    ["pc", "address", "size"],
                    ["0x1000", "0xfff0", "8"],
                    ["0x1005", "0x5550", "16"],
                ],
            )

    def test_malformed_rows_preserve_trace_distance_but_cannot_trigger(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            trace_path = temp_path / "commit_rw_trace.csv"
            output_path = temp_path / "hints_trace5.csv"

            _write_trace(
                trace_path,
                [
                    _trace_row("0x2000", "0xaaa0", cache_hit="1"),
                    _trace_row("not-a-pc", "0xbbb0", cache_hit="1"),
                    _trace_row("0x2002", "0xccc0", cache_hit="1"),
                    _trace_row("0x2003", "0xddd0", cache_hit="1"),
                    _trace_row("0x2004", "0xeee0", cache_hit="1"),
                    _trace_row("0x2005", "0xfff0", cache_hit="1"),
                    _trace_row("0x2006", "0x1110", cache_hit="0"),
                    _trace_row("0x2007", "0x2220", cache_hit="0"),
                ],
            )

            stats = generate_hints_from_trace(
                trace_path=trace_path,
                output_path=output_path,
                trace_lookback=5,
            )

            self.assertEqual(stats.rows_read, 8)
            self.assertEqual(stats.hints_written, 1)
            self.assertEqual(stats.skipped_cache_hits, 5)
            self.assertEqual(stats.skipped_missing_pc, 1)
            self.assertEqual(stats.skipped_early_pc, 0)
            self.assertEqual(stats.malformed_rows, 1)

            with output_path.open("r", encoding="utf-8", newline="") as file:
                rows = list(csv.reader(file))

            self.assertEqual(
                rows,
                [
                    ["pc", "address", "size"],
                    ["0x2002", "0x2220", "8"],
                ],
            )

    def test_generate_multiple_lookbacks_uses_process_executor(self):
        executor_calls = []

        class RecordingExecutor:
            def __init__(self, max_workers):
                self.max_workers = max_workers

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def map(self, func, jobs):
                jobs = list(jobs)
                executor_calls.append((self.max_workers, jobs))
                return [func(job) for job in jobs]

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            trace_path = temp_path / "commit_rw_trace.csv"

            _write_trace(
                trace_path,
                [
                    _trace_row("0x3000", "0xaaa0", cache_hit="1"),
                    _trace_row("0x3001", "0xbbb0", cache_hit="1"),
                    _trace_row("0x3002", "0xccc0", cache_hit="0"),
                    _trace_row("0x3003", "0xddd0", cache_hit="0"),
                ],
            )

            results = generate_hints_for_lookbacks_from_trace(
                trace_path=trace_path,
                trace_lookbacks=[1, 2],
                output_path_for_lookback=(
                    lambda lookback: temp_path / f"hints_trace{lookback}.csv"
                ),
                max_workers=2,
                executor_class=RecordingExecutor,
            )

            self.assertEqual(len(executor_calls), 1)
            max_workers, jobs = executor_calls[0]
            self.assertEqual(max_workers, 2)
            self.assertEqual([job.trace_lookback for job in jobs], [1, 2])
            self.assertEqual([result.trace_lookback for result in results], [1, 2])
            self.assertEqual(
                [result.stats.hints_written for result in results],
                [2, 2],
            )
            self.assertTrue((temp_path / "hints_trace1.csv").is_file())
            self.assertTrue((temp_path / "hints_trace2.csv").is_file())


if __name__ == "__main__":
    unittest.main()
