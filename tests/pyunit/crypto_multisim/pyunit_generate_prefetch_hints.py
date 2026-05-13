#!/usr/bin/env python3

import csv
import sys
import tempfile
import unittest
from pathlib import Path


GEM5_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(GEM5_ROOT / "configs" / "crypto_multisim"))

from generate_prefetch_hints import (
    generate_hints_from_trace,
    parse_objdump_instruction_pcs_from_text,
)


class GeneratePrefetchHintsTest(unittest.TestCase):
    def test_parse_objdump_instruction_pcs_keeps_static_order(self):
        objdump_text = """

/tmp/test_binary:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <main>:
  401000:       push   %rbp
  401001:       mov    %rsp,%rbp
  401004:       mov    $0x0,%eax

0000000000401010 <helper>:
  401010:       ret
"""

        self.assertEqual(
            parse_objdump_instruction_pcs_from_text(objdump_text),
            [0x401000, 0x401001, 0x401004, 0x401010],
        )

    def test_generate_hints_preserves_trace_order_and_skips_unusable_rows(self):
        instruction_pcs = [0x1000 + index for index in range(25)]

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            trace_path = temp_path / "commit_rw_trace.csv"
            output_path = temp_path / "hints_pc20.csv"

            with trace_path.open("w", encoding="utf-8", newline="") as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=[
                        "thread_id",
                        "instruction_pointer",
                        "access_type",
                        "memory_address",
                        "access_size",
                        "cache_hit",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "thread_id": "0",
                        "instruction_pointer": "0x1014",
                        "access_type": "R",
                        "memory_address": "0xaaa0",
                        "access_size": "8",
                        "cache_hit": "0",
                    }
                )
                writer.writerow(
                    {
                        "thread_id": "0",
                        "instruction_pointer": "0x7ffff801e543",
                        "access_type": "W",
                        "memory_address": "0xbbbb",
                        "access_size": "8",
                        "cache_hit": "0",
                    }
                )
                writer.writerow(
                    {
                        "thread_id": "0",
                        "instruction_pointer": "0x1002",
                        "access_type": "R",
                        "memory_address": "0xcccc",
                        "access_size": "4",
                        "cache_hit": "0",
                    }
                )
                writer.writerow(
                    {
                        "thread_id": "0",
                        "instruction_pointer": "0x1018",
                        "access_type": "R",
                        "memory_address": "0xddd0",
                        "access_size": "16",
                        "cache_hit": "0",
                    }
                )
                writer.writerow(
                    {
                        "thread_id": "0",
                        "instruction_pointer": "0x1015",
                        "access_type": "R",
                        "memory_address": "0xeeee",
                        "access_size": "8",
                        "cache_hit": "1",
                    }
                )

            stats = generate_hints_from_trace(
                trace_path=trace_path,
                instruction_pcs=instruction_pcs,
                output_path=output_path,
                lookback=20,
            )

            self.assertEqual(stats.rows_read, 5)
            self.assertEqual(stats.hints_written, 2)
            self.assertEqual(stats.skipped_missing_pc, 1)
            self.assertEqual(stats.skipped_early_pc, 1)
            self.assertEqual(stats.skipped_cache_hits, 1)
            self.assertEqual(stats.malformed_rows, 0)

            with output_path.open("r", encoding="utf-8", newline="") as file:
                rows = list(csv.reader(file))

            self.assertEqual(
                rows,
                [
                    ["pc", "address", "size"],
                    ["0x1000", "0xaaa0", "8"],
                    ["0x1004", "0xddd0", "16"],
                ],
            )

    def test_generate_hints_can_use_seeded_random_lookback_range(self):
        instruction_pcs = [0x2000 + index for index in range(16)]

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            trace_path = temp_path / "commit_rw_trace.csv"
            output_path = temp_path / "hints_random.csv"

            with trace_path.open("w", encoding="utf-8", newline="") as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=[
                        "thread_id",
                        "instruction_pointer",
                        "access_type",
                        "memory_address",
                        "access_size",
                        "cache_hit",
                    ],
                )
                writer.writeheader()
                for pc, address in [
                    ("0x2005", "0xaaa0"),
                    ("0x2006", "0xbbb0"),
                    ("0x2007", "0xccc0"),
                    ("0x2008", "0xddd0"),
                ]:
                    writer.writerow(
                        {
                            "thread_id": "0",
                            "instruction_pointer": pc,
                            "access_type": "R",
                            "memory_address": address,
                            "access_size": "8",
                            "cache_hit": "0",
                        }
                    )

            stats = generate_hints_from_trace(
                trace_path=trace_path,
                instruction_pcs=instruction_pcs,
                output_path=output_path,
                lookback_min=2,
                lookback_max=4,
                lookback_seed=1,
            )

            self.assertEqual(stats.rows_read, 4)
            self.assertEqual(stats.hints_written, 4)
            self.assertEqual(stats.skipped_cache_hits, 0)
            self.assertEqual(stats.skipped_missing_pc, 0)
            self.assertEqual(stats.skipped_early_pc, 0)

            with output_path.open("r", encoding="utf-8", newline="") as file:
                rows = list(csv.reader(file))

            self.assertEqual(
                rows,
                [
                    ["pc", "address", "size"],
                    ["0x2003", "0xaaa0", "8"],
                    ["0x2002", "0xbbb0", "8"],
                    ["0x2005", "0xccc0", "8"],
                    ["0x2005", "0xddd0", "8"],
                ],
            )


if __name__ == "__main__":
    unittest.main()
