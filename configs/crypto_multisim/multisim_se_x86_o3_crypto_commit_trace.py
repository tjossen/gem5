# Copyright (c) 2026
#
# MultiSim SE benchmark runner for crypto workloads with joined committed-memory
# and L1D cache-result trace capture.
#
# Run from the gem5 root directory:
#   build/X86/gem5.opt -m gem5.utils.multisim configs/crypto_multisim/multisim_se_x86_o3_crypto_commit_trace.py

import atexit
import csv
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from m5.objects import SimpleMemTrace
from m5.util import addToPath

import gem5.utils.multisim as multisim

SCRIPT_DIR = Path(__file__).resolve().parent
addToPath(str(SCRIPT_DIR))

import multisim_se_x86_o3_crypto as base

from gem5.components.boards.simple_board import SimpleBoard
from gem5.components.memory import SingleChannelDDR4_2400
from gem5.components.processors.base_cpu_core import BaseCPUCore
from gem5.components.processors.base_cpu_processor import BaseCPUProcessor
from gem5.isas import ISA
from gem5.resources.resource import BinaryResource
from gem5.simulate.simulator import Simulator

DISABLED_PREFETCHER_MAP = {level: None for level in base.PREFETCHER_LEVELS}
COMMIT_TRACE_FILE = "commit_rw_trace.csv"
JOINED_TRACE_HEADER = [
    "thread_id",
    "seq_num",
    "instruction_pointer",
    "access_type",
    "memory_address",
    "access_size",
    "l1d_access",
    "cache_hit",
]
COMMITTED_TRACE_HEADER = JOINED_TRACE_HEADER[:6]


@dataclass(frozen=True)
class TraceJoinStats:
    committed_rows: int
    joined_rows: int
    committed_without_l1d: int
    l1d_only_rows: int
    malformed_committed_rows: int
    malformed_l1d_rows: int


@dataclass
class _L1DAccessSummary:
    rows: int = 0
    cache_hit: bool = True


def _cpu_trace_path_for_outdir(outdir: Path) -> Path:
    return (
        Path(outdir)
        / f"board.processor.cores.core.traceListener.{COMMIT_TRACE_FILE}"
    )


def _l1d_trace_path_for_outdir(outdir: Path) -> Path:
    return (
        Path(outdir)
        / f"board.cache_hierarchy.l1d_cache_0.traceListener.{COMMIT_TRACE_FILE}"
    )


def _joined_trace_path_for_outdir(outdir: Path) -> Path:
    return Path(outdir) / COMMIT_TRACE_FILE


def _trace_path_for_outdir(outdir: Path) -> Path:
    return _l1d_trace_path_for_outdir(outdir)


def _sort_trace_by_seq_num(trace_path: Path) -> None:
    tmp_path = trace_path.with_name(trace_path.name + ".sorted.tmp")
    with trace_path.open("rb", buffering=0) as input_file:
        header = input_file.readline()
        if not header:
            raise RuntimeError(f"Cannot sort empty trace file {trace_path}")
        columns = header.decode("utf-8").rstrip("\n").split(",")
        if "seq_num" not in columns:
            raise RuntimeError(
                f"Trace file {trace_path} has no seq_num column; "
                "regenerate traces with the current SimpleCacheTrace"
            )
        seq_column = columns.index("seq_num") + 1
        with tmp_path.open("wb", buffering=0) as output_file:
            output_file.write(header)
            subprocess.run(
                ["sort", "-s", "-t,", f"-k{seq_column},{seq_column}n"],
                stdin=input_file,
                stdout=output_file,
                check=True,
            )
    os.replace(tmp_path, trace_path)


def _parse_seq_num(row: dict[str, str]) -> int | None:
    try:
        return int(row.get("seq_num", ""))
    except ValueError:
        return None


def _cache_hit_value(value: str | None) -> bool | None:
    if value == "1":
        return True
    if value == "0":
        return False
    return None


def _load_l1d_accesses(
    l1d_trace_path: Path,
) -> tuple[dict[int, _L1DAccessSummary], int]:
    accesses: dict[int, _L1DAccessSummary] = {}
    malformed_rows = 0

    with Path(l1d_trace_path).open("r", encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            seq_num = _parse_seq_num(row)
            cache_hit = _cache_hit_value(row.get("cache_hit"))
            if seq_num is None or cache_hit is None:
                malformed_rows += 1
                continue

            summary = accesses.setdefault(seq_num, _L1DAccessSummary())
            summary.rows += 1
            summary.cache_hit = summary.cache_hit and cache_hit

    return accesses, malformed_rows


def _join_committed_and_l1d_traces(
    committed_trace_path: Path,
    l1d_trace_path: Path,
    output_path: Path,
) -> TraceJoinStats:
    l1d_accesses, malformed_l1d_rows = _load_l1d_accesses(l1d_trace_path)
    unmatched_l1d_seq_nums = set(l1d_accesses)

    committed_rows = 0
    joined_rows = 0
    committed_without_l1d = 0
    malformed_committed_rows = 0

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_path.with_name(output_path.name + ".join.tmp")

    with Path(committed_trace_path).open(
        "r", encoding="utf-8", newline=""
    ) as committed_file, tmp_path.open(
        "w", encoding="utf-8", newline=""
    ) as output_file:
        reader = csv.DictReader(committed_file)
        writer = csv.DictWriter(output_file, fieldnames=JOINED_TRACE_HEADER)
        writer.writeheader()

        for row in reader:
            seq_num = _parse_seq_num(row)
            if seq_num is None:
                malformed_committed_rows += 1
                continue

            committed_rows += 1
            output_row = {
                column: row.get(column, "")
                for column in COMMITTED_TRACE_HEADER
            }
            l1d_summary = l1d_accesses.get(seq_num)
            if l1d_summary is None:
                output_row["l1d_access"] = "0"
                output_row["cache_hit"] = ""
                committed_without_l1d += 1
            else:
                output_row["l1d_access"] = "1"
                output_row["cache_hit"] = "1" if l1d_summary.cache_hit else "0"
                joined_rows += 1
                unmatched_l1d_seq_nums.discard(seq_num)

            writer.writerow(output_row)

    os.replace(tmp_path, output_path)
    l1d_only_rows = sum(
        l1d_accesses[seq_num].rows for seq_num in unmatched_l1d_seq_nums
    )
    return TraceJoinStats(
        committed_rows=committed_rows,
        joined_rows=joined_rows,
        committed_without_l1d=committed_without_l1d,
        l1d_only_rows=l1d_only_rows,
        malformed_committed_rows=malformed_committed_rows,
        malformed_l1d_rows=malformed_l1d_rows,
    )


def _finalize_joined_trace_for_outdir(outdir: Path) -> None:
    outdir = Path(outdir)
    cpu_trace_path = _cpu_trace_path_for_outdir(outdir)
    l1d_trace_path = _l1d_trace_path_for_outdir(outdir)
    joined_trace_path = _joined_trace_path_for_outdir(outdir)

    _sort_trace_by_seq_num(l1d_trace_path)
    stats = _join_committed_and_l1d_traces(
        cpu_trace_path, l1d_trace_path, joined_trace_path
    )
    print(
        f"Joined committed and L1D traces into {joined_trace_path}: "
        f"committed_rows={stats.committed_rows}, "
        f"joined_rows={stats.joined_rows}, "
        f"committed_without_l1d={stats.committed_without_l1d}, "
        f"l1d_only_rows={stats.l1d_only_rows}, "
        f"malformed_committed_rows={stats.malformed_committed_rows}, "
        f"malformed_l1d_rows={stats.malformed_l1d_rows}"
    )


class CryptoCommitTraceCaptureSimulator:
    def __init__(
        self,
        benchmark_name: str,
        binary_path: Path,
        arguments: list[str],
    ) -> None:
        self._benchmark_name = benchmark_name
        self._binary_path = binary_path
        self._arguments = arguments
        self._outdir = None
        self._id = f"crypto_{benchmark_name}_commit_trace"

    def get_id(self):
        return self._id

    def set_id(self, simulator_id: str) -> None:
        self._id = simulator_id

    def override_outdir(self, outdir: Path) -> None:
        self._outdir = Path(outdir)

    def _build_simulator(self) -> Simulator:
        cache_hierarchy = base.ThreeLevelClassicCacheHierarchy(
            prefetcher_map=DISABLED_PREFETCHER_MAP,
            **{f"l1d_{k}": v for k, v in base.L1D_CONFIG.items()},
            **{f"l1i_{k}": v for k, v in base.L1I_CONFIG.items()},
            **{f"l2_{k}": v for k, v in base.L2_CONFIG.items()},
            **{f"l3_{k}": v for k, v in base.L3_CONFIG.items()},
            cache_line_size=base.CACHE_LINE_SIZE,
            l1d_trace_file=COMMIT_TRACE_FILE,
        )
        cpu = base._create_x86_o3_cpu()
        cpu.traceListener = SimpleMemTrace()
        cpu.traceListener.traceFile = COMMIT_TRACE_FILE
        board = SimpleBoard(
            clk_freq=base.CLOCK_FREQUENCY,
            processor=BaseCPUProcessor(
                cores=[BaseCPUCore(core=cpu, isa=ISA.X86)]
            ),
            memory=SingleChannelDDR4_2400(size=base.MEMORY_SIZE),
            cache_hierarchy=cache_hierarchy,
        )
        board.set_se_binary_workload(
            binary=BinaryResource(
                local_path=str(self._binary_path), architecture=ISA.X86
            ),
            arguments=self._arguments,
        )

        return Simulator(board=board, id=self._id, outdir=self._outdir)

    def run(self) -> None:
        outdir = (
            Path(self._outdir)
            if self._outdir is not None
            else base.M5OUT_ROOT / self._id
        )
        atexit.register(_finalize_joined_trace_for_outdir, outdir)
        self._build_simulator().run()


active_benchmarks = [
    name for name, enabled in base.ENABLED_BENCHMARKS.items() if enabled
]
if not active_benchmarks:
    raise RuntimeError("At least one benchmark must be enabled.")

multisim.set_num_processes(
    min(base.MAX_PARALLEL_SIMULATIONS, len(active_benchmarks))
)

for benchmark_name in active_benchmarks:
    multisim.add_simulator(
        CryptoCommitTraceCaptureSimulator(
            benchmark_name=benchmark_name,
            binary_path=base._resolve_binary_path(
                base.BENCHMARK_PATH_CANDIDATES[benchmark_name]
            ),
            arguments=base.BENCHMARK_ARGUMENTS.get(benchmark_name, []),
        )
    )
