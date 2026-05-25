# Copyright (c) 2026
#
# MultiSim SE benchmark runner for crypto workloads with a custom x86 O3 core.
#
# Run from the gem5 root directory:
#   build/X86/gem5.opt -m gem5.utils.multisim configs/crypto_multisim/multisim_se_x86_o3_crypto.py

import csv
import fcntl
import os
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from m5.objects import (
    LTAGE,
    LTAGE_TAGE,
    X86O3CPU,
    AMPMPrefetcher,
    BadAddr,
    BOPPrefetcher,
    BranchPredictor,
    Cache,
    HintBasedPrefetcher,
    IMPv2Prefetcher,
    IndirectMemoryPrefetcher,
    L2XBar,
    SimpleCacheTrace,
    STeMSPrefetcher,
    StridePrefetcher,
    SystemXBar,
    TaggedPrefetcher,
)

import gem5.utils.multisim as multisim
from gem5.components.boards.simple_board import SimpleBoard
from gem5.components.cachehierarchies.abstract_cache_hierarchy import (
    AbstractCacheHierarchy,
)
from gem5.components.cachehierarchies.classic.abstract_classic_cache_hierarchy import (
    AbstractClassicCacheHierarchy,
)
from gem5.components.memory import SingleChannelDDR4_2400
from gem5.components.processors.base_cpu_core import BaseCPUCore
from gem5.components.processors.base_cpu_processor import BaseCPUProcessor
from gem5.isas import ISA
from gem5.resources.resource import BinaryResource
from gem5.simulate.simulator import Simulator
from gem5.utils.override import overrides

from generate_prefetch_hints import (
    DEFAULT_TRACE_LINE_LOOKBACK,
    generate_hints_for_lookbacks_from_trace,
)
from inspect_commit_rw_trace import find_trace_file

GEM5_ROOT = SCRIPT_DIR.parent.parent
SRC_ROOT = GEM5_ROOT.parent
M5OUT_ROOT = GEM5_ROOT / "m5out"


# --- Benchmark setup ---
# Flip booleans to quickly include/exclude a benchmark.
ENABLED_BENCHMARKS = {
    "chacha20": True,
    "kyber768": True,
    "sha256": True,
    "curve25519": True,
}

# Paths are relative to SRC_ROOT unless absolute.
BENCHMARK_PATH_CANDIDATES = {
    "chacha20": [
        "crypto-programs/test_openssl/chacha20/test_ossl_chacha20_baseline",
    ],
    # Preferred Kyber768 paths first; current tree may only have 768 baseline
    # prebuilt. Disable kyber768 above or point to your own binary.
    "kyber768": [
        "crypto-programs/kyber/ref/test_kyber768_baseline",
        # "crypto-programs/kyber/avx2/test_kyber768_baseline",
    ],
    "sha256": [
        "crypto-programs/test_openssl/sha256/test_ossl_sha256_baseline",
    ],
    "curve25519": [
        "crypto-programs/test_openssl/curve25519/test_ossl_curve25519_baseline",
    ],
}

BENCHMARK_ARGUMENTS = {
    "chacha20": [],
    "kyber768": [],
    "sha256": [],
    "curve25519": [],
}

MAX_PARALLEL_SIMULATIONS = 16


# --- Architecture setup ---
CLOCK_FREQUENCY = "3GHz"
MEMORY_SIZE = "8GiB"
CACHE_LINE_SIZE = 64

CPU_WIDTH = 8
LOAD_QUEUE_ENTRIES = 192
STORE_QUEUE_ENTRIES = 114
ROB_ENTRIES = 512
IQ_ENTRIES = 96
PHYS_INT_REGS = 280
PHYS_FLOAT_REGS = 332

# None keeps gem5 LTAGE defaults; an integer overrides all logTagTableSizes entries.
LTAGE_LOG_TAG_TABLE_SIZE = None

L1D_CONFIG = {"size": "48KiB", "assoc": 12, "latency": 5}
L1I_CONFIG = {"size": "32KiB", "assoc": 8, "latency": 5}
L2_CONFIG = {
    "size": "1024KiB",
    "assoc": 16,
    "latency": 14,
}  # rounded from 1280KiB
L3_CONFIG = {"size": "32MiB", "assoc": 16, "latency": 40}  # rounded from 30MiB

COMMIT_TRACE_START_INST = 0

PREFETCHER_TYPES = [
    None,
    "hint",
    # "indirect",
    # "IMPv2",
    # "stride",
    # "tagged",
    # "ampm",
    # "bop",
    # "stems",
]
PREFETCHER_LEVELS = ("l1i", "l1d", "l2", "l3")
# Manually choose which cache-level combinations to sweep.
# Each entry enables prefetcher variation only on those levels.
# Levels not listed in an entry are fixed to None for that entry.
# Example:
# LEVEL_COMBINATIONS_TO_TEST = [
#     ("l1d",),
#     ("l2",),
#     ("l1d", "l2"),
#     ("l1i", "l1d", "l2", "l3"),
# ]
LEVEL_COMBINATIONS_TO_TEST = [
    ("l1i",),
    ("l1d",),
    ("l2",),
    ("l3",),
    ("l1d", "l2"),
    ("l1d", "l3"),
    ("l2", "l3"),
    ("l1d", "l2", "l3"),
    ("l1i", "l1d", "l2", "l3"),  # all levels
]
SUMMARY_CSV_NAME = "crypto_prefetcher_sweep.csv"
DEFAULT_HINT_LOOKBACK = DEFAULT_TRACE_LINE_LOOKBACK
# HINT_LOOKBACKS_TO_TEST = [1, 2, 3, 4, 5, 10, 20]
HINT_LOOKBACKS_TO_TEST = range(1, 31)
HINT_GENERATION_PARALLELISM = min(
    MAX_PARALLEL_SIMULATIONS, len(HINT_LOOKBACKS_TO_TEST)
)
DEFAULT_HINT_CSV_NAME = f"hints_trace{DEFAULT_HINT_LOOKBACK}.csv"
HINT_GENERATION_LOCK_NAME = ".crypto_hints_trace_lookbacks.lock"


def hint_csv_name(trace_lookback: int = DEFAULT_HINT_LOOKBACK) -> str:
    return f"hints_trace{trace_lookback}.csv"


def default_hint_path(
    benchmark_name: str,
    trace_lookback: int = DEFAULT_HINT_LOOKBACK,
) -> Path:
    return (
        M5OUT_ROOT
        / f"crypto_{benchmark_name}_commit_trace"
        / hint_csv_name(trace_lookback)
    )


def _hint_generation_lock_path() -> Path:
    M5OUT_ROOT.mkdir(parents=True, exist_ok=True)
    return M5OUT_ROOT / HINT_GENERATION_LOCK_NAME


def _hint_generation_dependencies(trace_path: Path) -> list[Path]:
    """List of files that the hint generation depends on. If any of these files are newer than the generated hint file, the hints likely need to be regenerated."""
    return [
        trace_path,
        Path(__file__).resolve(),
        SCRIPT_DIR / "generate_prefetch_hints.py",
    ]


def _hint_file_is_current(
    output_path: Path, dependency_paths: list[Path]
) -> bool:
    """Check if the hint file exists and is newer than all dependencies. If not, it likely needs to be regenerated."""
    if not output_path.is_file():
        return False
    if any(not path.is_file() for path in dependency_paths):
        return False

    output_mtime = output_path.stat().st_mtime
    return all(
        output_mtime >= path.stat().st_mtime for path in dependency_paths
    )


def _hint_generation_parallelism(job_count: int) -> int:
    my_max = HINT_GENERATION_PARALLELISM
    my_max = 16
    return max(1, min(my_max, job_count))


class ThreeLevelClassicCacheHierarchy(AbstractClassicCacheHierarchy):
    """Private L1/L2 per-core with a shared L3 and classic memory system."""

    _PREFETCHER_CLASSES = {
        "hint": HintBasedPrefetcher,
        "indirect": IndirectMemoryPrefetcher,
        "IMPv2": IMPv2Prefetcher,
        "stride": StridePrefetcher,
        "tagged": TaggedPrefetcher,
        "ampm": AMPMPrefetcher,
        "bop": BOPPrefetcher,
        "stems": STeMSPrefetcher,
    }

    def __init__(
        self,
        prefetcher_map: dict[str, str | None],
        l1d_size: str,
        l1d_assoc: int,
        l1d_latency: int,
        l1i_size: str,
        l1i_assoc: int,
        l1i_latency: int,
        l2_size: str,
        l2_assoc: int,
        l2_latency: int,
        l3_size: str,
        l3_assoc: int,
        l3_latency: int,
        benchmark_name: str | None = None,
        hint_lookback: int = DEFAULT_HINT_LOOKBACK,
        cache_line_size: int = 64,
        l1d_trace_file: str | None = None,
    ) -> None:
        super().__init__()
        self._prefetcher_map = prefetcher_map
        self._benchmark_name = benchmark_name
        self._hint_lookback = hint_lookback
        self._l1d_trace_file = l1d_trace_file
        self._l1d_caches = []
        self._l1d_size, self._l1d_assoc, self._l1d_latency = (
            l1d_size,
            l1d_assoc,
            l1d_latency,
        )
        self._l1i_size, self._l1i_assoc, self._l1i_latency = (
            l1i_size,
            l1i_assoc,
            l1i_latency,
        )
        self._l2_size, self._l2_assoc, self._l2_latency = (
            l2_size,
            l2_assoc,
            l2_latency,
        )
        self._l3_size, self._l3_assoc, self._l3_latency = (
            l3_size,
            l3_assoc,
            l3_latency,
        )
        self._cache_line_size = cache_line_size

        self.membus = SystemXBar(width=64)
        self.membus.badaddr_responder = BadAddr()
        self.membus.default = self.membus.badaddr_responder.pio

    def _hint_file_path(self) -> Path:
        if self._benchmark_name is None:
            raise ValueError(
                "HintBasedPrefetcher requires benchmark_name to resolve hints"
            )
        return default_hint_path(self._benchmark_name, self._hint_lookback)

    def _get_prefetcher(self, level: str, cache: Cache | None = None, cpu=None):
        prefetcher_type = self._prefetcher_map.get(level)
        if prefetcher_type is None:
            return None
        if prefetcher_type not in self._PREFETCHER_CLASSES:
            raise ValueError(
                f"Unknown prefetcher type {prefetcher_type!r} for level {level}. "
                "Use one of: None, 'hint', 'indirect', 'IMPv2', 'stride', "
                "'tagged', 'ampm', 'bop', 'stems'."
            )
        if prefetcher_type == "hint":
            if cache is None or cpu is None:
                raise ValueError(
                    "HintBasedPrefetcher requires a cache and CPU probe source"
                )
            prefetcher = HintBasedPrefetcher(
                hints_file=str(self._hint_file_path()),
                on_inst=False,
                on_write=False,
                on_miss=False,
                prefetch_on_access=False,
            )
            prefetcher.registerCache(cache)
            prefetcher.listenFromProbeO3CommitInstructions(
                cpu.get_simobject()
            )
            return prefetcher
        if prefetcher_type == "indirect":
            # In this gem5 version, IndirectMemoryPrefetcher may receive hit
            # probes with requests that do not carry payload data. Restricting
            # it to miss events avoids PrefetchInfo::get() panics.
            return IndirectMemoryPrefetcher(
                on_inst=False,
                on_write=False,
                on_miss=True,
                prefetch_on_pf_hit=False,
            )
        # if prefetcher_type == "IMPv2":
        #     # IMPv2 is optimized for miss-based prefetching to avoid issues
        #     # with prefetch hit probes that lack payload data
        #     return IMPv2Prefetcher(
        #         on_inst=False,
        #         on_write=False,
        #         on_miss=True,
        #         prefetch_on_pf_hit=False,
        #     )
        return self._PREFETCHER_CLASSES[prefetcher_type]()

    @overrides(AbstractClassicCacheHierarchy)
    def get_mem_side_port(self):
        return self.membus.mem_side_ports

    @overrides(AbstractClassicCacheHierarchy)
    def get_cpu_side_port(self):
        return self.membus.cpu_side_ports

    @overrides(AbstractCacheHierarchy)
    def incorporate_cache(self, board):
        board.cache_line_size = self._cache_line_size
        board.connect_system_port(self.membus.cpu_side_ports)
        cores = list(board.get_processor().get_cores())
        hint_core = cores[0] if cores else None

        for _, port in board.get_mem_ports():
            self.membus.mem_side_ports = port

        self.l3bus = L2XBar(width=64)
        self._l3cache = Cache(
            size=self._l3_size,
            assoc=self._l3_assoc,
            tag_latency=self._l3_latency,
            data_latency=self._l3_latency,
            response_latency=self._l3_latency,
            mshrs=64,
            tgts_per_mshr=32,
            clusivity="mostly_incl",
        )
        l3_prefetcher = self._get_prefetcher("l3", self._l3cache, hint_core)
        if l3_prefetcher is not None:
            self._l3cache.prefetcher = l3_prefetcher
        l3_node = self.add_root_child("l3_cache", self._l3cache)
        self._l3cache.cpu_side = self.l3bus.mem_side_ports
        self._l3cache.mem_side = self.membus.cpu_side_ports

        for i, cpu in enumerate(cores):
            l2bus = L2XBar(width=64)
            setattr(self, f"l2bus_{i}", l2bus)

            l2cache = Cache(
                size=self._l2_size,
                assoc=self._l2_assoc,
                tag_latency=self._l2_latency,
                data_latency=self._l2_latency,
                response_latency=self._l2_latency,
                mshrs=32,
                tgts_per_mshr=24,
                clusivity="mostly_incl",
            )
            l2_prefetcher = self._get_prefetcher("l2", l2cache, cpu)
            if l2_prefetcher is not None:
                l2cache.prefetcher = l2_prefetcher
            l2_node = l3_node.add_child(f"l2_cache_{i}", l2cache)

            l1icache = Cache(
                size=self._l1i_size,
                assoc=self._l1i_assoc,
                tag_latency=self._l1i_latency,
                data_latency=self._l1i_latency,
                response_latency=self._l1i_latency,
                mshrs=16,
                tgts_per_mshr=20,
                is_read_only=True,
                writeback_clean=False,
            )
            l1i_prefetcher = self._get_prefetcher("l1i", l1icache, cpu)
            if l1i_prefetcher is not None:
                l1icache.prefetcher = l1i_prefetcher
            l2_node.add_child(f"l1i_cache_{i}", l1icache)

            l1dcache = Cache(
                size=self._l1d_size,
                assoc=self._l1d_assoc,
                tag_latency=self._l1d_latency,
                data_latency=self._l1d_latency,
                response_latency=self._l1d_latency,
                mshrs=16,
                tgts_per_mshr=20,
                writeback_clean=False,
            )
            self._l1d_caches.append(l1dcache)
            if self._l1d_trace_file is not None:
                l1dcache.traceListener = SimpleCacheTrace(
                    traceFile=self._l1d_trace_file
                )
            l1d_prefetcher = self._get_prefetcher("l1d", l1dcache, cpu)
            if l1d_prefetcher is not None:
                l1dcache.prefetcher = l1d_prefetcher
            l2_node.add_child(f"l1d_cache_{i}", l1dcache)

            l2bus.mem_side_ports = l2cache.cpu_side
            l2cache.mem_side = self.l3bus.cpu_side_ports
            l1icache.mem_side = l2bus.cpu_side_ports
            l1dcache.mem_side = l2bus.cpu_side_ports

            cpu.connect_icache(l1icache.cpu_side)
            cpu.connect_dcache(l1dcache.cpu_side)
            cpu.connect_walker_ports(
                l2bus.cpu_side_ports, l2bus.cpu_side_ports
            )
            cpu.connect_interrupt(
                self.membus.mem_side_ports, self.membus.cpu_side_ports
            )


def _create_x86_o3_cpu(cpu_id: int = 0) -> X86O3CPU:
    cpu = X86O3CPU(cpu_id=cpu_id)

    cpu.fetchWidth = CPU_WIDTH
    cpu.decodeWidth = CPU_WIDTH
    cpu.renameWidth = CPU_WIDTH
    cpu.dispatchWidth = CPU_WIDTH
    cpu.issueWidth = CPU_WIDTH
    cpu.wbWidth = CPU_WIDTH
    cpu.commitWidth = CPU_WIDTH

    cpu.LQEntries = LOAD_QUEUE_ENTRIES
    cpu.SQEntries = STORE_QUEUE_ENTRIES
    cpu.numROBEntries = ROB_ENTRIES
    cpu.instQueues[0].numEntries = IQ_ENTRIES
    cpu.numPhysIntRegs = PHYS_INT_REGS
    cpu.numPhysFloatRegs = PHYS_FLOAT_REGS

    if LTAGE_LOG_TAG_TABLE_SIZE is None:
        cpu.branchPred = BranchPredictor(conditionalBranchPred=LTAGE())
    else:
        tage = LTAGE_TAGE()
        tage.logTagTableSizes = [int(LTAGE_LOG_TAG_TABLE_SIZE)] * len(
            tage.logTagTableSizes
        )
        cpu.branchPred = BranchPredictor(
            conditionalBranchPred=LTAGE(tage=tage)
        )

    return cpu


def _prefetcher_slug(prefetcher_type: str | None) -> str:
    return "none" if prefetcher_type is None else prefetcher_type.lower()


def _prefetcher_map_has_hint(prefetcher_map: dict[str, str | None]) -> bool:
    return any(
        prefetcher_type == "hint" for prefetcher_type in prefetcher_map.values()
    )


def _hint_lookbacks_for_prefetcher_map(
    prefetcher_map: dict[str, str | None],
) -> list[int | None]:
    if _prefetcher_map_has_hint(prefetcher_map):
        return list(HINT_LOOKBACKS_TO_TEST)
    return [None]


def _benchmark_label(
    benchmark_name: str,
    prefetcher_map: dict[str, str | None],
    hint_lookback: int | None,
) -> str:
    if _prefetcher_map_has_hint(prefetcher_map):
        if hint_lookback is None:
            raise ValueError("hint prefetcher simulations require hint_lookback")
        return f"{benchmark_name}_trace{hint_lookback}"
    return benchmark_name


def _simulation_id(
    benchmark_name: str,
    prefetcher_map: dict[str, str | None],
    hint_lookback: int | None,
) -> str:
    benchmark_label = _benchmark_label(
        benchmark_name, prefetcher_map, hint_lookback
    )
    return (
        "crypto_"
        + benchmark_label
        + "__"
        + "_".join(
            f"{level}-{_prefetcher_slug(prefetcher_map[level])}"
            for level in PREFETCHER_LEVELS
        )
    )


def _make_prefetcher_map(
    prefetchers: tuple[str | None, str | None, str | None, str | None],
) -> dict[str, str | None]:
    return dict(zip(PREFETCHER_LEVELS, prefetchers, strict=True))


def _validate_level_combination(
    level_combination: tuple[str, ...],
) -> tuple[str, ...]:
    invalid_levels = [
        level for level in level_combination if level not in PREFETCHER_LEVELS
    ]
    if invalid_levels:
        raise ValueError(
            "Invalid cache levels in LEVEL_COMBINATIONS_TO_TEST: "
            + ", ".join(invalid_levels)
            + f". Valid levels are: {', '.join(PREFETCHER_LEVELS)}"
        )
    return tuple(dict.fromkeys(level_combination))


def _iter_prefetcher_maps_for_level_combination(
    level_combination: tuple[str, ...],
):
    active_levels = set(_validate_level_combination(level_combination))
    for selected_prefetcher in PREFETCHER_TYPES:
        yield {
            level: (selected_prefetcher if level in active_levels else None)
            for level in PREFETCHER_LEVELS
        }


def _summary_path() -> Path:
    M5OUT_ROOT.mkdir(parents=True, exist_ok=True)
    return M5OUT_ROOT / SUMMARY_CSV_NAME


def _completed_summary_ids() -> set[str]:
    summary_file = _summary_path()
    if not summary_file.is_file():
        return set()

    completed_ids = set()
    with summary_file.open("r", encoding="utf-8", newline="") as csv_file:
        fcntl.flock(csv_file, fcntl.LOCK_SH)
        try:
            reader = csv.DictReader(csv_file)
            if (
                reader.fieldnames is None
                or "simulation_id" not in reader.fieldnames
            ):
                return set()
            for row in reader:
                simulation_id = (row.get("simulation_id") or "").strip()
                if simulation_id:
                    completed_ids.add(simulation_id)
        finally:
            fcntl.flock(csv_file, fcntl.LOCK_UN)

    return completed_ids


def _extract_stat_value(
    stats_path: Path,
    stat_name: str,
    max_attempts: int = 100,  # 10 seconds
    retry_delay_seconds: float = 0.1,
):
    for attempt in range(max_attempts):
        if stats_path.exists():
            with stats_path.open("r", encoding="utf-8") as stats_file:
                for line in stats_file:
                    stripped = line.strip()
                    if (
                        not stripped
                        or stripped.startswith("#")
                        or stripped.startswith("-")
                    ):
                        continue
                    fields = stripped.split()
                    if len(fields) >= 2 and fields[0] == stat_name:
                        return fields[1]
        if attempt != max_attempts - 1:
            time.sleep(retry_delay_seconds)
    raise KeyError(f"Stat {stat_name!r} not found in {stats_path}")


def _wait_for_stats_ready(
    stats_path: Path,
    max_attempts: int = 120,  # 1 minute
    retry_delay_seconds: float = 0.5,
) -> bool:
    for attempt in range(max_attempts):
        if stats_path.exists() and stats_path.stat().st_size > 0:
            return True
        if attempt != max_attempts - 1:
            time.sleep(retry_delay_seconds)
    return False


def _record_summary_row(
    stats_path: Path,
    benchmark_name: str,
    prefetcher_map: dict[str, str | None],
) -> bool:
    if not _wait_for_stats_ready(stats_path):
        return True

    try:
        sim_seconds = float(_extract_stat_value(stats_path, "simSeconds"))
    except KeyError:
        final_tick = float(_extract_stat_value(stats_path, "finalTick"))
        sim_freq = float(_extract_stat_value(stats_path, "simFreq"))
        sim_seconds = final_tick / sim_freq if sim_freq else float("nan")

    sim_insts = int(_extract_stat_value(stats_path, "simInsts"))

    try:
        sim_cycles = int(
            _extract_stat_value(
                stats_path, "board.processor.cores.core.numCycles"
            )
        )
    except KeyError:
        sim_ticks = float(_extract_stat_value(stats_path, "simTicks"))
        sim_freq = float(_extract_stat_value(stats_path, "simFreq"))
        clock_hz = float(CLOCK_FREQUENCY.rstrip("GHz")) * 1e9
        sim_cycles = int((sim_ticks / sim_freq) * clock_hz) if sim_freq else 0

    try:
        ipc = float(
            _extract_stat_value(stats_path, "board.processor.cores.core.ipc")
        )
    except KeyError:
        ipc = sim_insts / sim_cycles if sim_cycles else float("nan")

    summary_file = _summary_path()
    row = {
        "simulation_id": stats_path.parent.name,
        "benchmark": benchmark_name,
        "l1i_prefetcher": _prefetcher_slug(prefetcher_map["l1i"]),
        "l1d_prefetcher": _prefetcher_slug(prefetcher_map["l1d"]),
        "l2_prefetcher": _prefetcher_slug(prefetcher_map["l2"]),
        "l3_prefetcher": _prefetcher_slug(prefetcher_map["l3"]),
        "ipc": f"{ipc:.6f}",
        "sim_seconds": f"{sim_seconds:.9f}",
        "sim_insts": str(sim_insts),
        "sim_cycles": str(sim_cycles),
    }

    with summary_file.open("a+", encoding="utf-8", newline="") as csv_file:
        fcntl.flock(csv_file, fcntl.LOCK_EX)
        csv_file.seek(0, os.SEEK_END)
        writer = csv.DictWriter(csv_file, fieldnames=list(row.keys()))
        if csv_file.tell() == 0:
            writer.writeheader()
        writer.writerow(row)
        csv_file.flush()
        os.fsync(csv_file.fileno())
        fcntl.flock(csv_file, fcntl.LOCK_UN)

    return True


class CryptoPrefetcherSweepSimulator:
    def __init__(
        self,
        benchmark_name: str,
        binary_path: Path,
        arguments: list[str],
        prefetcher_map: dict[str, str | None],
        hint_lookback: int | None = None,
    ) -> None:
        self._benchmark_name = benchmark_name
        self._benchmark_label = _benchmark_label(
            benchmark_name, prefetcher_map, hint_lookback
        )
        self._hint_lookback = hint_lookback
        self._binary_path = binary_path
        self._arguments = arguments
        self._prefetcher_map = prefetcher_map
        self._outdir = None
        self._id = _simulation_id(
            self._benchmark_name, self._prefetcher_map, self._hint_lookback
        )

    def get_id(self):
        return self._id

    def set_id(self, simulator_id: str) -> None:
        self._id = simulator_id

    def override_outdir(self, outdir: Path) -> None:
        self._outdir = Path(outdir)

    def _build_simulator(self) -> Simulator:
        cache_hierarchy = ThreeLevelClassicCacheHierarchy(
            prefetcher_map=self._prefetcher_map,
            **{f"l1d_{k}": v for k, v in L1D_CONFIG.items()},
            **{f"l1i_{k}": v for k, v in L1I_CONFIG.items()},
            **{f"l2_{k}": v for k, v in L2_CONFIG.items()},
            **{f"l3_{k}": v for k, v in L3_CONFIG.items()},
            benchmark_name=self._benchmark_name,
            hint_lookback=(
                self._hint_lookback
                if self._hint_lookback is not None
                else DEFAULT_HINT_LOOKBACK
            ),
            cache_line_size=CACHE_LINE_SIZE,
        )
        board = SimpleBoard(
            clk_freq=CLOCK_FREQUENCY,
            processor=BaseCPUProcessor(
                cores=[BaseCPUCore(core=_create_x86_o3_cpu(), isa=ISA.X86)]
            ),
            memory=SingleChannelDDR4_2400(size=MEMORY_SIZE),
            cache_hierarchy=cache_hierarchy,
        )
        board.set_se_binary_workload(
            binary=BinaryResource(
                local_path=str(self._binary_path), architecture=ISA.X86
            ),
            arguments=self._arguments,
        )

        return Simulator(
            board=board,
            id=self._id,
            outdir=self._outdir,
        )

    def run(self) -> None:
        simulator = self._build_simulator()
        simulator.run()
        if self._outdir is not None:
            try:
                import m5

                m5.stats.dump()
                _record_summary_row(
                    stats_path=self._outdir / "stats.txt",
                    benchmark_name=self._benchmark_label,
                    prefetcher_map=self._prefetcher_map,
                )
            except Exception as summary_error:
                print(
                    "Warning: could not append summary row for "
                    f"{self._id}: {summary_error}"
                )


def _resolve_binary_path(candidates):
    for candidate in candidates:
        path = Path(candidate)
        if not path.is_absolute():
            path = SRC_ROOT / path
        resolved = path.resolve()
        if resolved.is_file() and resolved.stat().st_mode & 0o111:
            return resolved
    raise FileNotFoundError(
        "Could not find an executable benchmark binary. Checked:\n"
        + "\n".join(f"  - {c}" for c in candidates)
        + "\nBuild the target, update BENCHMARK_PATH_CANDIDATES, or disable it."
    )


def _resolve_hint_generation_inputs(
    benchmark_names: list[str],
    hint_lookbacks: list[int] = HINT_LOOKBACKS_TO_TEST,
) -> list[tuple[str, Path, Path, Path, int]]:
    resolved_inputs: list[tuple[str, Path, Path, Path, int]] = []
    errors: list[str] = []

    for benchmark_name in benchmark_names:
        trace_path = None
        binary_path = None
        try:
            trace_path = find_trace_file(benchmark_name).resolve()
        except FileNotFoundError as error:
            errors.append(str(error))

        try:
            binary_path = _resolve_binary_path(
                BENCHMARK_PATH_CANDIDATES[benchmark_name]
            )
        except (KeyError, FileNotFoundError) as error:
            errors.append(str(error))

        if trace_path is not None and binary_path is not None:
            for hint_lookback in hint_lookbacks:
                resolved_inputs.append(
                    (
                        benchmark_name,
                        trace_path,
                        binary_path,
                        default_hint_path(benchmark_name, hint_lookback),
                        hint_lookback,
                    )
                )

    if errors:
        raise FileNotFoundError(
            "Cannot generate hint prefetcher inputs before running the "
            "sweep. Generate commit traces first with "
            "multisim_se_x86_o3_crypto_commit_trace.py.\n"
            + "\n".join(f"  - {error}" for error in errors)
        )

    return resolved_inputs


def _generate_hint_files_for_benchmarks(benchmark_names: list[str]) -> None:
    if "hint" not in PREFETCHER_TYPES:
        return

    hint_inputs = _resolve_hint_generation_inputs(
        benchmark_names, HINT_LOOKBACKS_TO_TEST
    )
    lock_path = _hint_generation_lock_path()

    with lock_path.open("w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        print(
            "Generating hint prefetcher inputs for enabled crypto benchmarks "
            f"(trace-line lookbacks={HINT_LOOKBACKS_TO_TEST})"
        )
        stale_hint_files = {}
        for (
            benchmark_name,
            trace_path,
            binary_path,
            output_path,
            hint_lookback,
        ) in hint_inputs:
            dependencies = _hint_generation_dependencies(trace_path)
            if _hint_file_is_current(output_path, dependencies):
                print(
                    f"  {benchmark_name} trace{hint_lookback}: "
                    f"hints are current at {output_path}"
                )
                continue
            key = (benchmark_name, trace_path)
            stale_hint_files.setdefault(key, {})[hint_lookback] = output_path

        for (benchmark_name, trace_path), output_paths in stale_hint_files.items():
            hint_lookbacks = list(output_paths)
            max_workers = _hint_generation_parallelism(len(hint_lookbacks))
            print(
                f"  {benchmark_name}: generating {len(hint_lookbacks)} "
                f"stale hint files with {max_workers} worker processes"
            )
            results = generate_hints_for_lookbacks_from_trace(
                trace_path=trace_path,
                trace_lookbacks=hint_lookbacks,
                output_path_for_lookback=(
                    lambda lookback, output_paths=output_paths: output_paths[lookback]
                ),
                max_workers=max_workers,
            )
            for result in results:
                print(
                    f"  {benchmark_name} trace{result.trace_lookback}: "
                    f"wrote {result.stats.hints_written} hints from "
                    f"{result.stats.rows_read} trace rows to "
                    f"{result.output_path}"
                )
        fcntl.flock(lock_file, fcntl.LOCK_UN)


def main() -> None:
    active_benchmarks = [
        name for name, enabled in ENABLED_BENCHMARKS.items() if enabled
    ]
    if not active_benchmarks:
        raise RuntimeError("At least one benchmark must be enabled.")

    _generate_hint_files_for_benchmarks(active_benchmarks)

    completed_simulation_ids = _completed_summary_ids()
    skipped_completed = 0
    simulator_specs = []
    seen_specs = set()
    for benchmark_name in active_benchmarks:
        for level_combination in LEVEL_COMBINATIONS_TO_TEST:
            for prefetcher_map in _iter_prefetcher_maps_for_level_combination(
                level_combination
            ):
                for hint_lookback in _hint_lookbacks_for_prefetcher_map(
                    prefetcher_map
                ):
                    key = (
                        benchmark_name,
                        tuple(
                            prefetcher_map[level]
                            for level in PREFETCHER_LEVELS
                        ),
                        hint_lookback,
                    )
                    if key in seen_specs:
                        continue
                    seen_specs.add(key)

                    simulation_id = _simulation_id(
                        benchmark_name, prefetcher_map, hint_lookback
                    )
                    if simulation_id in completed_simulation_ids:
                        skipped_completed += 1
                        continue

                    simulator_specs.append(
                        (benchmark_name, prefetcher_map, hint_lookback)
                    )

    if skipped_completed:
        print(
            f"Resume: skipping {skipped_completed} simulations already "
            f"present in {_summary_path()}"
        )
    if not simulator_specs:
        print("Resume: no remaining simulations to schedule.")
        return

    multisim.set_num_processes(
        min(MAX_PARALLEL_SIMULATIONS, len(simulator_specs))
    )

    for benchmark_name, prefetcher_map, hint_lookback in simulator_specs:
        multisim.add_simulator(
            CryptoPrefetcherSweepSimulator(
                benchmark_name=benchmark_name,
                binary_path=_resolve_binary_path(
                    BENCHMARK_PATH_CANDIDATES[benchmark_name]
                ),
                arguments=BENCHMARK_ARGUMENTS.get(benchmark_name, []),
                prefetcher_map=prefetcher_map,
                hint_lookback=hint_lookback,
            )
        )


if __name__ in {"__m5_main__", "gem5target"}:
    main()
