# Copyright (c) 2026
#
# MultiSim SE benchmark runner for crypto workloads with a custom x86 O3 core.
#
# Run from the gem5 root directory:
#   build/X86/gem5.opt -m gem5.utils.multisim configs/crypto_multisim/multisim_se_x86_o3_crypto.py

import csv
import fcntl
import os
import time
from pathlib import Path

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

SCRIPT_DIR = Path(__file__).resolve().parent
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
    "indirect",
    "IMPv2",
    "stride",
    "tagged",
    "ampm",
    "bop",
    "stems",
]
# "hint" is intentionally available to hand-selected maps but is not included
# in PREFETCHER_TYPES yet, so the default sweep remains unchanged.
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
DEFAULT_HINT_LOOKBACK = 20
DEFAULT_HINT_CSV_NAME = f"hints_pc{DEFAULT_HINT_LOOKBACK}.csv"


def default_hint_path(benchmark_name: str) -> Path:
    return (
        M5OUT_ROOT
        / f"crypto_{benchmark_name}_commit_trace"
        / DEFAULT_HINT_CSV_NAME
    )


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
        cache_line_size: int = 64,
    ) -> None:
        super().__init__()
        self._prefetcher_map = prefetcher_map
        self._benchmark_name = benchmark_name
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
        return default_hint_path(self._benchmark_name)

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
            prefetcher.listenFromProbeRetiredInstructions(
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
    ) -> None:
        self._benchmark_name = benchmark_name
        self._binary_path = binary_path
        self._arguments = arguments
        self._prefetcher_map = prefetcher_map
        self._outdir = None
        self._id = (
            "crypto_"
            + benchmark_name
            + "__"
            + "_".join(
                f"{level}-{_prefetcher_slug(prefetcher_map[level])}"
                for level in PREFETCHER_LEVELS
            )
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
                    benchmark_name=self._benchmark_name,
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


def main() -> None:
    active_benchmarks = [
        name for name, enabled in ENABLED_BENCHMARKS.items() if enabled
    ]
    if not active_benchmarks:
        raise RuntimeError("At least one benchmark must be enabled.")

    simulator_specs = []
    seen_specs = set()
    for benchmark_name in active_benchmarks:
        for level_combination in LEVEL_COMBINATIONS_TO_TEST:
            for prefetcher_map in _iter_prefetcher_maps_for_level_combination(
                level_combination
            ):
                key = (
                    benchmark_name,
                    tuple(
                        prefetcher_map[level] for level in PREFETCHER_LEVELS
                    ),
                )
                if key not in seen_specs:
                    seen_specs.add(key)
                    simulator_specs.append((benchmark_name, prefetcher_map))

    multisim.set_num_processes(
        min(MAX_PARALLEL_SIMULATIONS, len(simulator_specs))
    )

    for benchmark_name, prefetcher_map in simulator_specs:
        multisim.add_simulator(
            CryptoPrefetcherSweepSimulator(
                benchmark_name=benchmark_name,
                binary_path=_resolve_binary_path(
                    BENCHMARK_PATH_CANDIDATES[benchmark_name]
                ),
                arguments=BENCHMARK_ARGUMENTS.get(benchmark_name, []),
                prefetcher_map=prefetcher_map,
            )
        )


if __name__ == "__m5_main__":
    main()
