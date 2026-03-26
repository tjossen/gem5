# Copyright (c) 2026
#
# MultiSim SE benchmark runner for crypto workloads with a custom x86 O3 core.
#
# Run from the gem5 root directory:
#   build/X86/gem5.opt -m gem5.utils.multisim \
#       configs/crypto_multisim/multisim_se_x86_o3_crypto.py

from pathlib import Path

import gem5.utils.multisim as multisim
from m5.objects import (
    AMPMPrefetcher,
    BadAddr,
    BOPPrefetcher,
    BranchPredictor,
    Cache,
    IndirectMemoryPrefetcher,
    IMPv2Prefetcher,
    L2XBar,
    LTAGE,
    LTAGE_TAGE,
    STeMSPrefetcher,
    StridePrefetcher,
    SystemXBar,
    TaggedPrefetcher,
    X86O3CPU,
)

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
GEM5_ROOT  = SCRIPT_DIR.parent.parent
SRC_ROOT   = GEM5_ROOT.parent


# --- Benchmark setup ---
# Flip booleans to quickly include/exclude a benchmark.
ENABLED_BENCHMARKS = {
    "chacha20":   True,
    "kyber512":   True, 
    "sha256":     True,
    "curve25519": True,
}

# Paths are relative to SRC_ROOT unless absolute.
BENCHMARK_PATH_CANDIDATES = {
    "chacha20": [
        "crypto-programs/test_openssl/chacha20/test_ossl_chacha20_baseline",
    ],
    # Preferred Kyber512 paths first; current tree may only have 768 baseline
    # prebuilt. Disable kyber512 above or point to your own binary.
    "kyber512": [
        "crypto-programs/kyber/ref/test/test_kyber512",
        "crypto-programs/kyber/avx2/test/test_kyber512",
        "crypto-programs/kyber/ref/test_kyber768_baseline",
        "crypto-programs/kyber/avx2/test_kyber768_baseline",
    ],
    "sha256": [
        "crypto-programs/test_openssl/sha256/test_ossl_sha256_baseline",
    ],
    "curve25519": [
        "crypto-programs/test_openssl/curve25519/test_ossl_curve25519_baseline",
    ],
}

BENCHMARK_ARGUMENTS = {
    "chacha20":   [],
    "kyber512":   [],
    "sha256":     [],
    "curve25519": [],
}

MAX_PARALLEL_SIMULATIONS = 4


# --- Architecture setup ---
CLOCK_FREQUENCY = "3GHz"
MEMORY_SIZE     = "8GiB"
CACHE_LINE_SIZE = 64

CPU_WIDTH           = 8
LOAD_QUEUE_ENTRIES  = 192
STORE_QUEUE_ENTRIES = 114
ROB_ENTRIES         = 512
IQ_ENTRIES          = 96
PHYS_INT_REGS       = 280
PHYS_FLOAT_REGS     = 332

# None keeps gem5 LTAGE defaults; an integer overrides all logTagTableSizes entries.
LTAGE_LOG_TAG_TABLE_SIZE = None

L1D_CONFIG = {"size": "48KiB",   "assoc": 12, "latency": 5}
L1I_CONFIG = {"size": "32KiB",   "assoc": 8,  "latency": 5}
L2_CONFIG  = {"size": "1024KiB", "assoc": 16, "latency": 14}  # rounded from 1280KiB
L3_CONFIG  = {"size": "32MiB",   "assoc": 16, "latency": 40}  # rounded from 30MiB

# Set PREFETCHER_TYPE = None to disable; options: "indirect", "IMPv2", "stride", "tagged", "ampm", "bop", "stems".
PREFETCHER_TYPE   = "IMPv2"
PREFETCHER_LEVELS = {"l1i": False, "l1d": True, "l2": True, "l3": False}


class ThreeLevelClassicCacheHierarchy(AbstractClassicCacheHierarchy):
    """Private L1/L2 per-core with a shared L3 and classic memory system."""

    _PREFETCHER_CLASSES = {
        "indirect": IndirectMemoryPrefetcher,
        "IMPv2":  IMPv2Prefetcher,
        "stride": StridePrefetcher,
        "tagged": TaggedPrefetcher,
        "ampm":   AMPMPrefetcher,
        "bop":    BOPPrefetcher,
        "stems":  STeMSPrefetcher,
    }

    def __init__(
        self,
        l1d_size: str, l1d_assoc: int, l1d_latency: int,
        l1i_size: str, l1i_assoc: int, l1i_latency: int,
        l2_size: str,  l2_assoc: int,  l2_latency: int,
        l3_size: str,  l3_assoc: int,  l3_latency: int,
        cache_line_size: int = 64,
    ) -> None:
        super().__init__()
        self._l1d_size, self._l1d_assoc, self._l1d_latency = l1d_size, l1d_assoc, l1d_latency
        self._l1i_size, self._l1i_assoc, self._l1i_latency = l1i_size, l1i_assoc, l1i_latency
        self._l2_size,  self._l2_assoc,  self._l2_latency  = l2_size,  l2_assoc,  l2_latency
        self._l3_size,  self._l3_assoc,  self._l3_latency  = l3_size,  l3_assoc,  l3_latency
        self._cache_line_size = cache_line_size

        self.membus = SystemXBar(width=64)
        self.membus.badaddr_responder = BadAddr()
        self.membus.default = self.membus.badaddr_responder.pio

    def _get_prefetcher(self, level: str):
        if PREFETCHER_TYPE is None or not PREFETCHER_LEVELS.get(level, False):
            return None
        if PREFETCHER_TYPE not in self._PREFETCHER_CLASSES:
            raise ValueError(
                f"Unknown PREFETCHER_TYPE {PREFETCHER_TYPE!r}. "
                "Use one of: None, 'indirect', 'IMPv2', 'stride', 'tagged', 'ampm', 'bop', 'stems'."
            )
        if PREFETCHER_TYPE == "indirect":
            # In this gem5 version, IndirectMemoryPrefetcher may receive hit
            # probes with requests that do not carry payload data. Restricting
            # it to miss events avoids PrefetchInfo::get() panics.
            return IndirectMemoryPrefetcher(
                on_inst=False,
                on_write=False,
                on_miss=True,
                prefetch_on_pf_hit=False,
            )
        # if PREFETCHER_TYPE == "IMPv2":
        #     # IMPv2 is optimized for miss-based prefetching to avoid issues
        #     # with prefetch hit probes that lack payload data
        #     return IMPv2Prefetcher(
        #         on_inst=False,
        #         on_write=False,
        #         on_miss=True,
        #         prefetch_on_pf_hit=False,
        #     )
        return self._PREFETCHER_CLASSES[PREFETCHER_TYPE]()

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
        l3_prefetcher = self._get_prefetcher("l3")
        if l3_prefetcher is not None:
            self._l3cache.prefetcher = l3_prefetcher
        l3_node = self.add_root_child("l3_cache", self._l3cache)
        self._l3cache.cpu_side = self.l3bus.mem_side_ports
        self._l3cache.mem_side = self.membus.cpu_side_ports

        for i, cpu in enumerate(board.get_processor().get_cores()):
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
            l2_prefetcher = self._get_prefetcher("l2")
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
            l1i_prefetcher = self._get_prefetcher("l1i")
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
            l1d_prefetcher = self._get_prefetcher("l1d")
            if l1d_prefetcher is not None:
                l1dcache.prefetcher = l1d_prefetcher
            l2_node.add_child(f"l1d_cache_{i}", l1dcache)

            l2bus.mem_side_ports = l2cache.cpu_side
            l2cache.mem_side = self.l3bus.cpu_side_ports
            l1icache.mem_side = l2bus.cpu_side_ports
            l1dcache.mem_side = l2bus.cpu_side_ports

            cpu.connect_icache(l1icache.cpu_side)
            cpu.connect_dcache(l1dcache.cpu_side)
            cpu.connect_walker_ports(l2bus.cpu_side_ports, l2bus.cpu_side_ports)
            cpu.connect_interrupt(self.membus.mem_side_ports, self.membus.cpu_side_ports)


def _create_x86_o3_cpu(cpu_id: int = 0) -> X86O3CPU:
    cpu = X86O3CPU(cpu_id=cpu_id)

    cpu.fetchWidth    = CPU_WIDTH
    cpu.decodeWidth   = CPU_WIDTH
    cpu.renameWidth   = CPU_WIDTH
    cpu.dispatchWidth = CPU_WIDTH
    cpu.issueWidth    = CPU_WIDTH
    cpu.wbWidth       = CPU_WIDTH
    cpu.commitWidth   = CPU_WIDTH

    cpu.LQEntries               = LOAD_QUEUE_ENTRIES
    cpu.SQEntries               = STORE_QUEUE_ENTRIES
    cpu.numROBEntries           = ROB_ENTRIES
    cpu.instQueues[0].numEntries = IQ_ENTRIES
    cpu.numPhysIntRegs          = PHYS_INT_REGS
    cpu.numPhysFloatRegs        = PHYS_FLOAT_REGS

    if LTAGE_LOG_TAG_TABLE_SIZE is None:
        cpu.branchPred = BranchPredictor(conditionalBranchPred=LTAGE())
    else:
        tage = LTAGE_TAGE()
        tage.logTagTableSizes = [int(LTAGE_LOG_TAG_TABLE_SIZE)] * len(tage.logTagTableSizes)
        cpu.branchPred = BranchPredictor(conditionalBranchPred=LTAGE(tage=tage))

    return cpu


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


def _create_board(binary_path: Path, arguments: list[str]) -> SimpleBoard:
    cache_hierarchy = ThreeLevelClassicCacheHierarchy(
        **{f"l1d_{k}": v for k, v in L1D_CONFIG.items()},
        **{f"l1i_{k}": v for k, v in L1I_CONFIG.items()},
        **{f"l2_{k}":  v for k, v in L2_CONFIG.items()},
        **{f"l3_{k}":  v for k, v in L3_CONFIG.items()},
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
        binary=BinaryResource(local_path=str(binary_path), architecture=ISA.X86),
        arguments=arguments,
    )
    return board


active_benchmarks = [name for name, enabled in ENABLED_BENCHMARKS.items() if enabled]
if not active_benchmarks:
    raise RuntimeError("At least one benchmark must be enabled.")

multisim.set_num_processes(min(MAX_PARALLEL_SIMULATIONS, len(active_benchmarks)))

for name in active_benchmarks:
    board = _create_board(
        binary_path=_resolve_binary_path(BENCHMARK_PATH_CANDIDATES[name]),
        arguments=BENCHMARK_ARGUMENTS.get(name, []),
    )
    multisim.add_simulator(Simulator(board=board, id=f"crypto_{name}"))
