# Copyright (c) 2026
#
# MultiSim SE benchmark runner for crypto workloads with ElasticTrace capture.
#
# Run from the gem5 root directory:
#   build/X86/gem5.opt -m gem5.utils.multisim configs/crypto_multisim/multisim_se_x86_o3_crypto_etrace.py

from pathlib import Path

from m5.objects import (
    CommMonitor,
    MemTraceProbe,
    SimpleMemTrace,
)
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
FULL_MEM_TRACE_FILE = "datatraffic.proto.gz"


class TracedThreeLevelClassicCacheHierarchy(
    base.ThreeLevelClassicCacheHierarchy
):
    """Adds packet probes to capture full memory traffic leaving the membus."""

    def __init__(self, *args, trace_file: str, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._trace_file = trace_file
        self._packet_monitors = []
        self._packet_trace_probes = []

    def incorporate_cache(self, board):
        board.cache_line_size = self._cache_line_size
        board.connect_system_port(self.membus.cpu_side_ports)

        # Interpose per-memory-port monitors to observe all requests heading
        # from the cache hierarchy to memory controllers.
        for channel_idx, (_, port) in enumerate(board.get_mem_ports()):
            monitor = CommMonitor()
            trace_file = self._trace_file
            if channel_idx > 0 and trace_file.endswith(".gz"):
                trace_file = trace_file[:-3] + f".chan{channel_idx}.gz"
            elif channel_idx > 0:
                trace_file = trace_file + f".chan{channel_idx}"

            trace_probe = MemTraceProbe(
                manager=[monitor],
                probe_name="PktRequest",
                trace_file=trace_file,
                trace_compress=True,
                with_pc=True,
            )

            monitor.mem_side_port = port
            self.membus.mem_side_ports = monitor.cpu_side_port
            setattr(self, f"packet_monitor_{channel_idx}", monitor)
            setattr(self, f"packet_trace_probe_{channel_idx}", trace_probe)
            self._packet_monitors.append(monitor)
            self._packet_trace_probes.append(trace_probe)

        self.l3bus = base.L2XBar(width=64)
        self._l3cache = base.Cache(
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
            l2bus = base.L2XBar(width=64)
            setattr(self, f"l2bus_{i}", l2bus)

            l2cache = base.Cache(
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

            l1icache = base.Cache(
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

            l1dcache = base.Cache(
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
            cpu.connect_walker_ports(
                l2bus.cpu_side_ports, l2bus.cpu_side_ports
            )
            cpu.connect_interrupt(
                self.membus.mem_side_ports, self.membus.cpu_side_ports
            )


class CryptoTraceCaptureSimulator:
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
        self._id = f"crypto_{benchmark_name}_etrace_fullmem"

    def get_id(self):
        return self._id

    def set_id(self, simulator_id: str) -> None:
        self._id = simulator_id

    def override_outdir(self, outdir: Path) -> None:
        self._outdir = Path(outdir)

    def _build_simulator(self) -> Simulator:
        cache_hierarchy = TracedThreeLevelClassicCacheHierarchy(
            prefetcher_map=DISABLED_PREFETCHER_MAP,
            **{f"l1d_{k}": v for k, v in base.L1D_CONFIG.items()},
            **{f"l1i_{k}": v for k, v in base.L1I_CONFIG.items()},
            **{f"l2_{k}": v for k, v in base.L2_CONFIG.items()},
            **{f"l3_{k}": v for k, v in base.L3_CONFIG.items()},
            cache_line_size=base.CACHE_LINE_SIZE,
            trace_file=FULL_MEM_TRACE_FILE,
        )
        cpu = base._create_x86_o3_cpu()
        cpu.traceListener = SimpleMemTrace(
            traceFile="commit_rw_trace.csv",
            startTraceInst=base.ELASTIC_TRACE_START_INST,
            cacheHitMissLevel=-1,
        )
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
        CryptoTraceCaptureSimulator(
            benchmark_name=benchmark_name,
            binary_path=base._resolve_binary_path(
                base.BENCHMARK_PATH_CANDIDATES[benchmark_name]
            ),
            arguments=base.BENCHMARK_ARGUMENTS.get(benchmark_name, []),
        )
    )
