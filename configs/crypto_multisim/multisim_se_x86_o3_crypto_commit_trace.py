# Copyright (c) 2026
#
# MultiSim SE benchmark runner for crypto workloads with L1D cache-access
# hit/miss trace capture.
#
# Run from the gem5 root directory:
#   build/X86/gem5.opt -m gem5.utils.multisim configs/crypto_multisim/multisim_se_x86_o3_crypto_commit_trace.py

from pathlib import Path

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
        CryptoCommitTraceCaptureSimulator(
            benchmark_name=benchmark_name,
            binary_path=base._resolve_binary_path(
                base.BENCHMARK_PATH_CANDIDATES[benchmark_name]
            ),
            arguments=base.BENCHMARK_ARGUMENTS.get(benchmark_name, []),
        )
    )
