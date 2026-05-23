#!/usr/bin/env python3

import importlib.util
import io
import os
import sys
import tempfile
import time
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace


GEM5_ROOT = Path(__file__).resolve().parents[3]
CONFIG_PATH = (
    GEM5_ROOT / "configs" / "crypto_multisim" / "multisim_se_x86_o3_crypto.py"
)


def _install_module(name, module):
    sys.modules[name] = module
    return module


def _install_import_stubs():
    m5 = _install_module("m5", types.ModuleType("m5"))
    m5_objects = _install_module("m5.objects", types.ModuleType("m5.objects"))
    m5.objects = m5_objects

    for class_name in [
        "LTAGE",
        "LTAGE_TAGE",
        "X86O3CPU",
        "AMPMPrefetcher",
        "BadAddr",
        "BOPPrefetcher",
        "BranchPredictor",
        "Cache",
        "HintBasedPrefetcher",
        "IMPv2Prefetcher",
        "IndirectMemoryPrefetcher",
        "L2XBar",
        "SimpleCacheTrace",
        "STeMSPrefetcher",
        "StridePrefetcher",
        "SystemXBar",
        "TaggedPrefetcher",
    ]:
        setattr(m5_objects, class_name, type(class_name, (), {}))

    gem5 = _install_module("gem5", types.ModuleType("gem5"))
    components = _install_module(
        "gem5.components", types.ModuleType("gem5.components")
    )
    gem5.components = components

    boards = _install_module(
        "gem5.components.boards", types.ModuleType("gem5.components.boards")
    )
    simple_board = _install_module(
        "gem5.components.boards.simple_board",
        types.ModuleType("gem5.components.boards.simple_board"),
    )
    boards.simple_board = simple_board
    simple_board.SimpleBoard = type("SimpleBoard", (), {})

    cachehierarchies = _install_module(
        "gem5.components.cachehierarchies",
        types.ModuleType("gem5.components.cachehierarchies"),
    )
    abstract_cache_hierarchy = _install_module(
        "gem5.components.cachehierarchies.abstract_cache_hierarchy",
        types.ModuleType(
            "gem5.components.cachehierarchies.abstract_cache_hierarchy"
        ),
    )
    abstract_cache_hierarchy.AbstractCacheHierarchy = type(
        "AbstractCacheHierarchy", (), {}
    )
    cachehierarchies.abstract_cache_hierarchy = abstract_cache_hierarchy

    classic = _install_module(
        "gem5.components.cachehierarchies.classic",
        types.ModuleType("gem5.components.cachehierarchies.classic"),
    )
    abstract_classic = _install_module(
        "gem5.components.cachehierarchies.classic.abstract_classic_cache_hierarchy",
        types.ModuleType(
            "gem5.components.cachehierarchies.classic."
            "abstract_classic_cache_hierarchy"
        ),
    )

    class AbstractClassicCacheHierarchy:
        def __init__(self, *args, **kwargs):
            pass

    abstract_classic.AbstractClassicCacheHierarchy = AbstractClassicCacheHierarchy
    classic.abstract_classic_cache_hierarchy = abstract_classic

    memory = _install_module(
        "gem5.components.memory", types.ModuleType("gem5.components.memory")
    )
    memory.SingleChannelDDR4_2400 = type("SingleChannelDDR4_2400", (), {})

    processors = _install_module(
        "gem5.components.processors",
        types.ModuleType("gem5.components.processors"),
    )
    base_cpu_core = _install_module(
        "gem5.components.processors.base_cpu_core",
        types.ModuleType("gem5.components.processors.base_cpu_core"),
    )
    base_cpu_core.BaseCPUCore = type("BaseCPUCore", (), {})
    processors.base_cpu_core = base_cpu_core

    base_cpu_processor = _install_module(
        "gem5.components.processors.base_cpu_processor",
        types.ModuleType("gem5.components.processors.base_cpu_processor"),
    )
    base_cpu_processor.BaseCPUProcessor = type("BaseCPUProcessor", (), {})
    processors.base_cpu_processor = base_cpu_processor

    isas = _install_module("gem5.isas", types.ModuleType("gem5.isas"))
    isas.ISA = type("ISA", (), {"X86": object()})

    resources = _install_module(
        "gem5.resources", types.ModuleType("gem5.resources")
    )
    resource = _install_module(
        "gem5.resources.resource", types.ModuleType("gem5.resources.resource")
    )
    resource.BinaryResource = type("BinaryResource", (), {})
    resources.resource = resource

    simulate = _install_module(
        "gem5.simulate", types.ModuleType("gem5.simulate")
    )
    simulator = _install_module(
        "gem5.simulate.simulator", types.ModuleType("gem5.simulate.simulator")
    )
    simulator.Simulator = type("Simulator", (), {})
    simulate.simulator = simulator

    utils = _install_module("gem5.utils", types.ModuleType("gem5.utils"))
    override = _install_module(
        "gem5.utils.override", types.ModuleType("gem5.utils.override")
    )
    override.overrides = lambda _base: (lambda func: func)
    utils.override = override

    multisim = _install_module(
        "gem5.utils.multisim", types.ModuleType("gem5.utils.multisim")
    )
    multisim.set_num_processes = lambda *_args, **_kwargs: None
    multisim.add_simulator = lambda *_args, **_kwargs: None
    utils.multisim = multisim


def _load_config_module():
    _install_import_stubs()
    module_name = "multisim_se_x86_o3_crypto_under_test"
    spec = importlib.util.spec_from_file_location(module_name, CONFIG_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class CryptoMultisimHintGenerationTest(unittest.TestCase):
    def test_l1d_trace_listener_attaches_when_trace_file_is_configured(self):
        config = _load_config_module()

        class FakeCache(SimpleNamespace):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.cpu_side = None
                self.mem_side = None

        class FakeTrace(SimpleNamespace):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)

        class FakeXBar(SimpleNamespace):
            def __init__(self, **_kwargs):
                super().__init__(cpu_side_ports=object(), mem_side_ports=object())

        class FakeBadAddr(SimpleNamespace):
            def __init__(self):
                super().__init__(pio=object())

        class FakeNode:
            def add_child(self, *_args, **_kwargs):
                return self

        class FakeCore:
            def connect_icache(self, _port):
                pass

            def connect_dcache(self, _port):
                pass

            def connect_walker_ports(self, _itb, _dtb):
                pass

            def connect_interrupt(self, _pio, _int_req):
                pass

        class FakeProcessor:
            def get_cores(self):
                return [FakeCore()]

        class FakeBoard(SimpleNamespace):
            def __init__(self):
                super().__init__(cache_line_size=None)

            def connect_system_port(self, _port):
                pass

            def get_mem_ports(self):
                return [(None, object())]

            def get_processor(self):
                return FakeProcessor()

        config.Cache = FakeCache
        config.SimpleCacheTrace = FakeTrace
        config.SystemXBar = FakeXBar
        config.L2XBar = FakeXBar
        config.BadAddr = FakeBadAddr

        hierarchy = config.ThreeLevelClassicCacheHierarchy(
            prefetcher_map={level: None for level in config.PREFETCHER_LEVELS},
            l1d_trace_file="commit_rw_trace.csv",
            **{f"l1d_{key}": value for key, value in config.L1D_CONFIG.items()},
            **{f"l1i_{key}": value for key, value in config.L1I_CONFIG.items()},
            **{f"l2_{key}": value for key, value in config.L2_CONFIG.items()},
            **{f"l3_{key}": value for key, value in config.L3_CONFIG.items()},
        )
        hierarchy.add_root_child = lambda *_args, **_kwargs: FakeNode()

        hierarchy.incorporate_cache(FakeBoard())

        self.assertEqual(len(hierarchy._l1d_caches), 1)
        self.assertEqual(
            hierarchy._l1d_caches[0].traceListener.traceFile,
            "commit_rw_trace.csv",
        )

    def test_generates_hints_for_each_configured_lookback(self):
        config = _load_config_module()
        generation_calls = []

        trace_path = Path("/tmp/sha256/commit_rw_trace.csv")
        binary_path = Path("/tmp/sha256_binary")

        def fake_generate_hints_for_lookbacks_from_trace(**kwargs):
            lookbacks = list(kwargs["trace_lookbacks"])
            output_paths = [
                kwargs["output_path_for_lookback"](lookback)
                for lookback in lookbacks
            ]
            generation_calls.append(
                {
                    "trace_path": kwargs["trace_path"],
                    "trace_lookbacks": lookbacks,
                    "output_paths": output_paths,
                    "max_workers": kwargs["max_workers"],
                }
            )
            return [
                SimpleNamespace(
                    trace_lookback=lookback,
                    output_path=output_path,
                    stats=SimpleNamespace(hints_written=2, rows_read=3),
                )
                for lookback, output_path in zip(
                    lookbacks, output_paths, strict=True
                )
            ]

        config.PREFETCHER_TYPES = ["hint"]
        config.HINT_LOOKBACKS_TO_TEST = [1, 5, 20]
        config.BENCHMARK_PATH_CANDIDATES = {"sha256": ["sha256_binary"]}
        config.find_trace_file = lambda benchmark_name: trace_path
        config._resolve_binary_path = lambda candidates: binary_path
        config.generate_hints_for_lookbacks_from_trace = (
            fake_generate_hints_for_lookbacks_from_trace
        )

        with redirect_stdout(io.StringIO()):
            config._generate_hint_files_for_benchmarks(["sha256"])

        self.assertEqual(config.DEFAULT_HINT_LOOKBACK, 15)
        self.assertEqual(config.DEFAULT_HINT_CSV_NAME, "hints_trace15.csv")
        self.assertEqual(
            generation_calls,
            [
                {
                    "trace_path": trace_path,
                    "trace_lookbacks": [1, 5, 20],
                    "output_paths": [
                        config.default_hint_path("sha256", 1),
                        config.default_hint_path("sha256", 5),
                        config.default_hint_path("sha256", 20),
                    ],
                    "max_workers": 3,
                }
            ],
        )

    def test_missing_trace_fails_before_generating_any_hints(self):
        config = _load_config_module()
        generation_calls = []

        def fake_find_trace_file(benchmark_name):
            if benchmark_name == "missing_trace":
                raise FileNotFoundError("missing_trace has no commit trace")
            return Path(f"/tmp/{benchmark_name}/commit_rw_trace.csv")

        def fake_generate_hints_for_lookbacks_from_trace(**kwargs):
            generation_calls.append(kwargs)
            raise AssertionError("hint generation ran before validation ended")

        config.PREFETCHER_TYPES = ["hint"]
        config.HINT_LOOKBACKS_TO_TEST = [1, 5]
        config.BENCHMARK_PATH_CANDIDATES = {
            "has_trace": ["has_trace_binary"],
            "missing_trace": ["missing_trace_binary"],
        }
        config.find_trace_file = fake_find_trace_file
        config._resolve_binary_path = (
            lambda candidates: Path(f"/tmp/{candidates[0]}")
        )
        config.generate_hints_for_lookbacks_from_trace = (
            fake_generate_hints_for_lookbacks_from_trace
        )

        with self.assertRaisesRegex(FileNotFoundError, "missing_trace"):
            config._generate_hint_files_for_benchmarks(
                ["has_trace", "missing_trace"]
            )

        self.assertEqual(generation_calls, [])

    def test_stale_hint_files_are_submitted_to_generator_batch(self):
        config = _load_config_module()
        generation_calls = []

        trace_path = Path("/tmp/sha256/commit_rw_trace.csv")
        binary_path = Path("/tmp/sha256_binary")

        def fake_generate_hints_for_lookbacks_from_trace(**kwargs):
            lookbacks = list(kwargs["trace_lookbacks"])
            generation_calls.append(
                {
                    "trace_path": kwargs["trace_path"],
                    "trace_lookbacks": lookbacks,
                    "max_workers": kwargs["max_workers"],
                }
            )
            return [
                SimpleNamespace(
                    trace_lookback=lookback,
                    output_path=kwargs["output_path_for_lookback"](lookback),
                    stats=SimpleNamespace(hints_written=2, rows_read=3),
                )
                for lookback in lookbacks
            ]

        config.PREFETCHER_TYPES = ["hint"]
        config.HINT_LOOKBACKS_TO_TEST = [1, 5, 20]
        config.HINT_GENERATION_PARALLELISM = 2
        config.BENCHMARK_PATH_CANDIDATES = {"sha256": ["sha256_binary"]}
        config.find_trace_file = lambda benchmark_name: trace_path
        config._resolve_binary_path = lambda candidates: binary_path
        config._hint_file_is_current = lambda output_path, dependencies: False
        config._hint_generation_lock_path = lambda: Path("/tmp/hint_generation.lock")
        config.generate_hints_for_lookbacks_from_trace = (
            fake_generate_hints_for_lookbacks_from_trace
        )

        with redirect_stdout(io.StringIO()):
            config._generate_hint_files_for_benchmarks(["sha256"])

        self.assertEqual(
            generation_calls,
            [
                {
                    "trace_path": trace_path,
                    "trace_lookbacks": [1, 5, 20],
                    "max_workers": 3,
                }
            ],
        )

    def test_current_hint_files_skip_regeneration_per_lookback(self):
        config = _load_config_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            trace_path = temp_path / "commit_rw_trace.csv"
            binary_path = temp_path / "benchmark"
            lock_path = temp_path / "hint_generation.lock"

            trace_path.write_text("trace\n", encoding="utf-8")
            binary_path.write_text("binary\n", encoding="utf-8")
            for lookback in [5, 10]:
                output_path = temp_path / f"hints_trace{lookback}.csv"
                output_path.write_text("pc,address,size\n", encoding="utf-8")
                fresh_time = time.time() + 60
                os.utime(output_path, (fresh_time, fresh_time))

            def unexpected_generate(**_kwargs):
                raise AssertionError(
                    "hint generation should not run for fresh hints"
                )

            config.PREFETCHER_TYPES = ["hint"]
            config.HINT_LOOKBACKS_TO_TEST = [5, 10]
            config.BENCHMARK_PATH_CANDIDATES = {"sha256": ["sha256_binary"]}
            config.find_trace_file = lambda benchmark_name: trace_path
            config._resolve_binary_path = lambda candidates: binary_path
            config.default_hint_path = (
                lambda benchmark_name, trace_lookback=config.DEFAULT_HINT_LOOKBACK: (
                    temp_path / f"hints_trace{trace_lookback}.csv"
                )
            )
            config._hint_generation_lock_path = lambda: lock_path
            config.generate_hints_for_lookbacks_from_trace = unexpected_generate

            with redirect_stdout(io.StringIO()):
                config._generate_hint_files_for_benchmarks(["sha256"])

    def test_hint_simulator_label_and_id_include_lookback(self):
        config = _load_config_module()
        prefetcher_map = {
            "l1i": None,
            "l1d": None,
            "l2": "hint",
            "l3": None,
        }

        simulator = config.CryptoPrefetcherSweepSimulator(
            benchmark_name="sha256",
            binary_path=Path("/tmp/sha256_binary"),
            arguments=[],
            prefetcher_map=prefetcher_map,
            hint_lookback=10,
        )

        self.assertEqual(simulator._benchmark_label, "sha256_trace10")
        self.assertTrue(simulator.get_id().startswith("crypto_sha256_trace10__"))

    def test_non_hint_simulator_does_not_include_lookback(self):
        config = _load_config_module()
        prefetcher_map = {
            "l1i": None,
            "l1d": None,
            "l2": None,
            "l3": None,
        }

        simulator = config.CryptoPrefetcherSweepSimulator(
            benchmark_name="sha256",
            binary_path=Path("/tmp/sha256_binary"),
            arguments=[],
            prefetcher_map=prefetcher_map,
            hint_lookback=None,
        )

        self.assertEqual(simulator._benchmark_label, "sha256")
        self.assertTrue(simulator.get_id().startswith("crypto_sha256__"))

    def test_main_registers_hint_simulators_per_lookback(self):
        config = _load_config_module()
        simulators = []

        config.ENABLED_BENCHMARKS = {"sha256": True}
        config.PREFETCHER_TYPES = [None, "hint"]
        config.LEVEL_COMBINATIONS_TO_TEST = [("l2",)]
        config.HINT_LOOKBACKS_TO_TEST = [1, 5]
        config.BENCHMARK_PATH_CANDIDATES = {"sha256": ["sha256_binary"]}
        config.BENCHMARK_ARGUMENTS = {"sha256": []}
        config._generate_hint_files_for_benchmarks = lambda benchmark_names: None
        config._completed_summary_ids = lambda: set()
        config._resolve_binary_path = lambda candidates: Path("/tmp/sha256_binary")
        config.multisim.add_simulator = simulators.append
        config.multisim.set_num_processes = lambda *_args, **_kwargs: None

        config.main()

        self.assertEqual(
            [simulator.get_id() for simulator in simulators],
            [
                "crypto_sha256__l1i-none_l1d-none_l2-none_l3-none",
                "crypto_sha256_trace1__l1i-none_l1d-none_l2-hint_l3-none",
                "crypto_sha256_trace5__l1i-none_l1d-none_l2-hint_l3-none",
            ],
        )

    def test_main_skips_simulators_already_present_in_summary_csv(self):
        config = _load_config_module()
        simulators = []

        with tempfile.TemporaryDirectory() as temp_dir:
            summary_path = Path(temp_dir) / "crypto_prefetcher_sweep.csv"
            summary_path.write_text(
                "simulation_id,benchmark,l1i_prefetcher,l1d_prefetcher,"
                "l2_prefetcher,l3_prefetcher,ipc,sim_seconds,sim_insts,"
                "sim_cycles\n"
                "crypto_sha256_trace1__l1i-none_l1d-none_l2-hint_l3-none,"
                "sha256_trace1,none,none,hint,none,1.0,0.1,10,10\n",
                encoding="utf-8",
            )

            config.ENABLED_BENCHMARKS = {"sha256": True}
            config.PREFETCHER_TYPES = ["hint"]
            config.LEVEL_COMBINATIONS_TO_TEST = [("l2",)]
            config.HINT_LOOKBACKS_TO_TEST = [1, 5]
            config.BENCHMARK_PATH_CANDIDATES = {"sha256": ["sha256_binary"]}
            config.BENCHMARK_ARGUMENTS = {"sha256": []}
            config._summary_path = lambda: summary_path
            config._generate_hint_files_for_benchmarks = (
                lambda benchmark_names: None
            )
            config._resolve_binary_path = (
                lambda candidates: Path("/tmp/sha256_binary")
            )
            config.multisim.add_simulator = simulators.append
            config.multisim.set_num_processes = lambda *_args, **_kwargs: None

            with redirect_stdout(io.StringIO()):
                config.main()

        self.assertEqual(
            [simulator.get_id() for simulator in simulators],
            [
                "crypto_sha256_trace5__l1i-none_l1d-none_l2-hint_l3-none",
            ],
        )


if __name__ == "__main__":
    unittest.main()
