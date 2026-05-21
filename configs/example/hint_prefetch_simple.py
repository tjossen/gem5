import m5
import sys
from pathlib import Path

from m5.objects import *


GEM5_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = GEM5_ROOT.parent

DEFAULT_BINARY = (
    SRC_ROOT
    / "crypto-programs/test_openssl/sha256/test_ossl_sha256_baseline"
)
DEFAULT_HINTS_FILE = (
    GEM5_ROOT / "m5out/crypto_sha256_commit_trace/hints_trace5.csv"
)
HELLO_BINARY = (
    GEM5_ROOT / "tests/test-progs/hello/bin/x86/linux/hello"
)

binary = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_BINARY
if not binary.exists():
    binary = HELLO_BINARY.resolve()

hints_file = (
    Path(sys.argv[2]).resolve()
    if len(sys.argv) > 2
    else DEFAULT_HINTS_FILE.resolve()
)

system = System()
system.clk_domain = SrcClockDomain()
system.clk_domain.clock = "1GHz"
system.clk_domain.voltage_domain = VoltageDomain()
system.mem_mode = "timing"
system.mem_ranges = [AddrRange("512MiB")]

system.cpu = X86TimingSimpleCPU()

system.membus = SystemXBar()

system.cpu.icache = Cache(
    size="32KiB",
    assoc=8,
    tag_latency=1,
    data_latency=1,
    response_latency=1,
    mshrs=16,
    tgts_per_mshr=20,
    is_read_only=True,
)
system.cpu.icache.cpu_side = system.cpu.icache_port
system.cpu.icache.mem_side = system.membus.cpu_side_ports

system.cpu.dcache = Cache(
    size="32KiB",
    assoc=8,
    tag_latency=1,
    data_latency=1,
    response_latency=1,
    mshrs=16,
    tgts_per_mshr=20,
)
system.cpu.dcache.cpu_side = system.cpu.dcache_port
system.cpu.dcache.mem_side = system.membus.cpu_side_ports

hint_prefetcher = HintBasedPrefetcher(hints_file=str(hints_file))
hint_prefetcher.registerCache(system.cpu.dcache)
hint_prefetcher.listenFromProbeRetiredInstructions(system.cpu)
system.cpu.dcache.prefetcher = hint_prefetcher

system.cpu.createInterruptController()
system.cpu.interrupts[0].pio = system.membus.mem_side_ports
system.cpu.interrupts[0].int_requestor = system.membus.cpu_side_ports
system.cpu.interrupts[0].int_responder = system.membus.mem_side_ports

system.mem_ctrl = MemCtrl()
system.mem_ctrl.dram = DDR3_1600_8x8()
system.mem_ctrl.dram.range = system.mem_ranges[0]
system.mem_ctrl.port = system.membus.mem_side_ports

system.system_port = system.membus.cpu_side_ports

system.workload = SEWorkload.init_compatible(str(binary))

process = Process()
process.cmd = [str(binary)]

system.cpu.workload = process
system.cpu.createThreads()

root = Root(full_system=False, system=system)
m5.instantiate()

print(f"Binary: {binary}")
print(f"Hints: {hints_file}")
exit_event = m5.simulate(m5.ticks.fromSeconds(0.001))
print(f"Exiting @ tick {m5.curTick()} because {exit_event.getCause()}")
