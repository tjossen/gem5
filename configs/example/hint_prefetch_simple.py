#!/usr/bin/env python3
# Example configuration for hint-based prefetcher
# This script demonstrates how to use the HintBasedPrefetcher with a CSV hints file

import m5
from m5.objects import *

# Create system
system = System()
system.clk_domain = ClockDomain(clock='1GHz')
system.mem_mode = 'timing'

# Create CPU
system.cpu = X86O3CPU(clk_domain=system.clk_domain)

# Create memory bus
system.membus = SystemXBar()

# Create L1 instruction cache
system.cpu.icache = L1Cache(size='32kB', assoc=8, tag_latency=1, 
                             data_latency=1, response_latency=1)
system.cpu.icache.cpu_side = system.cpu.icache_port
system.cpu.icache.mem_side = system.membus.cpu_side_ports

# Create L1 data cache
system.cpu.dcache = L1Cache(size='32kB', assoc=8, tag_latency=1,
                             data_latency=1, response_latency=1)
system.cpu.dcache.cpu_side = system.cpu.dcache_port
system.cpu.dcache.mem_side = system.membus.cpu_side_ports

# Attach hint-based prefetcher to L1 data cache
# Create hints file path (relative to current directory or absolute)
hints_file = 'example_hints.csv'
system.cpu.dcache.prefetcher = HintBasedPrefetcher(
    hints_file=hints_file,
    hints_format='csv',
    match_on='access',
    issue_all_hints=True
)

# Create main memory
system.mem_ctrl = MemoryController()
system.mem_ctrl.port = system.membus.mem_side_ports

# Create memory
memory = SimpleMemory(latency='10ns')
system.memory = memory

# Set up the memory system
system.system_port = system.membus.cpu_side_ports

# Create process
process = Process()
process.cmd = ['./test_binary']

system.cpu.workload = process
system.cpu.createThreadContext()

# Run simulation
root = Root(full_system=False, system=system)
m5.instantiate()
m5.simulate(m5.ticks.fromSeconds(1))
