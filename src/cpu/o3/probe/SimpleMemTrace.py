from m5.objects.Probe import *


class SimpleMemTrace(ProbeListenerObject):
    type = "SimpleMemTrace"
    cxx_class = "gem5::o3::SimpleMemTrace"
    cxx_header = "cpu/o3/probe/simple_mem_trace.hh"

    traceFile = Param.String("mem_accesses.csv", "CSV trace file name")
    startTraceInst = Param.UInt64(
        0,
        "Number of committed instructions to skip before tracing",
    )
    cacheHitMissLevel = Param.Int(
        -1,
        "Reserved for future cache hit/miss annotation support",
    )
