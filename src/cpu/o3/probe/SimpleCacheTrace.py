from m5.objects.Probe import *


class SimpleCacheTrace(ProbeListenerObject):
    type = "SimpleCacheTrace"
    cxx_class = "gem5::o3::SimpleCacheTrace"
    cxx_header = "cpu/o3/probe/simple_cache_trace.hh"

    traceFile = Param.String("cache_accesses.csv", "CSV trace file name")
