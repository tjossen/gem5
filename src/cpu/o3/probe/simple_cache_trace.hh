/*
 * Copyright (c) 2026
 *
 * L1D cache hit/miss CSV trace for O3 workloads.
 */

#ifndef __CPU_O3_PROBE_SIMPLE_CACHE_TRACE_HH__
#define __CPU_O3_PROBE_SIMPLE_CACHE_TRACE_HH__

#include <fstream>

#include "mem/cache/cache_probe_arg.hh"
#include "params/SimpleCacheTrace.hh"
#include "sim/probe/probe_listener_object.hh"

namespace gem5
{

namespace o3
{

class SimpleCacheTrace : public ProbeListenerObject
{
  public:
    explicit SimpleCacheTrace(const SimpleCacheTraceParams &params);

    void regProbeListeners() override;

  private:
    void traceHit(const CacheAccessProbeArg &arg);
    void traceMiss(const CacheAccessProbeArg &arg);
    void traceCacheAccess(const CacheAccessProbeArg &arg, bool cacheHit);
    void flushTraces();

    std::ofstream traceStream;
};

} // namespace o3
} // namespace gem5

#endif // __CPU_O3_PROBE_SIMPLE_CACHE_TRACE_HH__
