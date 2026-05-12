/*
 * Copyright (c) 2026
 *
 * Commit-stage read/write trace for O3 workloads.
 */

#ifndef __CPU_O3_PROBE_SIMPLE_MEM_TRACE_HH__
#define __CPU_O3_PROBE_SIMPLE_MEM_TRACE_HH__

#include <fstream>
#include <string>

#include "cpu/o3/dyn_inst_ptr.hh"
#include "params/SimpleMemTrace.hh"
#include "sim/probe/probe_listener_object.hh"

namespace gem5
{

namespace o3
{

class SimpleMemTrace : public ProbeListenerObject
{
  public:
    explicit SimpleMemTrace(const SimpleMemTraceParams &params);

    void regProbeListeners() override;

  private:
    void traceCommit(const DynInstPtr& dynInst);
    void flushTraces();

    std::ofstream traceStream;
    const uint64_t startTraceInst;
    uint64_t committedInsts = 0;
};

} // namespace o3
} // namespace gem5

#endif // __CPU_O3_PROBE_SIMPLE_MEM_TRACE_HH__
