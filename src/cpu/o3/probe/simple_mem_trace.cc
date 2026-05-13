#include "cpu/o3/probe/simple_mem_trace.hh"

#include <cinttypes>

#include "base/callback.hh"
#include "base/logging.hh"
#include "base/output.hh"
#include "cpu/o3/dyn_inst.hh"
#include "debug/SimpleMemTrace.hh"

namespace gem5
{

namespace o3
{

SimpleMemTrace::SimpleMemTrace(const SimpleMemTraceParams &params)
    : ProbeListenerObject(params),
      startTraceInst(params.startTraceInst)
{
    const std::string filename = simout.resolve(
        name() + "." + params.traceFile);
    traceStream.open(filename, std::ios::out | std::ios::trunc);
    fatal_if(!traceStream.is_open(),
        "Could not open commit trace file %s", filename);

    traceStream
        << "thread_id,instruction_pointer,access_type,"
        << "memory_address,access_size,cache_hit\n";

    registerExitCallback([this]() { flushTraces(); });
}

void
SimpleMemTrace::flushTraces()
{
    if (traceStream.is_open()) {
        traceStream.flush();
        traceStream.close();
    }
}

void
SimpleMemTrace::traceCommit(const DynInstPtr& dynInst)
{
    const bool tracing_enabled = committedInsts >= startTraceInst;
    ++committedInsts;

    if (!tracing_enabled) {
        return;
    }

    if (!dynInst->isLoad() && !dynInst->isStore()) {
        return;
    }

    if (!dynInst->hasRequest() || !dynInst->effAddrValid() ||
        dynInst->effSize == 0) {
        return;
    }

    const char *access_type = dynInst->isLoad() ? "R" : "W";
    const Addr pc = dynInst->pcState().instAddr();
    const Addr addr = dynInst->physEffAddr;
    const unsigned size = dynInst->effSize;

    traceStream
        << dynInst->threadNumber << ','
        << "0x" << std::hex << pc << std::dec << ','
        << access_type << ','
        << "0x" << std::hex << addr << std::dec << ','
        << size << ','
        << (dynInst->isCacheHit() ? 1 : 0) << '\n';
}

void
SimpleMemTrace::regProbeListeners()
{
    typedef ProbeListenerArg<SimpleMemTrace, DynInstPtr> DynInstListener;
    connectListener<DynInstListener>
        (this, "Commit", &SimpleMemTrace::traceCommit);
}

} // namespace o3
} // namespace gem5
