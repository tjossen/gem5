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
        << "thread_id,seq_num,instruction_pointer,access_type,"
        << "memory_address,access_size\n";

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

    traceStream
        << dynInst->threadNumber << ','
        << dynInst->seqNum << ','
        << "0x" << std::hex << dynInst->pcState().instAddr() << std::dec
        << ','
        << (dynInst->isLoad() ? 'R' : 'W') << ','
        << "0x" << std::hex << dynInst->physEffAddr << std::dec << ','
        << dynInst->effSize << '\n';
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
