#include "cpu/o3/probe/simple_cache_trace.hh"

#include "base/callback.hh"
#include "base/logging.hh"
#include "base/output.hh"
#include "debug/SimpleCacheTrace.hh"
#include "mem/packet.hh"
#include "mem/request.hh"
#include "sim/core.hh"

namespace gem5
{

namespace o3
{

SimpleCacheTrace::SimpleCacheTrace(const SimpleCacheTraceParams &params)
    : ProbeListenerObject(params)
{
    const std::string filename = simout.resolve(
        name() + "." + params.traceFile);
    traceStream.open(filename, std::ios::out | std::ios::trunc);
    fatal_if(!traceStream.is_open(),
        "Could not open cache trace file %s", filename);

    traceStream
        << "thread_id,seq_num,instruction_pointer,access_type,"
        << "memory_address,access_size,cache_hit\n";

    registerExitCallback([this]() { flushTraces(); });
}

void
SimpleCacheTrace::flushTraces()
{
    if (traceStream.is_open()) {
        traceStream.flush();
        traceStream.close();
    }
}

void
SimpleCacheTrace::traceHit(const CacheAccessProbeArg &arg)
{
    traceCacheAccess(arg, true);
}

void
SimpleCacheTrace::traceMiss(const CacheAccessProbeArg &arg)
{
    traceCacheAccess(arg, false);
}

void
SimpleCacheTrace::traceCacheAccess(
    const CacheAccessProbeArg &arg, bool cacheHit)
{
    const PacketPtr pkt = arg.pkt;
    if (pkt == nullptr || !pkt->isDemand() || pkt->req == nullptr) {
        return;
    }

    const RequestPtr req = pkt->req;
    if (!req->hasPaddr() || !req->hasPC() || !req->hasInstSeqNum()) {
        return;
    }

    const char *accessType = nullptr;
    if (pkt->isWrite()) {
        accessType = "W";
    } else if (pkt->isRead()) {
        accessType = "R";
    } else {
        return;
    }

    const ContextID contextId = req->hasContextId() ? req->contextId() : 0;

    traceStream
        << contextId << ','
        << req->getReqInstSeqNum() << ','
        << "0x" << std::hex << req->getPC() << std::dec << ','
        << accessType << ','
        << "0x" << std::hex << req->getPaddr() << std::dec << ','
        << pkt->getSize() << ','
        << (cacheHit ? 1 : 0) << '\n';
}

void
SimpleCacheTrace::regProbeListeners()
{
    typedef ProbeListenerArg<
        SimpleCacheTrace, CacheAccessProbeArg> CacheAccessListener;

    connectListener<CacheAccessListener>(
        this, "Hit", &SimpleCacheTrace::traceHit);
    connectListener<CacheAccessListener>(
        this, "Miss", &SimpleCacheTrace::traceMiss);
}

} // namespace o3
} // namespace gem5
