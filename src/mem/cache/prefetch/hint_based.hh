/*
 * Copyright (c) 2026
 * All rights reserved.
 */

/**
 * @file
 * Hint-based prefetcher header.
 */

#ifndef __MEM_CACHE_PREFETCH_HINT_BASED_HH__
#define __MEM_CACHE_PREFETCH_HINT_BASED_HH__

#include <fstream>
#include <list>
#include <sstream>
#include <utility>
#include <vector>

#include "base/statistics.hh"
#include "mem/cache/base.hh"
#include "mem/cache/prefetch/queued.hh"
#include "mem/packet.hh"
#include "sim/probe/probe.hh"

namespace gem5
{

class SimObject;
struct HintBasedPrefetcherParams;

namespace prefetch
{

class HintBased : public Queued
{
  protected:
    struct Hint
    {
        Addr pc;
        Addr address;
        unsigned size;
    };

    struct QueuedHint
    {
        PacketPtr pkt;
        Tick readyTime;
        Addr triggerPC;
        Addr requestAddr;
        Addr blockAddr;
        unsigned requestSize;
        Addr hintAddr;
        unsigned hintSize;
        size_t hintIndex;
    };

    /** Hints in chronological trace order. */
    std::vector<Hint> hints;
    size_t hintCursor = 0;

    /** Packets queued by retired-PC hint matches. */
    std::list<QueuedHint> hintQueue;

    const std::string hintsFilePath;
    BaseCache *cache = nullptr;

    class PrefetchListenerPC : public ProbeListenerArgBase<Addr>
    {
      public:
        PrefetchListenerPC(HintBased &_parent, std::string name)
            : ProbeListenerArgBase(std::move(name)), parent(_parent)
        {}

        void notify(const Addr& pc) override;

      protected:
        HintBased &parent;
    };

    std::vector<ProbeListenerPtr<PrefetchListenerPC>> listenersPC;

    struct HintBasedStats : public statistics::Group
    {
        HintBasedStats(statistics::Group *parent);
        statistics::Scalar hintsMatched;
        statistics::Scalar hintSegmentsGenerated;
        statistics::Scalar hintSegmentsQueued;
        statistics::Scalar hintSegmentsDroppedQueueFull;
        statistics::Scalar hintSegmentsSkippedRedundant;
        statistics::Scalar retiredPCsObserved;
        statistics::Scalar retiredPCsSkipped;
        statistics::Scalar hintsLoaded;
        statistics::Scalar csvParseErrors;
    } statsHintBased;

    /**
     * Load hints from CSV file.
     * CSV format: one hint per line as "PC,address,size".
     * Comments (lines starting with #) are ignored.
     * @param filePath Path to the CSV hints file
     */
    void loadHintsFromCSV(const std::string &filePath);
    void notifyRetiredInst(const Addr pc);
    void queueHint(const Hint &hint, const size_t hintIndex);
    void queueHintSegment(const Hint &hint, const size_t hintIndex,
                          const Addr requestAddr,
                          const unsigned requestSize);
    bool segmentAlreadyQueued(const Addr blockAddr) const;
    void scheduleCacheSend();

  public:
    HintBased(const HintBasedPrefetcherParams &p);
    ~HintBased();

    void calculatePrefetch(const PrefetchInfo &pfi,
                           std::vector<AddrPriority> &addresses,
                           const CacheAccessor &cache) override;

    PacketPtr getPacket() override;

    Tick nextPrefetchReadyTime() const override;

    void addEventProbeRetiredInsts(SimObject *obj, const char *name);

    void setCache(BaseCache *_cache)
    {
        cache = _cache;
    }
};

} // namespace prefetch
} // namespace gem5

#endif // __MEM_CACHE_PREFETCH_HINT_BASED_HH__
