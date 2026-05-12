/*
 * Hint-based prefetcher implementation
 */

#include "mem/cache/prefetch/hint_based.hh"

#include <algorithm>
#include <cctype>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include "base/logging.hh"
#include "debug/HWPrefetch.hh"
#include "mem/cache/base.hh"
#include "params/HintBasedPrefetcher.hh"
#include "sim/core.hh"

using namespace gem5;
using namespace gem5::prefetch;

namespace
{

std::string
trim(const std::string &value)
{
    const size_t start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    const size_t end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

bool
isCommentOrEmpty(const std::string &line)
{
    const std::string stripped = trim(line);
    return stripped.empty() || stripped[0] == '#';
}

} // anonymous namespace

HintBased::HintBasedStats::HintBasedStats(statistics::Group *parent)
    : statistics::Group(parent),
      ADD_STAT(hintsMatched, statistics::units::Count::get(),
               "Number of chronological hints matched by retired PCs"),
      ADD_STAT(hintSegmentsGenerated, statistics::units::Count::get(),
               "Number of cache-line-contained hint request segments "
               "generated"),
      ADD_STAT(hintSegmentsQueued, statistics::units::Count::get(),
               "Number of hint prefetch request segments queued"),
      ADD_STAT(hintSegmentsDroppedQueueFull, statistics::units::Count::get(),
               "Number of hint request segments dropped because the queue "
               "is full"),
      ADD_STAT(hintSegmentsSkippedRedundant, statistics::units::Count::get(),
               "Number of hint request segments skipped by line-based filters"),
      ADD_STAT(retiredPCsObserved, statistics::units::Count::get(),
               "Number of retired PCs observed by the hint prefetcher"),
      ADD_STAT(retiredPCsSkipped, statistics::units::Count::get(),
               "Number of retired PCs that did not match the current hint"),
      ADD_STAT(hintsLoaded, statistics::units::Count::get(),
               "Number of hints loaded"),
      ADD_STAT(csvParseErrors, statistics::units::Count::get(),
               "Number of CSV parsing errors")
{
}

HintBased::HintBased(const HintBasedPrefetcherParams &p)
  : Queued(p), hintsFilePath(p.hints_file),
    statsHintBased(this)
{
    if (!hintsFilePath.empty()) {
        DPRINTF(HWPrefetch, "HintBased: Loading hints from file: %s\n",
                hintsFilePath);
        loadHintsFromCSV(hintsFilePath);
    } else {
        inform("HintBased: No hints file specified (hints_file parameter is empty)\n");
    }
}

HintBased::~HintBased()
{
    for (auto &entry : hintQueue) {
        delete entry.pkt;
    }
}

void
HintBased::calculatePrefetch(const PrefetchInfo &pfi,
                              std::vector<AddrPriority> &addresses,
                              const CacheAccessor &cache)
{
    // HintBased is driven by retired instruction PCs, not cache accesses.
}

void
HintBased::loadHintsFromCSV(const std::string &filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open()) {
        warn("HintBased: Could not open hints file '%s'\n", filePath);
        return;
    }

    std::string line;
    int lineNum = 0;
    while (std::getline(file, line)) {
        lineNum++;

        if (isCommentOrEmpty(line)) {
            continue;
        }

        line = trim(line);
        if (line == "pc,address,size") {
            continue;
        }

        std::vector<std::string> fields;
        std::stringstream lineStream(line);
        std::string field;
        while (std::getline(lineStream, field, ',')) {
            fields.push_back(trim(field));
        }

        if (fields.size() != 3) {
            warn("HintBased: CSV parse error at line %d: expected "
                 "pc,address,size in '%s'\n", lineNum, line);
            statsHintBased.csvParseErrors++;
            continue;
        }

        try {
            const Addr pc = std::stoull(fields[0], nullptr, 0);
            const Addr addr = std::stoull(fields[1], nullptr, 0);
            const uint64_t parsedSize = std::stoull(fields[2], nullptr, 0);
            if (parsedSize == 0 ||
                parsedSize > std::numeric_limits<unsigned>::max() ||
                parsedSize > std::numeric_limits<Addr>::max() - addr) {
                warn("HintBased: CSV parse error at line %d: invalid size "
                     "in '%s'\n", lineNum, line);
                statsHintBased.csvParseErrors++;
                continue;
            }
            const unsigned size = static_cast<unsigned>(parsedSize);
            hints.push_back({pc, addr, size});
            statsHintBased.hintsLoaded++;
        } catch (const std::exception &e) {
            warn("HintBased: CSV parse error at line %d: failed to parse "
                 "'%s': %s\n", lineNum, line, e.what());
            statsHintBased.csvParseErrors++;
        }
    }

    file.close();
    inform("HintBased: loaded %llu hints from '%s' with %llu parse errors\n",
           (unsigned long long)hints.size(), filePath,
           (unsigned long long)statsHintBased.csvParseErrors.value());
}

void
HintBased::notifyRetiredInst(const Addr pc)
{
    statsHintBased.retiredPCsObserved++;

    if (hintCursor >= hints.size()) {
        statsHintBased.retiredPCsSkipped++;
        return;
    }

    const Addr expectedPC = hints[hintCursor].pc;
    if (pc != expectedPC) {
        statsHintBased.retiredPCsSkipped++;
        return;
    }

    do {
        const size_t matchedCursor = hintCursor;
        const Hint &hint = hints[hintCursor];
        queueHint(hint, matchedCursor);
        statsHintBased.hintsMatched++;
        hintCursor++;
    } while (hintCursor < hints.size() && hints[hintCursor].pc == pc);

    scheduleCacheSend();
}

void
HintBased::queueHint(const Hint &hint, const size_t hintIndex)
{
    Addr requestAddr = hint.address;
    unsigned remaining = hint.size;

    while (remaining > 0) {
        const Addr blockAddr = blockAddress(requestAddr);
        const Addr nextBlockAddr = blockAddr + blkSize;
        const Addr bytesInBlock = nextBlockAddr > requestAddr ?
            nextBlockAddr - requestAddr : remaining;
        const unsigned requestSize = std::min<unsigned>(
            remaining, static_cast<unsigned>(bytesInBlock));

        queueHintSegment(hint, hintIndex, requestAddr, requestSize);

        requestAddr += requestSize;
        remaining -= requestSize;
    }
}

bool
HintBased::segmentAlreadyQueued(const Addr blockAddr) const
{
    for (const auto &entry : hintQueue) {
        if (entry.blockAddr == blockAddr) {
            return true;
        }
    }

    return false;
}

void
HintBased::queueHintSegment(const Hint &hint, const size_t hintIndex,
                            const Addr requestAddr,
                            const unsigned requestSize)
{
    statsHintBased.hintSegmentsGenerated++;

    const Addr targetBlockAddr = blockAddress(requestAddr);
    if (queueFilter && segmentAlreadyQueued(targetBlockAddr)) {
        statsHintBased.hintSegmentsSkippedRedundant++;
        statsQueued.pfBufferHit++;
        DPRINTF(HWPrefetch, "HintBased: redundant queued segment "
                "cursor=%llu PC=%#x Addr=%#x size=%u block=%#x\n",
                (unsigned long long)hintIndex, hint.pc, requestAddr,
                requestSize, targetBlockAddr);
        return;
    }

    if (cacheSnoop && cache &&
        (cache->inCache(targetBlockAddr, false) ||
         cache->inMissQueue(targetBlockAddr, false))) {
        statsHintBased.hintSegmentsSkippedRedundant++;
        statsQueued.pfInCache++;
        DPRINTF(HWPrefetch, "HintBased: redundant cache segment "
                "cursor=%llu PC=%#x Addr=%#x size=%u block=%#x\n",
                (unsigned long long)hintIndex, hint.pc, requestAddr,
                requestSize, targetBlockAddr);
        return;
    }

    if (hintQueue.size() >= queueSize) {
        statsHintBased.hintSegmentsDroppedQueueFull++;
        statsQueued.pfRemovedFull++;
        DPRINTF(HWPrefetch, "HintBased: queue full, dropping segment "
                "cursor=%llu PC=%#x Addr=%#x size=%u block=%#x\n",
                (unsigned long long)hintIndex, hint.pc, requestAddr,
                requestSize, targetBlockAddr);
        return;
    }

    RequestPtr req = std::make_shared<Request>(
        requestAddr, requestSize, 0, requestorId);
    req->setPC(hint.pc);
    req->taskId(context_switch_task_id::Prefetcher);

    PacketPtr pkt = new Packet(req, MemCmd::HardPFReq);
    pkt->allocate();

    const Tick readyTime = curTick() + clockPeriod() * latency;
    hintQueue.push_back({pkt, readyTime, hint.pc, requestAddr,
                         targetBlockAddr, requestSize, hint.address,
                         hint.size, hintIndex});
    statsHintBased.hintSegmentsQueued++;
    statsQueued.pfIdentified++;

    DPRINTF(HWPrefetch, "HintBased: queued segment cursor=%llu PC=%#x "
            "Addr=%#x size=%u block=%#x hint_addr=%#x hint_size=%u "
            "ready=%llu\n",
            (unsigned long long)hintIndex, hint.pc, requestAddr, requestSize,
            targetBlockAddr, hint.address, hint.size, readyTime);
}

void
HintBased::scheduleCacheSend()
{
    if (cache == nullptr || hintQueue.empty()) {
        return;
    }

    cache->schedMemSideSendEvent(std::max(hintQueue.front().readyTime,
                                          curTick()));
}

PacketPtr
HintBased::getPacket()
{
    if (hintQueue.empty() || hintQueue.front().readyTime > curTick()) {
        return nullptr;
    }

    PacketPtr pkt = hintQueue.front().pkt;
    DPRINTF(HWPrefetch, "HintBased: issuing segment cursor=%llu PC=%#x "
            "Addr=%#x size=%u block=%#x hint_addr=%#x hint_size=%u "
            "queue_size=%llu\n",
            (unsigned long long)hintQueue.front().hintIndex,
            hintQueue.front().triggerPC, hintQueue.front().requestAddr,
            hintQueue.front().requestSize, hintQueue.front().blockAddr,
            hintQueue.front().hintAddr, hintQueue.front().hintSize,
            (unsigned long long)hintQueue.size());
    hintQueue.pop_front();

    prefetchStats.pfIssued++;
    issuedPrefetches += 1;
    return pkt;
}

Tick
HintBased::nextPrefetchReadyTime() const
{
    return hintQueue.empty() ? MaxTick : hintQueue.front().readyTime;
}

void
HintBased::PrefetchListenerPC::notify(const Addr& pc)
{
    parent.notifyRetiredInst(pc);
}

void
HintBased::addEventProbeRetiredInsts(SimObject *obj, const char *name)
{
    ProbeManager *pm = obj->getProbeManager();
    listenersPC.push_back(pm->connect<PrefetchListenerPC>(*this, name));
}
