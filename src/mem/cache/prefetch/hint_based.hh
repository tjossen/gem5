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

#include <unordered_map>
#include <vector>
#include <fstream>
#include <sstream>
#include "mem/cache/prefetch/queued.hh"
#include "mem/packet.hh"
#include "base/statistics.hh"

namespace gem5
{

struct HintBasedPrefetcherParams;

namespace prefetch
{

class HintBased : public Queued
{
  protected:
    /** Map from PC to list of hinted addresses */
    std::unordered_map<Addr, std::vector<Addr>> hintsByPC;

    const bool issueAllHints;
    const std::string matchOn;  // "access" or "miss"
    const std::string hintsFilePath;

    struct HintBasedStats : public statistics::Group
    {
        HintBasedStats(statistics::Group *parent);
        statistics::Scalar prefetchesIssued;
        statistics::Scalar prefetchesSkipped;
        statistics::Scalar hintsLoaded;
        statistics::Scalar csvParseErrors;
    } statsHintBased;

    /**
     * Load hints from CSV file.
     * CSV format: one hint per line as "PC,address" (hex values, with or without 0x prefix)
     * Comments (lines starting with #) are ignored.
     * @param filePath Path to the CSV hints file
     */
    void loadHintsFromCSV(const std::string &filePath);

  public:
    HintBased(const HintBasedPrefetcherParams &p);
    ~HintBased() = default;

    void calculatePrefetch(const PrefetchInfo &pfi,
                           std::vector<AddrPriority> &addresses,
                           const CacheAccessor &cache) override;
};

} // namespace prefetch
} // namespace gem5

#endif // __MEM_CACHE_PREFETCH_HINT_BASED_HH__