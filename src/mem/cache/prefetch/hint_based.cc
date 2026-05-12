/*
 * Hint-based prefetcher implementation
 */

#include "mem/cache/prefetch/hint_based.hh"
#include "base/logging.hh"
#include "debug/HWPrefetch.hh"
#include "params/HintBasedPrefetcher.hh"
#include <sstream>

using namespace std;
using namespace gem5::prefetch;

HintBased::HintBasedStats::HintBasedStats(statistics::Group *parent)
    : statistics::Group(parent),
      ADD_STAT(prefetchesIssued, statistics::units::Count::get(),
               "Number of prefetches issued by hint matching"),
      ADD_STAT(prefetchesSkipped, statistics::units::Count::get(),
               "Number of prefetches skipped (no matching hints)"),
      ADD_STAT(hintsLoaded, statistics::units::Count::get(),
               "Number of hints loaded"),
      ADD_STAT(csvParseErrors, statistics::units::Count::get(),
               "Number of CSV parsing errors")
{
}

HintBased::HintBased(const HintBasedPrefetcherParams &p)
  : Queued(p), issueAllHints(p.issue_all_hints), 
    matchOn(p.match_on), hintsFilePath(p.hints_file),
    statsHintBased(this)
{
    // Load hints from CSV file if provided
    if (!hintsFilePath.empty()) {
        DPRINTF(HWPrefetch, "HintBased: Loading hints from file: %s\n", 
                hintsFilePath);
        loadHintsFromCSV(hintsFilePath);
    } else {
        inform("HintBased: No hints file specified (hints_file parameter is empty)\n");
    }
}

void
HintBased::calculatePrefetch(const PrefetchInfo &pfi,
                              std::vector<AddrPriority> &addresses,
                              const CacheAccessor &cache)
{
    // If no PC available, skip hint matching
    if (!pfi.hasPC()) {
        statsHintBased.prefetchesSkipped++;
        return;
    }

    Addr pc = pfi.getPC();
    
    // Look up hints for this PC
    auto it = hintsByPC.find(pc);
    if (it != hintsByPC.end()) {
        // Found matching hints for this PC
        const std::vector<Addr> &hinted_addrs = it->second;
        int count = 0;
        for (Addr hint_addr : hinted_addrs) {
            if (issueAllHints || count == 0) {
                addresses.push_back(AddrPriority(hint_addr, 0));
                statsHintBased.prefetchesIssued++;
                DPRINTF(HWPrefetch, "HintBased: PC=0x%x matched, issuing prefetch for Addr=0x%x\n",
                        pc, hint_addr);
                count++;
            }
        }
    } else {
        // No matching hints for this PC
        statsHintBased.prefetchesSkipped++;
        DPRINTF(HWPrefetch, "HintBased: PC=0x%x not found in hints\n", pc);
    }
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
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Trim whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        size_t end = line.find_last_not_of(" \t\r\n");
        line = line.substr(start, end - start + 1);

        // Skip if now empty
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Parse CSV: PC,address
        size_t comma_pos = line.find(',');
        if (comma_pos == std::string::npos) {
            warn("HintBased: CSV parse error at line %d: no comma found in '%s'\n",
                 lineNum, line);
            statsHintBased.csvParseErrors++;
            continue;
        }

        std::string pc_str = line.substr(0, comma_pos);
        std::string addr_str = line.substr(comma_pos + 1);

        // Trim whitespace from both parts
        pc_str = pc_str.substr(0, pc_str.find_last_not_of(" \t") + 1);
        addr_str = addr_str.substr(addr_str.find_first_not_of(" \t"));
        addr_str = addr_str.substr(0, addr_str.find_last_not_of(" \t") + 1);

        try {
            Addr pc = std::stoul(pc_str, nullptr, 16);
            Addr addr = std::stoul(addr_str, nullptr, 16);
            hintsByPC[pc].push_back(addr);
            statsHintBased.hintsLoaded++;
            DPRINTF(HWPrefetch, "HintBased: Loaded hint PC=0x%x -> Addr=0x%x (line %d)\n",
                    pc, addr, lineNum);
        } catch (const std::exception &e) {
            warn("HintBased: CSV parse error at line %d: failed to parse '%s,%s': %s\n",
                 lineNum, pc_str, addr_str, e.what());
            statsHintBased.csvParseErrors++;
        }
    }

    file.close();
    inform("HintBased: Finished loading hints from '%s'.\n",
           filePath);
}

