#pragma once
// The incremental static cache: everything one file contributes to a run
// (its findings, its lock orders and what it learned about taint), keyed by the
// file's path and content, the parser version and the flags that change what is
// analysed. A second run on an unchanged tree reads these instead of parsing.
#include "analyzer.h"
#include "report.h"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace lcstatic {

struct CachedFile
{
    std::vector<lcreport::Finding> findings;
    std::vector<std::string> notes;
    std::vector<LockOrder> orders;
    std::set<std::string> shared_names;
    TaintDb taint;
    bool analyzed = false;
};

// Bump when the analysis output changes shape or meaning: every old entry is
// then a miss, never a stale finding.
inline constexpr uint32_t kCacheParserVersion = 1;

// FNV-1a of the path and contents, so a copy at another path is its own entry.
uint64_t cache_key(const std::string &absolute_path, const std::string &content,
                   bool malware);

std::string cache_file(const std::string &directory, uint64_t key);

// False on a missing, truncated or older-format file: the caller re-analyses.
bool load_cache(const std::string &path, CachedFile *out);
bool save_cache(const std::string &path, const CachedFile &file);

} // namespace lcstatic
