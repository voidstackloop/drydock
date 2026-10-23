#include "internal.h"
#include "protocol.h"

#include <fstream>
#include <map>
#include <set>
#include <sstream>

namespace lcreport {
namespace {

uint64_t to_u64(const std::string &s, int base = 10) {
    try {
        return std::stoull(s, nullptr, base);
    } catch (...) {
        return 0;
    }
}

// Splits "k=v k=v ... msg=rest of line" into a map.
std::map<std::string, std::string> fields(const std::string &line) {
    std::map<std::string, std::string> out;
    size_t pos = line.find(' ');
    while (pos != std::string::npos && pos < line.size()) {
        size_t start = pos + 1;
        size_t eq = line.find('=', start);
        if (eq == std::string::npos)
            break;
        std::string k = line.substr(start, eq - start);
        if (k == "msg" || k == "exe") {
            out[k] = line.substr(eq + 1);
            break;
        }
        size_t end = line.find(' ', eq);
        out[k] =
            line.substr(eq + 1, end == std::string::npos ? std::string::npos
                                                         : end - eq - 1);
        pos = end;
    }
    return out;
}

Process &process(Report &r, uint32_t pid) {
    for (Process &p : r.processes)
        if (p.pid == pid)
            return p;
    r.processes.push_back(Process{});
    r.processes.back().pid = pid;
    return r.processes.back();
}

} // namespace

bool parse_runtime_stream(const std::string &path, Report &out) {
    std::ifstream in(path);
    if (!in)
        return false;
    std::map<std::pair<uint32_t, uint32_t>, std::string> modules;
    std::map<uint32_t, std::string>
        any_pid_modules; // forked children reuse ids
    std::map<std::string, size_t> by_key;
    // Processes with a stream of their own. An untraced child writes a lone
    // record just before it execs; many children can write the same one.
    std::set<uint32_t> headed;
    Finding *cur = nullptr;
    std::string line;
    while (std::getline(in, line)) {
        if (line.size() < 1)
            continue;
        const char tag = line[0];
        if (tag == 'H') {
            auto f = fields(line);
            Process &p = process(out, uint32_t(to_u64(f["pid"])));
            p.exe = f["exe"];
            headed.insert(p.pid);
        } else if (tag == 'M') {
            std::istringstream ss(line.substr(2));
            uint32_t pid = 0, id = 0;
            ss >> pid >> id;
            std::string p;
            std::getline(ss, p);
            if (!p.empty() && p[0] == ' ')
                p.erase(0, 1);
            modules[{pid, id}] = p;
            any_pid_modules[id] = p;
        } else if (tag == 'B') {
            auto f = fields(line);
            if (auto it = by_key.find(f["key"]);
                it != by_key.end() && !f["key"].empty() &&
                !headed.count(uint32_t(to_u64(f["pid"])))) {
                ++out.findings[it->second].occurrences;
                cur = nullptr; // its stack lines repeat the first one's
                continue;
            }
            Finding fd;
            fd.type = f["type"];
            fd.pid = uint32_t(to_u64(f["pid"]));
            fd.address = to_u64(f["addr"], 16);
            fd.size = to_u64(f["size"]);
            fd.tid = uint32_t(to_u64(f["tid"]));
            fd.key = f["key"];
            fd.category = f["cat"];
            fd.blocks = to_u64(f["blocks"]);
            fd.bytes = to_u64(f["bytes"]);
            fd.message = f["msg"];
            out.findings.push_back(std::move(fd));
            cur = &out.findings.back();
            by_key[cur->key] = out.findings.size() - 1;
        } else if (tag == 'S' && cur && line.size() > 3) {
            std::vector<Frame> *stack = nullptr;
            switch (line[2]) {
            case 'a':
                stack = &cur->access;
                break;
            case 'l':
                stack = &cur->alloc;
                break;
            case 'f':
                stack = &cur->freed;
                break;
            default:
                continue;
            }
            std::istringstream ss(line.substr(3));
            std::string tok;
            while (ss >> tok) {
                size_t colon = tok.find(':');
                if (colon == std::string::npos)
                    continue;
                Frame fr;
                uint32_t id = uint32_t(to_u64(tok.substr(0, colon)));
                fr.offset = to_u64(tok.substr(colon + 1), 16);
                if (id) {
                    auto it = modules.find({cur->pid, id});
                    if (it != modules.end())
                        fr.module = it->second;
                    else if (auto jt = any_pid_modules.find(id);
                             jt != any_pid_modules.end())
                        fr.module = jt->second;
                }
                stack->push_back(std::move(fr));
            }
        } else if (tag == 'X') {
            cur = nullptr;
        } else if (tag == 'D') {
            auto f = fields(line);
            auto it = by_key.find(f["key"]);
            if (it != by_key.end())
                out.findings[it->second].occurrences += to_u64(f["count"]);
        } else if (tag == 'T') {
            auto f = fields(line);
            Process &p = process(out, uint32_t(to_u64(f["pid"])));
            p.stats.allocs = to_u64(f["allocs"]);
            p.stats.frees = to_u64(f["frees"]);
            p.stats.bytes = to_u64(f["bytes"]);
            p.stats.live_blocks = to_u64(f["live_blocks"]);
            p.stats.live_bytes = to_u64(f["live_bytes"]);
            p.stats.peak_bytes = to_u64(f["peak_bytes"]);
            p.stats.dropped = to_u64(f["dropped"]);
            p.scanned = f["scanned"] == "1";
        } else if (tag == 'Z') {
            auto f = fields(line);
            process(out, uint32_t(to_u64(f["pid"]))).complete = true;
        }
    }
    return true;
}

} // namespace lcreport
