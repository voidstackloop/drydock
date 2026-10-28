#include "internal.h"
#include "malware.h"
#include "protocol.h"
#include "vulnerability.h"

#include <algorithm>
#include <cctype>
#include <map>
#include <ostream>
#include <unistd.h>

namespace lcreport {
namespace {

std::string cwd_prefix() {
    char buf[4096];
    if (!getcwd(buf, sizeof buf))
        return {};
    std::string s(buf);
    std::replace(s.begin(), s.end(), '\\', '/'); // Windows: paths in findings use '/'
    return s + "/";
}

std::string shorten(const std::string &file, const std::string &cwd) {
    if (!cwd.empty() && file.rfind(cwd, 0) == 0)
        return file.substr(cwd.size());
    return file;
}

std::string basename_of(const std::string &p) {
    size_t s = p.rfind('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

void print_stack(std::ostream &os, const char *label,
                 const std::vector<Frame> &stack, const std::string &cwd) {
    if (stack.empty())
        return;
    os << "    " << label << ":\n";
    for (size_t i = 0; i < stack.size(); ++i) {
        const Frame &fr = stack[i];
        os << "      #" << i << ' ';
        if (!fr.function.empty())
            os << fr.function;
        else if (fr.file.empty())
            os << (fr.module.empty() ? std::string("??")
                                     : basename_of(fr.module));
        else
            os << "??";
        if (!fr.file.empty()) {
            os << " at " << shorten(fr.file, cwd);
            if (fr.line)
                os << ':' << fr.line;
        } else if (!fr.module.empty()) {
            os << " (" << basename_of(fr.module) << '+' << hex(fr.offset)
               << ')';
        } else {
            os << " (" << hex(fr.offset) << ')';
        }
        if (fr.inlined)
            os << " [inlined]";
        os << '\n';
    }
}

// The route text from outside took to the dangerous call: one line per step,
// in the order it happened.
void print_flow(std::ostream &os, const std::vector<Frame> &flow,
                const std::string &cwd) {
    if (flow.size() < 2)
        return;
    os << "    how the text got here:\n";
    for (size_t i = 0; i < flow.size(); ++i) {
        const Frame &fr = flow[i];
        os << "      #" << i << ' ' << fr.what;
        if (!fr.function.empty())
            os << " in " << fr.function;
        if (!fr.file.empty()) {
            os << " at " << shorten(fr.file, cwd);
            if (fr.line)
                os << ':' << fr.line;
        }
        os << '\n';
    }
}

std::string category_words(const std::string &c) {
    if (c == lcproto::kCatDefinite)
        return "definitely lost";
    if (c == lcproto::kCatIndirect)
        return "indirectly lost";
    if (c == lcproto::kCatPossible)
        return "possibly lost";
    if (c == lcproto::kCatReachable)
        return "still reachable";
    if (c == lcproto::kCatFd)
        return "file descriptor";
    if (c == lcproto::kCatStream)
        return "FILE stream";
    if (c == lcproto::kCatDir)
        return "directory stream";
    if (c == lcproto::kCatProcess)
        return "child process";
    return c;
}

std::string upper(std::string s) {
    for (char &c : s)
        c = char(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

std::string plural(uint64_t n, const char *one, const char *many) {
    return std::to_string(n) + ' ' + (n == 1 ? one : many);
}

} // namespace

void render_console(const Report &r, std::ostream &os) {
    const std::string cwd = cwd_prefix();
    os << "leakcheck: " << r.mode << " analysis of";
    for (const auto &a : r.command)
        os << ' ' << a;
    os << "\n";
    for (const auto &n : r.notes)
        os << "note: " << n << "\n";

    size_t idx = 0;
    for (const Finding &f : r.findings) {
        os << "\n[" << ++idx << "] " << upper(severity_of(f)) << ' ' << f.type;
        if ((f.type == lcproto::kLeak || f.type == lcproto::kResourceLeak) &&
            !f.category.empty() && f.category != "static")
            os << " (" << category_words(f.category) << ')';
        if (f.reachable)
            os << " [reachable from outside input]";
        os << ": " << f.message << "\n";
        if (const lcmal::Family *fam = lcmal::family_of(f.type.c_str()))
            os << "    malware family: " << fam->name << "\n";
        if (const lcvuln::VulnInfo *vuln = lcvuln::vuln_of(f.type.c_str()))
            os << "    vulnerability: CWE-" << vuln->cwe << " (" << vuln->name
               << ") [" << vuln->severity << "]\n";
        if (r.mode == "dynamic") {
            std::string where;
            if (f.type == lcproto::kLeak)
                where = "first block at " + hex(f.address) + " (" +
                        std::to_string(f.size) + " bytes)";
            else if (!is_resource(f) && f.category != lcproto::kCatSignal)
                where =
                    "address " + hex(f.address); // (a handle's number or
                                                 // signal is in its message)
            if (f.tid)
                where += (where.empty() ? "thread " : ", thread ") +
                         std::to_string(f.tid);
            if (r.processes.size() > 1)
                where +=
                    (where.empty() ? "pid " : ", pid ") + std::to_string(f.pid);
            if (!where.empty())
                os << "    " << where << "\n";
        }
        print_stack(os, access_label(f), f.access, cwd);
        print_flow(os, f.flow, cwd);
        print_stack(os, freed_label(f), f.freed, cwd);
        print_stack(os, alloc_label(f), f.alloc, cwd);
        if (f.occurrences > 1)
            os << "    (seen " << f.occurrences
               << " times with the same stacks)\n";
    }

    os << "\n== Summary ==\n";
    std::map<std::string, uint64_t> by_type;
    std::map<std::string, std::pair<uint64_t, uint64_t>>
        leaks; // category -> blocks, bytes
    size_t problems = 0;
    for (const Finding &f : r.findings) {
        if (is_problem_at(f, r.min_severity))
            ++problems;
        if (f.type == lcproto::kLeak && r.mode == "dynamic") {
            leaks[f.category].first += f.blocks;
            leaks[f.category].second += f.bytes;
        } else {
            by_type[f.type] += 1;
        }
    }
    os << "  problems: " << problems << "\n";
    if (!by_type.empty()) {
        os << "  errors:  ";
        bool first = true;
        for (const auto &[t, n] : by_type) {
            os << (first ? " " : ", ") << n << ' ' << t;
            first = false;
        }
        os << "\n";
    }
    if (r.mode == "dynamic") {
        for (const char *c : {lcproto::kCatDefinite, lcproto::kCatIndirect,
                              lcproto::kCatPossible, lcproto::kCatReachable}) {
            auto it = leaks.find(c);
            if (it == leaks.end())
                continue;
            os << "  " << category_words(c) << ": "
               << plural(it->second.second, "byte", "bytes") << " in "
               << plural(it->second.first, "block", "blocks") << "\n";
        }
        for (const Process &p : r.processes) {
            os << "  heap (pid " << p.pid
               << "): " << plural(p.stats.allocs, "allocation", "allocations")
               << ", " << plural(p.stats.frees, "release", "releases") << ", "
               << plural(p.stats.bytes, "byte", "bytes") << " allocated, peak "
               << plural(p.stats.peak_bytes, "byte", "bytes") << " in use, "
               << plural(p.stats.live_bytes, "byte", "bytes") << " in "
               << plural(p.stats.live_blocks, "block", "blocks")
               << " still in use at exit\n";
            if (!p.complete)
                os << "  warning: pid " << p.pid
                   << " ended abnormally; its leak check did not run\n";
            if (p.stats.dropped)
                os << "  warning: " << p.stats.dropped
                   << " further findings were dropped\n";
        }
        if (r.ran) {
            if (r.signal)
                os << "  target:   killed by signal " << r.signal << "\n";
            else
                os << "  target:   exited with status " << r.exit_code << "\n";
        }
    } else {
        os << "  files analyzed: " << r.files_analyzed << "\n";
    }
}

} // namespace lcreport
