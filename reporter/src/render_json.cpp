#include "internal.h"
#include "malware.h"
#include "protocol.h"
#include "vulnerability.h"

#include <map>

namespace lcreport {
namespace {

void frames(Json &j, const std::vector<Frame> &stack) {
    j.begin_array();
    for (const Frame &fr : stack) {
        j.begin_object();
        if (!fr.function.empty())
            j.kv("function", fr.function);
        if (!fr.file.empty()) {
            j.kv("file", fr.file);
            j.kv("line", fr.line);
            if (fr.column)
                j.kv("column", fr.column);
        }
        if (!fr.module.empty()) {
            j.kv("module", fr.module);
            j.kv("offset", hex(fr.offset));
        }
        if (fr.inlined)
            j.kv("inlined", true);
        if (!fr.what.empty())
            j.kv("what", fr.what);
        j.end_object();
    }
    j.end_array();
}

} // namespace

void render_json(const Report &r, std::ostream &os) {
    Json j(os);
    j.begin_object();
    j.key("tool")
        .begin_object()
        .kv("name", kToolName)
        .kv("version", kToolVersion)
        .end_object();
    j.kv("mode", r.mode);
    j.key("command").begin_array();
    for (const auto &a : r.command)
        j.value(a);
    j.end_array();
    if (r.mode == "dynamic" && r.ran) {
        j.key("target").begin_object();
        j.kv("status", r.signal ? "signaled" : "exited");
        if (r.signal)
            j.kv("signal", r.signal);
        else
            j.kv("exit_code", r.exit_code);
        j.end_object();
    }

    std::map<std::string, uint64_t> by_type;
    std::map<std::string, std::pair<uint64_t, uint64_t>> leaks;
    uint64_t problems = 0;
    for (const Finding &f : r.findings) {
        problems += is_problem_at(f, r.min_severity);
        by_type[f.type] += 1;
        if (f.type == lcproto::kLeak && !f.category.empty() &&
            f.category != "static") {
            leaks[f.category].first += f.blocks;
            leaks[f.category].second += f.bytes;
        }
    }
    j.key("summary").begin_object();
    j.kv("problems", problems);
    j.key("by_type").begin_object();
    for (const auto &[t, n] : by_type)
        j.kv(t, n);
    j.end_object();
    if (r.mode == "dynamic") {
        j.key("leaks").begin_object();
        for (const auto &[c, v] : leaks)
            j.key(c)
                .begin_object()
                .kv("blocks", v.first)
                .kv("bytes", v.second)
                .end_object();
        j.end_object();
    } else {
        j.kv("files_analyzed", uint64_t(r.files_analyzed));
    }
    j.end_object();

    if (r.mode == "dynamic") {
        j.key("processes").begin_array();
        for (const Process &p : r.processes) {
            j.begin_object();
            j.kv("pid", uint64_t(p.pid)).kv("executable", p.exe);
            j.kv("complete", p.complete).kv("leak_check", p.scanned);
            j.key("heap").begin_object();
            j.kv("allocations", p.stats.allocs).kv("releases", p.stats.frees);
            j.kv("bytes_allocated", p.stats.bytes)
                .kv("peak_bytes", p.stats.peak_bytes);
            j.kv("live_blocks_at_exit", p.stats.live_blocks)
                .kv("live_bytes_at_exit", p.stats.live_bytes);
            j.kv("dropped_findings", p.stats.dropped);
            j.end_object();
            j.end_object();
        }
        j.end_array();
    }

    j.key("findings").begin_array();
    uint64_t id = 0;
    for (const Finding &f : r.findings) {
        j.begin_object();
        j.kv("id", ++id);
        j.kv("type", f.type);
        if (!f.category.empty())
            j.kv("category", f.category);
        j.kv("severity", severity_of(f));
        j.kv("message", f.message);
        if (const lcmal::Family *fam = lcmal::family_of(f.type.c_str()))
            j.kv("malware_family", fam->name);
        if (const lcvuln::VulnInfo *vuln = lcvuln::vuln_of(f.type.c_str())) {
            j.kv("cwe", uint64_t(vuln->cwe));
            j.kv("vulnerability", vuln->name);
            j.kv("vuln_severity", vuln->severity);
        }
        if (const Frame *p = primary_frame(f); p && !p->file.empty()) {
            j.key("location").begin_object();
            j.kv("file", p->file).kv("line", p->line);
            if (p->column)
                j.kv("column", p->column);
            if (!p->function.empty())
                j.kv("function", p->function);
            j.end_object();
        }
        if (r.mode == "dynamic") {
            j.kv("address", hex(f.address));
            j.kv("size", f.size);
            j.kv("pid", uint64_t(f.pid)).kv("thread", uint64_t(f.tid));
        }
        if (f.type == lcproto::kLeak && f.blocks)
            j.kv("blocks", f.blocks).kv("bytes", f.bytes);
        j.kv("occurrences", f.occurrences);
        if (f.flow.size() > 1) {
            j.key("flow");
            frames(j, f.flow);
        }
        j.key("stacks").begin_object();
        if (!f.access.empty()) {
            j.key("access");
            frames(j, f.access);
        }
        if (!f.alloc.empty()) {
            j.key("alloc");
            frames(j, f.alloc);
        }
        if (!f.freed.empty()) {
            j.key("free");
            frames(j, f.freed);
        }
        j.end_object();
        j.end_object();
    }
    j.end_array();

    j.key("notes").begin_array();
    for (const auto &n : r.notes)
        j.value(n);
    j.end_array();
    j.end_object();
}

} // namespace lcreport
