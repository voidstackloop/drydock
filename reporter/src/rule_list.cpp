// --rule-list: the inventory a compliance or platform team needs without
// reading the source: every rule, the CWE it maps to, its severity, and
// whether a default run reports it.
#include "internal.h"
#include "malware.h"
#include "protocol.h"
#include "vulnerability.h"

#include <cstdio>
#include <ostream>

namespace lcreport {
namespace {

// The severity a default run gives this rule. Rules that honest software also
// triggers (persistence, packing, anti-analysis) are warnings; vulnerability
// rules follow the CWE's own severity.
const char *default_level(const Rule &rule) {
    if (const lcvuln::VulnInfo *v = lcvuln::vuln_of(rule.id)) {
        const std::string s = v->severity;
        return s == "critical" || s == "high" ? "error" : s == "medium" ? "warning" : "note";
    }
    if (const lcmal::Family *f = lcmal::family_of(rule.id))
        return f->weak ? "warning" : "error";
    const std::string id = rule.id;
    if (id == lcproto::kPersistence || id == lcproto::kAntiAnalysis ||
        id == lcproto::kObfuscated || id == lcproto::kDropper ||
        id == lcproto::kCredAccess || id == lcproto::kNetScan ||
        id == lcproto::kSuspiciousBin || id == lcproto::kSystemTamper)
        return "warning";
    if (id == lcproto::kLeak || id == lcproto::kResourceLeak ||
        id == lcproto::kDangling || id == lcproto::kBindReuse)
        return "warning";
    return "error";
}

} // namespace

void render_rule_list(bool json, std::ostream &os) {
    if (json) {
        Json j(os);
        j.begin_array();
        for (const Rule &r : rules()) {
            j.begin_object();
            j.kv("id", r.id).kv("name", r.name);
            if (const lcvuln::VulnInfo *v = lcvuln::vuln_of(r.id)) {
                j.kv("cwe", uint64_t(v->cwe));
                j.kv("vulnerability_severity", v->severity);
            } else {
                j.key("cwe").null();
                j.key("vulnerability_severity").null();
            }
            j.kv("default_severity", default_level(r));
            j.kv("strict", strict_rule(r.id));
            j.kv("enabled", !strict_rule(r.id));
            j.kv("summary", r.summary);
            j.kv("help", r.help);
            j.end_object();
        }
        j.end_array();
        return;
    }
    os << "ID\tNAME\tCWE\tSEVERITY\tDEFAULT\tWHEN\n";
    for (const Rule &r : rules()) {
        const lcvuln::VulnInfo *v = lcvuln::vuln_of(r.id);
        char cwe[16] = "-";
        if (v)
            std::snprintf(cwe, sizeof cwe, "%d", v->cwe);
        os << r.id << '\t' << r.name << '\t' << cwe << '\t'
           << (v ? v->severity : "n/a") << '\t' << default_level(r) << '\t'
           << (strict_rule(r.id) ? "strict-only" : "default") << '\n';
    }
}

} // namespace lcreport
