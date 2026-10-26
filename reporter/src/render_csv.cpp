// -f csv: Standard RFC 4180 CSV export for spreadsheet import,
// enterprise vulnerability management databases, and Jira ticketing.
#include "internal.h"
#include "vulnerability.h"

#include <ostream>

namespace lcreport {
namespace {

std::string escape_csv(const std::string &s) {
    bool needs_quotes = false;
    for (char c : s) {
        if (c == ',' || c == '"' || c == '\n' || c == '\r') {
            needs_quotes = true;
            break;
        }
    }
    if (!needs_quotes)
        return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"')
            out += "\"\"";
        else
            out.push_back(c);
    }
    out += "\"";
    return out;
}

} // namespace

void render_csv(const Report &r, std::ostream &os) {
    os << "rule_id,cwe,severity,file,line,column,function,category,message,help_url\n";
    for (const Finding &f : r.findings) {
        const Frame *p = primary_frame(f);
        std::string file = p ? p->file : "";
        int line = p ? p->line : 0;
        int col = p ? p->column : 0;
        std::string fn = p ? p->function : "";
        std::string cwe_id = "";
        std::string help_url = "";

        if (const lcvuln::VulnInfo *v = lcvuln::vuln_of(f.type.c_str())) {
            cwe_id = std::to_string(v->cwe);
            help_url = "https://cwe.mitre.org/data/definitions/" + cwe_id + ".html";
        }

        os << escape_csv(f.type) << ","
           << escape_csv(cwe_id) << ","
           << escape_csv(severity_of(f)) << ","
           << escape_csv(file) << ","
           << line << ","
           << col << ","
           << escape_csv(fn) << ","
           << escape_csv(f.category) << ","
           << escape_csv(f.message) << ","
           << escape_csv(help_url) << "\n";
    }
}

} // namespace lcreport
