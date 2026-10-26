// -f html: one self-contained page per report, no JavaScript and no external
// files, so it can be attached to a CI run or opened from a file share. One
// table row per finding, with the route text from outside took when it has one.
#include "internal.h"

#include <ostream>

namespace lcreport {
namespace {

std::string html(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20 && c != '\t' && c != '\n')
                out.push_back(' ');
            else
                out.push_back(c);
        }
    }
    return out;
}

std::string where(const Frame *p) {
    if (!p || p->file.empty())
        return {};
    std::string out = p->file;
    if (p->line)
        out += ":" + std::to_string(p->line);
    if (!p->function.empty())
        out += " in " + p->function;
    return out;
}

} // namespace

void render_html(const Report &r, std::ostream &os) {
    size_t problems = 0;
    for (const Finding &f : r.findings)
        problems += is_problem_at(f, r.min_severity) ? 1 : 0;
    os << "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=" "\"utf-8\"" ">\n"
       << "<title>leakcheck " << html(r.mode) << " report</title>\n"
       << "<style>table{border-collapse:collapse}"
       << "th,td{border:1px solid #ccc;padding:.3em .6em;text-align:left}</style>\n"
       << "</head>\n<body>\n<h1>leakcheck " << html(r.mode) << " report</h1>\n<p>"
       << r.findings.size() << " finding(s), " << problems << " problem(s)";
    if (r.files_analyzed)
        os << ", " << r.files_analyzed << " file(s) analyzed";
    os << ".</p>\n";
    for (const std::string &n : r.notes)
        os << "<p>" << html(n) << "</p>\n";
    if (r.findings.empty()) {
        os << "<p>No findings.</p>\n</body>\n</html>\n";
        return;
    }
    os << "<table>\n<tr><th>severity</th><th>finding</th><th>detail</th></tr>\n";
    for (const Finding &f : r.findings) {
        const std::string severity = severity_of(f);
        const std::string at = where(primary_frame(f));
        os << "<tr><td>" << html(severity)
           << "</td><td>" << html(f.type) << "</td><td>" << html(f.message);
        if (!at.empty())
            os << "<br>" << html(at);
        if (!f.flow.empty()) {
            os << "<br>route:<ol>";
            for (const Frame &s : f.flow) {
                os << "<li>" << html(s.what.empty() ? s.function : s.what);
                const std::string sw = where(&s);
                if (!sw.empty())
                    os << " at " << html(sw);
                os << "</li>";
            }
            os << "</ol>";
        }
        os << "</td></tr>\n";
    }
    os << "</table>\n</body>\n</html>\n";
}

} // namespace lcreport
