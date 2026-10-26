// -f junit: the format GitLab, Jenkins, Buildkite and most test reporters
// already read. One test case per finding, so a pull request shows which rule
// failed where, and a clean run still has a test case to report.
#include "internal.h"

#include <algorithm>
#include <ostream>

namespace lcreport {
namespace {

std::string xml(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&apos;"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20 && c != '\t' && c != '\n')
                out.push_back(' ');
            else
                out.push_back(c);
        }
    }
    return out;
}

} // namespace

void render_junit(const Report &r, std::ostream &os) {
    size_t failures = 0;
    for (const Finding &f : r.findings)
        failures += is_problem_at(f, r.min_severity);
    const size_t tests = std::max<size_t>(1, r.findings.size());
    os << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    os << "<testsuite name=\"leakcheck." << xml(r.mode) << "\" tests=\"" << tests
       << "\" failures=\"" << failures << "\" errors=\"0\" skipped=\"0\">\n";
    if (r.findings.empty()) {
        os << "  <testcase classname=\"leakcheck\" name=\"no findings\"/>\n";
    }
    size_t id = 0;
    for (const Finding &f : r.findings) {
        const Frame *p = primary_frame(f);
        std::string where = p && !p->file.empty() ? p->file : std::string("the file");
        if (p && p->line)
            where += ":" + std::to_string(p->line);
        const std::string name = f.type + " at " + where;
        os << "  <testcase classname=\"leakcheck." << xml(f.type) << "\" name=\""
           << xml(name) << "\"";
        const std::string severity = severity_of(f);
        os << " file=\"" << xml(p ? p->file : "") << "\"";
        if (p && p->line)
            os << " line=\"" << p->line << "\"";
        if (!is_problem_at(f, r.min_severity)) {
            os << ">\n    <system-out>" << xml(severity + ": " + f.message)
               << "</system-out>\n  </testcase>\n";
            ++id;
            continue;
        }
        os << ">\n    <failure type=\"" << xml(f.type) << "\" message=\""
           << xml(severity + ": " + f.message) << "\">";
        os << xml(f.message + "\n" + where);
        os << "</failure>\n  </testcase>\n";
        ++id;
    }
    (void)id;
    os << "</testsuite>\n";
}

} // namespace lcreport
