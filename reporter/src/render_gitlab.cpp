// -f gitlab: GitLab Code Quality JSON artifact format.
// https://docs.gitlab.com/ee/ci/testing/code_quality.html
#include "internal.h"

#include <ostream>

namespace lcreport {
namespace {

const char *gitlab_severity(const Finding &f) {
    const std::string s = severity_of(f);
    if (s == "critical")
        return "critical";
    if (s == "high" || s == "error")
        return "major";
    if (s == "medium" || s == "warning")
        return "minor";
    return "info";
}

} // namespace

void render_gitlab(const Report &r, std::ostream &os) {
    Json j(os);
    j.begin_array();
    for (const Finding &f : r.findings) {
        const Frame *p = primary_frame(f);
        std::string path = p && !p->file.empty() ? p->file : "unknown";
        int line = p && p->line > 0 ? p->line : 1;

        j.begin_object()
            .kv("description", f.message)
            .kv("check_name", f.type)
            .kv("fingerprint", f.key.empty() ? std::to_string(stable_hash(f.type + "|" + path + "|" + std::to_string(line))) : f.key)
            .kv("severity", gitlab_severity(f))
            .key("location")
            .begin_object()
                .kv("path", path)
                .key("lines")
                .begin_object()
                    .kv("begin", line)
                .end_object()
            .end_object()
        .end_object();
    }
    j.end_array();
}

} // namespace lcreport
