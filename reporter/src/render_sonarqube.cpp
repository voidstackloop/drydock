// -f sonarqube: Official SonarQube Generic Issue Import JSON format.
// https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/importing-external-issues/generic-issue-import-format/
#include "internal.h"

#include <ostream>

namespace lcreport {
namespace {

const char *sonar_severity(const Finding &f) {
    const std::string s = severity_of(f);
    if (s == "critical")
        return "BLOCKER";
    if (s == "high" || s == "error")
        return "CRITICAL";
    if (s == "medium" || s == "warning")
        return "MAJOR";
    return "MINOR";
}

} // namespace

void render_sonarqube(const Report &r, std::ostream &os) {
    Json j(os);
    j.begin_object();
    j.key("issues").begin_array();
    for (const Finding &f : r.findings) {
        const Frame *p = primary_frame(f);
        std::string path = p && !p->file.empty() ? p->file : "unknown";
        int line = p && p->line > 0 ? p->line : 1;

        j.begin_object()
            .kv("engineId", "leakcheck")
            .kv("ruleId", f.type)
            .kv("severity", sonar_severity(f))
            .kv("type", "VULNERABILITY")
            .key("primaryLocation")
            .begin_object()
                .kv("message", f.message)
                .kv("filePath", path)
                .key("textRange")
                .begin_object()
                    .kv("startLine", line)
                .end_object()
            .end_object()
        .end_object();
    }
    j.end_array();
    j.end_object();
}

} // namespace lcreport
