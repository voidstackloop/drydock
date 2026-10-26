#include "internal.h"
#include "protocol.h"
#include "vulnerability.h"

#include <algorithm>
#include <cctype>
#include <unistd.h>

namespace lcreport {
namespace {

std::string cwd() {
    char buf[4096];
    if (!getcwd(buf, sizeof buf))
        return {};
    std::string s(buf);
    std::replace(s.begin(), s.end(), '\\', '/'); // Windows: URIs use '/'
    return s;
}

std::string uri_escape(const std::string &s) {
    static const char *hexd = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '/' || c == '-' || c == '_' || c == '.' ||
            c == '~')
            out += char(c);
        else {
            out += '%';
            out += hexd[c >> 4];
            out += hexd[c & 15];
        }
    }
    return out;
}

// Files under the working directory become SRCROOT-relative, which is what
// code-scanning services expect; anything else stays an absolute file URI.
void artifact(Json &j, const std::string &file, const std::string &root) {
    j.key("artifactLocation").begin_object();
    if (!root.empty() && file.rfind(root + "/", 0) == 0) {
        j.kv("uri", uri_escape(file.substr(root.size() + 1)));
        j.kv("uriBaseId", "SRCROOT");
    } else if (!file.empty() && file[0] == '/') {
        j.kv("uri", "file://" + uri_escape(file));
    } else {
        j.kv("uri", uri_escape(file));
        j.kv("uriBaseId", "SRCROOT");
    }
    j.end_object();
}

void location(Json &j, const Frame &fr, const std::string &root,
              const std::string &text) {
    j.begin_object();
    if (!text.empty())
        j.key("message").begin_object().kv("text", text).end_object();
    if (!fr.file.empty()) {
        j.key("physicalLocation").begin_object();
        artifact(j, fr.file, root);
        if (fr.line > 0) {
            j.key("region").begin_object().kv("startLine", fr.line);
            if (fr.column > 0)
                j.kv("startColumn", fr.column);
            j.end_object();
        }
        j.end_object();
    }
    std::string name = fr.function;
    if (name.empty() && !fr.module.empty())
        name = fr.module + "+" + hex(fr.offset);
    if (!name.empty()) {
        j.key("logicalLocations").begin_array();
        j.begin_object()
            .kv("fullyQualifiedName", name)
            .kv("kind", "function")
            .end_object();
        j.end_array();
    }
    j.end_object();
}

void stack(Json &j, const std::vector<Frame> &frames, const char *label,
           const std::string &root) {
    if (frames.empty())
        return;
    j.begin_object();
    j.key("message").begin_object().kv("text", label).end_object();
    j.key("frames").begin_array();
    for (const Frame &fr : frames) {
        j.begin_object();
        j.key("location");
        location(j, fr, root, "");
        if (!fr.module.empty())
            j.kv("module", fr.module);
        j.end_object();
    }
    j.end_array();
    j.end_object();
}

// SARIF's way of showing a route: one threadFlow, one location per step, in
// the order the text moved.
void code_flow(Json &j, const std::vector<Frame> &flow,
               const std::string &root) {
    if (flow.size() < 2)
        return;
    j.key("codeFlows").begin_array().begin_object();
    j.key("message")
        .begin_object()
        .kv("text", "how text from outside reached this call")
        .end_object();
    j.key("threadFlows").begin_array().begin_object();
    j.key("locations").begin_array();
    for (const Frame &fr : flow) {
        j.begin_object();
        j.key("location");
        location(j, fr, root, fr.what);
        j.end_object();
    }
    j.end_array();
    j.end_object().end_array();
    j.end_object().end_array();
}

std::string rule_help_uri(const std::string &id) {
    return "https://github.com/voidstackloop/drydock/blob/main/docs/rules/" + id + ".md";
}

int rule_index(const std::string &id) {
    const auto &rs = rules();
    for (size_t i = 0; i < rs.size(); ++i)
        if (id == rs[i].id)
            return int(i);
    return -1;
}

const char *level_of(const Finding &f) {
    const std::string s = severity_of(f);
    return s == "error" ? "error" : s == "warning" ? "warning" : "note";
}

} // namespace

void render_sarif(const Report &r, std::ostream &os) {
    const std::string root = cwd();
    Json j(os);
    j.begin_object();
    j.kv("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
    j.kv("version", "2.1.0");
    j.key("runs").begin_array();
    j.begin_object();

    j.key("tool").begin_object().key("driver").begin_object();
    j.kv("name", kToolName)
        .kv("version", kToolVersion)
        .kv("semanticVersion", kToolVersion);
    j.key("rules").begin_array();
    for (const Rule &rule : rules()) {
        j.begin_object();
        j.kv("id", rule.id).kv("name", rule.name);
        j.key("shortDescription")
            .begin_object()
            .kv("text", rule.summary)
            .end_object();
        j.key("fullDescription")
            .begin_object()
            .kv("text", rule.help)
            .end_object();
        j.key("help").begin_object().kv("text", rule.help).end_object();
        j.kv("helpUri", rule_help_uri(rule.id));
        j.key("defaultConfiguration")
            .begin_object()
            .kv("level", "error")
            .end_object();
        if (const lcvuln::VulnInfo *vuln = lcvuln::vuln_of(rule.id)) {
            j.key("relationships").begin_array().begin_object();
            j.key("target").begin_object();
            j.kv("id", std::to_string(vuln->cwe));
            j.key("toolComponent").begin_object().kv("name", "CWE").end_object();
            j.end_object();
            j.key("kinds").begin_array().value("superset").end_array();
            j.end_object().end_array();
            j.key("properties").begin_object();
            j.key("tags").begin_array();
            j.value("security");
            j.value("external/cwe/cwe-" + std::to_string(vuln->cwe));
            j.end_array();
            j.kv("cwe", uint64_t(vuln->cwe));
            j.kv("precision", "high");
            j.kv("security-severity", vuln->severity == std::string("critical") ? "9.0" :
                                      vuln->severity == std::string("high") ? "7.5" :
                                      vuln->severity == std::string("medium") ? "5.5" : "3.0");
            j.end_object();
        }
        j.end_object();
    }
    j.end_array();
    j.end_object().end_object();

    // The CWE taxonomy, so a reviewer can group results by weakness instead of
    // by our rule ids. One taxon per weakness this build knows.
    j.key("taxonomies").begin_array().begin_object();
    j.kv("name", "CWE")
        .kv("version", "4.15")
        .kv("organization", "MITRE")
        .kv("informationUri", "https://cwe.mitre.org/")
        .kv("isComprehensive", false);
    j.key("taxa").begin_array();
    std::vector<int> cwes;
    for (const lcvuln::VulnInfo &v : lcvuln::kVulns)
        if (std::find(cwes.begin(), cwes.end(), v.cwe) == cwes.end())
            cwes.push_back(v.cwe);
    std::sort(cwes.begin(), cwes.end());
    for (int cwe : cwes) {
        const lcvuln::VulnInfo *v = lcvuln::vuln_by_cwe(cwe);
        j.begin_object();
        j.kv("id", std::to_string(cwe));
        if (v)
            j.kv("name", v->name);
        if (v) {
            j.key("shortDescription").begin_object().kv("text", v->summary).end_object();
            j.kv("helpUri", "https://cwe.mitre.org/data/definitions/" +
                                 std::to_string(cwe) + ".html");
        }
        j.end_object();
    }
    j.end_array();
    j.end_object().end_array();

    j.key("originalUriBaseIds").begin_object();
    j.key("SRCROOT")
        .begin_object()
        .kv("uri", "file://" + uri_escape(root) + "/")
        .end_object();
    j.end_object();

    j.key("invocations").begin_array().begin_object();
    j.key("arguments").begin_array();
    for (const auto &a : r.command)
        j.value(a);
    j.end_array();
    j.kv("executionSuccessful", true);
    if (r.mode == "dynamic" && r.ran && !r.signal)
        j.kv("exitCode", r.exit_code);
    if (!r.notes.empty()) {
        j.key("toolExecutionNotifications").begin_array();
        for (const auto &n : r.notes) {
            j.begin_object();
            j.key("message").begin_object().kv("text", n).end_object();
            j.kv("level", "note");
            j.end_object();
        }
        j.end_array();
    }
    j.end_object().end_array();

    j.key("results").begin_array();
    for (const Finding &f : r.findings) {
        j.begin_object();
        j.kv("ruleId", f.type);
        if (int idx = rule_index(f.type); idx >= 0)
            j.kv("ruleIndex", idx);
        j.kv("level", level_of(f));
        std::string text = f.message;
        if (f.occurrences > 1)
            text += " (seen " + std::to_string(f.occurrences) + " times)";
        j.key("message").begin_object().kv("text", text).end_object();
        if (const Frame *p = primary_frame(f)) {
            j.key("locations").begin_array();
            location(j, *p, root, "");
            j.end_array();
        }
        code_flow(j, f.flow, root);
        j.key("stacks").begin_array();
        stack(j, f.access, access_label(f), root);
        stack(j, f.freed, freed_label(f), root);
        stack(j, f.alloc, alloc_label(f), root);
        j.end_array();
        if (!f.key.empty())
            j.key("partialFingerprints")
                .begin_object()
                .kv("leakcheck/v1", f.key)
                .end_object();
        j.key("properties").begin_object();
        if (const lcvuln::VulnInfo *vuln = lcvuln::vuln_of(f.type.c_str())) {
            j.kv("cwe", uint64_t(vuln->cwe));
            j.kv("vulnerability", vuln->name);
            j.kv("vuln_severity", vuln->severity);
        }
        if (!f.category.empty())
            j.kv("category", f.category);
        j.kv("occurrences", f.occurrences);
        if (f.type == lcproto::kLeak && f.blocks)
            j.kv("blocks", f.blocks).kv("bytes", f.bytes);
        if (r.mode == "dynamic")
            j.kv("address", hex(f.address)).kv("size", f.size);
        j.end_object();
        j.end_object();
    }
    j.end_array();

    j.end_object();
    j.end_array();
    j.end_object();
}

} // namespace lcreport
