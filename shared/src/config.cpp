#include "config.h"
#include "report.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>

namespace fs = std::filesystem;

namespace lcconfig {
namespace {

std::string trim(const std::string &s) {
    const size_t b = s.find_first_not_of(" \t\r\n");
    const size_t e = s.find_last_not_of(" \t\r\n");
    return b == std::string::npos ? std::string() : s.substr(b, e - b + 1);
}

std::string lower(std::string s) {
    for (char &c : s)
        c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Removes a # comment that is not inside a quoted string.
std::string strip_comment(const std::string &line) {
    bool quoted = false;
    for (size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '\\' &&
            (quoted || (i + 1 < line.size() && line[i + 1] == '#')))
            ++i;
        else if (line[i] == '"')
            quoted = !quoted;
        else if (line[i] == '#' && !quoted)
            return line.substr(0, i);
    }
    return line;
}

bool unquote(const std::string &text, std::string *out, std::string *error) {
    const std::string t = trim(text);
    if (t.size() < 2 || t.front() != '"' || t.back() != '"') {
        *error = "expected a quoted string";
        return false;
    }
    out->clear();
    for (size_t i = 1; i + 1 < t.size(); ++i) {
        if (t[i] == '\\' && i + 2 < t.size()) {
            const char e = t[++i];
            out->push_back(e == 'n' ? '\n' : e == 't' ? '\t' : e);
        } else {
            out->push_back(t[i]);
        }
    }
    return true;
}

bool integer(const std::string &text, int *out) {
    const std::string t = trim(text);
    if (t.empty())
        return false;
    char *end = nullptr;
    const long v = std::strtol(t.c_str(), &end, 10);
    if (*end || v < -1 || v > 1000000)
        return false;
    *out = int(v);
    return true;
}

// ["a", "b"] or a single "a"; entries may be quoted or bare.
bool array(const std::string &text, std::vector<std::string> *out, std::string *error) {
    std::string t = trim(text);
    if (t.empty()) {
        *error = "expected a string or a list of strings";
        return false;
    }
    if (t.front() != '[') {
        std::string v;
        if (t.front() == '"') {
            if (!unquote(t, &v, error))
                return false;
        } else {
            v = t;
        }
        if (!v.empty())
            out->push_back(v);
        return true;
    }
    if (t.back() != ']') {
        *error = "a list does not end with ']'";
        return false;
    }
    t = t.substr(1, t.size() - 2);
    std::string item;
    bool quoted = false;
    for (size_t i = 0; i <= t.size(); ++i) {
        const char c = i < t.size() ? t[i] : ',';
        if (c == '"')
            quoted = !quoted;
        if (c == ',' && !quoted) {
            std::string v = trim(item);
            item.clear();
            if (v.empty())
                continue;
            if (v.front() == '"') {
                if (!unquote(v, &v, error))
                    return false;
            }
            out->push_back(v);
        } else {
            item.push_back(c);
        }
    }
    return true;
}

bool set_string(const std::string &key, const std::string &value, Settings *s,
                const std::string &where, std::string *error) {
    std::string v;
    if (!unquote(value, &v, error)) {
        *error = where + ": " + key + ": " + *error;
        return false;
    }
    if (key == "format") {
        if (v != "console" && v != "json" && v != "sarif" && v != "junit") {
            *error = where + ": format must be console, json, sarif or junit";
            return false;
        }
        s->format = v;
    } else if (key == "suppressions") {
        s->suppressions = v;
    } else if (key == "baseline") {
        s->baseline = v;
    } else if (key == "min-severity") {
        if (v != "error" && v != "warning" && v != "note") {
            *error = where + ": min-severity must be error, warning or note";
            return false;
        }
        s->min_severity = v;
    } else {
        *error = where + ": unknown key '" + key + "'";
        return false;
    }
    return true;
}

bool set_key(const std::string &key_in, const std::string &value, Settings *s,
             const std::string &where, std::string *error) {
    std::string key = lower(key_in);
    std::replace(key.begin(), key.end(), '_', '-');
    if (key == "jobs" || key == "error-exitcode") {
        int v = -1;
        if (!integer(value, &v) || v < 1 || v > (key == "jobs" ? 256 : 255)) {
            *error = where + ": " + key + (key == "jobs" ? " expects 1-256" : " expects 1-255");
            return false;
        }
        (key == "jobs" ? s->jobs : s->error_exitcode) = v;
        return true;
    }
    if (key == "exclude" || key == "excludes") {
        if (!array(value, &s->exclude, error)) {
            *error = where + ": exclude: " + *error;
            return false;
        }
        return true;
    }
    if (key == "enable-rules" || key == "disable-rules") {
        std::vector<std::string> &out =
            key == "enable-rules" ? s->enable_rules : s->disable_rules;
        const std::vector<std::string> &opposite =
            key == "enable-rules" ? s->disable_rules : s->enable_rules;
        const size_t before = out.size();
        if (!array(value, &out, error)) {
            *error = where + ": " + key + ": " + *error;
            return false;
        }
        for (size_t i = before; i < out.size(); ++i) {
            if (std::find(opposite.begin(), opposite.end(), out[i]) != opposite.end()) {
                *error = where + ": rule '" + out[i] +
                         "' cannot be both enabled and disabled in one section";
                return false;
            }
        }
        return true;
    }
    return set_string(key, value, s, where, error);
}

Settings *section_for(FileConfig *cfg, const std::string &name) {
    if (name == "static")
        return &cfg->static_mode;
    if (name == "scan")
        return &cfg->scan_mode;
    if (name == "dynamic")
        return &cfg->dynamic_mode;
    if (name == "ai-features" || name == "ai_features")
        return &cfg->ai_features_mode;
    return nullptr;
}

} // namespace

bool find_upwards(const std::string &start, const std::string &name, std::string *path) {
    std::error_code ec;
    fs::path dir = fs::absolute(start, ec);
    if (ec)
        return false;
    if (!fs::is_directory(dir, ec))
        dir = dir.parent_path();
    for (;;) {
        const fs::path candidate = dir / name;
        if (fs::is_regular_file(candidate, ec)) {
            *path = candidate.generic_string();
            return true;
        }
        const fs::path parent = dir.parent_path();
        if (parent == dir || parent.empty())
            return false;
        dir = parent;
    }
}

bool load(const std::string &path, FileConfig *cfg, std::string *error) {
    std::ifstream in(path);
    if (!in) {
        *error = "cannot read '" + path + "'";
        return false;
    }
    std::error_code ec;
    cfg->found = true;
    cfg->path = path;
    cfg->root = fs::absolute(fs::path(path), ec).parent_path().generic_string();
    Settings *current = &cfg->all;
    std::string current_rule;
    std::string line;
    int no = 0;
    while (std::getline(in, line)) {
        ++no;
        const std::string where = path + ":" + std::to_string(no);
        line = trim(strip_comment(line));
        if (line.empty())
            continue;
        if (line.front() == '[') {
            if (line.back() != ']') {
                *error = where + ": a section ends with ']'";
                return false;
            }
            const std::string name = lower(trim(line.substr(1, line.size() - 2)));
            if (name.rfind("rules.", 0) == 0 || name.rfind("rule.", 0) == 0) {
                current_rule = name.substr(name.find('.') + 1);
                current = nullptr;
                continue;
            }
            current_rule.clear();
            current = section_for(cfg, name);
            if (!current) {
                *error = where + ": unknown section '" + name +
                         "' (static, scan, dynamic or ai-features)";
                return false;
            }
            continue;
        }
        const size_t eq = line.find('=');
        if (eq == std::string::npos || eq == 0) {
            *error = where + ": expected key = value";
            return false;
        }
        if (!current_rule.empty()) {
            std::string k = lower(trim(line.substr(0, eq)));
            if (k == "severity") {
                std::string v;
                if (!unquote(line.substr(eq + 1), &v, error))
                    v = trim(line.substr(eq + 1));
                cfg->rule_severities[current_rule] = lower(v);
                continue;
            }
            *error = where + ": unknown key '" + k + "' in [" + current_rule + "]";
            return false;
        }
        if (!set_key(trim(line.substr(0, eq)), line.substr(eq + 1), current, where, error))
            return false;
    }
    return true;
}

void apply(Command &command, const FileConfig &cfg) {
    // A path in the file is relative to the file, not to where the command ran.
    auto anchor = [&](const std::string &p) {
        if (p.empty() || !fs::path(p).is_relative())
            return p;
        return (fs::path(cfg.root) / p).lexically_normal().generic_string();
    };
    std::vector<RulePolicy> configured_policy;
    auto fill = [&](const Settings &s) {
        if (!command.format_set && !s.format.empty())
            command.format = s.format;
        if (!command.jobs_set && s.jobs > 0)
            command.jobs = s.jobs;
        if (!command.suppressions_set && !s.suppressions.empty())
            command.suppressions = anchor(s.suppressions);
        if (!command.min_severity_set && !s.min_severity.empty())
            command.min_severity = s.min_severity;
        if (!command.error_exitcode_set && s.error_exitcode > 0)
            command.error_exitcode = s.error_exitcode;
        if (!command.baseline_set && !s.baseline.empty()) {
            command.baseline_path = anchor(s.baseline);
            command.baseline_mode = "compare";
        }
        for (const std::string &pattern : s.exclude)
            command.excludes.push_back({cfg.root, pattern});
        for (const std::string &id : s.enable_rules)
            configured_policy.push_back({id, true});
        for (const std::string &id : s.disable_rules)
            configured_policy.push_back({id, false});
    };
    fill(cfg.all);
    if (command.mode == "static")
        fill(cfg.static_mode);
    else if (command.mode == "scan")
        fill(cfg.scan_mode);
    else if (command.mode == "dynamic")
        fill(cfg.dynamic_mode);
    else if (command.mode == "ai-features")
        fill(cfg.ai_features_mode);
    configured_policy.insert(configured_policy.end(), command.rule_policy.begin(),
                             command.rule_policy.end());
    command.rule_policy = std::move(configured_policy);
    for (const auto &[rule, sev] : cfg.rule_severities)
        command.rule_severities[rule] = sev;
}

bool load_ignore_file(Command &command, std::string *error) {
    std::string path;
    if (!find_upwards(command.target, ".leakcheckignore", &path))
        return true;
    std::ifstream in(path);
    if (!in) {
        *error = "cannot read '" + path + "'";
        return false;
    }
    std::error_code ec;
    const std::string base =
        fs::absolute(fs::path(path), ec).parent_path().generic_string();
    std::string line;
    int no = 0;
    while (std::getline(in, line)) {
        ++no;
        std::string t = trim(strip_comment(line));
        if (t.empty())
            continue;
        const bool escaped_marker =
            t.size() > 1 && t.front() == '\\' && (t[1] == '!' || t[1] == '#');
        if (escaped_marker)
            t.erase(0, 1);
        const bool negated = !escaped_marker && t.front() == '!';
        const std::string pattern = negated ? t.substr(1) : t;
        if (pattern.empty()) {
            *error = path + ":" + std::to_string(no) + ": a negated pattern needs a glob";
            return false;
        }
        command.excludes.push_back({base, pattern, negated});
    }
    return true;
}

namespace {

// Every suffix of `rel` that starts a path component. "a/b/c.cpp" gives
// "a/b/c.cpp", "b/c.cpp" and "c.cpp", so "vendor/*" also hides a/vendor/x.
bool match_suffixes(const std::string &pattern, const std::string &rel) {
    if (lcreport::glob_match(pattern.c_str(), rel.c_str()))
        return true;
    for (size_t i = rel.find('/'); i != std::string::npos; i = rel.find('/', i + 1))
        if (lcreport::glob_match(pattern.c_str(), rel.c_str() + i + 1))
            return true;
    return false;
}

} // namespace

bool excluded(const std::string &path, const std::vector<ExcludeRule> &rules,
              std::string *which) {
    if (rules.empty())
        return false;
    std::error_code ec;
    const std::string abs = fs::absolute(path, ec).lexically_normal().generic_string();
    bool is_excluded = false;
    for (const ExcludeRule &rule : rules) {
        std::string pattern = rule.pattern;
        while (pattern.rfind("./", 0) == 0)
            pattern = pattern.substr(2);
        while (!pattern.empty() && pattern.back() == '/')
            pattern.pop_back();
        if (pattern.empty())
            continue;
        std::string base = rule.base;
        while (!base.empty() && base.back() == '/')
            base.pop_back();
        const std::string rel =
            !base.empty() && abs.size() > base.size() && abs.compare(0, base.size(), base) == 0 &&
                    abs[base.size()] == '/'
                ? abs.substr(base.size() + 1)
                : abs;
        bool hit = false;
        if (pattern.front() == '/') {
            hit = lcreport::glob_match(pattern.c_str(), abs.c_str());
        } else if (pattern.find('/') == std::string::npos) {
            // A bare name hides that file, that directory, or a path component.
            const std::string name = fs::path(rel).filename().string();
            hit = lcreport::glob_match(pattern.c_str(), name.c_str());
            for (size_t at = 0; !hit && at <= rel.size();) {
                const size_t end = rel.find('/', at);
                const std::string part =
                    rel.substr(at, end == std::string::npos ? std::string::npos : end - at);
                hit = !part.empty() && lcreport::glob_match(pattern.c_str(), part.c_str());
                if (end == std::string::npos)
                    break;
                at = end + 1;
            }
            hit = hit || match_suffixes(pattern, rel);
        } else {
            hit = match_suffixes(pattern, rel);
        }
        if (hit) {
            is_excluded = !rule.negated;
            if (which)
                *which = (rule.negated ? "!" : "") + pattern;
        }
    }
    return is_excluded;
}

std::string effective(const Command &command, const FileConfig &cfg) {
    std::ostringstream out;
    out << "# leakcheck " << (cfg.found ? cfg.path : "settings (no leakcheck.toml)")
        << "\n[mode]\nname = \"" << command.mode << "\"\ntarget = \"" << command.target
        << "\"\n\n[effective]\nformat = \"" << command.format << "\"\nmin-severity = \""
        << command.min_severity << "\"\nerror-exitcode = " << command.error_exitcode
        << "\njobs = " << command.jobs << "\n";
    if (!command.suppressions.empty())
        out << "suppressions = \"" << command.suppressions << "\"\n";
    if (!command.baseline_path.empty())
        out << "baseline = \"" << command.baseline_path << "\"\nbaseline-mode = \""
            << command.baseline_mode << "\"\n";
    if (!command.changed_only.empty())
        out << "changed-only = \"" << command.changed_only << "\"\n";
    out << "cache = " << (command.no_cache ? "off" : "on") << "\n";
    out << "malware = " << (command.malware ? "true" : "false") << "\n";
    std::map<std::string, bool> policy;
    for (const RulePolicy &setting : command.rule_policy)
        policy[setting.id] = setting.enabled;
    if (!policy.empty()) {
        out << "\n[rule-policy]\nenable-rules = [";
        bool comma = false;
        for (const auto &[id, enabled] : policy)
            if (enabled) {
                out << (comma ? ", " : "") << '"' << id << '"';
                comma = true;
            }
        out << "]\ndisable-rules = [";
        comma = false;
        for (const auto &[id, enabled] : policy)
            if (!enabled) {
                out << (comma ? ", " : "") << '"' << id << '"';
                comma = true;
            }
        out << "]\n";
    }
    out << "\n[exclude]\n";
    for (const ExcludeRule &r : command.excludes)
        out << "pattern = \"" << (r.negated ? "!" : "") << r.pattern
            << "\"  # from " << r.base << "\n";
    return out.str();
}

} // namespace lcconfig
