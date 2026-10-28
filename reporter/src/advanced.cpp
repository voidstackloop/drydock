// Advanced offline passes: reachability ranking, custom rules, ownership
// summaries, fuzz-harness stubs, dependency audit, scan proof, trend DB.
// Everything here works on the report and the source tree; no network,
// no server, no new third-party code.
#include "report.h"

#include "command.h"
#include "config.h"
#include "protocol.h"
#include "malware.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace lcreport {
namespace {

namespace fs = std::filesystem;

std::string trim(std::string s) {
    size_t b = 0;
    while (b < s.size() && std::isspace((unsigned char)s[b]))
        ++b;
    size_t e = s.size();
    while (e > b && std::isspace((unsigned char)s[e - 1]))
        --e;
    return s.substr(b, e - b);
}

std::vector<std::string> split_pipe(const std::string &s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

bool read_text(const std::string &path, std::string *out) {
    std::ifstream in(fs::path(path), std::ios::binary);
    if (!in)
        return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    *out = ss.str();
    return true;
}

int line_of(const std::string &text, size_t off) {
    int line = 1;
    for (size_t i = 0; i < off && i < text.size(); ++i)
        if (text[i] == '\n')
            ++line;
    return line;
}

// A callee whose name says it takes ownership: free-like, destroy, close,
// release, unref, dispose, cleanup. glib, OpenSSL and most C code follow it.
bool takes_ownership(const std::string &callee) {
    std::string low = callee;
    for (char &c : low)
        c = char(std::tolower((unsigned char)c));
    auto ends = [&](const char *s) {
        size_t n = std::string(s).size();
        return low.size() >= n && low.compare(low.size() - n, n, s) == 0;
    };
    auto starts = [&](const char *s) {
        size_t n = std::string(s).size();
        return low.compare(0, n, s) == 0;
    };
    if (low == "free" || low == "fclose" || low == "pclose" ||
        low == "close" || low == "delete")
        return true;
    return ends("free") || ends("destroy") || ends("release") ||
           ends("cleanup") || ends("dispose") || ends("unref") ||
           ends("deref") || starts("free_") || ends("_free") ||
           ends("close");
}

} // namespace

void mark_reachable(Report &r) {
    size_t n = 0;
    for (Finding &f : r.findings) {
        // A flow is only attached when outside text was traced to the sink,
        // so a non-empty flow is the definition of reachable here.
        if (!f.flow.empty() && !f.reachable) {
            f.reachable = true;
            ++n;
        }
    }
    if (n)
        r.notes.push_back(std::to_string(n) + " finding(s) reachable from outside " +
                          "input (taint flow attached) — fix these first");
}

bool apply_custom_rules(Report &r, const std::vector<std::string> &files,
                        const std::string &rules_path, std::string *error) {
    struct Rule {
        std::string id, pattern, message, severity;
    };
    std::string text;
    if (!read_text(rules_path, &text)) {
        *error = "cannot read --custom-rules file '" + rules_path + "'";
        return false;
    }
    std::vector<Rule> rules;
    std::istringstream in(text);
    std::string line;
    int lineno = 0;
    while (std::getline(in, line)) {
        ++lineno;
        line = trim(line);
        if (line.empty() || line[0] == '#')
            continue;
        std::vector<std::string> parts = split_pipe(line);
        if (parts.size() < 3 || parts.size() > 4) {
            *error = rules_path + ":" + std::to_string(lineno) +
                     ": want 'id | pattern | message [| severity]'";
            return false;
        }
        Rule rl{trim(parts[0]), trim(parts[1]), trim(parts[2]),
                parts.size() == 4 ? trim(parts[3]) : "warning"};
        if (rl.id.empty() || rl.pattern.empty() || rl.message.empty()) {
            *error = rules_path + ":" + std::to_string(lineno) + ": empty field";
            return false;
        }
        for (char c : rl.id)
            if (!std::isalnum((unsigned char)c) && c != '-' && c != '_') {
                *error = rules_path + ":" + std::to_string(lineno) +
                         ": rule id must be [a-z0-9-_]+";
                return false;
            }
        if (rl.severity != "error" && rl.severity != "warning" && rl.severity != "note") {
            *error = rules_path + ":" + std::to_string(lineno) +
                     ": severity must be error, warning or note";
            return false;
        }
        rules.push_back(std::move(rl));
    }
    size_t added = 0;
    for (const std::string &file : files) {
        std::string src;
        if (!read_text(file, &src))
            continue;
        for (const Rule &rl : rules) {
            size_t hits = 0;
            for (size_t off = src.find(rl.pattern);
                 off != std::string::npos && hits < 20;
                 off = src.find(rl.pattern, off + 1)) {
                Finding f;
                f.type = "custom/" + rl.id;
                f.category = "static";
                f.message = rl.message + " (custom rule " + rl.id + ")";
                f.severity_override = rl.severity;
                f.access.push_back(Frame());
                f.access.back().file = file;
                f.access.back().line = line_of(src, off);
                f.key = std::to_string(stable_hash(f.type + "|" + file + "|" +
                                                   std::to_string(f.access.back().line) +
                                                   "|" + f.message));
                r.findings.push_back(std::move(f));
                ++hits;
                ++added;
            }
        }
    }
    if (added)
        r.notes.push_back(std::to_string(added) + " finding(s) from --custom-rules " +
                          rules_path);
    return true;
}

// The function whose body holds `pos`: the nearest definition-shaped line
// above it (`... name(...) {`). Empty when it cannot be told.
std::string enclosing_function(const std::string &src, size_t pos) {
    size_t end = src.rfind('\n', pos);
    for (int back = 0; back < 80 && end != std::string::npos; ++back) {
        size_t start = (end == 0) ? 0 : src.rfind('\n', end - 1);
        start = (start == std::string::npos) ? 0 : start + 1;
        std::string line = src.substr(start, end - start);
        size_t paren = line.find('(');
        size_t brace = line.find('{');
        if (paren != std::string::npos && brace != std::string::npos &&
            paren < brace && line.find(';') == std::string::npos) {
            size_t ne = paren;
            while (ne > 0 && std::isspace((unsigned char)line[ne - 1]))
                --ne;
            size_t ns = ne;
            while (ns > 0 && (std::isalnum((unsigned char)line[ns - 1]) ||
                              line[ns - 1] == '_' || line[ns - 1] == ':'))
                --ns;
            std::string name = line.substr(ns, ne - ns);
            size_t col = name.rfind("::");
            if (col != std::string::npos)
                name = name.substr(col + 2);
            if (!name.empty() && name != "if" && name != "for" &&
                name != "while" && name != "switch")
                return name;
        }
        if (end == 0)
            break;
        end = (start == 0) ? std::string::npos : start - 1;
    }
    return {};
}

// True when `var` is declared at file scope: only a global can be handed
// from one function to another, so only a global is eligible for the
// cross-function transfer below. Locals are the analyzer's own business:
// it sees every path in the function, this pass does not.
bool is_file_global(const std::string &src, const std::string &var) {
    const char LF = char(10);
    const char SQ = char(39);
    const char DQ = char(34);
    const char BS = char(92);
    int depth = 0;
    int depth_at_start = 0;
    bool in_str = false, in_chr = false, in_bc = false, in_lc = false;
    size_t line_start = 0;
    size_t lc_start = std::string::npos;
    auto whole_word_at = [](const std::string &line, const std::string &w) {
        for (size_t q = line.find(w); q != std::string::npos;
             q = line.find(w, q + 1)) {
            bool wb = (q == 0) || (!std::isalnum((unsigned char)line[q - 1]) &&
                                   line[q - 1] != '_');
            size_t e = q + w.size();
            bool wa = (e >= line.size()) ||
                      (!std::isalnum((unsigned char)line[e]) && line[e] != '_');
            if (wb && wa)
                return q;
        }
        return std::string::npos;
    };
    for (size_t i = 0; i <= src.size(); ++i) {
        char c = (i < src.size()) ? src[i] : LF;
        char n = (i + 1 < src.size()) ? src[i + 1] : 0;
        if (c == LF || i == src.size()) {
            size_t e = (lc_start == std::string::npos) ? i : lc_start;
            if (depth_at_start == 0 && !in_bc && e > line_start) {
                std::string line = src.substr(line_start, e - line_start);
                std::string t = trim(line);
                if (!t.empty() && t[0] != '#' &&
                    line.find(';') != std::string::npos) {
                    size_t vp = whole_word_at(line, var);
                    if (vp != std::string::npos) {
                        size_t par = line.find('(');
                        if (par == std::string::npos || vp < par)
                            return true;
                    }
                }
            }
            line_start = i + 1;
            depth_at_start = depth;
            lc_start = std::string::npos;
            in_lc = false;
            continue;
        }
        if (in_lc)
            continue;
        if (in_bc) {
            if (c == '*' && n == '/') {
                in_bc = false;
                ++i;
            }
            continue;
        }
        if (in_str) {
            if (c == BS)
                ++i;
            else if (c == DQ)
                in_str = false;
            continue;
        }
        if (in_chr) {
            if (c == BS)
                ++i;
            else if (c == SQ)
                in_chr = false;
            continue;
        }
        if (c == '/' && n == '/') {
            in_lc = true;
            lc_start = i;
            continue;
        }
        if (c == '/' && n == '*') {
            in_bc = true;
            continue;
        }
        if (c == DQ) {
            in_str = true;
            continue;
        }
        if (c == SQ) {
            in_chr = true;
            continue;
        }
        if (c == '{')
            ++depth;
        else if (c == '}') {
            if (depth > 0)
                --depth;
        }
    }
    return false;
}
// External releasers (g_free, SSL_free, ...) have no definition here; a
// `free` in the name is trusted on its own.
bool defined_releaser(const std::map<std::string, std::string> &contents,
                      const std::string &name) {
    std::string low = name;
    for (char &c : low)
        c = char(std::tolower((unsigned char)c));
    const bool free_in_name = low.find("free") != std::string::npos;
    bool defined = false, releases = false;
    for (const auto &[file, src] : contents) {
        for (size_t pos = src.find(name); pos != std::string::npos;
             pos = src.find(name, pos + 1)) {
            // A definition looks like `name(` at line start-ish without a
            // trailing `;` on the same line (a declaration or call).
            size_t ls = src.rfind('\n', pos);
            ls = (ls == std::string::npos) ? 0 : ls + 1;
            size_t le = src.find('\n', pos);
            std::string line =
                src.substr(ls, le == std::string::npos ? le : le - ls);
            size_t paren = line.find('(');
            if (paren == std::string::npos || line.find(name) > paren)
                continue;
            if (line.find(';') != std::string::npos &&
                line.find('{') == std::string::npos)
                continue; // declaration or prototype, not the body
            defined = true;
            std::string body = src.substr(pos, 4000);
            for (const char *kw :
                 {"free(", "delete", "fclose(", "pclose(", "closedir(",
                  "close(", "release(", "unref(", "EVP_PKEY_free",
                  "X509_free", "BIO_free", "xmlFree", "av_free"}) {
                if (body.find(kw) != std::string::npos) {
                    releases = true;
                    break;
                }
            }
            if (releases)
                return true;
        }
    }
    return !defined && free_in_name;
}

void apply_ownership_summaries(Report &r, const std::vector<std::string> &files) {
    // Interprocedural ownership on the cheap: the analyzer reasons within one
    // function, so a block handed to a releaser elsewhere looks leaked. When
    // the leaked variable is passed to a function whose name says it releases
    // (free-like/destroy/close/unref/...), that is a transfer, not a leak.
    std::map<std::string, std::string> contents;
    for (const std::string &file : files) {
        std::string src;
        if (read_text(file, &src))
            contents[file] = std::move(src);
        if (contents.size() >= 2000)
            break; // bound memory on huge trees; the rest keep their findings
    }
    auto var_of = [](const Finding &f) -> std::string {
        // Leak messages quote the variable: 'buf' was allocated ...
        size_t a = f.message.find('\'');
        if (a == std::string::npos)
            return {};
        size_t b = f.message.find('\'', a + 1);
        if (b == std::string::npos || b - a > 64)
            return {};
        return f.message.substr(a + 1, b - a - 1);
    };
    size_t dropped = 0;
    std::vector<Finding> kept;
    kept.reserve(r.findings.size());
    for (Finding &f : r.findings) {
        bool drop = false;
        if ((f.type == lcproto::kLeak || f.type == lcproto::kResourceLeak) &&
            f.category == "static") {
            const std::string var = var_of(f);
            const Frame *p = primary_frame(f);
            if (!var.empty() && p && !p->file.empty()) {
                auto it = contents.find(p->file);
                if (it == contents.end()) {
                    // The scan ran on relative paths while findings carry
                    // absolute ones (or the reverse): match by suffix.
                    for (auto jt = contents.begin(); jt != contents.end(); ++jt) {
                        const std::string &k = jt->first;
                        if (k.size() >= p->file.size() &&
                            k.compare(k.size() - p->file.size(), p->file.size(),
                                      p->file) == 0) {
                            it = jt;
                            break;
                        }
                        if (p->file.size() > k.size() &&
                            p->file.compare(p->file.size() - k.size(), k.size(),
                                            k) == 0) {
                            it = jt;
                            break;
                        }
                    }
                }
                if (it != contents.end()) {
                    const std::string &src = it->second;
                    // Same-function releases are the analyzer
                    // business: only cross-function transfers qualify.
                    const bool cross_fn = is_file_global(src, var);
                    // Find calls `name(...var...)`: the variable handed over.
                    for (size_t pos = cross_fn ? src.find(var) : std::string::npos;
                         pos != std::string::npos;
                         pos = src.find(var, pos + 1)) {
                        size_t lp = src.rfind('(', pos);
                        if (lp == std::string::npos)
                            continue;
                        // Between the paren and the variable only argument
                        // characters may appear; anything else (a `;`, `)` or
                        // brace) means this paren belongs to an earlier call.
                        bool args = true;
                        for (size_t k = lp + 1; k < pos; ++k) {
                            char c = src[k];
                            if (c == ';' || c == ')' || c == '{' || c == '}') {
                                args = false;
                                break;
                            }
                        }
                        if (!args)
                            continue;
                        if (pos - lp > var.size() + 24)
                            continue;
                        // Walk back over `name(` to get the callee.
                        size_t ne = lp;
                        while (ne > 0 && std::isspace((unsigned char)src[ne - 1]))
                            --ne;
                        size_t ns = ne;
                        while (ns > 0 && (std::isalnum((unsigned char)src[ns - 1]) ||
                                          src[ns - 1] == '_' || src[ns - 1] == ':' ||
                                          src[ns - 1] == '>' || src[ns - 1] == '.'))
                            --ns;
                        std::string callee = src.substr(ns, ne - ns);
                        size_t col = callee.rfind("::");
                        if (col != std::string::npos)
                            callee = callee.substr(col + 2);
                        size_t dot = callee.rfind('.');
                        if (dot != std::string::npos)
                            callee = callee.substr(dot + 1);
                        size_t arr = callee.rfind("->");
                        if (arr != std::string::npos)
                            callee = callee.substr(arr + 2);
                        if (callee.empty() || !takes_ownership(callee))
                            continue;
                        if (!defined_releaser(contents, callee))
                            continue;
                        // Same-function releases are the analyzer's own
                        // business: it sees every path, this pass does not.
                        // Only a transfer to another function (init/fini
                        // lifecycles, globals) is suppressed here.
                        {
                            const Frame *pf = primary_frame(f);
                            const std::string here =
                                pf ? pf->function : std::string();
                            if (here.empty() ||
                                enclosing_function(src, pos) == here)
                                continue;
                        }
                        // The transfer only covers this value: a later
                        // reassignment (`b = ...`, `b[...]`, `b++`) means a
                        // newer allocation leaks instead. Whole-word search
                        // after the call.
                        bool reused = false;
                        for (size_t q = pos + var.size(); q < src.size();
                             q = src.find(var, q)) {
                            if (q == std::string::npos)
                                break;
                            bool wb = (q == 0) ||
                                      (!std::isalnum((unsigned char)src[q - 1]) &&
                                       src[q - 1] != '_');
                            size_t e = q + var.size();
                            bool wa = (e >= src.size()) ||
                                      (!std::isalnum((unsigned char)src[e]) &&
                                       src[e] != '_');
                            if (wb && wa) {
                                reused = true;
                                break;
                            }
                            q = e;
                        }
                        if (!reused) {
                            drop = true;
                            break;
                        }
                    }
                }
            }
        }
        if (drop) {
            ++dropped;
        } else {
            kept.push_back(std::move(f));
        }
    }
    r.findings = std::move(kept);
    if (dropped)
        r.notes.push_back(
            std::to_string(dropped) +
            " leak(s) treated as ownership transfers (variable handed to a " +
            "releasing function in another scope) rather than leaks");
}

void gen_fuzz_harnesses(const Report &r, const std::string &dir,
                        std::vector<std::string> &notes) {
    static const std::set<std::string> kSinks = {
        "command-injection", "format-string", "unbounded-copy",
        "buffer-overflow", "buffer-underflow", "integer-overflow",
        "path-traversal", "sql-injection", "xss"};
    size_t n = 0;
    std::error_code ec;
    fs::create_directories(dir, ec);
    if (ec) {
        notes.push_back("cannot create --gen-fuzz dir '" + dir + "': " + ec.message());
        return;
    }
    for (const Finding &f : r.findings) {
        if (!f.reachable && !kSinks.count(f.type))
            continue;
        const Frame *p = primary_frame(f);
        if (!p || p->file.empty())
            continue;
        std::string base = fs::path(p->file).filename().string();
        for (char &c : base)
            if (!std::isalnum((unsigned char)c) && c != '.' && c != '-' && c != '_')
                c = '_';
        std::string type = f.type;
        for (char &c : type)
            if (!std::isalnum((unsigned char)c))
                c = '_';
        std::string path =
            (fs::path(dir) / ("fuzz_" + type + "_" + base + "_" +
                              std::to_string(p->line) + ".cpp"))
                .generic_string();
        if (fs::exists(path, ec))
            continue;
        std::ofstream out(fs::path(path), std::ios::binary);
        if (!out)
            continue;
        out << "// libFuzzer stub from `leakcheck static --gen-fuzz`.\n"
            << "// Sink: " << f.type << " at " << p->file << ":" << p->line;
        if (!p->function.empty())
            out << " in " << p->function << "()";
        out << "\n// Finding: " << f.message << "\n"
            << "// Wire the sink call below, then build with -fsanitize=fuzzer.\n"
            << "#include <cstddef>\n"
            << "#include <cstdint>\n"
            << "#include <string>\n"
            << "\n"
            << "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            << "    std::string input(reinterpret_cast<const char *>(data), size);\n"
            << "    (void)input;\n"
            << "    // TODO: call the sink with `input` and assert no crash/leak.\n"
            << "    return 0;\n"
            << "}\n";
        ++n;
    }
    notes.push_back(std::to_string(n) + " libFuzzer stub harness(es) in " + dir +
                    " (wire each sink call, then build with -fsanitize=fuzzer)");
}

void audit_dependencies(const std::string &target, const std::vector<ExcludeRule> &excludes,
                        Report &r) {
    // Unpinned dependencies are how a CVE walks in: a branch name or a star
    // today is a different commit tomorrow. Exact pins are only listed so the
    // note can say what was checked.
    std::vector<std::string> manifests;
    std::error_code ec;
    auto consider = [&](const std::string &path) {
        std::string low = path;
        for (char &c : low)
            c = char(std::tolower((unsigned char)c));
        std::string base = fs::path(low).filename().string();
        if (base == "conanfile.txt" || base == "conanfile.py" ||
            base == "vcpkg.json" || base == "cmakelists.txt" ||
            base == "build.gradle" || base == "package.json" ||
            base == "go.mod" || base == "cargo.toml" || base == "requirements.txt")
            manifests.push_back(path);
    };
    // A negation keeps excluded directories traversable, as in collection.
    const bool can_reinclude =
        std::any_of(excludes.begin(), excludes.end(),
                    [](const ExcludeRule &rule) { return rule.negated; });
    if (fs::is_directory(target, ec)) {
        for (auto it = fs::recursive_directory_iterator(target, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec)
                break;
            const std::string p = it->path().generic_string();
            std::error_code e2;
            if (it->is_directory(e2)) {
                // Never dependency declarations: VCS stores, build trees
                // and vendored copies (static prunes the same set; without
                // this a node_modules tree fills the 50-manifest cap with
                // noise before the root manifest is ever read).
                const std::string base = it->path().filename().generic_string();
                if (!base.empty() && (base[0] == '.' || base.rfind("build", 0) == 0 ||
                    base == "CMakeFiles" || base == "node_modules" ||
                    base == "third_party")) {
                    it.disable_recursion_pending();
                    continue;
                }
                if (lcconfig::excluded(p, excludes) && !can_reinclude)
                    it.disable_recursion_pending();
                continue;
            }
            if (it->is_regular_file(e2) && !lcconfig::excluded(p, excludes))
                consider(p);
            if (manifests.size() >= 50)
                break;
        }
    } else if (!lcconfig::excluded(target, excludes)) {
        consider(target);
    }
    size_t pinned = 0, loose = 0;
    auto flag = [&](const std::string &file, int line, const std::string &dep,
                    const std::string &why) {
        Finding f;
        f.type = "unpinned-dependency";
        f.category = "static";
        f.message = "dependency '" + dep + "' " + why + " (" + file + ")";
        f.access.push_back(Frame());
        f.access.back().file = file;
        f.access.back().line = line;
        f.key = std::to_string(
            stable_hash(f.type + "|" + file + "|" + dep + "|" + why));
        r.findings.push_back(std::move(f));
        ++loose;
    };
    for (const std::string &m : manifests) {
        std::string src;
        if (!read_text(m, &src))
            continue;
        std::string base = fs::path(m).filename().string();
        std::istringstream in(src);
        std::string line;
        int lineno = 0;
        bool in_requires = false;
        while (std::getline(in, line)) {
            ++lineno;
            std::string t = trim(line);
            if (base == "conanfile.txt") {
                if (!t.empty() && t[0] == '[')
                    in_requires = (t == "[requires]");
                if (in_requires && !t.empty() && t[0] != '#' && t[0] != '[') {
                    if (t.find('*') != std::string::npos ||
                        (t.find('/') == std::string::npos && t.find('@') == std::string::npos))
                        flag(m, lineno, t, "has no exact version pin");
                    else
                        ++pinned;
                }
            } else if (base == "vcpkg.json") {
                std::string s = trim(t);
                if (!s.empty() && s[0] == '"') {
                    // "name" without a sibling version>= is unpinned; a line
                    // carrying version>= counts as pinned.
                    if (s.find("version>=") != std::string::npos)
                        ++pinned;
                    else if (s.back() == ',' || s.back() == '"' || s == "\"dependencies\":" ||
                             s.find("dependencies") != std::string::npos) {
                        // header or bare name fragment; judge the block below
                    } else if (s.size() < 60 && s.find(':') == std::string::npos) {
                        flag(m, lineno, s, "has no version>= pin");
                    }
                }
            } else if (base == "CMakeLists.txt") {
                if (t.find("FetchContent_Declare") != std::string::npos) {
                    // Collect the following ~6 lines for GIT_TAG.
                    std::string block = t;
                    for (int k = 0; k < 6 && std::getline(in, line); ++k) {
                        ++lineno;
                        block += "\n" + line;
                    }
                    size_t g = block.find("GIT_TAG");
                    if (g == std::string::npos) {
                        flag(m, lineno, block.substr(0, 48), "FetchContent has no GIT_TAG");
                    } else {
                        std::string tag = trim(block.substr(g + 7));
                        bool sha = tag.size() >= 40 &&
                                   std::all_of(tag.begin(), tag.begin() + 40, ::isxdigit);
                        bool ver = !tag.empty() && (tag[0] == 'v' || std::isdigit((unsigned char)tag[0]));
                        if (!sha && !ver)
                            flag(m, lineno, tag.substr(0, 32),
                                 "FetchContent GIT_TAG tracks a branch, not a version");
                        else
                            ++pinned;
                    }
                }
                if (t.find("http://") != std::string::npos)
                    flag(m, lineno, "url", "downloads over plain http://");
            }
        }
    }
    r.notes.push_back("--audit-deps: " + std::to_string(manifests.size()) +
                      " manifest(s), " + std::to_string(pinned) + " pinned, " +
                      std::to_string(loose) + " unpinned finding(s)");
}

void prove_findings(Report &r) {
    // A malware family named from a single sign is a guess; two independent
    // signs in the same file is evidence. Uncorroborated families stay in the
    // report but fail the gate as warnings, not errors.
    std::map<std::string, size_t> total_by_file;
    std::map<std::string, size_t> same_by_file;
    for (const Finding &f : r.findings) {
        std::string file = f.access.empty() ? std::string() : f.access.front().file;
        total_by_file[file]++;
        if (lcmal::family_of(f.type.c_str()))
            same_by_file[file + "\0" + f.type]++;
    }
    size_t demoted = 0;
    for (Finding &f : r.findings) {
        if (!lcmal::family_of(f.type.c_str()))
            continue;
        std::string file = f.access.empty() ? std::string() : f.access.front().file;
        size_t others = total_by_file[file] - same_by_file[file + "\0" + f.type];
        if (others == 0 && f.severity_override.empty()) {
            f.severity_override = "warning";
            ++demoted;
        }
    }
    if (demoted)
        r.notes.push_back("--prove: " + std::to_string(demoted) +
                          " uncorroborated malware-family finding(s) demoted to warnings");
}

void emit_vcxproj(const std::vector<std::string> &files, const std::string &path,
                  std::vector<std::string> &notes) {
    // A VS project over exactly the files that were scanned, so a Windows
    // developer can open what the report talks about. Not a build: no
    // toolchain, configs or references, just the file list.
    std::ofstream out(fs::path(path), std::ios::binary);
    if (!out) {
        notes.push_back("cannot write --vcxproj file '" + path + "'");
        return;
    }
    auto xml_escape = [](const std::string &s) {
        std::string e;
        for (char c : s) {
            if (c == '&')
                e += "&amp;";
            else if (c == '<')
                e += "&lt;";
            else if (c == '"')
                e += "&quot;";
            else
                e += c;
        }
        return e;
    };
    size_t compile = 0, include = 0;
    std::ostringstream items;
    for (const std::string &f : files) {
        std::string ext = fs::path(f).extension().string();
        for (char &c : ext)
            c = char(std::tolower((unsigned char)c));
        if (ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".cxx") {
            items << "    <ClCompile Include=\"" << xml_escape(f) << "\" />\n";
            ++compile;
        } else if (ext == ".h" || ext == ".hh" || ext == ".hpp" ||
                   ext == ".hxx") {
            items << "    <ClInclude Include=\"" << xml_escape(f) << "\" />\n";
            ++include;
        }
    }
    out << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        << "<Project DefaultTargets=\"Build\" "
           "xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\n"
        << "  <ItemGroup>\n"
        << items.str() << "  </ItemGroup>\n"
        << "</Project>\n";
    notes.push_back("--vcxproj: " + std::to_string(compile) + " source(s), " +
                    std::to_string(include) + " header(s) listed in '" + path +
                    "'");
}

void write_fix_commit(Report &r, const std::string &path) {
    // The `-f patch` renderer already knows the one-line safe fixes; this
    // saves that diff to a file and checks it applies, so the developer's
    // own `git commit` is one step away. Nothing is staged or committed
    // here: the tool must not write the user's history behind their back.
    std::ostringstream diff;
    render_patch(r, diff);
    const std::string text = diff.str();
    if (text.empty()) {
        r.notes.push_back("--fix-commit: no auto-fixable findings, no patch written");
        return;
    }
    {
        std::ofstream out(fs::path(path), std::ios::binary);
        if (!out) {
            r.notes.push_back("cannot write --fix-commit file '" + path + "'");
            return;
        }
        out << text;
    }
    size_t hunks = 0;
    for (size_t p = 0; (p = text.find("\n@@ ", p)) != std::string::npos; ++p)
        ++hunks;
    if (text.compare(0, 3, "@@ ") == 0)
        ++hunks;
#ifdef _WIN32
#define lc_popen _popen
#define lc_pclose _pclose
#else
#define lc_popen popen
#define lc_pclose pclose
#endif
    // Best-effort `git apply --check`: a note, never a failure. When git is
    // missing or this is not a repository there is simply nothing to verify.
    bool checked = false, clean = false;
    std::string refused;
    // --unsafe-paths: findings carry absolute paths, which git rejects by
    // default. Safe here: --check only reads, it never writes or stages.
    if (FILE *pipe = lc_popen(("git apply --check --unsafe-paths -- \"" + path +
                                "\" 2>&1")
                                   .c_str(),
                               "r")) {
        char buf[256];
        std::string out;
        while (fgets(buf, sizeof buf, pipe) && out.size() < 300)
            out += buf;
        checked = true;
        clean = lc_pclose(pipe) == 0;
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
            out.pop_back();
        refused = out;
    }
#undef lc_popen
#undef lc_pclose
    std::string note = "--fix-commit: " + std::to_string(hunks) +
                       " auto-fix hunk(s) in '" + path + "'";
    if (!checked)
        note += " (git not run: not a repository or git missing)";
    else if (clean)
        note += " (`git apply --check` clean)";
    else
        note += " (`git apply --check`: " + refused + ")";
    r.notes.push_back(std::move(note));
}

int run_trend(const Command &command) {
    const std::string db = command.trend_db.empty() ? "leakcheck-trend.csv"
                                                    : command.trend_db;
    std::string text;
    if (!read_text(command.target, &text)) {
        std::fprintf(stderr, "leakcheck: cannot read report '%s'\n",
                     command.target.c_str());
        return 1;
    }
    // The JSON report writes one `"type": "<id>"` per finding; the summary
    // counts by_type keys, never `"type"`, so this counts findings.
    size_t findings = 0, errors = 0, warnings = 0;
    for (size_t p = 0; (p = text.find("\"type\"", p)) != std::string::npos; ++p)
        ++findings;
    for (size_t p = 0; (p = text.find("\"severity\": \"error\"", p)) != std::string::npos;
         ++p)
        ++errors;
    for (size_t p = 0;
         (p = text.find("\"severity\": \"warning\"", p)) != std::string::npos; ++p)
        ++warnings;
    std::time_t now = std::time(nullptr);
    char stamp[32];
    std::strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%S", std::localtime(&now));
    bool fresh = !fs::exists(db);
    {
        std::ofstream out(db, std::ios::app);
        if (!out) {
            std::fprintf(stderr, "leakcheck: cannot write trend db '%s'\n", db.c_str());
            return 1;
        }
        if (fresh)
            out << "timestamp,report,findings,errors,warnings\n";
        out << stamp << "," << command.target << "," << findings << "," << errors
            << "," << warnings << "\n";
    }
    std::string rows;
    read_text(db, &rows);
    std::istringstream in(rows);
    std::string line;
    std::vector<std::string> keep;
    while (std::getline(in, line))
        if (!trim(line).empty())
            keep.push_back(line);
    size_t from = keep.size() > 11 ? keep.size() - 11 : 0;
    std::printf("--- leakcheck trend (%s) ---\n", db.c_str());
    for (size_t i = from; i < keep.size(); ++i)
        std::printf("%s\n", keep[i].c_str());
    return 0;
}

} // namespace lcreport
