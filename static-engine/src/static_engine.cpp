#include "static_engine.h"
#include "analyzer.h"
#include "command.h"
#include "lexer.h"
#include "parser.h"
#include "report.h"
#include "scan_engine.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <thread>
#include <functional>
#include <set>
#include <sstream>

namespace fs = std::filesystem;

namespace {

const std::set<std::string> kSourceExts = {".c",   ".cc",  ".cpp", ".cxx",
                                           ".c++", ".h",   ".hh",  ".hpp",
                                           ".hxx", ".inl", ".ipp"};

bool read_file(const std::string &path, std::string *out) {
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    *out = ss.str();
    return true;
}

// Just enough JSON to read compile_commands.json: an array of objects with
// string members. Returns the "file" entries resolved against "directory".
class CompileDb {
  public:
    explicit CompileDb(const std::string &text) : s_(text) {}

    bool parse(std::vector<std::string> *files, std::string *error) {
        if (!eat('[')) {
            *error = "expected a JSON array";
            return false;
        }
        if (eat(']'))
            return true;
        for (;;) {
            std::string file, dir;
            if (!object(&file, &dir)) {
                *error = "malformed entry near offset " + std::to_string(i_);
                return false;
            }
            if (!file.empty()) {
                fs::path p(file);
                if (p.is_relative() && !dir.empty())
                    p = fs::path(dir) / p;
                files->push_back(p.lexically_normal().generic_string());
            }
            if (eat(','))
                continue;
            if (eat(']'))
                return true;
            *error = "expected ',' or ']' near offset " + std::to_string(i_);
            return false;
        }
    }

  private:
    void ws() {
        while (i_ < s_.size() &&
               std::isspace(static_cast<unsigned char>(s_[i_])))
            ++i_;
    }
    bool eat(char c) {
        ws();
        if (i_ < s_.size() && s_[i_] == c) {
            ++i_;
            return true;
        }
        return false;
    }
    // The four hex digits at s_[at...], or -1.
    int hex4(size_t at) const {
        if (at + 4 > s_.size())
            return -1;
        int v = 0;
        for (size_t k = 0; k < 4; ++k) {
            const char h = s_[at + k];
            const int d = h >= '0' && h <= '9' ? h - '0' : h >= 'a' && h <= 'f' ? h - 'a' + 10
                          : h >= 'A' && h <= 'F' ? h - 'A' + 10 : -1;
            if (d < 0)
                return -1;
            v = v * 16 + d;
        }
        return v;
    }
    static void utf8(int cp, std::string *out) {
        if (cp < 0x80) {
            out->push_back(char(cp));
        } else if (cp < 0x800) {
            out->push_back(char(0xC0 | (cp >> 6)));
            out->push_back(char(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out->push_back(char(0xE0 | (cp >> 12)));
            out->push_back(char(0x80 | ((cp >> 6) & 0x3F)));
            out->push_back(char(0x80 | (cp & 0x3F)));
        } else {
            out->push_back(char(0xF0 | (cp >> 18)));
            out->push_back(char(0x80 | ((cp >> 12) & 0x3F)));
            out->push_back(char(0x80 | ((cp >> 6) & 0x3F)));
            out->push_back(char(0x80 | (cp & 0x3F)));
        }
    }
    bool string(std::string *out) {
        ws();
        if (i_ >= s_.size() || s_[i_] != '"')
            return false;
        ++i_;
        while (i_ < s_.size() && s_[i_] != '"') {
            char c = s_[i_++];
            if (c == '\\' && i_ < s_.size()) {
                char e = s_[i_++];
                switch (e) {
                case 'n':
                    c = '\n';
                    break;
                case 't':
                    c = '\t';
                    break;
                case 'r':
                    c = '\r';
                    break;
                case 'u': { // \uXXXX, a surrogate pair for a character beyond U+FFFF: written as UTF-8
                    int cp = hex4(i_);
                    if (cp < 0) {
                        c = '?';
                        i_ = std::min(s_.size(), i_ + 4);
                        break;
                    }
                    i_ += 4;
                    if (cp >= 0xD800 && cp < 0xDC00 && i_ + 6 <= s_.size() && s_[i_] == '\\' &&
                        s_[i_ + 1] == 'u') {
                        const int lo = hex4(i_ + 2);
                        if (lo >= 0xDC00 && lo < 0xE000) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            i_ += 6;
                        }
                    }
                    utf8(cp, out);
                    continue;
                }
                default:
                    c = e;
                }
            }
            out->push_back(c);
        }
        if (i_ >= s_.size())
            return false;
        ++i_;
        return true;
    }
    // Reads any value; only strings are returned.
    bool value(std::string *str) {
        ws();
        if (i_ >= s_.size())
            return false;
        char c = s_[i_];
        if (c == '"')
            return string(str);
        if (c == '{' || c == '[') {
            int depth = 0;
            bool in_str = false;
            for (; i_ < s_.size(); ++i_) {
                char d = s_[i_];
                if (in_str) {
                    if (d == '\\')
                        ++i_;
                    else if (d == '"')
                        in_str = false;
                    continue;
                }
                if (d == '"')
                    in_str = true;
                else if (d == '{' || d == '[')
                    ++depth;
                else if ((d == '}' || d == ']') && --depth == 0) {
                    ++i_;
                    return true;
                }
            }
            return false;
        }
        while (i_ < s_.size() && s_[i_] != ',' && s_[i_] != '}' &&
               s_[i_] != ']')
            ++i_;
        return true;
    }
    bool object(std::string *file, std::string *dir) {
        if (!eat('{'))
            return false;
        if (eat('}'))
            return true;
        for (;;) {
            std::string key, val;
            if (!string(&key) || !eat(':') || !value(&val))
                return false;
            if (key == "file")
                *file = val;
            else if (key == "directory")
                *dir = val;
            if (eat(','))
                continue;
            return eat('}');
        }
    }

    const std::string &s_;
    size_t i_ = 0;
};

bool skip_dir(const std::string &name) {
    return name.empty() || name[0] == '.' || name.rfind("build", 0) == 0 ||
           name == "CMakeFiles" || name == "node_modules" ||
           name == "third_party";
}

bool collect(const std::string &target, std::vector<std::string> *files,
             std::string *error) {
    std::error_code ec;
    fs::path p(target);
    if (!fs::exists(p, ec)) {
        *error = "'" + target + "' does not exist";
        return false;
    }
    if (fs::is_directory(p, ec)) {
        auto it = fs::recursive_directory_iterator(
            p, fs::directory_options::skip_permission_denied, ec);
        for (; !ec && it != fs::recursive_directory_iterator();
             it.increment(ec)) {
            const fs::path &e = it->path();
            if (it->is_directory(ec)) {
                if (skip_dir(e.filename().string()))
                    it.disable_recursion_pending();
                continue;
            }
            if (kSourceExts.count(e.extension().string()))
                files->push_back(e.lexically_normal().generic_string());
        }
        std::sort(files->begin(), files->end());
        return true;
    }
    if (p.extension() == ".json") {
        std::string text;
        if (!read_file(target, &text)) {
            *error = "cannot read '" + target + "'";
            return false;
        }
        std::string why;
        if (!CompileDb(text).parse(files, &why)) {
            *error = target + ": " + why;
            return false;
        }
        std::sort(files->begin(), files->end());
        files->erase(std::unique(files->begin(), files->end()), files->end());
        return true;
    }
    files->push_back(p.lexically_normal().generic_string());
    return true;
}

lcreport::Frame frame_at(const std::string &file, const std::string &fn,
                         int line, int col) {
    lcreport::Frame f;
    f.file = file;
    f.function = fn;
    f.line = line;
    f.column = col;
    return f;
}

// The route an Issue carries (see lcstatic::FlowStep) as report frames.
std::vector<lcreport::Frame> flow_of(const lcstatic::Issue &issue,
                                     const std::string &file) {
    std::vector<lcreport::Frame> out;
    for (const lcstatic::FlowStep &s : issue.flow) {
        lcreport::Frame f =
            frame_at(s.file.empty() ? file : s.file, s.function, s.line, s.col);
        f.what = s.what;
        out.push_back(std::move(f));
    }
    return out;
}

lcreport::Finding finding_for(const std::string &abs,
                              const lcstatic::Issue &issue) {
    lcreport::Finding f;
    f.type = issue.rule;
    f.category = "static";
    f.message = issue.message;
    f.access.push_back(frame_at(abs, issue.function, issue.line, issue.col));
    f.flow = flow_of(issue, abs);
    if (issue.alloc_line)
        f.alloc.push_back(frame_at(abs, issue.function, issue.alloc_line, 0));
    if (issue.free_line)
        f.freed.push_back(frame_at(abs, issue.function, issue.free_line, 0));
    // Line numbers left out so the fingerprint survives edits above it.
    const std::string id =
        issue.rule + "|" + abs + "|" + issue.function + "|" + issue.message;
    f.key = std::to_string(std::hash<std::string>{}(id));
    return f;
}

} // namespace

int run_static_analysis(const Command &command) {
    std::vector<std::string> files;
    std::string error;
    if (!collect(command.target, &files, &error)) {
        fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return 1;
    }

    lcreport::Report report;
    report.mode = "static";
    report.command.push_back(command.target);

    // Orders that conflict between functions: reported at the second, with
    // where the first locks the other way round (in another file: named).
    auto report_inversion = [&](const lcstatic::LockOrder &first,
                                const lcstatic::LockOrder &second,
                                const std::string &first_file,
                                const std::string &second_file,
                                std::vector<lcreport::Finding> *out) {
        lcreport::Finding f;
        f.type = "lock-order-inversion";
        f.category = "static";
        f.message =
            "'" + second.taken + "' is locked" +
            (second.via.empty() ? "" : " (in " + second.via + "())") +
            " while holding '" + second.held + "', but " + first.function +
            "() " +
            (first_file == second_file
                 ? std::string()
                 : "in " + fs::path(first_file).filename().string() + " ") +
            "locks them in the opposite order: two threads running both "
            "deadlock";
        f.access.push_back(
            frame_at(second_file, second.function, second.line, 0));
        f.alloc.push_back(frame_at(first_file, first.function, first.line, 0));
        f.freed.push_back(
            frame_at(second_file, second.function, second.held_line, 0));
        const std::string id = f.type + "|" + second_file + "|" +
                               second.function + "|" + f.message;
        f.key = std::to_string(std::hash<std::string>{}(id));
        out->push_back(std::move(f));
    };
    // Files are independent (the cross-file order check runs after the join),
    // so they are analysed by a pool of workers. Each file keeps its own
    // results and they are merged in file order, so the report is the same
    // whatever the number of threads.
    struct StaticResult {
        std::vector<lcreport::Finding> findings;
        std::vector<std::string> notes;
        std::vector<lcstatic::LockOrder> orders;
        std::set<std::string> shared_names;
        lcstatic::TaintDb taint; // what this file learned about outside text
        bool analyzed = false;
    };
    std::vector<StaticResult> results(files.size());
    std::atomic<size_t> next{0};

    auto analyse_one = [&](size_t i) {
        const std::string &file = files[i];
        StaticResult &out = results[i];
        std::string src;
        if (!read_file(file, &src)) {
            out.notes.push_back("cannot read " + file);
            return;
        }
        out.analyzed = true;
        std::error_code ec;
        const std::string abs =
            fs::absolute(file, ec).lexically_normal().generic_string();
        if (command.malware) { // --malware: the code is also read for malware families
            lcreport::Report mal;
            scan_into_report(&mal, abs, src, true);
            for (lcreport::Finding &f : mal.findings)
                out.findings.push_back(std::move(f));
        }
        const auto tokens = lcstatic::lex(src);
        std::vector<lcstatic::LockOrder> orders;
        lcstatic::Allocators allocators; // helpers defined earlier in the file
        lcstatic::Releasers releasers;
        auto add = [&](const lcstatic::Issue &issue) {
            out.findings.push_back(finding_for(abs, issue));
        };
        const auto fns = lcstatic::parse_functions(tokens);
        for (const auto &fn : fns)
            for (const auto &issue : lcstatic::analyze_function(
                     fn, &orders, &allocators, &releasers))
                add(issue);
        for (const auto &issue : lcstatic::signal_unsafe_calls(tokens, fns))
            add(issue);
        for (const auto &issue :
             lcstatic::security_issues(tokens, fns, &out.taint))
            add(issue);
        // The facts name the file they were seen in: another file's finding
        // points back here.
        for (lcstatic::TaintSink &s : out.taint.sinks)
            s.file = abs;
        for (lcstatic::TaintEdge &e : out.taint.edges)
            e.file = abs;
        for (lcstatic::TaintCaller &c : out.taint.callers)
            c.file = abs;
        orders = lcstatic::with_calls(orders);
        for (const auto &[first, second] : lcstatic::lock_inversions(
                 orders, lcstatic::file_scope_names(tokens)))
            report_inversion(first, second, abs, abs, &out.findings);
        const auto shared = lcstatic::file_scope_names(tokens, true);
        for (lcstatic::LockOrder o : orders)
            if (shared.count(o.held) && shared.count(o.taken)) {
                o.file = abs;
                out.shared_names.insert(o.held);
                out.shared_names.insert(o.taken);
                out.orders.push_back(std::move(o));
            }
    };

    size_t workers = command.jobs > 0
                         ? size_t(command.jobs)
                         : std::max<size_t>(1, std::thread::hardware_concurrency());
    workers = std::min(workers, files.size());
    auto work = [&] {
        for (size_t i = next++; i < files.size(); i = next++) {
            try {
                analyse_one(i);
            } catch (const std::exception &e) { // (out of memory on a huge file)
                results[i].notes.push_back("cannot analyse " + files[i] + ": " + e.what());
            }
        }
    };
    if (workers <= 1) {
        work();
    } else {
        std::vector<std::thread> pool;
        for (size_t t = 0; t < workers; ++t)
            pool.emplace_back(work);
        for (std::thread &t : pool)
            t.join();
    }

    std::vector<lcstatic::LockOrder> shared_orders;
    std::set<std::string> shared_mutexes;
    lcstatic::TaintDb taint_db;
    for (StaticResult &r : results) {
        for (std::string &note : r.notes)
            report.notes.push_back(std::move(note));
        if (r.analyzed)
            ++report.files_analyzed;
        for (lcreport::Finding &f : r.findings)
            report.findings.push_back(std::move(f));
        for (lcstatic::LockOrder &o : r.orders)
            shared_orders.push_back(std::move(o));
        shared_mutexes.insert(r.shared_names.begin(), r.shared_names.end());
        for (lcstatic::TaintSink &s : r.taint.sinks)
            taint_db.sinks.push_back(std::move(s));
        for (lcstatic::TaintEdge &e : r.taint.edges)
            taint_db.edges.push_back(std::move(e));
        for (lcstatic::TaintCaller &c : r.taint.callers)
            taint_db.callers.push_back(std::move(c));
    }

    // Calls in one file that hand outside text to a parameter that reaches a
    // dangerous call in another (or on through another): reported at the call,
    // with the route. Only across files, so a single file is never reported
    // twice for it.
    for (auto &[file, issue] : lcstatic::resolve_taint(taint_db))
        report.findings.push_back(finding_for(file, issue));

    // The same global mutexes locked in opposite orders by two files (pairs
    // within one file were reported above).
    for (const auto &[first, second] :
         lcstatic::lock_inversions(shared_orders, shared_mutexes))
        if (first.file != second.file)
            report_inversion(first, second, first.file, second.file, &report.findings);
    if (files.empty())
        report.notes.push_back("no C or C++ source files found");
    if (command.malware)
        lcreport::add_composite_findings(report);

    if (!command.suppressions.empty() &&
        !lcreport::apply_suppressions(command.suppressions, report, &error)) {
        fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return 1;
    }
    if (!lcreport::write_report(report, command.format, command.output,
                                &error)) {
        fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return 1;
    }
    size_t problems = 0;
    for (const auto &f : report.findings)
        problems += lcreport::is_problem(f);
    if (!command.output.empty())
        fprintf(
            stderr,
            "leakcheck: %zu problem(s) in %zu file(s); report written to %s\n",
            problems, report.files_analyzed, command.output.c_str());
    return problems ? command.error_exitcode : 0;
}
