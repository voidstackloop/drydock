#include "static_engine.h"
#include "analyzer.h"
#include "cache.h"
#include "command.h"
#include "config.h"
#include "lexer.h"
#include "parser.h"
#include "report.h"
#include "scan_engine.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>
#include <functional>
#include <set>
#include <sstream>

namespace fs = std::filesystem;

namespace {

// std::filesystem::u8path is deprecated in C++20 (and removed in C++26):
// build the path from a UTF-8 sequence instead, so -Werror stays clean on
// newer GCC/Clang (Ubuntu 26, macOS) without changing behaviour.
inline fs::path utf8_to_path(const std::string &s) {
    return fs::path(reinterpret_cast<const char8_t *>(s.c_str()));
}

const std::set<std::string> kSourceExts = {".c",   ".cc",  ".cpp", ".cxx",
                                           ".c++", ".h",   ".hh",  ".hpp",
                                           ".hxx", ".inl", ".ipp"};

inline std::string normalize_generic_path(const fs::path &p) {
    std::string s = p.lexically_normal().generic_string();
#ifdef _WIN32
    const std::string orig = p.string();
    if ((orig.rfind("\\\\", 0) == 0 || orig.rfind("//", 0) == 0) &&
        s.rfind("//", 0) != 0 && s.rfind("/", 0) == 0) {
        s = "/" + s;
    }
#endif
    return s;
}

inline std::string to_absolute_generic_path(const fs::path &p) {
#ifdef _WIN32
    std::string s = p.string();
    if (s.rfind("\\\\", 0) == 0 || s.rfind("//", 0) == 0) {
        for (char &c : s) {
            if (c == '\\')
                c = '/';
        }
        return s;
    }
#endif
    std::error_code ec;
    return normalize_generic_path(fs::absolute(p, ec));
}

bool read_file(const std::string &path, std::string *out) {
    std::string open_path = path;
#ifdef _WIN32
    if (open_path.size() >= 2 && open_path[0] == '/' && open_path[1] != '/') {
        if (open_path.find('/', 1) != std::string::npos) {
            std::string candidate = "/" + open_path;
            std::error_code ec;
            if (fs::exists(utf8_to_path(candidate), ec)) {
                open_path = candidate;
            }
        }
    }
#endif
    // A new file is briefly unreadable while antivirus or the indexer holds
    // it open, which on Windows lost cross-file findings: the skipped file
    // took its caller or its sink with it, so the report came back clean
    // with exit 0. Retry briefly; a file that stays unreadable still
    // reports "cannot read" instead of failing the open once and moving on.
    for (int attempt = 0;; ++attempt) {
        std::ifstream in(utf8_to_path(open_path), std::ios::binary);
        if (in) {
            std::ostringstream ss;
            ss << in.rdbuf();
            *out = ss.str();
            return true;
        }
        if (attempt >= 50)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
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
                files->push_back(normalize_generic_path(p));
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

struct Hidden
{
    size_t files = 0, dirs = 0;
};

void note_hidden(lcreport::Report *report, const Hidden &hidden)
{
    if (!hidden.files && !hidden.dirs)
        return;
    std::string text = std::to_string(hidden.files) + " file(s)";
    if (hidden.dirs)
        text += " and " + std::to_string(hidden.dirs) + " director(ies)";
    report->notes.push_back(text + " excluded by leakcheck.toml, .leakcheckignore or --exclude");
}

bool collect(const std::string &target, const Command &command,
             std::vector<std::string> *files, Hidden *hidden, std::string *error) {
    std::error_code ec;
    fs::path p(target);
    if (!fs::exists(p, ec)) {
        *error = "'" + target + "' does not exist";
        return false;
    }
    if (fs::is_directory(p, ec)) {
        // shortcut: any negation keeps excluded directories traversable; add
        // prefix-aware pruning if this shows up in large-tree profiles.
        const bool can_reinclude = std::any_of(
            command.excludes.begin(), command.excludes.end(),
            [](const ExcludeRule &rule) { return rule.negated; });
        auto it = fs::recursive_directory_iterator(
            p, fs::directory_options::skip_permission_denied, ec);
        for (; !ec && it != fs::recursive_directory_iterator();
             it.increment(ec)) {
            const fs::path &e = it->path();
            if (it->is_directory(ec)) {
                const bool by_rule =
                    lcconfig::excluded(e.generic_string(), command.excludes);
                if (by_rule && !can_reinclude)
                    ++hidden->dirs;
                if ((by_rule && !can_reinclude) || skip_dir(e.filename().string()))
                    it.disable_recursion_pending();
                continue;
            }
            if (!kSourceExts.count(e.extension().string()))
                continue;
            if (lcconfig::excluded(e.generic_string(), command.excludes)) {
                ++hidden->files;
                continue;
            }
            files->push_back(normalize_generic_path(e));
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
        std::erase_if(*files, [&](const std::string &file) {
            if (!lcconfig::excluded(file, command.excludes))
                return false;
            ++hidden->files;
            return true;
        });
        return true;
    }
    if (lcconfig::excluded(p.generic_string(), command.excludes)) {
        ++hidden->files;
        return true;
    }
    files->push_back(normalize_generic_path(p));
    return true;
}

// ---- --changed-only: ask git which files a pull request touches -----------

#ifdef _WIN32
#define lc_popen _popen
#define lc_pclose _pclose
#else
#define lc_popen popen
#define lc_pclose pclose
#endif

std::string quote(const std::string &s) {
#ifdef _WIN32
    return "\"" + s + "\"";
#else
    std::string out = "'";
    for (char c : s) {
        if (c == '\'')
            out += "'\\''";
        else
            out += c;
    }
    return out + "'";
#endif
}

// Runs git and returns its output lines. False (with the first lines of its
// error output) when git is missing, the directory is not a repository, or the
// ref does not resolve: a gate must not silently analyse everything instead.
bool git_lines(const std::string &root, const std::vector<std::string> &args,
               std::vector<std::string> *lines, std::string *error) {
    std::string command = "git -C " + quote(root);
    for (const std::string &a : args)
        command += " " + quote(a);
    command += " 2>&1";
    FILE *pipe = lc_popen(command.c_str(), "r");
    if (!pipe) {
        *error = "cannot run git";
        return false;
    }
    std::string output;
    char buffer[512];
    while (fgets(buffer, sizeof buffer, pipe))
        output += buffer;
    const int status = lc_pclose(pipe);
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (!line.empty())
            lines->push_back(line);
    }
    if (status != 0) {
        *error = "git " + args.front() + " failed:";
        for (size_t i = 0; i < lines->size() && i < 3; ++i)
            *error += " " + (*lines)[i];
        return false;
    }
    return true;
}

// Drops files that git says are unchanged since `ref`, and says how many.
bool changed_only(const Command &command, std::vector<std::string> *files,
                  size_t *skipped, std::string *error) {
    const std::string ref = command.changed_only;
    if (ref.empty())
        return true;
    for (char c : ref)
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '/' ||
              c == '@' || c == '{' || c == '}' || c == '^' || c == '~' || c == ':' || c == '-')) {
            *error = "--changed-only takes a git ref, not '" + ref + "'";
            return false;
        }
    std::error_code ec;
    fs::path start(command.target);
    if (!fs::is_directory(start, ec))
        start = start.parent_path();
    std::vector<std::string> lines;
    if (!git_lines(start.generic_string(), {"rev-parse", "--show-toplevel"}, &lines, error)) {
        *error = "--changed-only needs a git checkout: " + *error;
        return false;
    }
    if (lines.empty()) {
        *error = "--changed-only needs a git checkout: git named no repository root";
        return false;
    }
    const std::string root = lines.front();
    lines.clear();
    if (!git_lines(root, {"diff", "--name-only", ref}, &lines, error))
        return false;
    std::vector<std::string> untracked;
    if (!git_lines(root, {"ls-files", "--others", "--exclude-standard"}, &untracked, error))
        return false;
    lines.insert(lines.end(), untracked.begin(), untracked.end());
    std::set<std::string> changed;
    for (const std::string &line : lines) {
        changed.insert(to_absolute_generic_path(fs::path(root) / line));
    }
    std::vector<std::string> kept;
    for (const std::string &file : *files) {
        const std::string abs = to_absolute_generic_path(file);
        bool match = changed.count(abs);
        if (!match) {
            for (const std::string &ch : changed) {
                std::error_code eq_ec;
                if (fs::equivalent(utf8_to_path(file), utf8_to_path(ch), eq_ec)) {
                    match = true;
                    break;
                }
            }
        }
        if (match)
            kept.push_back(file);
        else
            ++*skipped;
    }
    *files = std::move(kept);
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
    f.key = std::to_string(lcreport::stable_hash(id));
    return f;
}

void apply_diff_base(const std::string &ref, lcreport::Report &r) {
    if (ref.empty())
        return;
    std::string cmd = "git diff -U0 " + ref;
#ifdef _WIN32
    FILE *pipe = _popen(cmd.c_str(), "r");
#else
    FILE *pipe = popen(cmd.c_str(), "r");
#endif
    if (!pipe)
        return;
    std::map<std::string, std::vector<std::pair<int, int>>> changed_ranges;
    char line[1024];
    std::string current_file;
    while (fgets(line, sizeof(line), pipe)) {
        if (strncmp(line, "+++ b/", 6) == 0) {
            current_file = line + 6;
            while (!current_file.empty() && (current_file.back() == '\n' || current_file.back() == '\r'))
                current_file.pop_back();
        } else if (strncmp(line, "@@ ", 3) == 0 && !current_file.empty()) {
            const char *plus = strchr(line + 3, '+');
            if (plus) {
                int start = 0, count = 1;
                if (sscanf(plus + 1, "%d,%d", &start, &count) >= 1) {
                    changed_ranges[current_file].push_back({start, start + count - 1});
                }
            }
        }
    }
#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif

    size_t filtered = 0;
    std::erase_if(r.findings, [&](const lcreport::Finding &f) {
        const lcreport::Frame *p = lcreport::primary_frame(f);
        if (!p || p->file.empty())
            return false;
        std::string rel = p->file;
        auto it = changed_ranges.find(rel);
        if (it == changed_ranges.end()) {
            for (const auto &pair : changed_ranges) {
                if (rel.size() >= pair.first.size() &&
                    rel.compare(rel.size() - pair.first.size(), pair.first.size(), pair.first) == 0) {
                    it = changed_ranges.find(pair.first);
                    break;
                }
            }
        }
        if (it == changed_ranges.end()) {
            ++filtered;
            return true;
        }
        for (const auto &rng : it->second) {
            if (p->line >= rng.first && p->line <= rng.second)
                return false;
        }
        ++filtered;
        return true;
    });
    if (filtered) {
        r.notes.push_back(std::to_string(filtered) + " finding(s) filtered out because untouched in git diff against " + ref);
    }
}

} // namespace

int run_static_analysis(const Command &command) {
    const auto started = std::chrono::steady_clock::now();
    auto mark = [&](const char *what) {
        if (!getenv("LEAKCHECK_PROFILE"))
            return;
        const auto now = std::chrono::steady_clock::now();
        fprintf(stderr, "profile: %-14s %.3fs\n", what,
                std::chrono::duration<double>(now - started).count());
    };
    std::vector<std::string> files;
    Hidden hidden;
    std::string error;
    if (!collect(command.target, command, &files, &hidden, &error)) {
        fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return kExitCouldNotAnalyse;
    }
    size_t unchanged = 0;
    if (!changed_only(command, &files, &unchanged, &error)) {
        fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return kExitConfig;
    }
    if (command.list_only) {
        // --list: the collected targets, one per line, analysed nothing.
        for (const std::string &file : files)
            puts(file.c_str());
        return kExitClean;
    }

    lcreport::Report report;
    report.mode = "static";
    report.min_severity = command.min_severity;
    report.command.push_back(command.target);
    note_hidden(&report, hidden);
    if (!command.changed_only.empty())
        report.notes.push_back("changed-only: " + std::to_string(files.size()) +
                               " file(s) analysed, " + std::to_string(unchanged) +
                               " unchanged since " + command.changed_only + " skipped");

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
        f.key = std::to_string(lcreport::stable_hash(id));
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
    std::atomic<size_t> next{0}, cache_hits{0};
    // The cache lives beside the tree it describes, one directory for every
    // run, so it can be ignored by git as a whole.
    std::string cache_dir;
    if (!command.no_cache) {
        std::error_code ec;
        fs::path root = command.target;
        if (!fs::is_directory(root, ec))
            root = root.parent_path();
        if (root.empty())
            root = ".";
        cache_dir = (root / ".leakcheck-cache").generic_string();
        fs::create_directories(cache_dir, ec);
        if (ec)
            cache_dir.clear();
    }

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
        const std::string abs = to_absolute_generic_path(file);
        std::string cache_path;
        if (!cache_dir.empty()) {
            cache_path = lcstatic::cache_file(
                cache_dir, lcstatic::cache_key(abs, src, command.malware));
            lcstatic::CachedFile cached;
            if (lcstatic::load_cache(cache_path, &cached)) {
                out.findings = std::move(cached.findings);
                out.notes = std::move(cached.notes);
                out.orders = std::move(cached.orders);
                out.shared_names = std::move(cached.shared_names);
                out.taint = std::move(cached.taint);
                out.analyzed = cached.analyzed;
                ++cache_hits;
                return;
            }
        }
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
            if (issue.rule == "return-stack-address") {
                for (const auto &prev : out.findings) {
                    if (prev.type == "dangling-pointer" && !prev.access.empty() &&
                        prev.access[0].line == issue.line)
                        return;
                }
            }
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
        if (!cache_path.empty()) {
            lcstatic::CachedFile cached;
            cached.findings = out.findings;
            cached.notes = out.notes;
            cached.orders = out.orders;
            cached.shared_names = out.shared_names;
            cached.taint = out.taint;
            cached.analyzed = out.analyzed;
            lcstatic::save_cache(cache_path, cached);
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

    mark("analysed");
    if (cache_hits)
        report.notes.push_back(std::to_string(cache_hits.load()) +
                               " file(s) read from the incremental cache");
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
    mark("taint");

    // The same global mutexes locked in opposite orders by two files (pairs
    // within one file were reported above).
    for (const auto &[first, second] :
         lcstatic::lock_inversions(shared_orders, shared_mutexes))
        if (first.file != second.file)
            report_inversion(first, second, first.file, second.file, &report.findings);
    mark("lock-orders");
    if (files.empty())
        report.notes.push_back("no C or C++ source files found");
    if (command.malware)
        lcreport::add_composite_findings(report);
    if (!command.custom_rules.empty()) {
        if (!lcreport::apply_custom_rules(report, files, command.custom_rules,
                                          &error)) {
            fprintf(stderr, "leakcheck: %s\n", error.c_str());
            return kExitConfig;
        }
    }
    lcreport::apply_ownership_summaries(report, files);
    lcreport::mark_reachable(report);
    if (!command.gen_fuzz.empty())
        lcreport::gen_fuzz_harnesses(report, command.gen_fuzz, report.notes);
    if (!command.vcxproj.empty())
        lcreport::emit_vcxproj(files, command.vcxproj, report.notes);
    if (!command.fix_commit.empty())
        lcreport::write_fix_commit(report, command.fix_commit);
    lcreport::apply_rule_policy(report, command.rule_policy, command.strict);

    for (auto &f : report.findings) {
        auto it = command.rule_severities.find(f.type);
        if (it != command.rule_severities.end())
            f.severity_override = it->second;
    }

    if (!command.diff_base.empty())
        apply_diff_base(command.diff_base, report);

    if (!command.suppressions.empty() &&
        !lcreport::apply_suppressions(command.suppressions, report, &error)) {
        fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return kExitConfig;
    }
    if (!command.baseline_path.empty()) {
        if (command.baseline_mode == "write") {
            if (!lcreport::write_baseline(command.baseline_path, report, &error)) {
                fprintf(stderr, "leakcheck: %s\n", error.c_str());
                return kExitConfig;
            }
            report.notes.push_back("baseline written: " + std::to_string(report.findings.size()) +
                                   " finding(s) to " + command.baseline_path);
        } else {
            size_t known = 0;
            if (!lcreport::apply_baseline(command.baseline_path, report, &known, &error)) {
                fprintf(stderr, "leakcheck: %s\n", error.c_str());
                return kExitConfig;
            }
        }
    }
    mark("suppressed");
    if (!lcreport::write_report(report, command.format, command.output,
                                &error)) {
        fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return kExitCouldNotAnalyse;
    }
    mark("written");
    if (command.metrics)
        lcreport::render_metrics(report, std::cout);
    size_t problems = 0;
    for (const auto &f : report.findings)
        problems += lcreport::is_problem_at(f, command.min_severity);
    if (!command.output.empty())
        fprintf(
            stderr,
            "leakcheck: %zu problem(s) in %zu file(s); report written to %s\n",
            problems, report.files_analyzed, command.output.c_str());
    // Writing a baseline is the one commit that must go green: it records what
    // is there so that the next run gates only on new findings.
    if (command.baseline_mode == "write" && !command.baseline_path.empty())
        return kExitClean;
    return problems ? command.error_exitcode : kExitClean;
}
