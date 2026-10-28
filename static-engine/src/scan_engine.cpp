#include "scan_engine.h"
#include "ai_features.h"
#include "config.h"
#include "ai_model.h"
#include "protocol.h"
#include "report.h"
#include "rules.h"
#include "scan.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#else
#include <unistd.h>
#endif
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <thread>

namespace fs = std::filesystem;

namespace {

// std::filesystem::u8path is deprecated in C++20 (and removed in C++26):
// build the path from a UTF-8 sequence instead, so -Werror stays clean on
// newer GCC/Clang (Ubuntu 26, macOS) without changing behaviour.
inline fs::path utf8_to_path(const std::string &s) {
    return fs::path(reinterpret_cast<const char8_t *>(s.c_str()));
}

constexpr uintmax_t kMaxFile = 256u << 20; // bigger files are skipped
constexpr size_t kReadMax = 16u << 20;     // the first bytes of a file are read

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

// `known` is the file's size when it was listed: resize to what will actually
// be read, not to `cap` (a 16 MB resize zero-fills the whole buffer per file).
bool read_prefix(const std::string &path, size_t cap, std::string *out, size_t known) {
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
    std::ifstream in(utf8_to_path(open_path), std::ios::binary);
    if (!in)
        return false;
    out->resize(std::min(cap, known));
    in.read(&(*out)[0], std::streamsize(out->size()));
    out->resize(size_t(in.gcount()));
    return true;
}

std::string hex_offset(size_t n) {
    char b[32];
    std::snprintf(b, sizeof b, "offset 0x%zx", n);
    return b;
}

// The system's own copy of a program a file is named after, if the file is a
// different program: "/tmp/x/ls" is not "/bin/ls".
std::string shadowed_program(const std::string &path, const std::string &bytes,
                             lcscan::Kind kind) {
    if (kind == lcscan::Kind::Text || kind == lcscan::Kind::Binary)
        return {};
    const std::string name = fs::path(path).filename().string();
    bool known = false;
    for (const char *t : lcrules::kTrusted)
        known |= name == t;
    if (!known || lcrules::system_dir(path.c_str()))
        return {};
    std::error_code ec;
    for (const char *dir : {"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"}) {
        const std::string sys = dir + name;
        if (!fs::is_regular_file(sys, ec))
            continue;
        std::string theirs;
        if (!read_prefix(sys, bytes.size() + 1, &theirs, bytes.size() + 1))
            continue;
        if (theirs != bytes)
            return sys;
        return {}; // a copy of the real one
    }
    return {};
}

// The part of a path a fingerprint may depend on: relative to the scanned
// tree, so the same checkout on another machine (or another drive letter)
// gives the same finding the same identity.
std::string key_path(const std::string &abs, const std::string &root) {
    if (root.empty())
        return abs;
    std::error_code ec;
    const fs::path rel = fs::relative(abs, root, ec);
    return ec || rel.empty() ? abs : rel.generic_string();
}

void add_finding(lcreport::Report *report, const std::string &abs, const std::string &root,
                 const lcscan::Hit &h, size_t more) {
    lcreport::Finding f;
    f.type = h.type;
    f.category = lcproto::kCatScan;
    f.message = h.message + (more ? " (and " + std::to_string(more) + " more of the same kind)" : "");
    lcreport::Frame fr;
    fr.file = abs;
    fr.function = h.offset ? hex_offset(h.offset) : std::string("the file");
    fr.line = 1;
    f.access.push_back(fr);
    f.key = std::to_string(lcreport::stable_hash(h.type + "|" + key_path(abs, root) + "|" +
                                                  h.message));
    report->findings.push_back(std::move(f));
}

} // namespace

void scan_into_report(lcreport::Report *report, const std::string &abs, const std::string &bytes,
                      bool malware, const std::string &root) {
    std::vector<size_t> more;
    const std::vector<lcscan::Hit> hits = lcscan::scan_file(abs, bytes, &more, malware);
    for (size_t i = 0; i < hits.size(); ++i)
        add_finding(report, abs, root, hits[i], more[i]);
    if (const std::string sys = shadowed_program(abs, bytes, lcscan::kind_of(bytes)); !sys.empty()) {
        lcscan::Hit h;
        h.type = lcproto::kMasquerade;
        h.message = "it is called \"" + fs::path(abs).filename().string() +
                    "\" like the system's " + sys + ", but it is a different program: a "
                    "directory that comes first in PATH with such a file makes every "
                    "command of that name run this one";
        add_finding(report, abs, root, h, 0);
    }
}

namespace {

// What scanning one file gave, kept apart so that files can be scanned at the same time.
struct FileResult {
    std::vector<std::string> notes;
    lcreport::Report found; // only its findings are used
    bool scanned = false;
};

struct Hidden {
    size_t files = 0, dirs = 0;
};

// Every regular file under `target` (or the one file itself), in file order.
bool collect_files(const std::string &target_text, const Command &command,
                   std::vector<std::string> *files, Hidden *hidden) {
    std::error_code ec;
    const fs::path target(target_text);
    if (!fs::exists(fs::symlink_status(target, ec)))
        return false;
    if (fs::is_directory(target, ec)) {
        // shortcut: any negation keeps excluded directories traversable; add
        // prefix-aware pruning if this shows up in large-tree profiles.
        const bool can_reinclude = std::any_of(
            command.excludes.begin(), command.excludes.end(),
            [](const ExcludeRule &rule) { return rule.negated; });
        auto it = fs::recursive_directory_iterator(
            target, fs::directory_options::skip_permission_denied, ec);
        for (; !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
            const std::string p = it->path().generic_string();
            if (p == "/proc" || p == "/sys" || p == "/dev") {
                it.disable_recursion_pending();
                continue;
            }
            std::error_code e2;
            if (it->is_directory(e2)) {
                // Never anyone's target: version-control object stores are
                // packed blobs, and .leakcheck-cache is this tool's own output
                // (static skips dot-dirs the same way). An explicit file path
                // inside still scans; only recursion prunes.
                const std::string base = it->path().filename().generic_string();
                if (base == ".git" || base == ".hg" || base == ".svn" ||
                    base == ".bzr" || base == ".leakcheck-cache") {
                    it.disable_recursion_pending();
                    continue;
                }
                if (lcconfig::excluded(p, command.excludes)) {
                    if (!can_reinclude) {
                        ++hidden->dirs;
                        it.disable_recursion_pending();
                    }
                }
                continue;
            }
            if (it->is_symlink(e2) || !it->is_regular_file(e2))
                continue;
            if (lcconfig::excluded(p, command.excludes)) {
                ++hidden->files;
                continue;
            }
            files->push_back(p);
        }
        std::sort(files->begin(), files->end());
    } else if (!lcconfig::excluded(target.generic_string(), command.excludes)) {
        files->push_back(target.generic_string());
    } else {
        ++hidden->files;
    }
    return true;
}

void note_hidden(lcreport::Report *report, const Hidden &hidden) {
    if (!hidden.files && !hidden.dirs)
        return;
    std::string text = std::to_string(hidden.files) + " file(s)";
    if (hidden.dirs)
        text += " and " + std::to_string(hidden.dirs) + " director(ies)";
    report->notes.push_back(text + " excluded by leakcheck.toml, .leakcheckignore or --exclude");
}

// The directory the running binary is in, on every platform the tool ships
// for. Used to find the model and the preload library in an installed tree.
std::string executable_dir() {
#if defined(__linux__)
    char buf[4096];
    const ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0)
        return {};
    buf[n] = 0;
    return fs::path(buf).parent_path().generic_string();
#elif defined(_WIN32)
    char buf[4096];
    const DWORD n = GetModuleFileNameA(nullptr, buf, sizeof buf);
    if (n == 0 || n >= sizeof buf)
        return {};
    return fs::path(std::string(buf, n)).parent_path().generic_string();
#elif defined(__APPLE__)
    char buf[4096];
    uint32_t size = sizeof buf;
    if (_NSGetExecutablePath(buf, &size) != 0)
        return {};
    std::error_code ec;
    const fs::path real = fs::canonical(fs::path(buf), ec);
    return (ec ? fs::path(buf) : real).parent_path().generic_string();
#else
    return {};
#endif
}

// Where the model is when --ai-model is not given: next to the project root, at
// the path the build was configured with, or in an installed tree next to the
// binary (bin/leakcheck -> ../share/leakcheck/model).
std::string default_model_path() {
    std::error_code ec;
    if (fs::is_regular_file("model/pe-malware.ai", ec))
        return "model/pe-malware.ai";
#ifdef LEAKCHECK_MODEL_PATH
    if (fs::is_regular_file(LEAKCHECK_MODEL_PATH, ec))
        return LEAKCHECK_MODEL_PATH;
#endif
    const std::string self = executable_dir();
    if (!self.empty()) {
        const fs::path dir(self);
        for (const fs::path &candidate :
             {dir / "model/pe-malware.ai", dir.parent_path() / "model/pe-malware.ai",
              dir.parent_path() / "share/leakcheck/model/pe-malware.ai"})
            if (fs::is_regular_file(candidate, ec))
                return candidate.generic_string();
    }
    return {};
}

// The classifier's verdict as a finding: only above the threshold, and worded as
// what it is -- a statistical guess about the shape of the file, not a rule.
void ai_check(lcreport::Report *found, const std::string &abs, const std::string &root,
              const std::string &bytes, const lcscan::AiModel &model, double threshold) {
    std::vector<float> features;
    if (!lcscan::ai_pe_features(bytes, &features) || features.size() != model.features)
        return;
    // The model was trained on programs. On a real Windows install, resource-only
    // files were three quarters of its false alarms: they cannot run by
    // themselves, so it does not guess at them.
    if (!lcscan::ai_has_code(features))
        return;
    const double score = model.score(features);
    if (score < threshold)
        return;
    char numbers[128];
    std::snprintf(numbers, sizeof numbers, "%.3f", score);
    std::string at(numbers);
    std::snprintf(numbers, sizeof numbers, "%.2f", threshold);
    lcscan::Hit h;
    h.type = lcproto::kAiClassifier;
    h.message =
        "its Windows headers, sections and strings look like malware's, not a normal program's: "
        "a classifier trained on " +
        std::string(model.trained_on.empty() ? "known malware and normal Windows programs"
                                            : model.trained_on.c_str()) +
        " scores it " + at + " of 1 (" + std::to_string(int(score * 100)) + "% malicious, "
        "threshold " + std::to_string(int(threshold * 100)) +
        "%). This is a guess from the shape of the file, not a matched rule: "
        "what it does is still to be checked";
    add_finding(found, abs, root, h, 0);
}

// The classifier, when --ai asked for it: shared by all workers, read-only.
struct AiRun {
    const lcscan::AiModel *model = nullptr;
    double threshold = 0.5;
};

void scan_one(const std::string &file, bool malware, const AiRun &ai, const std::string &root,
              FileResult *out) {
    std::string open_path = file;
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
    std::error_code ec;
    const uintmax_t size = fs::file_size(utf8_to_path(open_path), ec);
    if (ec) {
        out->notes.push_back("cannot read " + file);
        return;
    }
    if (size > kMaxFile) {
        out->notes.push_back("skipped " + file + " (larger than 256 MB)");
        return;
    }
    std::string bytes;
    if (!read_prefix(file, kReadMax, &bytes, size_t(size))) {
        out->notes.push_back("cannot read " + file);
        return;
    }
    if (size > kReadMax)
        out->notes.push_back("scanned first 16 MB of " + file);
    out->scanned = true;
    const std::string abs = to_absolute_generic_path(file);
    scan_into_report(&out->found, abs, bytes, malware, root);
    if (ai.model)
        ai_check(&out->found, abs, root, bytes, *ai.model, ai.threshold);
}

} // namespace

int run_scan(const Command &command) {
    std::vector<std::string> files;
    Hidden hidden;
    if (!collect_files(command.target, command, &files, &hidden)) {
        std::fprintf(stderr, "leakcheck: '%s' does not exist\n", command.target.c_str());
        return kExitCouldNotAnalyse;
    }
    if (command.list_only) {
        // --list: the collected targets, one per line, scanned nothing.
        for (const std::string &file : files)
            std::puts(file.c_str());
        return kExitClean;
    }

    lcscan::AiModel model;
    AiRun ai;
    if (command.ai) {
        const std::string path =
            command.ai_model.empty() ? default_model_path() : command.ai_model;
        std::string error;
        if (path.empty() || !model.load(path, &error)) {
            std::fprintf(stderr,
                         "leakcheck: --ai needs a trained model: %s\n"
                         "  make one with tools/train_ai.py (it writes model/pe-malware.ai), "
                         "or pass --ai-model <file>\n",
                         path.empty() ? "no model/pe-malware.ai found" : error.c_str());
            return 1;
        }
        ai.model = &model;
        ai.threshold = command.ai_threshold > 0 ? command.ai_threshold : model.threshold;
    }

    lcreport::Report report;
    report.mode = "scan";
    report.min_severity = command.min_severity;
    report.command.push_back(command.target);
    note_hidden(&report, hidden);

    // Files are independent, and a scan is mostly waiting for the disk and
    // running over bytes, so several are scanned at once. Each file's result is
    // kept in its own slot and joined in file order, so the report is the same
    // whatever the number of threads.
    std::vector<FileResult> results(files.size());
    size_t workers = command.jobs > 0 ? size_t(command.jobs)
                                      : std::max<size_t>(1, std::thread::hardware_concurrency());
    workers = std::min(workers, files.size());
    // Fingerprints are relative to the scanned tree, not to the machine's
    // idea of where it is.
    std::error_code root_ec;
    fs::path root = fs::absolute(command.target, root_ec);
    if (!root_ec) {
        std::error_code dir_ec;
        if (!fs::is_directory(root, dir_ec))
            root = root.parent_path();
    }
    const std::string root_key = root_ec ? std::string() : root.generic_string();
    std::atomic<size_t> next{0};
    auto work = [&] {
        for (size_t i = next++; i < files.size(); i = next++) {
            try {
                scan_one(files[i], command.malware, ai, root_key, &results[i]);
            } catch (const std::exception &e) { // (out of memory on a huge file)
                results[i].notes.push_back("cannot scan " + files[i] + ": " + e.what());
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
    for (FileResult &r : results) {
        for (std::string &n : r.notes)
            report.notes.push_back(std::move(n));
        report.files_analyzed += r.scanned ? 1 : 0;
        for (lcreport::Finding &f : r.found.findings)
            report.findings.push_back(std::move(f));
    }
    if (files.empty())
        report.notes.push_back("no files found");
    if (command.malware)
        lcreport::add_composite_findings(report);
    if (command.audit_deps)
        lcreport::audit_dependencies(command.target, command.excludes, report);
    if (command.prove)
        lcreport::prove_findings(report);
    lcreport::mark_reachable(report);
    lcreport::apply_rule_policy(report, command.rule_policy, command.strict);

    std::string error;
    if (!command.suppressions.empty() &&
        !lcreport::apply_suppressions(command.suppressions, report, &error)) {
        std::fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return kExitConfig;
    }
    if (!command.baseline_path.empty()) {
        if (command.baseline_mode == "write") {
            if (!lcreport::write_baseline(command.baseline_path, report, &error)) {
                std::fprintf(stderr, "leakcheck: %s\n", error.c_str());
                return kExitConfig;
            }
            report.notes.push_back("baseline written: " + std::to_string(report.findings.size()) +
                                   " finding(s) to " + command.baseline_path);
        } else {
            size_t known = 0;
            if (!lcreport::apply_baseline(command.baseline_path, report, &known, &error)) {
                std::fprintf(stderr, "leakcheck: %s\n", error.c_str());
                return kExitConfig;
            }
        }
    }
    if (!lcreport::write_report(report, command.format, command.output, &error)) {
        std::fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return kExitCouldNotAnalyse;
    }
    size_t problems = 0;
    for (const auto &f : report.findings)
        problems += lcreport::is_problem_at(f, command.min_severity);
    if (!command.output.empty())
        std::fprintf(stderr, "leakcheck: %zu problem(s) in %zu file(s); report written to %s\n",
                     problems, report.files_analyzed, command.output.c_str());
    if (command.baseline_mode == "write" && !command.baseline_path.empty())
        return kExitClean;
    return problems ? command.error_exitcode : kExitClean;
}

int run_ai_features(const Command &command) {
    std::vector<std::string> files;
    Hidden hidden;
    if (!collect_files(command.target, command, &files, &hidden)) {
        std::fprintf(stderr, "leakcheck: '%s' does not exist\n", command.target.c_str());
        return kExitCouldNotAnalyse;
    }
    if (command.list_only) {
        // --list: the collected targets, one per line, read no contents.
        for (const std::string &file : files)
            std::puts(file.c_str());
        return kExitClean;
    }
    // The header names the columns, so the trainer can check them against the
    // model's own order instead of trusting that both sides agree.
    std::string out = "#features";
    for (size_t i = 0; i < lcscan::kAiFeatureCount; ++i)
        out += std::string(" ") + lcscan::kAiFeatureNames[i];
    out.push_back('\n');
    // Each file is read and turned into numbers on its own row and the rows are
    // joined in file order, so the same folder always prints the same lines.
    struct Row {
        std::string path, values;
    };
    std::vector<Row> rows(files.size());
    std::atomic<size_t> next{0}, read{0}, judged{0}, no_code{0};
    auto work = [&] {
        for (size_t i = next++; i < files.size(); i = next++) {
            const std::string &file = files[i];
            std::error_code ec;
            const uintmax_t size = fs::file_size(file, ec);
            if (ec || size > kMaxFile)
                continue;
            std::string bytes;
            if (!read_prefix(file, kReadMax, &bytes, size_t(size)))
                continue;
            ++read;
            try {
                std::vector<float> features;
                if (!lcscan::ai_pe_features(bytes, &features))
                    continue; // not a Windows program: the model knows nothing about it
                // The scanner leaves resource-only images out (see ai_check), so the
                // trainer must not learn from them: a row is a file --ai can judge.
                if (!lcscan::ai_has_code(features)) {
                    ++no_code;
                    continue;
                }
                ++judged;
                rows[i].path = to_absolute_generic_path(file);
                rows[i].values = lcscan::ai_features_line(features);
            } catch (const std::exception &) { // out of memory on a huge file
            }
        }
    };
    size_t workers = command.jobs > 0 ? size_t(command.jobs)
                                      : std::max<size_t>(1, std::thread::hardware_concurrency());
    workers = std::min(workers, std::max<size_t>(1, files.size()));
    if (workers <= 1) {
        work();
    } else {
        std::vector<std::thread> pool;
        for (size_t t = 0; t < workers; ++t)
            pool.emplace_back(work);
        for (std::thread &t : pool)
            t.join();
    }
    std::string body;
    for (const Row &row : rows)
        if (!row.path.empty())
            body += row.path + "\t" + row.values + "\n";
    out += body;
    std::fwrite(out.data(), 1, out.size(), stdout);
    std::fprintf(stderr,
                 "leakcheck: %zu of %zu file(s) are Windows programs with code (%zu "
                 "resource-only image(s) left out)\n",
                 judged.load(), read.load(), no_code.load());
    return 0;
}

// What the version line reports about the classifier: the file it finds, and
// the numbers from its header that make a bug report reproducible.
std::string model_description() {
    const std::string path = default_model_path();
    if (path.empty())
        return {};
    lcscan::AiModel model;
    std::string error;
    if (!model.load(path, &error))
        return path + " (will not load: " + error + ")";
    char threshold[32];
    std::snprintf(threshold, sizeof threshold, "%.2f", model.threshold);
    return path + " (" + std::to_string(model.trees.size()) + " trees, " +
           std::to_string(model.features) + " features, threshold " + threshold + ")";
}
