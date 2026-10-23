#include "scan_engine.h"
#include "ai_features.h"
#include "ai_model.h"
#include "protocol.h"
#include "report.h"
#include "rules.h"
#include "scan.h"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#if defined(__linux__)
#include <unistd.h>
#endif
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <thread>

namespace fs = std::filesystem;

namespace {

constexpr uintmax_t kMaxFile = 256u << 20; // bigger files are skipped
constexpr size_t kReadMax = 16u << 20;     // the first bytes of a file are read

// `known` is the file's size when it was listed: resize to what will actually
// be read, not to `cap` (a 16 MB resize zero-fills the whole buffer per file).
bool read_prefix(const std::string &path, size_t cap, std::string *out, size_t known) {
    std::ifstream in(path, std::ios::binary);
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

void add_finding(lcreport::Report *report, const std::string &abs, const lcscan::Hit &h,
                 size_t more) {
    lcreport::Finding f;
    f.type = h.type;
    f.category = lcproto::kCatScan;
    f.message = h.message + (more ? " (and " + std::to_string(more) + " more of the same kind)" : "");
    lcreport::Frame fr;
    fr.file = abs;
    fr.function = h.offset ? hex_offset(h.offset) : std::string("the file");
    fr.line = 1;
    f.access.push_back(fr);
    f.key = std::to_string(std::hash<std::string>{}(h.type + "|" + abs + "|" + h.message));
    report->findings.push_back(std::move(f));
}

} // namespace

void scan_into_report(lcreport::Report *report, const std::string &abs, const std::string &bytes,
                      bool malware) {
    std::vector<size_t> more;
    const std::vector<lcscan::Hit> hits = lcscan::scan_file(abs, bytes, &more, malware);
    for (size_t i = 0; i < hits.size(); ++i)
        add_finding(report, abs, hits[i], more[i]);
    if (const std::string sys = shadowed_program(abs, bytes, lcscan::kind_of(bytes)); !sys.empty()) {
        lcscan::Hit h;
        h.type = lcproto::kMasquerade;
        h.message = "it is called \"" + fs::path(abs).filename().string() +
                    "\" like the system's " + sys + ", but it is a different program: a "
                    "directory that comes first in PATH with such a file makes every "
                    "command of that name run this one";
        add_finding(report, abs, h, 0);
    }
}

namespace {

// What scanning one file gave, kept apart so that files can be scanned at the same time.
struct FileResult {
    std::vector<std::string> notes;
    lcreport::Report found; // only its findings are used
    bool scanned = false;
};

// Every regular file under `target` (or the one file itself), in file order.
bool collect_files(const std::string &target_text, std::vector<std::string> *files) {
    std::error_code ec;
    const fs::path target(target_text);
    if (!fs::exists(fs::symlink_status(target, ec)))
        return false;
    if (fs::is_directory(target, ec)) {
        auto it = fs::recursive_directory_iterator(
            target, fs::directory_options::skip_permission_denied, ec);
        for (; !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
            const std::string p = it->path().generic_string();
            if (p == "/proc" || p == "/sys" || p == "/dev") {
                it.disable_recursion_pending();
                continue;
            }
            std::error_code e2;
            if (it->is_symlink(e2) || !it->is_regular_file(e2))
                continue;
            files->push_back(p);
        }
        std::sort(files->begin(), files->end());
    } else {
        files->push_back(target.generic_string());
    }
    return true;
}

// Where the model is when --ai-model is not given: next to the project root or
// next to the leakcheck binary (build/leakcheck -> ../model).
std::string default_model_path() {
    std::error_code ec;
    if (fs::is_regular_file("model/pe-malware.ai", ec))
        return "model/pe-malware.ai";
#if defined(__linux__)
    char buf[4096];
    const ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n > 0) {
        buf[n] = 0;
        const fs::path dir = fs::path(buf).parent_path();
        for (const fs::path &candidate :
             {dir / "model/pe-malware.ai", dir.parent_path() / "model/pe-malware.ai"})
            if (fs::is_regular_file(candidate, ec))
                return candidate.generic_string();
    }
#endif
    return {};
}

// The classifier's verdict as a finding: only above the threshold, and worded as
// what it is -- a statistical guess about the shape of the file, not a rule.
void ai_check(lcreport::Report *found, const std::string &abs, const std::string &bytes,
              const lcscan::AiModel &model, double threshold) {
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
    add_finding(found, abs, h, 0);
}

// The classifier, when --ai asked for it: shared by all workers, read-only.
struct AiRun {
    const lcscan::AiModel *model = nullptr;
    double threshold = 0.5;
};

void scan_one(const std::string &file, bool malware, const AiRun &ai, FileResult *out) {
    std::error_code ec;
    const uintmax_t size = fs::file_size(file, ec);
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
    const std::string abs = fs::absolute(file, ec).lexically_normal().generic_string();
    scan_into_report(&out->found, abs, bytes, malware);
    if (ai.model)
        ai_check(&out->found, abs, bytes, *ai.model, ai.threshold);
}

} // namespace

int run_scan(const Command &command) {
    std::vector<std::string> files;
    if (!collect_files(command.target, &files)) {
        std::fprintf(stderr, "leakcheck: '%s' does not exist\n", command.target.c_str());
        return 1;
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
    report.command.push_back(command.target);

    // Files are independent, and a scan is mostly waiting for the disk and
    // running over bytes, so several are scanned at once. Each file's result is
    // kept in its own slot and joined in file order, so the report is the same
    // whatever the number of threads.
    std::vector<FileResult> results(files.size());
    size_t workers = command.jobs > 0 ? size_t(command.jobs)
                                      : std::max<size_t>(1, std::thread::hardware_concurrency());
    workers = std::min(workers, files.size());
    std::atomic<size_t> next{0};
    auto work = [&] {
        for (size_t i = next++; i < files.size(); i = next++) {
            try {
                scan_one(files[i], command.malware, ai, &results[i]);
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

    std::string error;
    if (!command.suppressions.empty() &&
        !lcreport::apply_suppressions(command.suppressions, report, &error)) {
        std::fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return 1;
    }
    if (!lcreport::write_report(report, command.format, command.output, &error)) {
        std::fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return 1;
    }
    size_t problems = 0;
    for (const auto &f : report.findings)
        problems += lcreport::is_problem(f);
    if (!command.output.empty())
        std::fprintf(stderr, "leakcheck: %zu problem(s) in %zu file(s); report written to %s\n",
                     problems, report.files_analyzed, command.output.c_str());
    return problems ? command.error_exitcode : 0;
}

int run_ai_features(const Command &command) {
    std::vector<std::string> files;
    if (!collect_files(command.target, &files)) {
        std::fprintf(stderr, "leakcheck: '%s' does not exist\n", command.target.c_str());
        return 1;
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
                rows[i].path = fs::absolute(file, ec).lexically_normal().generic_string();
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
