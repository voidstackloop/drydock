// --baseline: what a team already had when it turned the gate on. The
// fingerprint leaves out line numbers, so a reformat or an edit above a
// finding does not make it new again; it keeps the type, the file relative to
// the baseline, the enclosing function and the message.
#include "report.h"
#include "protocol.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_set>

namespace fs = std::filesystem;

namespace lcreport {
namespace {

uint64_t fnv1a(const std::string &s) {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

std::string hex64(uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "%016llx", static_cast<unsigned long long>(v));
    return b;
}

std::string relative_to(const std::string &file, const std::string &root) {
    if (file.empty())
        return {};
    std::error_code ec;
    fs::path abs = fs::absolute(fs::path(file), ec);
    if (ec)
        abs = fs::path(file);
    abs = abs.lexically_normal();
    const fs::path rel = fs::relative(abs, fs::path(root), ec);
    std::string out = (ec ? abs : rel).generic_string();
    while (out.rfind("./", 0) == 0)
        out = out.substr(2);
    return out;
}

std::string escape(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\')
            out += "\\\\";
        else if (c == '\t')
            out += "\\t";
        else if (c == '\n')
            out += "\\n";
        else if (c == '\r')
            out += "\\r";
        else
            out.push_back(c);
    }
    return out;
}

std::string baseline_root(const std::string &path) {
    std::error_code ec;
    const fs::path abs = fs::absolute(fs::path(path), ec).lexically_normal();
    return (ec ? fs::path(path) : abs).parent_path().generic_string();
}

// Messages name the line a block was allocated on ("allocated at line 10"); a
// refactor moves it. The line number is not part of the finding's identity.
std::string without_lines(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        if (s.compare(i, 5, "line ") == 0 && i + 5 < s.size() &&
            s[i + 5] >= '0' && s[i + 5] <= '9') {
            out += "line #";
            i += 5;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9')
                ++i;
        } else {
            out.push_back(s[i++]);
        }
    }
    return out;
}

struct Entry {
    std::string fingerprint, type, file, function, message;
};

} // namespace

std::string fingerprint(const Finding &f, const std::string &root) {
    const Frame *p = primary_frame(f);
    const std::string file = p ? relative_to(p->file, root) : std::string();
    // A scan finding carries the byte offset as its "function", and that moves
    // whenever anything above it in the file is edited. The type, file and
    // message already identify it (a scan reports one hit per type per file),
    // so the offset only made the baseline brittle.
    const std::string function =
        p && f.category != lcproto::kCatScan ? p->function : std::string();
    // \x1f cannot occur in a path or a message, so the fields cannot run into
    // each other.
    return hex64(fnv1a(f.type + "\x1f" + file + "\x1f" + function + "\x1f" +
                       without_lines(f.message)));
}

bool write_baseline(const std::string &path, const Report &r, std::string *error) {
    const std::string root = baseline_root(path);
    std::vector<Entry> entries;
    entries.reserve(r.findings.size());
    for (const Finding &f : r.findings) {
        const Frame *p = primary_frame(f);
        entries.push_back({fingerprint(f, root), f.type, p ? relative_to(p->file, root) : "",
                           p ? p->function : "", f.message});
    }
    std::sort(entries.begin(), entries.end(),
              [](const Entry &a, const Entry &b) { return a.fingerprint < b.fingerprint; });
    std::ofstream out(path, std::ios::trunc);
    if (!out) {
        *error = "cannot write the baseline to '" + path + "'";
        return false;
    }
    out << "leakcheck-baseline 1\n";
    for (const Entry &e : entries)
        out << e.fingerprint << '\t' << e.type << '\t' << escape(e.file) << '\t'
            << escape(e.function) << '\t' << escape(e.message) << '\n';
    out.flush();
    if (!out) {
        *error = "failed while writing the baseline to '" + path + "'";
        return false;
    }
    return true;
}

bool apply_baseline(const std::string &path, Report &r, size_t *known, std::string *error) {
    std::ifstream in(path);
    if (!in) {
        *error = "cannot read the baseline '" + path +
                 "' (write it once with --baseline write " + path + ")";
        return false;
    }
    const std::string root = baseline_root(path);
    std::string line;
    if (!std::getline(in, line) || line.rfind("leakcheck-baseline ", 0) != 0) {
        *error = path + " is not a leakcheck baseline (it starts with \"leakcheck-baseline 1\")";
        return false;
    }
    std::unordered_set<std::string> seen;
    int no = 1;
    while (std::getline(in, line)) {
        ++no;
        if (line.empty() || line[0] == '#')
            continue;
        const size_t tab = line.find('\t');
        const std::string fp = line.substr(0, tab);
        if (tab == std::string::npos || fp.size() != 16 ||
            fp.find_first_not_of("0123456789abcdef") != std::string::npos) {
            *error = path + ":" + std::to_string(no) + ": expected <fingerprint>\\t<type>\\t...";
            return false;
        }
        seen.insert(fp);
    }
    const size_t before = r.findings.size();
    std::erase_if(r.findings,
                  [&](const Finding &f) { return seen.count(fingerprint(f, root)) != 0; });
    *known = before - r.findings.size();
    if (*known)
        r.notes.push_back(std::to_string(*known) + " finding(s) already in the baseline " + path +
                          " (not gated)");
    return true;
}

} // namespace lcreport
