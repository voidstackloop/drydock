// -f patch / --suggest-fixes: Generates standard unified diff patch files
// with automatic remediations for classic dangerous functions.
#include "internal.h"

#include <fstream>
#include <map>
#include <ostream>
#include <sstream>
#include <vector>

namespace lcreport {
namespace {

struct FixReplacement {
    std::string original;
    std::string replacement;
};

FixReplacement suggest_fix(const Finding &f) {
    if (f.type == "unbounded-copy" || f.type == "unsafe-function") {
        if (f.message.find("strcpy(") != std::string::npos)
            return {"strcpy", "strlcpy"};
        if (f.message.find("strcat(") != std::string::npos)
            return {"strcat", "strlcat"};
        if (f.message.find("sprintf(") != std::string::npos)
            return {"sprintf", "snprintf"};
        if (f.message.find("gets(") != std::string::npos)
            return {"gets", "fgets"};
    }
    if (f.type == "insecure-tempfile") {
        if (f.message.find("tmpnam(") != std::string::npos)
            return {"tmpnam", "mkstemp"};
        if (f.message.find("tempnam(") != std::string::npos)
            return {"tempnam", "mkstemp"};
        if (f.message.find("mktemp(") != std::string::npos)
            return {"mktemp", "mkstemp"};
    }
    if (f.type == "uncleared-sensitive-data") {
        return {"memset", "explicit_bzero"};
    }
    if (f.type == "timing-attack") {
        return {"memcmp", "CRYPTO_memcmp"};
    }
    return {};
}

} // namespace

void render_patch(const Report &r, std::ostream &os) {
    // Group findings by file
    std::map<std::string, std::vector<const Finding *>> by_file;
    for (const Finding &f : r.findings) {
        const Frame *p = primary_frame(f);
        if (p && !p->file.empty() && p->line > 0)
            by_file[p->file].push_back(&f);
    }

    for (const auto &[path, findings] : by_file) {
        std::ifstream file(path);
        std::vector<std::string> lines;
        std::string line;
        while (std::getline(file, line))
            lines.push_back(line);

        bool header_printed = false;
        for (const Finding *f : findings) {
            const Frame *p = primary_frame(*f);
            if (!p || p->line <= 0 || size_t(p->line) > lines.size())
                continue;
            const FixReplacement fix = suggest_fix(*f);
            if (fix.original.empty())
                continue;

            size_t idx = size_t(p->line - 1);
            std::string cur = lines[idx];
            size_t pos = cur.find(fix.original);
            if (pos == std::string::npos)
                continue;

            std::string mod = cur;
            mod.replace(pos, fix.original.size(), fix.replacement);

            if (!header_printed) {
                os << "--- a/" << path << "\n";
                os << "+++ b/" << path << "\n";
                header_printed = true;
            }
            os << "@@ -" << p->line << ",1 +" << p->line << ",1 @@\n";
            os << "-" << cur << "\n";
            os << "+" << mod << "\n";
        }
    }
}

} // namespace lcreport
