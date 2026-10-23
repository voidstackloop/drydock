#include "internal.h"
#include "protocol.h"

#include <fstream>
#ifndef _WIN32
#include <fnmatch.h>
#endif

namespace lcreport {

// Shell glob (`*`, `?`, `[a-z]`, `[!x]`, `\x`), no special case for '/' or '.':
// fnmatch(pattern, text, 0) for platforms that have no fnmatch.
bool glob_match(const char *p, const char *t) {
    for (; *p; ++p, ++t) {
        if (*p == '*') {
            while (p[1] == '*')
                ++p;
            for (const char *s = t;; ++s) {
                if (glob_match(p + 1, s))
                    return true;
                if (!*s)
                    return false;
            }
        }
        if (!*t)
            return false;
        if (*p == '?')
            continue;
        if (*p == '[') {
            const char *q = p + 1;
            const bool neg = *q == '!' || *q == '^';
            q += neg;
            bool hit = false, closed = false;
            for (bool first = true; *q; first = false, ++q) {
                if (*q == ']' && !first) {
                    closed = true;
                    break;
                }
                if (q[1] == '-' && q[2] && q[2] != ']') {
                    hit |= *t >= *q && *t <= q[2];
                    q += 2;
                } else {
                    hit |= *t == *q;
                }
            }
            if (closed) {
                if (hit == neg)
                    return false;
                p = q;
                continue;
            }
            // no closing ']': '[' is an ordinary character
        } else if (*p == '\\' && p[1]) {
            ++p;
        }
        if (*p != *t)
            return false;
    }
    return !*t;
}

namespace {

struct SuppressRule {
    std::string type; // finding type, "leak", or "*"
    std::string pattern;
};

std::string trim(const std::string &s) {
    size_t b = s.find_first_not_of(" \t\r");
    size_t e = s.find_last_not_of(" \t\r");
    return b == std::string::npos ? std::string() : s.substr(b, e - b + 1);
}

bool type_matches(const std::string &rule, const Finding &f) {
    if (rule == "*")
        return true;
    if (rule == "leak")
        return f.type == lcproto::kLeak;
    return rule == f.type;
}

bool glob(const std::string &pattern, const std::string &text) {
#ifdef _WIN32
    return !text.empty() && glob_match(pattern.c_str(), text.c_str());
#else
    return !text.empty() && fnmatch(pattern.c_str(), text.c_str(), 0) == 0;
#endif
}

bool frame_matches(const std::string &pattern, const Frame &fr) {
    return glob(pattern, fr.function) || glob(pattern, fr.file) ||
           glob(pattern, fr.module);
}

// "near:<glob>" looks only at the innermost kNear frames of each stack, so a
// rule for an interpreter or framework does not also hide what the program
// itself allocated through it further up the stack. "top:<glob>" is the same
// with one frame: the interpreter's own leak, not a ctypes frame under it.
constexpr size_t kNear = 3;

bool matches(const SuppressRule &r, const Finding &f) {
    if (!type_matches(r.type, f))
        return false;
    size_t skip = 0, limit = size_t(-1);
    if (r.pattern.rfind("top:", 0) == 0) {
        skip = 4;
        limit = 1;
    } else if (r.pattern.rfind("near:", 0) == 0) {
        skip = 5;
        limit = kNear;
    }
    const std::string pattern = r.pattern.substr(skip);
    // No frame to glob against: "*" still means every finding, including one
    // whose stacks were not recorded.
    if (pattern == "*" && f.access.empty() && f.alloc.empty() && f.freed.empty())
        return true;
    for (const auto *s : {&f.access, &f.alloc, &f.freed})
        for (size_t i = 0; i < s->size() && i < limit; ++i)
            if (frame_matches(pattern, (*s)[i]))
                return true;
    return false;
}

bool same_frame(const Frame &a, const Frame &b) {
    return a.module == b.module && a.offset == b.offset &&
           a.function == b.function;
}

bool system_library(const Frame &f) {
    return f.module.rfind("/lib", 0) == 0 || f.module.rfind("/usr/lib", 0) == 0;
}

// The memory a library allocated for a handle that leaked (a DIR's buffer):
// its stack is the handle's open stack with only library frames on top.
bool owned_by_leaked_handle(const Finding &m, const std::vector<Finding> &all) {
    if (m.type != lcproto::kLeak)
        return false;
    for (const Finding &h : all) {
        if (h.type != lcproto::kResourceLeak || h.alloc.empty())
            continue;
        for (size_t k = 1; k < m.alloc.size(); ++k) {
            if (!system_library(m.alloc[k - 1]))
                break;
            bool same = true; // over the frames both stacks recorded
            for (size_t i = 0;
                 same && k + i < m.alloc.size() && i < h.alloc.size(); ++i)
                same = same_frame(m.alloc[k + i], h.alloc[i]);
            if (same)
                return true;
        }
    }
    return false;
}

} // namespace

// The start-up code a MinGW program carries (crtexe.c and its neighbours): it
// registers the atexit handlers, and the C runtime keeps that table's pointers
// encoded, so a scan for pointers cannot find them.
bool crt_startup_frame(const Frame &fr) {
    const size_t s = fr.file.find_last_of("/\\");
    const std::string b = s == std::string::npos ? fr.file : fr.file.substr(s + 1);
    for (const char *n : {"crtexe.c", "gccmain.c", "crt0_c.c", "tlssup.c", "dllmain.c", "pseudo-reloc.c"})
        if (b == n)
            return true;
    return b.rfind("ucrtbase_compa", 0) == 0;
}

void apply_default_suppressions(Report &r) {
    size_t before = r.findings.size();
    std::erase_if(r.findings, [](const Finding &f) {
        // Allocated directly by ld.so (the first frame is inside it): the
        // loader keeps these for the life of the process, and how they are
        // referenced depends on allocator alignment.
        return f.type == lcproto::kLeak && !f.alloc.empty() &&
               f.alloc.front().module.find("/ld-linux") != std::string::npos;
    });
    if (size_t n = before - r.findings.size())
        r.notes.push_back(
            std::to_string(n) +
            " leak report(s) inside the dynamic loader suppressed");

    before = r.findings.size();
    std::erase_if(r.findings, [](const Finding &f) {
        return f.type == lcproto::kLeak && !f.alloc.empty() && crt_startup_frame(f.alloc.front());
    });
    if (size_t n = before - r.findings.size())
        r.notes.push_back(std::to_string(n) +
                          " leak report(s) inside the C runtime's start-up code suppressed");

    // A block made entirely by Windows' own code (a DNS cache on a thread of its
    // own, say): no frame of the program is behind it, so the program cannot have
    // leaked it.
    before = r.findings.size();
    std::erase_if(r.findings, [](const Finding &f) {
        if (f.type != lcproto::kLeak || f.alloc.empty())
            return false;
        for (const Frame &fr : f.alloc) {
            std::string m = fr.module;
            for (char &c : m)
                c = c >= 'A' && c <= 'Z' ? char(c | 0x20) : c;
            if (m.find("\\windows\\system32\\") == std::string::npos &&
                m.find("\\windows\\syswow64\\") == std::string::npos &&
                m.find("\\windows\\winsxs\\") == std::string::npos)
                return false;
        }
        return true;
    });
    if (size_t n = before - r.findings.size())
        r.notes.push_back(std::to_string(n) + " leak report(s) made entirely by Windows itself suppressed");

    // winpthreads makes semaphores and events for its read-write locks and keeps
    // them with the lock: a handle it opened is not the program's to close.
    before = r.findings.size();
    std::erase_if(r.findings, [](const Finding &f) {
        if (f.type != lcproto::kResourceLeak || f.alloc.empty())
            return false;
        const std::string &m = f.alloc.front().module;
        const size_t s = m.find_last_of("/\\");
        return m.compare(s == std::string::npos ? 0 : s + 1, 12, "libwinpthrea") == 0;
    });
    if (size_t n = before - r.findings.size())
        r.notes.push_back(std::to_string(n) + " handle(s) held by the pthread library suppressed");

    // GCC's unwinder (Windows) keeps the state of the exceptions it has seen for
    // the life of the process, behind pointers into the middle of its blocks.
    before = r.findings.size();
    std::erase_if(r.findings, [](const Finding &f) {
        if (f.type != lcproto::kLeak || f.alloc.empty())
            return false;
        const std::string &m = f.alloc.front().module;
        const size_t s = m.find_last_of("/\\");
        return m.compare(s == std::string::npos ? 0 : s + 1, 8, "libgcc_s") == 0;
    });
    if (size_t n = before - r.findings.size())
        r.notes.push_back(std::to_string(n) + " leak report(s) inside GCC's unwinder suppressed");

    std::vector<bool> owned;
    for (const Finding &f : r.findings)
        owned.push_back(owned_by_leaked_handle(f, r.findings));
    size_t i = 0, folded = 0;
    std::erase_if(r.findings, [&](const Finding &) {
        folded += owned[i];
        return owned[i++];
    });
    if (folded)
        r.notes.push_back(std::to_string(folded) +
                          " memory leak report(s) belong to a leaked "
                          "descriptor, stream or directory and are reported "
                          "with it");
}

bool apply_suppressions(const std::string &path, Report &r,
                        std::string *error) {
    std::ifstream in(path);
    if (!in) {
        *error = "cannot read suppression file '" + path + "'";
        return false;
    }
    std::vector<SuppressRule> list;
    std::string line;
    int no = 0;
    while (std::getline(in, line)) {
        ++no;
        line = trim(line);
        if (line.empty() || line[0] == '#')
            continue;
        size_t colon = line.find(':');
        if (colon == std::string::npos || colon == 0 ||
            colon + 1 == line.size()) {
            *error =
                path + ":" + std::to_string(no) + ": expected <type>:<pattern>";
            return false;
        }
        list.push_back(
            {trim(line.substr(0, colon)), trim(line.substr(colon + 1))});
    }
    size_t before = r.findings.size();
    std::erase_if(r.findings, [&](const Finding &f) {
        for (const SuppressRule &s : list)
            if (matches(s, f))
                return true;
        return false;
    });
    if (size_t n = before - r.findings.size())
        r.notes.push_back(std::to_string(n) + " finding(s) suppressed by " +
                          path);
    return true;
}

} // namespace lcreport
