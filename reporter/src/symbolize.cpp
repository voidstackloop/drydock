#include "internal.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <map>
#include <set>
#include <string_view>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/wait.h>
#endif

namespace lcreport {
namespace {

#ifdef _WIN32
// The runtime writes module paths as UTF-8; Windows wants them wide.
std::wstring widen(const std::string &s) {
    if (s.empty())
        return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), &w[0], n);
    return w;
}

// Runs argv without a shell and captures stdout. Returns false if it could
// not be started or did not exit with status 0.
bool run_capture(const std::vector<std::string> &args, std::string *out) {
    std::wstring cmd;
    for (const auto &a : args)
        cmd += L"\"" + widen(a) + L"\" ";
    SECURITY_ATTRIBUTES sa = {sizeof sa, nullptr, TRUE};
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0))
        return false;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             &sa, OPEN_EXISTING, 0, nullptr);
    STARTUPINFOW si = {};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nul;
    si.hStdOutput = wr;
    si.hStdError = nul;
    PROCESS_INFORMATION pi = {};
    const BOOL ok = CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                   nullptr, nullptr, &si, &pi);
    CloseHandle(wr);
    if (nul != INVALID_HANDLE_VALUE)
        CloseHandle(nul);
    if (!ok) {
        CloseHandle(rd);
        return false;
    }
    char buf[65536];
    DWORD n = 0;
    while (ReadFile(rd, buf, sizeof buf, &n, nullptr) && n)
        out->append(buf, n);
    CloseHandle(rd);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}
#else
// Runs argv without a shell and captures stdout. Returns false if it could
// not be started or did not exit with status 0.
bool run_capture(const std::vector<std::string> &args, std::string *out) {
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0)
        return false;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    if (pid == 0) {
        dup2(fds[1], 1);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0)
            dup2(devnull, 2);
        std::vector<char *> argv;
        for (const auto &a : args)
            argv.push_back(const_cast<char *>(a.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    close(fds[1]);
    char buf[65536];
    for (;;) {
        ssize_t n = read(fds[0], buf, sizeof buf);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        out->append(buf, size_t(n));
    }
    close(fds[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}
#endif

bool is_hex_line(std::string_view s) {
    if (s.size() < 3 || s[0] != '0' || s[1] != 'x')
        return false;
    for (size_t i = 2; i < s.size(); ++i)
        if (!isxdigit(static_cast<unsigned char>(s[i])))
            return false;
    return true;
}

void parse_location(std::string loc, Frame &fr) {
    if (size_t d = loc.find(" (discriminator"); d != std::string::npos)
        loc.erase(d);
    size_t colon = loc.rfind(':');
    if (colon == std::string::npos)
        return;
    std::string file = loc.substr(0, colon);
    std::string line = loc.substr(colon + 1);
    if (file == "??" || file.empty())
        return;
    fr.file = file;
    fr.line = std::atoi(line.c_str());
}

using Resolved = std::map<uint64_t, std::vector<Frame>>;

#ifdef _WIN32
// The runtime reports offsets from where the module was loaded; addr2line wants
// the addresses the debug information was written with: the image base the
// linker chose, plus the offset.
uint64_t pe_image_base(const std::string &path) {
    FILE *f = _wfopen(widen(path).c_str(), L"rb");
    if (!f)
        return 0;
    unsigned char b[1024];
    const size_t n = fread(b, 1, sizeof b, f);
    fclose(f);
    if (n < 0x40 || b[0] != 'M' || b[1] != 'Z')
        return 0;
    const size_t pe = b[0x3c] | (size_t(b[0x3d]) << 8);
    if (pe + 24 + 32 > n || memcmp(b + pe, "PE\0\0", 4) != 0)
        return 0;
    const unsigned char *opt = b + pe + 24;
    uint64_t base = 0;
    if (opt[0] == 0x0b && opt[1] == 0x02) { // PE32+
        for (int i = 7; i >= 0; --i)
            base = (base << 8) | opt[24 + i];
    } else {
        for (int i = 3; i >= 0; --i)
            base = (base << 8) | opt[28 + i];
    }
    return base;
}
#endif

// addr2line -a prints each address, then (function, file:line) pairs: the
// innermost inlined function first, the real enclosing function last.
bool resolve_module(const std::string &module,
                    const std::set<uint64_t> &offsets, Resolved &out) {
    std::vector<uint64_t> list(offsets.begin(), offsets.end());
#ifdef _WIN32
    const uint64_t image_base = pe_image_base(module);
#else
    const uint64_t image_base = 0;
#endif
    for (size_t at = 0; at < list.size(); at += 4000) {
        std::vector<std::string> args = {"addr2line", "-a", "-f",  "-C",
                                         "-i",        "-e", module};
        size_t end = std::min(list.size(), at + 4000);
        for (size_t i = at; i < end; ++i)
            args.push_back(hex(list[i] + image_base));
        std::string text;
        if (!run_capture(args, &text))
            return false;
        // Walk newline-separated records without istringstream: each record
        // is one hex address line followed by (function, file:line) pairs.
        std::vector<Frame> *frames = nullptr;
        size_t idx = at;
        size_t p = 0;
        auto next_line = [&](std::string_view &ln) -> bool {
            if (p >= text.size())
                return false;
            size_t eol = text.find('\n', p);
            if (eol == std::string::npos) {
                ln = std::string_view(text).substr(p);
                p = text.size();
            } else {
                ln = std::string_view(text).substr(p, eol - p);
                p = eol + 1;
            }
            if (!ln.empty() && ln.back() == '\r')
                ln.remove_suffix(1);
            return true;
        };
        std::string_view ln;
        while (next_line(ln)) {
            if (is_hex_line(ln)) {
                if (idx >= end)
                    break;
                frames = &out[list[idx++]];
                continue;
            }
            if (!frames)
                continue;
            Frame fr;
            fr.module = module;
            if (ln != "??")
                fr.function = std::string(ln);
#ifdef _WIN32
            std::replace(fr.function.begin(), fr.function.end(), '\r', ' ');
#endif
            std::string_view loc;
            if (next_line(loc))
                parse_location(std::string(loc), fr);
            frames->push_back(std::move(fr));
        }
    }
    return true;
}

bool is_runtime_module(const std::string &m) {
    return m.find("/libc.so") != std::string::npos ||
           m.find("/ld-linux") != std::string::npos;
}

void trim(std::vector<Frame> &stack) {
    for (size_t i = 0; i < stack.size(); ++i) {
        if (stack[i].function == "main") {
            stack.resize(i + 1);
            return;
        }
    }
    while (!stack.empty()) {
        const Frame &b = stack.back();
        if (is_runtime_module(b.module) || b.function == "_start" ||
            b.function == "start_thread" || b.function == "clone3" ||
            b.function == "clone")
            stack.pop_back();
        else
            break;
    }
}

void expand(std::vector<Frame> &stack,
            const std::map<std::string, Resolved> &db) {
    std::vector<Frame> out;
    for (const Frame &fr : stack) {
        auto m = db.find(fr.module);
        if (m != db.end()) {
            auto r = m->second.find(fr.offset);
            if (r != m->second.end() && !r->second.empty()) {
                for (size_t i = 0; i < r->second.size(); ++i) {
                    Frame f = r->second[i];
                    f.offset = fr.offset;
                    f.inlined = i + 1 < r->second.size();
                    out.push_back(std::move(f));
                }
                continue;
            }
        }
        out.push_back(fr);
    }
    stack.swap(out);
    trim(stack);
}

} // namespace

void symbolize(Report &r) {
    std::map<std::string, std::set<uint64_t>> wanted;
    for (const Finding &f : r.findings)
        for (const auto *s : {&f.access, &f.alloc, &f.freed})
            for (const Frame &fr : *s)
                if (!fr.module.empty() && fr.function.empty())
                    wanted[fr.module].insert(fr.offset);
    std::map<std::string, Resolved> db;
    bool failed = false;
    for (const auto &[module, offs] : wanted) {
#ifdef _WIN32
        if (GetFileAttributesW(widen(module).c_str()) == INVALID_FILE_ATTRIBUTES)
            continue;
#else
        if (access(module.c_str(), R_OK) != 0)
            continue;
#endif
        if (!resolve_module(module, offs, db[module]))
            failed = true;
    }
    if (failed)
        r.notes.push_back(
            "addr2line was not available or failed for some modules; those "
            "frames are shown as module+offset");
    for (Finding &f : r.findings) {
        expand(f.access, db);
        expand(f.alloc, db);
        expand(f.freed, db);
        // The runtime's key depends on per-run ids; fingerprint the symbols.
        std::string id = f.type + '|' + f.category;
        for (const auto *s : {&f.access, &f.alloc, &f.freed})
            for (size_t i = 0; i < s->size() && i < 6; ++i)
                id += '|' + (*s)[i].function + '@' + (*s)[i].file + ':' +
                      std::to_string((*s)[i].line);
        f.key = hex(std::hash<std::string>{}(id));
    }
}

} // namespace lcreport
