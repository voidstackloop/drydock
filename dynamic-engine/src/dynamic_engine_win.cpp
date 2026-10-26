// `leakcheck dynamic` on Windows: start the program suspended, make it load
// leakcheck_preload.dll before its own entry point runs, wait for it, and read
// what the DLL wrote (dynamic_engine.cpp is the Linux side).
#include "dynamic_engine.h"
#include "command.h"
#include "protocol.h"
#include "report.h"
#include "win_inject.h"

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::wstring widen(const std::string &s) {
    if (s.empty())
        return {};
    int n = MultiByteToWideChar(CP_ACP, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.data(), int(s.size()), &w[0], n);
    return w;
}

// One argument as CommandLineToArgvW will read it back.
std::wstring quote(const std::wstring &a) {
    if (!a.empty() && a.find_first_of(L" \t\n\v\"") == std::wstring::npos)
        return a;
    std::wstring out = L"\"";
    for (size_t i = 0;; ++i) {
        size_t slashes = 0;
        while (i < a.size() && a[i] == L'\\') {
            ++slashes;
            ++i;
        }
        if (i == a.size()) {
            out.append(slashes * 2, L'\\');
            break;
        }
        if (a[i] == L'"')
            out.append(slashes * 2 + 1, L'\\');
        else
            out.append(slashes, L'\\');
        out += a[i];
    }
    return out + L"\"";
}

std::string last_error_text(DWORD e) {
    char b[256];
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, e, 0,
                             b, sizeof b, nullptr);
    while (n && (b[n - 1] == '\n' || b[n - 1] == '\r' || b[n - 1] == ' '))
        --n;
    b[n] = 0;
    return n ? b : "error " + std::to_string(e);
}

std::string make_report_file() {
    char dir[MAX_PATH + 1], name[MAX_PATH + 1];
    if (!GetTempPathA(sizeof dir, dir) || !GetTempFileNameA(dir, "lck", 0, name))
        return "";
    return name;
}

// The program must be 64-bit: the DLL and the injection are.
bool is_x64_image(const std::wstring &path) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE)
        return true; // let CreateProcess say what is wrong
    unsigned char b[4096];
    DWORD n = 0;
    ReadFile(f, b, sizeof b, &n, nullptr);
    CloseHandle(f);
    if (n < sizeof(IMAGE_DOS_HEADER))
        return true;
    auto *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(b);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || size_t(dos->e_lfanew) + 6 > n)
        return true;
    return *reinterpret_cast<uint16_t *>(b + dos->e_lfanew + 4) == IMAGE_FILE_MACHINE_AMD64;
}

bool inject(HANDLE process, HANDLE thread, const std::wstring &dll, std::string *error) {
    char why[128];
    if (lcinject::load_dll_first(process, thread, dll.c_str(), why, sizeof why))
        return true;
    *error = why;
    return false;
}

BOOL WINAPI ignore_ctrl_c(DWORD type) {
    // Like a shell waiting for a foreground job: Ctrl-C stops the program, and
    // leakcheck stays alive to report what happened.
    return type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT;
}

void set_env(const char *name, const std::string &value) { SetEnvironmentVariableA(name, value.c_str()); }

struct Outcome {
    bool started = false;
    std::string error;
    DWORD code = 0;
};

Outcome launch(const Command &command, const std::string &report) {
    Outcome out;
    std::wstring dll = widen(get_selfpath());
    const size_t slash = dll.find_last_of(L"\\/");
    dll = (slash == std::wstring::npos ? L"." : dll.substr(0, slash)) + L"\\" + widen(lcproto::kLibName);

    wchar_t found[MAX_PATH + 1];
    std::wstring target = widen(command.target);
    std::wstring app = target;
    if (SearchPathW(nullptr, target.c_str(), L".exe", MAX_PATH, found, nullptr))
        app = found;
    if (!is_x64_image(app)) {
        out.error = "'" + command.target + "' is not a 64-bit program: dynamic mode on Windows does not do 32-bit";
        return out;
    }

    set_env(lcproto::kEnvReport, report);
    set_env(lcproto::kEnvRootPid, "0");
    set_env(lcproto::kEnvQuarantineMb, std::to_string(command.quarantine_mb));
    set_env(lcproto::kEnvStackDepth, std::to_string(command.stack_depth));
    set_env(lcproto::kEnvGuardEvery, std::to_string(command.guard_every));
    set_env(lcproto::kEnvAbort, command.abort_on_error ? "1" : "0");
    set_env(lcproto::kEnvFastUnwind, command.fast_unwind ? "1" : "0");
    set_env(lcproto::kEnvLeaks, command.leak_check ? "1" : "0");
    set_env(lcproto::kEnvReachable, command.show_reachable ? "1" : "0");
    set_env(lcproto::kEnvTraceChildren, command.trace_children ? "1" : "0");
    set_env(lcproto::kEnvMalware, command.malware ? "1" : "0");

    std::wstring line = quote(target);
    for (const std::string &a : command.target_args)
        line += L" " + quote(widen(a));

    STARTUPINFOW si = {};
    si.cb = sizeof si;
    PROCESS_INFORMATION pi = {};
    SetConsoleCtrlHandler(ignore_ctrl_c, TRUE);
    if (!CreateProcessW(app.c_str(), &line[0], nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr,
                        &si, &pi)) {
        out.error = last_error_text(GetLastError());
        SetConsoleCtrlHandler(ignore_ctrl_c, FALSE);
        return out;
    }
    std::string err;
    if (!inject(pi.hProcess, pi.hThread, dll, &err)) {
        TerminateProcess(pi.hProcess, 127);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        out.error = err;
        SetConsoleCtrlHandler(ignore_ctrl_c, FALSE);
        return out;
    }
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &out.code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    SetConsoleCtrlHandler(ignore_ctrl_c, FALSE);
    out.started = true;
    return out;
}

} // namespace

std::string get_selfpath() {
    char b[MAX_PATH + 1];
    DWORD n = GetModuleFileNameA(nullptr, b, MAX_PATH);
    return std::string(b, n);
}

int run_dynamic_analysis(const Command &command) {
    const std::string self = get_selfpath();
    const size_t slash = self.find_last_of("\\/");
    const std::string dll = (slash == std::string::npos ? "." : self.substr(0, slash)) + "\\" + lcproto::kLibName;
    if (GetFileAttributesA(dll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "leakcheck: cannot find %s next to the leakcheck executable\n", lcproto::kLibName);
        return 1;
    }
    const std::string report_path = make_report_file();
    if (report_path.empty()) {
        fprintf(stderr, "leakcheck: cannot create a temporary report file\n");
        return 1;
    }

    Outcome run = launch(command, report_path);
    if (!run.started) {
        DeleteFileA(report_path.c_str());
        fprintf(stderr, "leakcheck: cannot run '%s': %s\n", command.target.c_str(), run.error.c_str());
        return 127;
    }

    lcreport::Report report;
    report.mode = "dynamic";
    report.command.push_back(command.target);
    report.command.insert(report.command.end(), command.target_args.begin(), command.target_args.end());
    report.ran = true;
    report.exit_code = int(run.code);

    lcreport::parse_runtime_stream(report_path, report);
    DeleteFileA(report_path.c_str());
    if (report.processes.empty())
        report.notes.push_back("the target produced no data: it may be 32-bit, or it ended before the "
                               "runtime was loaded");
    lcreport::symbolize(report);
    lcreport::apply_default_suppressions(report);
    lcreport::apply_rule_policy(report, command.rule_policy, command.strict);

    std::string error;
    if (!command.suppressions.empty() &&
        !lcreport::apply_suppressions(command.suppressions, report, &error)) {
        fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return 1;
    }
    if (!lcreport::write_report(report, command.format, command.output, &error)) {
        fprintf(stderr, "leakcheck: %s\n", error.c_str());
        return 1;
    }

    size_t problems = 0;
    for (const auto &f : report.findings)
        problems += lcreport::is_problem(f);
    if (!command.output.empty())
        fprintf(stderr, "leakcheck: %zu problem(s) found; report written to %s\n", problems,
                command.output.c_str());

    // Problems outrank the program's own status: a leak that exits 1 is still
    // the error code, and a clean program that exits 2 keeps 2.
    if (problems)
        return command.error_exitcode;
    if (report.exit_code != 0)
        return report.exit_code;
    if (report.processes.empty())
        return 1; // nothing was analysed: never report success
    return 0;
}
