// What a trojan, backdoor or dropper does, on Windows: the calls that start a
// program, write the files and registry keys that run at login, read the stores
// of passwords, write into other programs, ask whether a debugger is watching,
// clear the event log. The judgment is behavior.cpp's (shared with Linux); this
// file only turns each Windows call into the facts behavior.cpp asks for.
#include "behavior.h"
#include "rt.h"
#include "win_hooks.h"

#include <fcntl.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <urlmon.h>

#include <initializer_list>

namespace lc::win {
namespace {

bool g_on;

bool on() { return g_on && !tl_in_hook; }

// UTF-8 with '/' for the separator, in a fixed buffer, from either kind of string.
struct Text {
    char s[1024];
    explicit Text(const char *a) {
        size_t n = 0;
        for (; a && a[n] && n + 1 < sizeof s; ++n)
            s[n] = a[n] == '\\' ? '/' : a[n];
        s[n] = 0;
    }
    explicit Text(const wchar_t *w) {
        s[0] = 0;
        if (!w)
            return;
        int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, s, int(sizeof s) - 1, nullptr, nullptr);
        s[n > 0 ? n - 1 : 0] = 0;
        for (char *c = s; *c; ++c)
            if (*c == '\\')
                *c = '/';
    }
    const char *get() const { return s; }
};

// The program named by a command line: its first word, quoted or not.
struct Program {
    char s[512];
    explicit Program(const char *line) {
        size_t n = 0;
        const char *p = line;
        while (*p == ' ')
            ++p;
        const bool quoted = *p == '"';
        if (quoted)
            ++p;
        for (; *p && n + 1 < sizeof s && (quoted ? *p != '"' : *p != ' '); ++p)
            s[n++] = *p;
        s[n] = 0;
    }
};

bool is_other_process(HANDLE h) {
    if (!h || h == GetCurrentProcess())
        return false;
    const DWORD pid = GetProcessId(h);
    return pid != GetCurrentProcessId();
}

bool access_writes(DWORD a) {
    return a & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC);
}

} // namespace

// ---- the entry points res_win.cpp calls from its own hooks -------------------------------

namespace {
void open_file(const Text &t, DWORD access, DWORD disposition) {
    ErrnoSaver es;
    int flags = access_writes(access) ? O_WRONLY : O_RDONLY;
    if (disposition == CREATE_ALWAYS || disposition == TRUNCATE_EXISTING)
        flags |= O_TRUNC | O_CREAT;
    else if (disposition == CREATE_NEW || disposition == OPEN_ALWAYS)
        flags |= O_CREAT;
    if (flags & O_CREAT)
        flags |= O_WRONLY;
    behavior::opening(t.get(), flags);
}

void start_program(const char *file, const char *line, const char *how, const void *startup) {
    ErrnoSaver es;
    const Text f(file && *file ? file : "");
    const Text l(line ? line : "");
    if (f.s[0]) {
        behavior::process_start(f.get(), l.get(), how, startup);
    } else {
        const Program p(l.get());
        behavior::process_start(p.s, l.get(), how, startup);
    }
}
} // namespace

void behave_open(const char *path, DWORD access, DWORD disposition) {
    if (path && on())
        open_file(Text(path), access, disposition);
}
void behave_open(const wchar_t *path, DWORD access, DWORD disposition) {
    if (path && on())
        open_file(Text(path), access, disposition);
}
void behave_stream(const char *path, const char *mode) {
    if (!path || !mode || !on())
        return;
    ErrnoSaver es;
    behavior::opening_stream(Text(path).get(), mode);
}
void behave_stream(const wchar_t *path, const wchar_t *mode) {
    if (!path || !mode || !on())
        return;
    char m[16];
    size_t n = 0;
    for (; mode[n] && n + 1 < sizeof m; ++n)
        m[n] = char(mode[n]);
    m[n] = 0;
    ErrnoSaver es;
    behavior::opening_stream(Text(path).get(), m);
}
void behave_start(const char *app, const char *line, const void *startup) {
    if (on())
        start_program(app, line, "CreateProcess()", startup);
}
void behave_start(const wchar_t *app, const wchar_t *line, const void *startup) {
    if (on()) {
        const Text a(app), l(line);
        start_program(a.get(), l.get(), "CreateProcess()", startup);
    }
}
void behave_command(const char *cmd, const char *how) {
    if (cmd && on()) {
        ErrnoSaver es;
        const Text t(cmd);
        behavior::command(t.get(), how);
        const Program p(t.get());
        behavior::process_start(p.s, "", how, nullptr);
    }
}
void behave_remote_thread(HANDLE process, const char *how) {
    if (on() && is_other_process(process)) {
        ErrnoSaver es;
        behavior::injected(how);
    }
}

namespace {

// ---- files ------------------------------------------------------------------------------------

#define SA LPSECURITY_ATTRIBUTES

decltype(&DeleteFileA) real_DeleteFileA;
BOOL WINAPI hk_DeleteFileA(LPCSTR p) {
    if (on()) {
        ErrnoSaver es;
        behavior::deleting(Text(p).get(), "DeleteFile()");
    }
    return real_DeleteFileA(p);
}
decltype(&DeleteFileW) real_DeleteFileW;
BOOL WINAPI hk_DeleteFileW(LPCWSTR p) {
    if (on()) {
        ErrnoSaver es;
        behavior::deleting(Text(p).get(), "DeleteFile()");
    }
    return real_DeleteFileW(p);
}

void moved(const Text &from, const Text &to, const char *how) {
    ErrnoSaver es;
    behavior::replacing(to.get(), how);
    behavior::renamed(from.get(), to.get());
}
decltype(&MoveFileA) real_MoveFileA;
BOOL WINAPI hk_MoveFileA(LPCSTR a, LPCSTR b) {
    if (on() && b)
        moved(Text(a), Text(b), "MoveFile()");
    return real_MoveFileA(a, b);
}
decltype(&MoveFileW) real_MoveFileW;
BOOL WINAPI hk_MoveFileW(LPCWSTR a, LPCWSTR b) {
    if (on() && b)
        moved(Text(a), Text(b), "MoveFile()");
    return real_MoveFileW(a, b);
}
decltype(&MoveFileExA) real_MoveFileExA;
BOOL WINAPI hk_MoveFileExA(LPCSTR a, LPCSTR b, DWORD f) {
    if (on() && b)
        moved(Text(a), Text(b), "MoveFileEx()");
    return real_MoveFileExA(a, b, f);
}
decltype(&MoveFileExW) real_MoveFileExW;
BOOL WINAPI hk_MoveFileExW(LPCWSTR a, LPCWSTR b, DWORD f) {
    if (on() && b)
        moved(Text(a), Text(b), "MoveFileEx()");
    return real_MoveFileExW(a, b, f);
}
decltype(&CopyFileA) real_CopyFileA;
BOOL WINAPI hk_CopyFileA(LPCSTR a, LPCSTR b, BOOL f) {
    if (on() && b) {
        ErrnoSaver es;
        behavior::replacing(Text(b).get(), "CopyFile()");
    }
    return real_CopyFileA(a, b, f);
}
decltype(&CopyFileW) real_CopyFileW;
BOOL WINAPI hk_CopyFileW(LPCWSTR a, LPCWSTR b, BOOL f) {
    if (on() && b) {
        ErrnoSaver es;
        behavior::replacing(Text(b).get(), "CopyFile()");
    }
    return real_CopyFileW(a, b, f);
}
int(__cdecl *real_rename)(const char *, const char *);
int __cdecl hk_rename(const char *a, const char *b) {
    if (on() && b)
        moved(Text(a), Text(b), "rename()");
    return real_rename(a, b);
}
int(__cdecl *real__wrename)(const wchar_t *, const wchar_t *);
int __cdecl hk__wrename(const wchar_t *a, const wchar_t *b) {
    if (on() && b)
        moved(Text(a), Text(b), "rename()");
    return real__wrename(a, b);
}
int(__cdecl *real_remove)(const char *);
int __cdecl hk_remove(const char *p) {
    if (on()) {
        ErrnoSaver es;
        behavior::deleting(Text(p).get(), "remove()");
    }
    return real_remove(p);
}

// ---- programs --------------------------------------------------------------------------------

decltype(&WinExec) real_WinExec;
UINT WINAPI hk_WinExec(LPCSTR cmd, UINT show) {
    behave_command(cmd, "WinExec()");
    return real_WinExec(cmd, show);
}

void shell_execute(const Text &verb, const Text &file, const Text &params, const char *how) {
    ErrnoSaver es;
    char line[1024];
    Buf b(line, sizeof line);
    b.line(file.get()).c(' ').line(params.get());
    behavior::process_start(file.get(), b.cstr(), how, nullptr);
    if (!strcmp(verb.get(), "runas"))
        behavior::elevation(file.get(), how);
}
decltype(&ShellExecuteA) real_ShellExecuteA;
HINSTANCE WINAPI hk_ShellExecuteA(HWND w, LPCSTR v, LPCSTR f, LPCSTR p, LPCSTR d, INT s) {
    if (on() && f)
        shell_execute(Text(v), Text(f), Text(p), "ShellExecute()");
    return real_ShellExecuteA(w, v, f, p, d, s);
}
decltype(&ShellExecuteW) real_ShellExecuteW;
HINSTANCE WINAPI hk_ShellExecuteW(HWND w, LPCWSTR v, LPCWSTR f, LPCWSTR p, LPCWSTR d, INT s) {
    if (on() && f)
        shell_execute(Text(v), Text(f), Text(p), "ShellExecute()");
    return real_ShellExecuteW(w, v, f, p, d, s);
}
decltype(&ShellExecuteExA) real_ShellExecuteExA;
BOOL WINAPI hk_ShellExecuteExA(SHELLEXECUTEINFOA *i) {
    if (on() && i && i->lpFile)
        shell_execute(Text(i->lpVerb), Text(i->lpFile), Text(i->lpParameters), "ShellExecuteEx()");
    return real_ShellExecuteExA(i);
}
decltype(&ShellExecuteExW) real_ShellExecuteExW;
BOOL WINAPI hk_ShellExecuteExW(SHELLEXECUTEINFOW *i) {
    if (on() && i && i->lpFile)
        shell_execute(Text(i->lpVerb), Text(i->lpFile), Text(i->lpParameters), "ShellExecuteEx()");
    return real_ShellExecuteExW(i);
}

// ---- the memory of other programs --------------------------------------------------------------

decltype(&WriteProcessMemory) real_WriteProcessMemory;
BOOL WINAPI hk_WriteProcessMemory(HANDLE h, LPVOID a, LPCVOID b, SIZE_T n, SIZE_T *w) {
    if (on() && is_other_process(h)) {
        ErrnoSaver es;
        behavior::injected("WriteProcessMemory()");
    }
    return real_WriteProcessMemory(h, a, b, n, w);
}
decltype(&ReadProcessMemory) real_ReadProcessMemory;
BOOL WINAPI hk_ReadProcessMemory(HANDLE h, LPCVOID a, LPVOID b, SIZE_T n, SIZE_T *r) {
    if (on() && is_other_process(h)) {
        ErrnoSaver es;
        behavior::read_other_process("ReadProcessMemory()");
    }
    return real_ReadProcessMemory(h, a, b, n, r);
}
decltype(&VirtualAllocEx) real_VirtualAllocEx;
LPVOID WINAPI hk_VirtualAllocEx(HANDLE h, LPVOID a, SIZE_T n, DWORD t, DWORD p) {
    if (on() && is_other_process(h)) {
        ErrnoSaver es;
        behavior::injected("VirtualAllocEx()");
    }
    return real_VirtualAllocEx(h, a, n, t, p);
}
decltype(&QueueUserAPC) real_QueueUserAPC;
DWORD WINAPI hk_QueueUserAPC(PAPCFUNC f, HANDLE t, ULONG_PTR d) {
    if (on() && t && GetProcessIdOfThread(t) != GetCurrentProcessId()) {
        ErrnoSaver es;
        behavior::injected("QueueUserAPC()");
    }
    return real_QueueUserAPC(f, t, d);
}
decltype(&SetThreadContext) real_SetThreadContext;
BOOL WINAPI hk_SetThreadContext(HANDLE t, const CONTEXT *c) {
    if (on() && t && GetProcessIdOfThread(t) != GetCurrentProcessId()) {
        ErrnoSaver es;
        behavior::injected("SetThreadContext()");
    }
    return real_SetThreadContext(t, c);
}
// ntdll: the same, a layer down (what a program does to skip the hooks of kernel32)
LONG(WINAPI *real_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
LONG WINAPI hk_NtWriteVirtualMemory(HANDLE h, PVOID a, PVOID b, ULONG n, PULONG w) {
    if (on() && is_other_process(h)) {
        ErrnoSaver es;
        behavior::injected("NtWriteVirtualMemory()");
    }
    return real_NtWriteVirtualMemory(h, a, b, n, w);
}
LONG(WINAPI *real_NtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG);
LONG WINAPI hk_NtReadVirtualMemory(HANDLE h, PVOID a, PVOID b, ULONG n, PULONG w) {
    if (on() && is_other_process(h)) {
        ErrnoSaver es;
        behavior::read_other_process("NtReadVirtualMemory()");
    }
    return real_NtReadVirtualMemory(h, a, b, n, w);
}
// dbghelp: a dump of another program's memory is how the log-in process is stolen from
BOOL(WINAPI *real_MiniDumpWriteDump)(HANDLE, DWORD, HANDLE, int, void *, void *, void *);
BOOL WINAPI hk_MiniDumpWriteDump(HANDLE h, DWORD pid, HANDLE f, int type, void *a, void *b, void *c) {
    if (on() && pid != GetCurrentProcessId()) {
        ErrnoSaver es;
        behavior::read_other_process("MiniDumpWriteDump()");
    }
    return real_MiniDumpWriteDump(h, pid, f, type, a, b, c);
}

// ---- hiding from analysis ----------------------------------------------------------------------

decltype(&IsDebuggerPresent) real_IsDebuggerPresent;
BOOL WINAPI hk_IsDebuggerPresent() {
    if (on()) {
        ErrnoSaver es;
        behavior::debugger_probe("IsDebuggerPresent()");
    }
    return real_IsDebuggerPresent();
}
decltype(&CheckRemoteDebuggerPresent) real_CheckRemoteDebuggerPresent;
BOOL WINAPI hk_CheckRemoteDebuggerPresent(HANDLE h, PBOOL b) {
    if (on()) {
        ErrnoSaver es;
        behavior::debugger_probe("CheckRemoteDebuggerPresent()");
    }
    return real_CheckRemoteDebuggerPresent(h, b);
}
LONG(WINAPI *real_NtSetInformationThread)(HANDLE, int, PVOID, ULONG);
LONG WINAPI hk_NtSetInformationThread(HANDLE h, int cls, PVOID p, ULONG n) {
    if (on() && cls == 0x11) { // ThreadHideFromDebugger
        ErrnoSaver es;
        behavior::debugger_probe("NtSetInformationThread(ThreadHideFromDebugger)");
    }
    return real_NtSetInformationThread(h, cls, p, n);
}

// ---- privileges and logs ----------------------------------------------------------------------

struct Priv {
    LUID luid;
    char name[32];
};
Priv g_privs[8];
size_t g_nprivs;
SpinLock g_privs_lock;

void note_privilege(const char *name, const LUID *l) {
    for (const char *w : {"SeDebugPrivilege", "SeTcbPrivilege", "SeLoadDriverPrivilege", "SeTakeOwnershipPrivilege",
                          "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "SeBackupPrivilege",
                          "SeRestorePrivilege"})
        if (!strcmp(name, w)) {
            LockGuard g(g_privs_lock);
            if (g_nprivs < 8) {
                g_privs[g_nprivs].luid = *l;
                strncpy(g_privs[g_nprivs].name, name, 31);
                ++g_nprivs;
            }
            return;
        }
}
decltype(&LookupPrivilegeValueA) real_LookupPrivilegeValueA;
BOOL WINAPI hk_LookupPrivilegeValueA(LPCSTR s, LPCSTR n, PLUID l) {
    BOOL ok = real_LookupPrivilegeValueA(s, n, l);
    if (ok && n && on())
        note_privilege(n, l);
    return ok;
}
decltype(&LookupPrivilegeValueW) real_LookupPrivilegeValueW;
BOOL WINAPI hk_LookupPrivilegeValueW(LPCWSTR s, LPCWSTR n, PLUID l) {
    BOOL ok = real_LookupPrivilegeValueW(s, n, l);
    if (ok && n && on()) {
        char a[40];
        int k = WideCharToMultiByte(CP_ACP, 0, n, -1, a, sizeof a - 1, nullptr, nullptr);
        a[k > 0 ? k - 1 : 0] = 0;
        note_privilege(a, l);
    }
    return ok;
}
decltype(&AdjustTokenPrivileges) real_AdjustTokenPrivileges;
BOOL WINAPI hk_AdjustTokenPrivileges(HANDLE t, BOOL all, PTOKEN_PRIVILEGES p, DWORD n, PTOKEN_PRIVILEGES o, PDWORD r) {
    if (on() && p) {
        for (DWORD i = 0; i < p->PrivilegeCount; ++i) {
            if (!(p->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
                continue;
            char name[32] = "";
            {
                LockGuard g(g_privs_lock);
                for (size_t k = 0; k < g_nprivs; ++k)
                    if (g_privs[k].luid.LowPart == p->Privileges[i].Luid.LowPart &&
                        g_privs[k].luid.HighPart == p->Privileges[i].Luid.HighPart) {
                        strcpy(name, g_privs[k].name);
                        break;
                    }
            }
            if (name[0]) {
                ErrnoSaver es;
                behavior::privilege_enabled(name);
            }
        }
    }
    return real_AdjustTokenPrivileges(t, all, p, n, o, r);
}
decltype(&ClearEventLogA) real_ClearEventLogA;
BOOL WINAPI hk_ClearEventLogA(HANDLE h, LPCSTR f) {
    if (on()) {
        ErrnoSaver es;
        behavior::event_log_cleared("ClearEventLog()");
    }
    return real_ClearEventLogA(h, f);
}
decltype(&ClearEventLogW) real_ClearEventLogW;
BOOL WINAPI hk_ClearEventLogW(HANDLE h, LPCWSTR f) {
    if (on()) {
        ErrnoSaver es;
        behavior::event_log_cleared("ClearEventLog()");
    }
    return real_ClearEventLogW(h, f);
}

// ---- the registry ---------------------------------------------------------------------------------

// Where an open key is, so a value written through the handle can be placed.
struct Key {
    uintptr_t h;
    char path[320];
};
constexpr size_t kKeys = 128;
Key g_keys[kKeys];
SpinLock g_keys_lock;

const char *root_name(HKEY k) {
    switch (uint32_t(uintptr_t(k))) { // the predefined keys are sign-extended 32-bit values
    case 0x80000000: return "hkcr";
    case 0x80000001: return "hkcu";
    case 0x80000002: return "hklm";
    case 0x80000003: return "hku";
    case 0x80000005: return "hkcc";
    }
    return nullptr;
}

// "hklm/software/microsoft/..." for a key and a subkey.
void key_path(HKEY k, const Text &sub, char *out, size_t cap) {
    Buf b(out, cap);
    if (const char *r = root_name(k))
        b.s(r);
    else {
        LockGuard g(g_keys_lock);
        for (const Key &e : g_keys)
            if (e.h == uintptr_t(k)) {
                b.line(e.path);
                break;
            }
    }
    if (sub.s[0])
        b.c('/').line(sub.get());
    b.cstr();
}

void remember_key(HKEY k, const char *path) {
    LockGuard g(g_keys_lock);
    Key *use = nullptr;
    for (Key &e : g_keys) {
        if (e.h == uintptr_t(k)) {
            use = &e;
            break;
        }
        if (!e.h && !use)
            use = &e;
    }
    if (use) {
        use->h = uintptr_t(k);
        strncpy(use->path, path, sizeof use->path - 1);
        use->path[sizeof use->path - 1] = 0;
    }
}

// (KEY_READ and KEY_WRITE share READ_CONTROL: ask for the rights that change something)
bool key_writes(REGSAM sam) {
    return sam & (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | WRITE_DAC | WRITE_OWNER);
}

// The attempt is what counts (the account database is refused to a program that is not
// an administrator, and is still being asked for); a key that opened is remembered.
void key_attempt(HKEY parent, const Text &sub, bool write, const char *how) {
    ErrnoSaver es;
    char path[400];
    key_path(parent, sub, path, sizeof path);
    behavior::registry(path, write, how);
}
void key_opened(HKEY parent, const Text &sub, HKEY child) {
    ErrnoSaver es;
    char path[400];
    key_path(parent, sub, path, sizeof path);
    remember_key(child, path);
}

decltype(&RegCreateKeyExA) real_RegCreateKeyExA;
LSTATUS WINAPI hk_RegCreateKeyExA(HKEY k, LPCSTR sub, DWORD r, LPSTR c, DWORD o, REGSAM sam, SA sa, PHKEY out, LPDWORD d) {
    if (on())
        key_attempt(k, Text(sub), true, "RegCreateKeyEx()");
    LSTATUS s = real_RegCreateKeyExA(k, sub, r, c, o, sam, sa, out, d);
    if (s == ERROR_SUCCESS && out && on())
        key_opened(k, Text(sub), *out);
    return s;
}
decltype(&RegCreateKeyExW) real_RegCreateKeyExW;
LSTATUS WINAPI hk_RegCreateKeyExW(HKEY k, LPCWSTR sub, DWORD r, LPWSTR c, DWORD o, REGSAM sam, SA sa, PHKEY out, LPDWORD d) {
    if (on())
        key_attempt(k, Text(sub), true, "RegCreateKeyEx()");
    LSTATUS s = real_RegCreateKeyExW(k, sub, r, c, o, sam, sa, out, d);
    if (s == ERROR_SUCCESS && out && on())
        key_opened(k, Text(sub), *out);
    return s;
}
decltype(&RegOpenKeyExA) real_RegOpenKeyExA;
LSTATUS WINAPI hk_RegOpenKeyExA(HKEY k, LPCSTR sub, DWORD o, REGSAM sam, PHKEY out) {
    if (on())
        key_attempt(k, Text(sub), key_writes(sam), "RegOpenKeyEx()");
    LSTATUS s = real_RegOpenKeyExA(k, sub, o, sam, out);
    if (s == ERROR_SUCCESS && out && on())
        key_opened(k, Text(sub), *out);
    return s;
}
decltype(&RegOpenKeyExW) real_RegOpenKeyExW;
LSTATUS WINAPI hk_RegOpenKeyExW(HKEY k, LPCWSTR sub, DWORD o, REGSAM sam, PHKEY out) {
    if (on())
        key_attempt(k, Text(sub), key_writes(sam), "RegOpenKeyEx()");
    LSTATUS s = real_RegOpenKeyExW(k, sub, o, sam, out);
    if (s == ERROR_SUCCESS && out && on())
        key_opened(k, Text(sub), *out);
    return s;
}
void value_written(HKEY k, const Text &sub, const Text &name, const char *how) {
    ErrnoSaver es;
    char path[400];
    key_path(k, sub, path, sizeof path);
    if (name.s[0]) {
        const size_t n = strlen(path);
        snprintf(path + n, sizeof path - n, "/%s", name.get());
    }
    behavior::registry(path, true, how);
}
decltype(&RegSetValueExA) real_RegSetValueExA;
LSTATUS WINAPI hk_RegSetValueExA(HKEY k, LPCSTR n, DWORD r, DWORD t, const BYTE *d, DWORD cb) {
    if (on())
        value_written(k, Text(""), Text(n), "RegSetValueEx()");
    return real_RegSetValueExA(k, n, r, t, d, cb);
}
decltype(&RegSetValueExW) real_RegSetValueExW;
LSTATUS WINAPI hk_RegSetValueExW(HKEY k, LPCWSTR n, DWORD r, DWORD t, const BYTE *d, DWORD cb) {
    if (on())
        value_written(k, Text(""), Text(n), "RegSetValueEx()");
    return real_RegSetValueExW(k, n, r, t, d, cb);
}
decltype(&RegSetKeyValueA) real_RegSetKeyValueA;
LSTATUS WINAPI hk_RegSetKeyValueA(HKEY k, LPCSTR sub, LPCSTR n, DWORD t, LPCVOID d, DWORD cb) {
    if (on())
        value_written(k, Text(sub), Text(n), "RegSetKeyValue()");
    return real_RegSetKeyValueA(k, sub, n, t, d, cb);
}
decltype(&RegSetKeyValueW) real_RegSetKeyValueW;
LSTATUS WINAPI hk_RegSetKeyValueW(HKEY k, LPCWSTR sub, LPCWSTR n, DWORD t, LPCVOID d, DWORD cb) {
    if (on())
        value_written(k, Text(sub), Text(n), "RegSetKeyValue()");
    return real_RegSetKeyValueW(k, sub, n, t, d, cb);
}
decltype(&RegCloseKey) real_RegCloseKey;
LSTATUS WINAPI hk_RegCloseKey(HKEY k) {
    if (on()) {
        LockGuard g(g_keys_lock);
        for (Key &e : g_keys)
            if (e.h == uintptr_t(k))
                e.h = 0;
    }
    return real_RegCloseKey(k);
}

// ---- fetching a file --------------------------------------------------------------------------------

decltype(&URLDownloadToFileA) real_URLDownloadToFileA;
HRESULT WINAPI hk_URLDownloadToFileA(LPUNKNOWN c, LPCSTR url, LPCSTR f, DWORD r, LPBINDSTATUSCALLBACK cb) {
    if (on())
        behavior::downloads(Text(url).get(), Text(f).get(), "URLDownloadToFile()");
    return real_URLDownloadToFileA(c, url, f, r, cb);
}
decltype(&URLDownloadToFileW) real_URLDownloadToFileW;
HRESULT WINAPI hk_URLDownloadToFileW(LPUNKNOWN c, LPCWSTR url, LPCWSTR f, DWORD r, LPBINDSTATUSCALLBACK cb) {
    if (on())
        behavior::downloads(Text(url).get(), Text(f).get(), "URLDownloadToFile()");
    return real_URLDownloadToFileW(c, url, f, r, cb);
}

#define HK(NAME) {#NAME, reinterpret_cast<void *>(hk_##NAME), (void **)&real_##NAME, false}
const Hook g_hooks[] = {
    HK(DeleteFileA), HK(DeleteFileW), HK(MoveFileA), HK(MoveFileW), HK(MoveFileExA), HK(MoveFileExW),
    HK(CopyFileA), HK(CopyFileW), HK(rename), HK(_wrename), HK(remove),
    HK(WinExec), HK(ShellExecuteA), HK(ShellExecuteW), HK(ShellExecuteExA), HK(ShellExecuteExW),
    HK(WriteProcessMemory), HK(ReadProcessMemory), HK(VirtualAllocEx), HK(QueueUserAPC), HK(SetThreadContext),
    HK(NtWriteVirtualMemory), HK(NtReadVirtualMemory), HK(MiniDumpWriteDump),
    HK(IsDebuggerPresent), HK(CheckRemoteDebuggerPresent), HK(NtSetInformationThread),
    HK(LookupPrivilegeValueA), HK(LookupPrivilegeValueW), HK(AdjustTokenPrivileges),
    HK(ClearEventLogA), HK(ClearEventLogW),
    HK(RegCreateKeyExA), HK(RegCreateKeyExW), HK(RegOpenKeyExA), HK(RegOpenKeyExW), HK(RegSetValueExA),
    HK(RegSetValueExW), HK(RegSetKeyValueA), HK(RegSetKeyValueW), HK(RegCloseKey),
    HK(URLDownloadToFileA), HK(URLDownloadToFileW),
};
#undef HK

} // namespace

const Hook *behavior_hooks(size_t *n) {
    *n = sizeof g_hooks / sizeof g_hooks[0];
    return g_hooks;
}

void behavior_on() { g_on = true; }

} // namespace lc::win
