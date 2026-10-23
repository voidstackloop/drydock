// Handles on Windows: what the program opens (files, pipes, events, mutexes,
// threads, processes, directory searches, C streams) and never closes, what it
// closes twice, and what it uses after closing. interpose_io.cpp is the Linux
// side; the table is resources.cpp's.
#include "resources.h"
#include "win_hooks.h"

#include "init.h"
#include "win_inject.h"

#include <process.h>
#include <stdio.h>
#include <stdlib.h>

namespace lc::win {
namespace {

using res::Kind;

bool g_on;

bool on() { return g_on && !tl_in_hook; }

bool valid(HANDLE h) { return h && h != INVALID_HANDLE_VALUE; }

// Tells the table, keeping the program's last error as it was.
void note(Kind k, uint64_t h, const char *how) {
    if (!on())
        return;
    HookGuard hg;
    ErrnoSaver es;
    res::opened(k, h, how);
}

void note_closed(Kind k, uint64_t h) {
    HookGuard hg;
    ErrnoSaver es;
    res::closed(k, h);
}

// A call failed with ERROR_INVALID_HANDLE: use after close, if we saw it closed.
void bad_handle(HANDLE h, const char *how) {
    if (!on() || GetLastError() != ERROR_INVALID_HANDLE)
        return;
    HookGuard hg;
    ErrnoSaver es;
    res::used_closed(uint64_t(reinterpret_cast<uintptr_t>(h)), how);
}

void inherited(const char *how) {
    if (!on())
        return;
    HookGuard hg;
    ErrnoSaver es;
    res::check_inherited(how);
}

// ---- a call that returns a new handle ---------------------------------------------------

#define RET_HANDLE(NAME, PARAMS, ARGS, HOW, KIND)       \
    decltype(&NAME) real_##NAME;                        \
    HANDLE WINAPI hk_##NAME PARAMS {                    \
        HANDLE h = real_##NAME ARGS;                    \
        if (valid(h)) {                                 \
            note(KIND, uint64_t(uintptr_t(h)), HOW);    \
            if (HOW[6] == 'M') /* "Create""Mutex()" */  \
                lock_note_mutex(h);                     \
        }                                               \
        return h;                                       \
    }

#define SA LPSECURITY_ATTRIBUTES

decltype(&CreateFileA) real_CreateFileA;
HANDLE WINAPI hk_CreateFileA(LPCSTR n, DWORD a, DWORD s, SA sa, DWORD d, DWORD f, HANDLE t) {
    behave_open(n, a, d);
    HANDLE h = real_CreateFileA(n, a, s, sa, d, f, t);
    if (valid(h))
        note(Kind::Fd, uint64_t(uintptr_t(h)), "CreateFile()");
    return h;
}
decltype(&CreateFileW) real_CreateFileW;
HANDLE WINAPI hk_CreateFileW(LPCWSTR n, DWORD a, DWORD s, SA sa, DWORD d, DWORD f, HANDLE t) {
    behave_open(n, a, d);
    HANDLE h = real_CreateFileW(n, a, s, sa, d, f, t);
    if (valid(h))
        note(Kind::Fd, uint64_t(uintptr_t(h)), "CreateFile()");
    return h;
}
RET_HANDLE(CreateNamedPipeA, (LPCSTR n, DWORD o, DWORD m, DWORD x, DWORD ob, DWORD ib, DWORD t, SA sa),
           (n, o, m, x, ob, ib, t, sa), "CreateNamedPipe()", Kind::Fd)
RET_HANDLE(CreateNamedPipeW, (LPCWSTR n, DWORD o, DWORD m, DWORD x, DWORD ob, DWORD ib, DWORD t, SA sa),
           (n, o, m, x, ob, ib, t, sa), "CreateNamedPipe()", Kind::Fd)
RET_HANDLE(CreateEventA, (SA sa, BOOL m, BOOL i, LPCSTR n), (sa, m, i, n), "CreateEvent()", Kind::Fd)
RET_HANDLE(CreateEventW, (SA sa, BOOL m, BOOL i, LPCWSTR n), (sa, m, i, n), "CreateEvent()", Kind::Fd)
RET_HANDLE(CreateEventExA, (SA sa, LPCSTR n, DWORD f, DWORD a), (sa, n, f, a), "CreateEventEx()", Kind::Fd)
RET_HANDLE(CreateEventExW, (SA sa, LPCWSTR n, DWORD f, DWORD a), (sa, n, f, a), "CreateEventEx()", Kind::Fd)
RET_HANDLE(CreateMutexA, (SA sa, BOOL i, LPCSTR n), (sa, i, n), "CreateMutex()", Kind::Fd)
RET_HANDLE(CreateMutexW, (SA sa, BOOL i, LPCWSTR n), (sa, i, n), "CreateMutex()", Kind::Fd)
RET_HANDLE(CreateSemaphoreA, (SA sa, LONG i, LONG m, LPCSTR n), (sa, i, m, n), "CreateSemaphore()", Kind::Fd)
RET_HANDLE(CreateSemaphoreW, (SA sa, LONG i, LONG m, LPCWSTR n), (sa, i, m, n), "CreateSemaphore()", Kind::Fd)
RET_HANDLE(CreateWaitableTimerA, (SA sa, BOOL m, LPCSTR n), (sa, m, n), "CreateWaitableTimer()", Kind::Fd)
RET_HANDLE(CreateWaitableTimerW, (SA sa, BOOL m, LPCWSTR n), (sa, m, n), "CreateWaitableTimer()", Kind::Fd)
RET_HANDLE(CreateFileMappingA, (HANDLE f, SA sa, DWORD p, DWORD hi, DWORD lo, LPCSTR n), (f, sa, p, hi, lo, n),
           "CreateFileMapping()", Kind::Fd)
RET_HANDLE(CreateFileMappingW, (HANDLE f, SA sa, DWORD p, DWORD hi, DWORD lo, LPCWSTR n), (f, sa, p, hi, lo, n),
           "CreateFileMapping()", Kind::Fd)
RET_HANDLE(OpenProcess, (DWORD a, BOOL i, DWORD pid), (a, i, pid), "OpenProcess()", Kind::Process)
RET_HANDLE(OpenThread, (DWORD a, BOOL i, DWORD tid), (a, i, tid), "OpenThread()", Kind::Thread)
RET_HANDLE(CreateThread, (SA sa, SIZE_T st, LPTHREAD_START_ROUTINE f, LPVOID p, DWORD fl, LPDWORD id),
           (sa, st, f, p, fl, id), "CreateThread()", Kind::Thread)
decltype(&CreateRemoteThread) real_CreateRemoteThread;
HANDLE WINAPI hk_CreateRemoteThread(HANDLE pr, SA sa, SIZE_T st, LPTHREAD_START_ROUTINE f, LPVOID p, DWORD fl,
                                    LPDWORD id) {
    behave_remote_thread(pr, "CreateRemoteThread()");
    HANDLE h = real_CreateRemoteThread(pr, sa, st, f, p, fl, id);
    if (valid(h))
        note(Kind::Thread, uint64_t(uintptr_t(h)), "CreateRemoteThread()");
    return h;
}
RET_HANDLE(FindFirstFileA, (LPCSTR n, LPWIN32_FIND_DATAA d), (n, d), "FindFirstFile()", Kind::Dir)
RET_HANDLE(FindFirstFileW, (LPCWSTR n, LPWIN32_FIND_DATAW d), (n, d), "FindFirstFile()", Kind::Dir)
RET_HANDLE(FindFirstFileExA, (LPCSTR n, FINDEX_INFO_LEVELS l, LPVOID d, FINDEX_SEARCH_OPS o, LPVOID f, DWORD fl),
           (n, l, d, o, f, fl), "FindFirstFileEx()", Kind::Dir)
RET_HANDLE(FindFirstFileExW, (LPCWSTR n, FINDEX_INFO_LEVELS l, LPVOID d, FINDEX_SEARCH_OPS o, LPVOID f, DWORD fl),
           (n, l, d, o, f, fl), "FindFirstFileEx()", Kind::Dir)

uintptr_t(__cdecl *real__beginthreadex)(void *, unsigned, unsigned(__stdcall *)(void *), void *, unsigned, unsigned *);
uintptr_t __cdecl hk__beginthreadex(void *sa, unsigned st, unsigned(__stdcall *f)(void *), void *p, unsigned fl,
                                    unsigned *id) {
    uintptr_t h = real__beginthreadex(sa, st, f, p, fl, id);
    if (h && h != uintptr_t(-1))
        note(Kind::Thread, h, "_beginthreadex()");
    return h;
}

decltype(&CreatePipe) real_CreatePipe;
BOOL WINAPI hk_CreatePipe(PHANDLE r, PHANDLE w, SA sa, DWORD n) {
    BOOL ok = real_CreatePipe(r, w, sa, n);
    if (ok) {
        note(Kind::Fd, uint64_t(uintptr_t(*r)), "CreatePipe()");
        note(Kind::Fd, uint64_t(uintptr_t(*w)), "CreatePipe()");
    }
    return ok;
}

decltype(&DuplicateHandle) real_DuplicateHandle;
BOOL WINAPI hk_DuplicateHandle(HANDLE sp, HANDLE sh, HANDLE dp, LPHANDLE out, DWORD a, BOOL i, DWORD o) {
    const bool mine = on() && dp && (dp == GetCurrentProcess() || GetProcessId(dp) == GetCurrentProcessId());
    Kind k = Kind::Fd;
    if (mine) {
        HookGuard hg;
        ErrnoSaver es;
        k = res::kind_of(uint64_t(uintptr_t(sh)));
    }
    BOOL ok = real_DuplicateHandle(sp, sh, dp, out, a, i, o);
    if (ok && mine && out && *out)
        note(k, uint64_t(uintptr_t(*out)), "DuplicateHandle()");
    if (ok && (o & DUPLICATE_CLOSE_SOURCE) && on() &&
        (sp == GetCurrentProcess() || GetProcessId(sp) == GetCurrentProcessId())) {
        HookGuard hg;
        ErrnoSaver es;
        res::closed(res::kind_of(uint64_t(uintptr_t(sh))), uint64_t(uintptr_t(sh)));
    }
    return ok;
}

// ---- closing --------------------------------------------------------------------------------

decltype(&CloseHandle) real_CloseHandle;
BOOL WINAPI hk_CloseHandle(HANDLE h) {
    if (!on() || !valid(h))
        return real_CloseHandle(h);
    const uint64_t v = uint64_t(uintptr_t(h));
    Kind k;
    {
        HookGuard hg;
        ErrnoSaver es;
        k = res::kind_of(v);
    }
    BOOL ok = real_CloseHandle(h);
    const DWORD e = GetLastError();
    if (ok)
        lock_forget_mutex(h);
    {
        HookGuard hg;
        if (ok)
            res::closed(k, v);
        else if (e == ERROR_INVALID_HANDLE)
            res::close_failed(v, "CloseHandle()");
    }
    SetLastError(e);
    return ok;
}

decltype(&FindClose) real_FindClose;
BOOL WINAPI hk_FindClose(HANDLE h) {
    if (!on() || !valid(h))
        return real_FindClose(h);
    BOOL ok = real_FindClose(h);
    const DWORD e = GetLastError();
    {
        HookGuard hg;
        if (ok)
            res::closed(Kind::Dir, uint64_t(uintptr_t(h)));
        else if (e == ERROR_INVALID_HANDLE)
            res::close_failed(uint64_t(uintptr_t(h)), "FindClose()");
    }
    SetLastError(e);
    return ok;
}

// ---- C streams ---------------------------------------------------------------------------------

FILE *(__cdecl *real_fopen)(const char *, const char *);
FILE *__cdecl hk_fopen(const char *p, const char *m) {
    behave_stream(p, m);
    FILE *f = real_fopen(p, m);
    if (f)
        note(Kind::File, uint64_t(uintptr_t(f)), "fopen()");
    return f;
}
FILE *(__cdecl *real__wfopen)(const wchar_t *, const wchar_t *);
FILE *__cdecl hk__wfopen(const wchar_t *p, const wchar_t *m) {
    behave_stream(p, m);
    FILE *f = real__wfopen(p, m);
    if (f)
        note(Kind::File, uint64_t(uintptr_t(f)), "_wfopen()");
    return f;
}
FILE *(__cdecl *real__fsopen)(const char *, const char *, int);
FILE *__cdecl hk__fsopen(const char *p, const char *m, int sh) {
    behave_stream(p, m);
    FILE *f = real__fsopen(p, m, sh);
    if (f)
        note(Kind::File, uint64_t(uintptr_t(f)), "_fsopen()");
    return f;
}
errno_t(__cdecl *real_fopen_s)(FILE **, const char *, const char *);
errno_t __cdecl hk_fopen_s(FILE **out, const char *p, const char *m) {
    behave_stream(p, m);
    errno_t e = real_fopen_s(out, p, m);
    if (!e && out && *out)
        note(Kind::File, uint64_t(uintptr_t(*out)), "fopen_s()");
    return e;
}
FILE *(__cdecl *real_tmpfile)();
FILE *__cdecl hk_tmpfile() {
    FILE *f = real_tmpfile();
    if (f)
        note(Kind::File, uint64_t(uintptr_t(f)), "tmpfile()");
    return f;
}
FILE *(__cdecl *real__popen)(const char *, const char *);
FILE *__cdecl hk__popen(const char *c, const char *m) {
    behave_command(c, "_popen()");
    inherited("_popen()");
    FILE *f = real__popen(c, m);
    if (f)
        note(Kind::Pipe, uint64_t(uintptr_t(f)), "_popen()");
    return f;
}

// freopen closes the stream it is given and opens the file again as the same
// stream; if the reopen fails the stream is gone.
FILE *(__cdecl *real_freopen)(const char *, const char *, FILE *);
FILE *__cdecl hk_freopen(const char *p, const char *m, FILE *s) {
    behave_stream(p, m);
    FILE *f = real_freopen(p, m, s);
    if (on()) {
        HookGuard hg;
        ErrnoSaver es;
        if (f)
            res::opened(Kind::File, uint64_t(uintptr_t(f)), "freopen()");
        else
            res::forget(Kind::File, uint64_t(uintptr_t(s)));
    }
    return f;
}

int(__cdecl *real_fclose)(FILE *);
int __cdecl hk_fclose(FILE *f) {
    if (!on() || !f)
        return real_fclose(f);
    bool go;
    {
        HookGuard hg;
        ErrnoSaver es;
        go = res::closing(Kind::File, uint64_t(uintptr_t(f)), "fclose()");
    }
    if (!go) // already closed: the report is made, and the stream is not touched again
        return EOF;
    int r = real_fclose(f);
    HookGuard hg;
    ErrnoSaver es;
    res::closed(Kind::File, uint64_t(uintptr_t(f)));
    return r;
}
int(__cdecl *real__pclose)(FILE *);
int __cdecl hk__pclose(FILE *f) {
    if (!on() || !f)
        return real__pclose(f);
    bool go;
    {
        HookGuard hg;
        ErrnoSaver es;
        go = res::closing(Kind::Pipe, uint64_t(uintptr_t(f)), "_pclose()");
    }
    if (!go)
        return -1;
    int r = real__pclose(f);
    HookGuard hg;
    ErrnoSaver es;
    res::closed(Kind::Pipe, uint64_t(uintptr_t(f)));
    return r;
}
int(__cdecl *real__fcloseall)();
int __cdecl hk__fcloseall() {
    if (on()) {
        HookGuard hg;
        ErrnoSaver es;
        res::streams_closed();
    }
    return real__fcloseall();
}

// A stream used after fclose: reported, and the call goes on (the C runtime
// answers an error for a closed stream, or the slot has been reused).
void stream_used(FILE *f, const char *how) {
    if (!on() || !f)
        return;
    HookGuard hg;
    ErrnoSaver es;
    res::used_stream(uint64_t(uintptr_t(f)), how);
}

#define USE_STREAM(NAME, RET, PARAMS, ARGS, STREAM)  \
    RET(__cdecl *real_##NAME) PARAMS;               \
    RET __cdecl hk_##NAME PARAMS {                  \
        stream_used(STREAM, #NAME "()");            \
        return real_##NAME ARGS;                    \
    }

USE_STREAM(fread, size_t, (void *b, size_t s, size_t n, FILE *f), (b, s, n, f), f)
USE_STREAM(fwrite, size_t, (const void *b, size_t s, size_t n, FILE *f), (b, s, n, f), f)
USE_STREAM(fgets, char *, (char *b, int n, FILE *f), (b, n, f), f)
USE_STREAM(fputs, int, (const char *b, FILE *f), (b, f), f)
USE_STREAM(fgetc, int, (FILE * f), (f), f)
USE_STREAM(fputc, int, (int c, FILE *f), (c, f), f)
USE_STREAM(getc, int, (FILE * f), (f), f)
USE_STREAM(putc, int, (int c, FILE *f), (c, f), f)
USE_STREAM(ungetc, int, (int c, FILE *f), (c, f), f)
USE_STREAM(fflush, int, (FILE * f), (f), f)
USE_STREAM(fseek, int, (FILE * f, long o, int w), (f, o, w), f)
USE_STREAM(ftell, long, (FILE * f), (f), f)
USE_STREAM(rewind, void, (FILE * f), (f), f)

// ---- a program started from here ----------------------------------------------------------------

// --trace-children: the program is started suspended, made to load this library first, and
// let go (unless the caller wanted it suspended). A 32-bit program cannot take it; it runs
// untraced.
void follow_child(PROCESS_INFORMATION *pi, bool resume) {
    if (!pi)
        return;
    wchar_t dll[MAX_PATH + 1];
    DWORD n = GetModuleFileNameW(self_module(), dll, MAX_PATH);
    char why[128];
    BOOL wow = FALSE;
    if (n && n < MAX_PATH && IsWow64Process(pi->hProcess, &wow) && !wow)
        lcinject::load_dll_first(pi->hProcess, pi->hThread, dll, why, sizeof why);
    if (resume)
        ResumeThread(pi->hThread);
}

decltype(&CreateProcessA) real_CreateProcessA;
BOOL WINAPI hk_CreateProcessA(LPCSTR a, LPSTR c, SA pa, SA ta, BOOL inh, DWORD fl, LPVOID e, LPCSTR d,
                              LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi) {
    behave_start(a, c, si);
    if (inh)
        inherited("CreateProcess()");
    const bool follow = on() && g_cfg.trace_children && pi && !(fl & CREATE_SUSPENDED);
    BOOL ok = real_CreateProcessA(a, c, pa, ta, inh, follow ? fl | CREATE_SUSPENDED : fl, e, d, si, pi);
    if (ok && (follow || (on() && g_cfg.trace_children && pi)))
        follow_child(pi, follow);
    if (ok && pi) {
        note(Kind::Process, uint64_t(uintptr_t(pi->hProcess)), "CreateProcess()");
        note(Kind::Thread, uint64_t(uintptr_t(pi->hThread)), "CreateProcess()");
    }
    return ok;
}
decltype(&CreateProcessW) real_CreateProcessW;
BOOL WINAPI hk_CreateProcessW(LPCWSTR a, LPWSTR c, SA pa, SA ta, BOOL inh, DWORD fl, LPVOID e, LPCWSTR d,
                              LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    behave_start(a, c, si);
    if (inh)
        inherited("CreateProcess()");
    const bool follow = on() && g_cfg.trace_children && pi && !(fl & CREATE_SUSPENDED);
    BOOL ok = real_CreateProcessW(a, c, pa, ta, inh, follow ? fl | CREATE_SUSPENDED : fl, e, d, si, pi);
    if (ok && (follow || (on() && g_cfg.trace_children && pi)))
        follow_child(pi, follow);
    if (ok && pi) {
        note(Kind::Process, uint64_t(uintptr_t(pi->hProcess)), "CreateProcess()");
        note(Kind::Thread, uint64_t(uintptr_t(pi->hThread)), "CreateProcess()");
    }
    return ok;
}
int(__cdecl *real_system)(const char *);
int __cdecl hk_system(const char *c) {
    behave_command(c, "system()");
    if (c)
        inherited("system()");
    return real_system(c);
}

// ---- a handle used after it was closed ------------------------------------------------------------

#define USE_HANDLE(NAME, RET, PARAMS, ARGS, BAD)       \
    decltype(&NAME) real_##NAME;                       \
    RET WINAPI hk_##NAME PARAMS {                      \
        RET r = real_##NAME ARGS;                      \
        if (BAD)                                       \
            bad_handle(h, #NAME "()");                 \
        return r;                                      \
    }

USE_HANDLE(ReadFile, BOOL, (HANDLE h, LPVOID b, DWORD n, LPDWORD g, LPOVERLAPPED o), (h, b, n, g, o), !r)
USE_HANDLE(WriteFile, BOOL, (HANDLE h, LPCVOID b, DWORD n, LPDWORD g, LPOVERLAPPED o), (h, b, n, g, o), !r)
USE_HANDLE(FlushFileBuffers, BOOL, (HANDLE h), (h), !r)
USE_HANDLE(SetFilePointerEx, BOOL, (HANDLE h, LARGE_INTEGER d, PLARGE_INTEGER n, DWORD m), (h, d, n, m), !r)
USE_HANDLE(GetFileSizeEx, BOOL, (HANDLE h, PLARGE_INTEGER s), (h, s), !r)
USE_HANDLE(WaitForSingleObject, DWORD, (HANDLE h, DWORD ms), (h, ms),
           (lock_mutex_waited(h, r, uintptr_t(__builtin_return_address(0))), r == WAIT_FAILED))
USE_HANDLE(WaitForSingleObjectEx, DWORD, (HANDLE h, DWORD ms, BOOL a), (h, ms, a),
           (lock_mutex_waited(h, r, uintptr_t(__builtin_return_address(0))), r == WAIT_FAILED))
USE_HANDLE(SetEvent, BOOL, (HANDLE h), (h), !r)
USE_HANDLE(ResetEvent, BOOL, (HANDLE h), (h), !r)
USE_HANDLE(ReleaseMutex, BOOL, (HANDLE h), (h), (r && (lock_mutex_released(h), false)) || !r)
USE_HANDLE(GetExitCodeProcess, BOOL, (HANDLE h, LPDWORD c), (h, c), !r)
USE_HANDLE(GetExitCodeThread, BOOL, (HANDLE h, LPDWORD c), (h, c), !r)

#define HK(NAME) {#NAME, reinterpret_cast<void *>(hk_##NAME), (void **)&real_##NAME, false}
const Hook g_hooks[] = {
    HK(CreateFileA), HK(CreateFileW), HK(CreateNamedPipeA), HK(CreateNamedPipeW), HK(CreateEventA),
    HK(CreateEventW), HK(CreateEventExA), HK(CreateEventExW), HK(CreateMutexA), HK(CreateMutexW),
    HK(CreateSemaphoreA), HK(CreateSemaphoreW), HK(CreateWaitableTimerA), HK(CreateWaitableTimerW),
    HK(CreateFileMappingA), HK(CreateFileMappingW), HK(OpenProcess), HK(OpenThread), HK(CreateThread),
    HK(CreateRemoteThread), HK(FindFirstFileA), HK(FindFirstFileW), HK(FindFirstFileExA), HK(FindFirstFileExW),
    HK(_beginthreadex), HK(CreatePipe), HK(DuplicateHandle), HK(CloseHandle), HK(FindClose),
    HK(fopen), HK(_wfopen), HK(_fsopen), HK(fopen_s), HK(tmpfile), HK(_popen), HK(freopen), HK(fclose),
    HK(_pclose), HK(_fcloseall), HK(fread), HK(fwrite), HK(fgets), HK(fputs), HK(fgetc), HK(fputc), HK(getc),
    HK(putc), HK(ungetc), HK(fflush), HK(fseek), HK(ftell), HK(rewind),
    HK(CreateProcessA), HK(CreateProcessW), HK(system),
    HK(ReadFile), HK(WriteFile), HK(FlushFileBuffers), HK(SetFilePointerEx), HK(GetFileSizeEx),
    HK(WaitForSingleObject), HK(WaitForSingleObjectEx), HK(SetEvent), HK(ResetEvent), HK(ReleaseMutex),
    HK(GetExitCodeProcess), HK(GetExitCodeThread),
};
#undef HK

} // namespace

const Hook *resource_hooks(size_t *n) {
    *n = sizeof g_hooks / sizeof g_hooks[0];
    return g_hooks;
}

void resources_on() { g_on = true; }

} // namespace lc::win
