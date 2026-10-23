#pragma once
// The Windows side of the runtime: finding modules, patching their import
// tables so calls to the heap and the other watched functions come to us, and
// a few views of the process the shared code asks for (stacks, modules).
#include "rt.h"

#include <windows.h>

namespace lc::win {

// GetProcAddress with the function's own type.
template <class F> F proc_address(HMODULE m, const char *name) {
    return reinterpret_cast<F>(reinterpret_cast<void *>(GetProcAddress(m, name)));
}

// Every module the loader lists, with its UTF-8 path. Allocation free.
using ModuleFn = void (*)(uintptr_t base, size_t size, const char *path, void *ctx);
void for_each_module(ModuleFn fn, void *ctx);
// The module `addr` lies in: its path in `path`. False if none.
bool module_of(uintptr_t addr, char *path, size_t cap);
void exe_path(char *out, size_t cap);
void self_range(uintptr_t *lo, uintptr_t *hi);
HMODULE self_module();

// Return addresses of the calling thread, innermost first.
uint32_t capture_frames(uintptr_t *out, uint32_t max);
// A module that belongs to Windows or its C runtime rather than the program.
bool is_system_pc(uintptr_t pc);
// The C runtime itself (ucrtbase, msvcrt): the allocator the program's calls go through.
bool is_crt_pc(uintptr_t pc);
// Was the last stack captured on this thread made by Windows' own code (the first caller
// outside the C runtime is a Windows module)? Its blocks belong to Windows.
bool captured_from_system();
// Drops the leading and trailing frames inside such modules, keeping at least one.
uint32_t trim_system(uintptr_t *frames, uint32_t n);

struct Hook {
    const char *name;   // the imported function
    void *replacement;  // what the import table gets instead
    void **original;    // the first address found in a patched slot, if wanted
    bool crt;           // also patch the C runtime DLLs (they allocate on the program's behalf)
};

// Patches every loaded module (not Windows' own, and not this library) so the
// functions in `hooks` come to the replacements. Safe to call again for the
// modules loaded since.
void install_hooks(const Hook *hooks, size_t n);
void patch_new_modules();

// mem_win.cpp: the heap hooks. memory_start finds the real heap functions
// (before anything is patched), memory_on starts judging what passes through.
const Hook *memory_hooks(size_t *n);
void memory_start();
void memory_on();

// locks_win.cpp: critical sections, SRW locks, pthread locks.
const Hook *lock_hooks(size_t *n);
void locks_on();
// A mutex handle is a lock: taken by waiting for it, released by ReleaseMutex.
void lock_note_mutex(HANDLE h);
void lock_forget_mutex(HANDLE h);
void lock_mutex_waited(HANDLE h, DWORD result, uintptr_t pc);
void lock_mutex_released(HANDLE h);

// net_win.cpp: sockets and names.
const Hook *net_hooks(size_t *n);
void net_on();

// behavior_win.cpp: what the program does to the machine (the trojan checks).
const Hook *behavior_hooks(size_t *n);
void behavior_on();
// The hooks of res_win.cpp, which own these calls, tell it what is about to happen.
void behave_open(const char *path, DWORD access, DWORD disposition);
void behave_open(const wchar_t *path, DWORD access, DWORD disposition);
void behave_stream(const char *path, const char *mode);
void behave_stream(const wchar_t *path, const wchar_t *mode);
void behave_start(const char *app, const char *line, const void *startup);
void behave_start(const wchar_t *app, const wchar_t *line, const void *startup);
void behave_command(const char *cmd, const char *how);
void behave_remote_thread(HANDLE process, const char *how);

// res_win.cpp: handles, C streams, processes started from here.
const Hook *resource_hooks(size_t *n);
void resources_on();

} // namespace lc::win
