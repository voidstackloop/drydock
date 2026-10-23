// Start-up and shut-down of the runtime on Windows (init.cpp is the Linux side).
// The launcher makes the target load this DLL before its entry point runs; here
// the heap hooks go in, and the exit paths of the program are watched so the
// leak scan runs once the program is done with its memory.
#include "behavior.h"
#include "blocks.h"
#include "guard.h"
#include "heap.h"
#include "init.h"
#include "leakscan.h"
#include "locks.h"
#include "report.h"
#include "resources.h"
#include "rt.h"
#include "stacks.h"
#include "threads.h"
#include "win_hooks.h"

#include <cstring>

namespace lc {
namespace {

uint32_t g_scan_done;
uint32_t g_finish_done;

bool reporting() { return g_cfg.active && g_cfg.report_enabled; }

// Called once the program is finished with its heap: main returned or exit
// was called. Runs before atexit handlers, like LeakSanitizer. stack_lo is an
// address in the hook frame that handed control to us; everything below it is
// either dead or the runtime's own.
LC_NOINLINE void end_of_program_scan(uintptr_t stack_lo) {
    if (!reporting() || __atomic_exchange_n(&g_scan_done, 1u, __ATOMIC_ACQ_REL))
        return;
    HookGuard hg;
    ErrnoSaver es;
    blocks::lock_all();
    heap_verify_all_locked();
    if (g_cfg.leak_check)
        leakscan::run_locked(stack_lo);
    blocks::unlock_all();
}

void finish_report() {
    if (!reporting() || __atomic_exchange_n(&g_finish_done, 1u, __ATOMIC_ACQ_REL))
        return;
    locks::thread_exiting(0);
    HookGuard hg;
    ErrnoSaver es;
    // Judged last, after destructors and atexit handlers had their chance to
    // release what the program keeps while it runs.
    if (g_cfg.leak_check)
        res::report_at_exit();
    report::Stats st = heap_stats();
    st.scanned = g_cfg.leak_check && g_scan_done;
    report::finish(st);
}

// ---- the ways a program ends ---------------------------------------------------------

void (*real_exit)(int);
void (*real__exit)(int);
void (*real__Exit)(int);
void (*real_quick_exit)(int);
VOID(WINAPI *real_ExitProcess)(UINT);
BOOL(WINAPI *real_TerminateProcess)(HANDLE, UINT);

// The program's live frames begin above the hook that was called: its stack
// slots below are stale or ours. The registers of the caller are taken from
// the CPU, since the hook may keep or not keep them where the scan would look.
#define LC_ENDING() ending(uintptr_t(__builtin_frame_address(0)) + 16)

LC_NOINLINE void ending(uintptr_t stack_lo) {
    CONTEXT ctx;
    RtlCaptureContext(&ctx);
    // only the registers a call preserves: the others hold the hook's own leftovers
    const uintptr_t regs[] = {ctx.Rbx, ctx.Rbp, ctx.Rsi, ctx.Rdi, ctx.R12, ctx.R13, ctx.R14, ctx.R15};
    leakscan::set_extra_roots(regs, sizeof regs / sizeof regs[0]);
    end_of_program_scan(stack_lo);
    leakscan::set_extra_roots(nullptr, 0);
}

// exit() runs the atexit handlers and destructors after this: scan first.
void hk_exit(int status) {
    LC_ENDING();
    real_exit(status);
    TerminateProcess(GetCurrentProcess(), UINT(status));
}
// These skip the handlers, so the report is closed here.
void hk__exit(int status) {
    LC_ENDING();
    finish_report();
    real__exit(status);
}
void hk__Exit(int status) {
    LC_ENDING();
    finish_report();
    real__Exit(status);
}
void hk_quick_exit(int status) {
    LC_ENDING();
    finish_report();
    real_quick_exit(status);
}
VOID WINAPI hk_ExitProcess(UINT code) {
    LC_ENDING();
    finish_report();
    real_ExitProcess(code);
}
BOOL WINAPI hk_TerminateProcess(HANDLE h, UINT code) {
    if (h == GetCurrentProcess() || GetProcessId(h) == GetCurrentProcessId()) {
        LC_ENDING();
        finish_report();
    }
    return real_TerminateProcess(h, code);
}

#define H(name, fn, orig) {name, reinterpret_cast<void *>(fn), reinterpret_cast<void **>(orig), false}
const win::Hook g_exit_hooks[] = {
    H("exit", hk_exit, &real_exit),
    H("_exit", hk__exit, &real__exit),
    H("_Exit", hk__Exit, &real__Exit),
    H("quick_exit", hk_quick_exit, &real_quick_exit),
    H("ExitProcess", hk_ExitProcess, &real_ExitProcess),
    H("TerminateProcess", hk_TerminateProcess, &real_TerminateProcess),
};
#undef H

void start() {
    ts_init();
    load_config();
    if (!g_cfg.active)
        return;
    HookGuard hg;
    ErrnoSaver es;
    win::memory_start();
    page_size();
    stacks::init();
    threads::init();
    locks::init();
    guard::init();
    report::open_stream();
    stacks::set_ready();

    win::Hook all[256];
    size_t n = 0, nm = 0;
    for (const win::Hook *m = win::memory_hooks(&nm); nm--; ++m)
        all[n++] = *m;
    for (const win::Hook &h : g_exit_hooks)
        all[n++] = h;
    size_t nr = 0;
    for (const win::Hook *r = win::resource_hooks(&nr); nr--; ++r)
        all[n++] = *r;
    size_t nl = 0;
    for (const win::Hook *r = win::lock_hooks(&nl); nl--; ++r)
        all[n++] = *r;
    size_t nb = 0;
    for (const win::Hook *r = win::behavior_hooks(&nb); nb--; ++r)
        all[n++] = *r;
    size_t nn = 0;
    for (const win::Hook *r = win::net_hooks(&nn); nn--; ++r)
        all[n++] = *r;
    win::install_hooks(all, n);
    win::memory_on();
    win::resources_on();
    win::locks_on();
    win::behavior_on();
    win::net_on();
    behavior::started(0, nullptr); // is this program named like something Windows runs?
}

} // namespace

void ensure_init() {}

void stop_program(const char *why) {
    if (reporting() && !__atomic_exchange_n(&g_finish_done, 1u, __ATOMIC_ACQ_REL)) {
        HookGuard hg;
        report::Stats st = heap_stats();
        st.scanned = false;
        report::finish(st);
    }
    write_all(2, why, strlen(why));
    TerminateProcess(GetCurrentProcess(), 134); // 128 + SIGABRT, as on Linux
    for (;;) {
    }
}

} // namespace lc

using namespace lc;

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        start();
        break;
    case DLL_THREAD_ATTACH:
        if (g_cfg.active)
            threads::register_current();
        break;
    case DLL_THREAD_DETACH:
        if (g_cfg.active) {
            locks::thread_exiting(0);
            locks::thread_gone();
            threads::unregister_current();
            ts_exit();
        }
        break;
    case DLL_PROCESS_DETACH:
        // reserved != 0: the process is ending (an exit path that bypassed ours).
        if (reserved && reporting()) {
            LC_ENDING();
            finish_report();
        }
        break;
    }
    return TRUE;
}
