#include "init.h"
#include "behavior.h"
#include "blocks.h"
#include "guard.h"
#include "heap.h"
#include "leakscan.h"
#include "locks.h"
#include "report.h"
#include "resources.h"
#include "rt.h"
#include "signals.h"
#include "stacks.h"
#include "threads.h"

#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#if defined(__APPLE__)
#include <crt_externs.h> // _NSGetEnviron: where the environment lives on Darwin
#endif
#include <execinfo.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "lc_api.h"

namespace lc {
namespace {

#if defined(__APPLE__)
// libc's __exit: the call that does not run atexit handlers, which is what this
// file is. A language-linkage declaration is only legal at namespace scope, so
// it sits here rather than inside raw_exit (clang enforces that; gcc does not).
extern "C" __attribute__((noreturn)) void lc_sys_exit(int) __asm("__exit");
#endif

using MainFn = int (*)(int, char **, char **);
using StartMainFn = int (*)(MainFn, int, char **, void (*)(), void (*)(),
                            void (*)(), void *);
using ExitFn = void (*)(int);

uint32_t g_init_state; // 0 = not started, 1 = running, 2 = done
uint32_t g_scan_done;
uint32_t g_finish_done;
#if !defined(__APPLE__)
MainFn g_real_main; // only the glibc start hook runs a main_hook
#endif
ExitFn g_real_exit;
ExitFn g_real_uexit;

// The resource table's lock comes first: it is held while reporting and
// while mapping pages.
void fork_prepare() {
    g_fork_tid = current_tid();
    res::lock();
    locks::lock();
    blocks::lock_all();
    report::lock();
    stacks::lock_all();
    threads::lock();
    quarantine_lock();
    ih::lock();
    ranges_lock();
}

void fork_parent() {
    ranges_unlock();
    ih::unlock();
    quarantine_unlock();
    threads::unlock();
    stacks::unlock_all();
    report::unlock();
    blocks::unlock_all();
    locks::unlock();
    res::unlock();
    g_fork_tid = 0;
}

void fork_child() {
    res::reset_lock();
    locks::reset_lock();
    ranges_reset_lock();
    ih::reset_lock();
    quarantine_reset_lock();
    threads::reset_lock();
    stacks::reset_locks();
    report::reset_lock();
    blocks::reset_locks();
    tl_tid = 0;
    g_self_pid = uint32_t(getpid());
    threads::after_fork_child();
    if (g_cfg.trace_children)
        report::after_fork_child();
    else
        g_cfg.report_enabled = false;
}

bool reporting() { return g_cfg.active && g_cfg.report_enabled; }

// Called once the program is finished with its heap: main returned or exit
// was called. Runs before atexit handlers, like LeakSanitizer. stack_lo is
// an address in the hook frame that handed control to us; everything below
// it is either dead or the runtime's own.
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

// Spill callee-saved registers into this frame (they may hold the caller's
// live pointers) and return an address below the spill area.
#define LC_HOOK_FRAME_MARKER(var)                                              \
    __builtin_unwind_init();                                                   \
    volatile uintptr_t var##_slot = 0;                                         \
    const uintptr_t var = reinterpret_cast<uintptr_t>(&var##_slot)

void finish_report() {
    if (!reporting() ||
        __atomic_exchange_n(&g_finish_done, 1u, __ATOMIC_ACQ_REL))
        return;
    // A worker's pthread-key destructor already reported its locks. Main's
    // runs after the report is closed, or not at all.
    locks::thread_exiting(0);
    HookGuard hg;
    ErrnoSaver es;
    // Judged last, after destructors and atexit handlers had their chance
    // to close what the program keeps open while it runs.
    if (g_cfg.leak_check)
        res::report_at_exit();
    report::Stats st = heap_stats();
    st.scanned = g_cfg.leak_check && g_scan_done;
    report::finish(st);
}

// Reached through the __libc_start_main hook, which macOS does not have (there
// the interposer wraps main directly), so it only exists where it is called.
#if !defined(__APPLE__)
int main_hook(int argc, char **argv, char **envp) {
    behavior::started(argc, argv);
    int rc = g_real_main(argc, argv, envp);
    LC_HOOK_FRAME_MARKER(lo);
    end_of_program_scan(lo);
    return rc;
}
#endif

__attribute__((constructor(101))) void on_load() {
    ensure_init();
#if defined(__APPLE__)
    // dyld refuses an inserted library whose architecture the program does not
    // have, and Apple's own programs (/bin/sh, /bin/true, /usr/bin/sleep) are
    // arm64e: a program that runs a shell under analysis would abort in the
    // shell. Children are only analysed on request, so the variable goes here,
    // before the program or anything it spawns can see it. Linux keeps
    // LD_PRELOAD: glibc loads it everywhere, and a child that inherits it runs
    // as a passive runtime rather than aborting.
    //
    // The array is edited in place rather than through unsetenv(): that call is
    // one of the hooked ones, and this is the runtime tidying up after itself,
    // not the program touching its environment.
    if (!g_cfg.trace_children) {
        static constexpr char kPreload[] = "DYLD_INSERT_LIBRARIES=";
        char **env = *_NSGetEnviron();
        for (char **e = env; e && *e; ++e) {
            if (std::strncmp(*e, kPreload, sizeof kPreload - 1) == 0) {
                for (char **m = e; *m; ++m)
                    *m = *(m + 1);
                --e; // the slot now holds the entry that followed
            }
        }
    }
#endif
    if (!g_cfg.active)
        return;
    HookGuard hg;
    ErrnoSaver es;
    page_size();
    stacks::init();
    // The first backtrace() loads the unwinder with dlopen, which allocates.
    void *warm[4];
    backtrace(warm, 4);
    threads::init();
    locks::init();
    guard::init();
    g_real_exit = reinterpret_cast<ExitFn>(dlsym(RTLD_NEXT, "exit"));
    g_real_uexit = reinterpret_cast<ExitFn>(dlsym(RTLD_NEXT, "_exit"));
    pthread_atfork(fork_prepare, fork_parent, fork_child);
    report::open_stream();
    stacks::set_ready();
}

__attribute__((destructor(101))) void on_unload() {
    // Reached only if neither main_hook nor the exit wrappers ran the scan.
    if (!reporting())
        return;
    LC_HOOK_FRAME_MARKER(lo);
    end_of_program_scan(lo);
    finish_report();
}

[[noreturn]] void raw_exit(int status) {
#if defined(__APPLE__)
    lc_sys_exit(status);
#else
    syscall(SYS_exit_group, status);
#endif
    __builtin_unreachable();
}

} // namespace

void stop_program(const char *why) {
    if (reporting() &&
        !__atomic_exchange_n(&g_finish_done, 1u, __ATOMIC_ACQ_REL)) {
        HookGuard hg;
        report::Stats st = heap_stats();
        st.scanned = false;
        report::finish(st);
    }
    write_all(2, why, strlen(why));
    abort();
}

void ensure_init() {
    if (LC_LIKELY(__atomic_load_n(&g_init_state, __ATOMIC_ACQUIRE) == 2))
        return;
    uint32_t expected = 0;
    if (__atomic_compare_exchange_n(&g_init_state, &expected, 1u, false,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        {
            HookGuard hg;
            ErrnoSaver es;
            load_config();
            if (g_cfg.active)
                fd_reserve_make();
        }
        __atomic_store_n(&g_init_state, 2u, __ATOMIC_RELEASE);
        return;
    }
    while (__atomic_load_n(&g_init_state, __ATOMIC_ACQUIRE) != 2)
        yield_thread();
}

} // namespace lc

using namespace lc;

#if !defined(__APPLE__)
extern "C" __attribute__((visibility("default"))) int
__libc_start_main(MainFn main, int argc, char **argv, void (*init)(),
                  void (*fini)(), void (*rtld_fini)(), void *stack_end) {
    StartMainFn real;
    {
        HookGuard hg;
        real = reinterpret_cast<StartMainFn>(
            dlsym(RTLD_NEXT, "__libc_start_main"));
    }
    if (!real)
        die("cannot find __libc_start_main");
    ensure_init();
    if (!g_cfg.active)
        return real(main, argc, argv, init, fini, rtld_fini, stack_end);
    g_real_main = main;
    return real(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}
#endif

extern "C" __attribute__((visibility("default"), noreturn)) void
LC_FN(exit)(int status) noexcept {
    signals::unsafe_call("exit()"); // runs atexit handlers and destructors
    LC_HOOK_FRAME_MARKER(lo);
    end_of_program_scan(lo);
    if (!g_real_exit) {
        HookGuard hg;
        g_real_exit = reinterpret_cast<ExitFn>(dlsym(RTLD_NEXT, "exit"));
    }
    if (g_real_exit)
        g_real_exit(status);
    raw_exit(status);
}

// _exit skips atexit handlers and destructors, so finish the report here.
// Only for the root process itself: a vfork child shares our memory.
extern "C" __attribute__((visibility("default"), noreturn)) void
LC_FN(_exit)(int status) {
    if (reporting() && g_cfg.root_pid != 0 &&
        uint32_t(getpid()) == g_cfg.root_pid) {
        LC_HOOK_FRAME_MARKER(lo);
        end_of_program_scan(lo);
        finish_report();
    }
    if (!g_real_uexit) {
        HookGuard hg;
        g_real_uexit = reinterpret_cast<ExitFn>(dlsym(RTLD_NEXT, "_exit"));
    }
    if (g_real_uexit)
        g_real_uexit(status);
    raw_exit(status);
}

extern "C" __attribute__((visibility("default"), noreturn)) void
LC_FN(_Exit)(int status) noexcept {
    LC_FN(_exit)(status);
}
