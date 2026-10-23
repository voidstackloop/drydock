#include "behavior.h"
#include "init.h"
#include "locks.h"
#include "protocol.h"
#include "report.h"
#include "rt.h"
#include "stacks.h"

#include <cerrno>
#include <dlfcn.h>
#include <sys/syscall.h>
#include <unistd.h>

// C library functions that keep their result (or a scan position) in static
// storage shared by every thread: strtok, localtime, getpwnam, ... Called
// from two threads, they overwrite each other's result, once in a long while.
// The check is on who calls, not on whether the calls overlap: the program
// that gets away with it today is the one that fails under load.
//
// No libc headers for the wrapped types: the results are void *.
namespace lc::unsafe_libc {
namespace {

constexpr int kSnap = 4; // the first caller's locks kept for comparison

struct Watch {
    const char *name;
    const char *instead;
    uint32_t first_tid; // 0: never called, kBusy: being filled in
    uint32_t first_stack;
    uint32_t nlocks;
    uintptr_t locks[kSnap];
    uint8_t done; // reported, or shown to be serialized by a common lock
};
constexpr uint32_t kBusy = 0xffffffffu;

enum Fn {
    Strtok, Localtime, Gmtime, Ctime, Asctime, Getpwnam, Getpwuid, Getgrnam,
    Getgrgid, Gethostbyname, Gethostbyaddr, InetNtoa, Getlogin, Ttyname,
    Tmpnam, Getservbyname, Getservbyport, Getprotobyname, kFns
};

Watch g_watch[kFns] = {
    {"strtok", "strtok_r", 0, 0, 0, {}, 0},
    {"localtime", "localtime_r", 0, 0, 0, {}, 0},
    {"gmtime", "gmtime_r", 0, 0, 0, {}, 0},
    {"ctime", "ctime_r", 0, 0, 0, {}, 0},
    {"asctime", "asctime_r", 0, 0, 0, {}, 0},
    {"getpwnam", "getpwnam_r", 0, 0, 0, {}, 0},
    {"getpwuid", "getpwuid_r", 0, 0, 0, {}, 0},
    {"getgrnam", "getgrnam_r", 0, 0, 0, {}, 0},
    {"getgrgid", "getgrgid_r", 0, 0, 0, {}, 0},
    {"gethostbyname", "getaddrinfo", 0, 0, 0, {}, 0},
    {"gethostbyaddr", "getnameinfo", 0, 0, 0, {}, 0},
    {"inet_ntoa", "inet_ntop", 0, 0, 0, {}, 0},
    {"getlogin", "getlogin_r", 0, 0, 0, {}, 0},
    {"ttyname", "ttyname_r", 0, 0, 0, {}, 0},
    {"tmpnam", "mkstemp", 0, 0, 0, {}, 0},
    {"getservbyname", "getaddrinfo", 0, 0, 0, {}, 0},
    {"getservbyport", "getnameinfo", 0, 0, 0, {}, 0},
    {"getprotobyname", "getprotobyname_r", 0, 0, 0, {}, 0},
};

bool thread_alive(uint32_t tid) {
#if defined(__APPLE__)
    (void)tid;
    return true; // ponytail: no tgkill; a finished thread can still look live
#else
    const long rc = syscall(SYS_tgkill, int(g_self_pid ? g_self_pid : uint32_t(getpid())),
                            int(tid), 0);
    return rc == 0 || errno != ESRCH;
#endif
}

void report_two_threads(const Watch &w, uint32_t other) {
    char m[384];
    Buf msg(m, sizeof m);
    msg.s(w.name)
        .s("() keeps its result in static storage shared by every thread, and "
           "it is called from threads ")
        .u(w.first_tid)
        .s(" and ")
        .u(other)
        .s(" without a common lock: use ")
        .s(w.instead)
        .s("()");
    report::Finding f;
    f.type = lcproto::kThreadUnsafe;
    f.category = lcproto::kCatThread;
    f.tid = other;
    f.msg = msg.cstr();
    f.access_stack = stacks::capture();
    f.alloc_stack = w.first_stack; // where the first thread called it
    report::emit(f);
}

// `id` was called by the calling thread.
LC_NOINLINE void note_slow(Fn id) {
    if (tl_in_hook)
        return;
    ensure_init();
    if (!g_cfg.active)
        return;
    HookGuard hg;
    ErrnoSaver es;
    Watch &w = g_watch[id];
    const uint32_t me = current_tid();
    uint32_t first = __atomic_load_n(&w.first_tid, __ATOMIC_ACQUIRE);
    if (first == 0 &&
        __atomic_compare_exchange_n(&w.first_tid, &first, kBusy, false,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        w.first_stack = stacks::capture();
        w.nlocks = uint32_t(locks::held_snapshot(w.locks, kSnap));
        __atomic_store_n(&w.first_tid, me, __ATOMIC_RELEASE);
        return;
    }
    if (first == kBusy || first == me)
        return;
    // Another thread called it before.
    uintptr_t mine[kSnap];
    const size_t n = locks::held_snapshot(mine, kSnap);
    for (size_t i = 0; i < n; ++i)
        for (uint32_t j = 0; j < w.nlocks; ++j)
            if (mine[i] == w.locks[j]) { // one lock around the calls: fine
                __atomic_store_n(&w.done, 1, __ATOMIC_RELEASE);
                return;
            }
    if (!thread_alive(first)) { // it ended: the calls cannot overlap
        w.first_stack = stacks::capture();
        w.nlocks = uint32_t(n);
        for (size_t i = 0; i < n; ++i)
            w.locks[i] = mine[i];
        __atomic_store_n(&w.first_tid, me, __ATOMIC_RELEASE);
        return;
    }
    __atomic_store_n(&w.done, 1, __ATOMIC_RELEASE);
    report_two_threads(w, me);
}

inline void note(Fn id) {
    Watch &w = g_watch[id];
    if (LC_LIKELY(__atomic_load_n(&w.done, __ATOMIC_RELAXED)) ||
        (tl_tid && w.first_tid == tl_tid))
        return;
    note_slow(id);
}

template <class F> F real(F &slot, const char *name) {
    F f = __atomic_load_n(&slot, __ATOMIC_ACQUIRE);
    if (LC_UNLIKELY(!f)) {
        {
            HookGuard hg;
            f = reinterpret_cast<F>(dlsym(RTLD_NEXT, name));
        }
        if (!f)
            die("cannot find a libc function to forward to");
        __atomic_store_n(&slot, f, __ATOMIC_RELEASE);
    }
    return f;
}

} // namespace
} // namespace lc::unsafe_libc

using namespace lc;
using namespace lc::unsafe_libc;

#include "lc_api.h"
// ret name(params): note, then the real one
#define WRAP(ret, name, id, params, args)                                      \
    LC_API ret LC_FN(name) params {                                            \
        static ret(*real_fn) params;                                           \
        note(id);                                                              \
        return real(real_fn, #name) args;                                      \
    }

WRAP(char *, strtok, Strtok, (char *s, const char *d), (s, d))
WRAP(void *, localtime, Localtime, (const void *t), (t))
WRAP(void *, gmtime, Gmtime, (const void *t), (t))
WRAP(char *, ctime, Ctime, (const void *t), (t))
WRAP(char *, asctime, Asctime, (const void *tm), (tm))
WRAP(void *, getpwnam, Getpwnam, (const char *n), (n))
WRAP(void *, getpwuid, Getpwuid, (unsigned int u), (u))
WRAP(void *, getgrnam, Getgrnam, (const char *n), (n))
WRAP(void *, getgrgid, Getgrgid, (unsigned int g), (g))
// gethostbyname() does not call getaddrinfo(), so a look-alike host is missed there.
LC_API void *LC_FN(gethostbyname)(const char *n) {
    behavior::host(n, "gethostbyname()");
    static void *(*real_fn)(const char *);
    note(Gethostbyname);
    return real(real_fn, "gethostbyname")(n);
}

// gethostbyname2() does not call the public gethostbyname().
LC_API void *LC_FN(gethostbyname2)(const char *n, int af) {
    behavior::host(n, "gethostbyname2()");
    static void *(*real_fn)(const char *, int);
    return real(real_fn, "gethostbyname2")(n, af);
}
WRAP(void *, gethostbyaddr, Gethostbyaddr,
     (const void *a, unsigned int len, int type), (a, len, type))
WRAP(char *, inet_ntoa, InetNtoa, (unsigned int in), (in))
WRAP(char *, getlogin, Getlogin, (void), ())
WRAP(char *, ttyname, Ttyname, (int fd), (fd))
WRAP(char *, tmpnam, Tmpnam, (char *s), (s))
WRAP(void *, getservbyname, Getservbyname, (const char *n, const char *p),
     (n, p))
WRAP(void *, getservbyport, Getservbyport, (int port, const char *p),
     (port, p))
WRAP(void *, getprotobyname, Getprotobyname, (const char *n), (n))
