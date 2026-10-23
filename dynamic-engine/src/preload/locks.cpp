#include "locks.h"
#include "init.h"
#include "protocol.h"
#include "report.h"
#include "stacks.h"

#include <cerrno>
#include <cstring>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace lc::locks {
namespace {

constexpr uint32_t kMaxHeld = 16; // per thread; deeper ones untracked
constexpr size_t kEdgeCap = size_t(1) << 16; // power of two
constexpr size_t kNodeCap = size_t(1) << 14;
constexpr int kMaxCycle = 5; // longest cycle searched for, in mutexes
constexpr uintptr_t kDead = 1;

enum class LockKind { Mutex, Spin, Write, Read }; // Write/Read: rwlocks

struct Held {
    uintptr_t m;
    uintptr_t pc; // where it was locked: the wrapper's return address
    bool shared;  // a read-write lock held for reading
    LockKind kind;
};
LC_TLS Held tl_held[kMaxHeld];
LC_TLS uint32_t tl_nheld; // may exceed kMaxHeld

// "a was held while b was locked". a == 0: empty slot, kDead: removed.
struct Edge {
    uintptr_t a, b;
    uint32_t stack; // where b was locked
    uint32_t held;  // where a was locked (one frame)
    bool reported;
};

// ponytail: one global lock for the order graph, taken only when a thread
// locks a mutex while holding another; per-node locking if that contends.
SpinLock g_lock;
Edge *g_edges;
size_t g_used;      // live and dead slots
uintptr_t *g_nodes; // sorted addresses of the mutexes in some edge
size_t g_nnodes;

uint64_t mix(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

bool tables() {
    if (!g_edges) {
        g_edges = static_cast<Edge *>(map_pages(kEdgeCap * sizeof(Edge)));
        g_nodes =
            static_cast<uintptr_t *>(map_pages(kNodeCap * sizeof(uintptr_t)));
    }
    return g_edges && g_nodes;
}

// The edge a -> b, or the empty slot where it would go.
Edge *slot(Edge *t, uintptr_t a, uintptr_t b) {
    for (size_t i = mix(a * 31 + b) & (kEdgeCap - 1);;
         i = (i + 1) & (kEdgeCap - 1))
        if (!t[i].a || (t[i].a == a && t[i].b == b))
            return &t[i];
}

// Drops removed edges once they crowd the table.
void compact() {
    auto *t = static_cast<Edge *>(map_pages(kEdgeCap * sizeof(Edge)));
    if (!t)
        return;
    size_t n = 0;
    for (size_t i = 0; i < kEdgeCap; ++i)
        if (g_edges[i].a > kDead) {
            *slot(t, g_edges[i].a, g_edges[i].b) = g_edges[i];
            ++n;
        }
    unmap_pages(g_edges, kEdgeCap * sizeof(Edge));
    g_edges = t;
    g_used = n;
}

size_t lower_bound(uintptr_t v) {
    size_t lo = 0, hi = g_nnodes;
    while (lo < hi) {
        const size_t mid = (lo + hi) / 2;
        if (g_nodes[mid] < v)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

void add_node(uintptr_t m) {
    const size_t i = lower_bound(m);
    if ((i < g_nnodes && g_nodes[i] == m) || g_nnodes >= kNodeCap)
        return;
    memmove(&g_nodes[i + 1], &g_nodes[i], (g_nnodes - i) * sizeof(uintptr_t));
    g_nodes[i] = m;
    ++g_nnodes;
}

// Mutexes in [lo, hi) are gone (freed, destroyed or re-initialised): a new
// mutex at the same address must not inherit their order.
void forget_locked(uintptr_t lo, uintptr_t hi) {
    const size_t first = lower_bound(lo);
    size_t last = first;
    while (last < g_nnodes && g_nodes[last] < hi)
        ++last;
    if (first == last)
        return;
    memmove(&g_nodes[first], &g_nodes[last],
            (g_nnodes - last) * sizeof(uintptr_t));
    g_nnodes -= last - first;
    for (size_t i = 0; i < kEdgeCap; ++i) {
        Edge &e = g_edges[i];
        if (e.a > kDead && ((e.a >= lo && e.a < hi) || (e.b >= lo && e.b < hi)))
            e.a = e.b = kDead;
    }
}

// A chain of edges from -> ... -> to of at most `depth` edges, into path.
// ponytail: scans the whole table per step; new orders are rare.
int find_path(uintptr_t from, uintptr_t to, Edge **path, int depth) {
    if (depth == 0)
        return 0;
    for (size_t i = 0; i < kEdgeCap; ++i) {
        Edge &e = g_edges[i];
        if (e.a != from)
            continue;
        path[0] = &e;
        if (e.b == to)
            return 1;
        if (int n = find_path(e.b, to, path + 1, depth - 1))
            return n + 1;
    }
    return 0;
}

void report_inversion(uintptr_t a, uintptr_t b, int chain, uint32_t stack,
                      uint32_t held, uint32_t other) {
    char m[384];
    Buf msg(m, sizeof m);
    msg.s("lock ").p(b).s(" is taken while holding lock ").p(a);
    if (chain == 1)
        msg.s(", but elsewhere they are taken in the opposite order");
    else
        msg.s(", but other lock orders lead from it back to ")
            .p(a)
            .s(" (a cycle of ")
            .u(uint64_t(chain + 1))
            .s(" locks)");
    msg.s(": threads doing both at the same time deadlock");
    report::Finding f;
    f.type = lcproto::kLockOrder;
    f.category = lcproto::kCatLock;
    f.addr = b;
    f.tid = current_tid();
    f.msg = msg.cstr();
    f.access_stack = stack;
    f.alloc_stack = other;
    f.free_stack = held;
    f.fatal = true;
    report::emit(f);
}

// This thread locked b while holding h.
void ordered(const Held &h, uintptr_t b) {
    {
        LockGuard g(g_lock);
        if (!tables() || slot(g_edges, h.m, b)->a)
            return; // order already known
    }
    const uint32_t stack = stacks::capture();
    const uint32_t held = stacks::intern(&h.pc, 1);
    uint32_t other = 0;
    int chain = 0;
    {
        LockGuard g(g_lock);
        if (g_used * 4 >= kEdgeCap * 3)
            compact();
        Edge *e = slot(g_edges, h.m, b);
        if (e->a || g_used * 4 >= kEdgeCap * 3)
            return;
        *e = Edge{h.m, b, stack, held, false};
        ++g_used;
        add_node(h.m);
        add_node(b);
        Edge *path[kMaxCycle];
        chain = find_path(b, h.m, path, kMaxCycle - 1);
        if (chain) {
            bool fresh = !e->reported;
            for (int i = 0; i < chain; ++i)
                fresh = fresh && !path[i]->reported;
            if (!fresh)
                chain = 0;
            e->reported = true;
            for (int i = 0; i < chain; ++i)
                path[i]->reported = true;
            if (chain)
                other = path[chain - 1]->stack; // where the cycle closes on a
        }
    }
    if (chain)
        report_inversion(h.m, b, chain, stack, held, other);
}

// glibc's mutex type (PTHREAD_MUTEX_KIND_MASK_NP): 0 normal, 1 recursive,
// 2 error-checking, 3 adaptive.
bool relock_deadlocks(uintptr_t m) {
#if defined(__APPLE__)
    (void)m;
    return true; // ponytail: no glibc __kind; a second lock is treated as fatal
#else
    const int kind =
        reinterpret_cast<const pthread_mutex_t *>(m)->__data.__kind;
    return (kind & 3) == PTHREAD_MUTEX_NORMAL || (kind & 3) == 3;
#endif
}

// Would taking m again (as k) wait for this very thread, forever? Recursive
// and error-checking mutexes return instead, and glibc answers EDEADLK for
// a read-write lock this thread holds for writing.
bool waits_for_itself(uintptr_t m, LockKind k, const Held &h) {
    switch (k) {
    case LockKind::Mutex:
        return relock_deadlocks(m);
    case LockKind::Spin:
        return true;
    case LockKind::Write: // its own read lock never goes away
        return h.shared;
    case LockKind::Read: // readers share
        return false;
    }
    return false;
}

bool owned_by_me(int owner); // defined with the fork-child rule, below

// A foreign unlock of a normal mutex releases it (glibc clears __owner),
// but only the unlocking thread's held list is updated. The thread that
// locked it still has a record. That record is stale: the next lock takes
// the mutex, or waits for whoever holds it now, and does not deadlock on
// itself. Untracked overflow is left alone: this mutex may never have been
// one of those.
void drop_stolen(uintptr_t m) {
#if defined(__APPLE__)
    (void)m; // ponytail: glibc __owner is Linux-only
    return;
#else
    if (owned_by_me(
            reinterpret_cast<const pthread_mutex_t *>(m)->__data.__owner))
        return;
    const uint32_t n = tl_nheld < kMaxHeld ? tl_nheld : kMaxHeld;
    for (uint32_t i = n; i-- > 0;) {
        if (tl_held[i].m != m)
            continue;
        memmove(&tl_held[i], &tl_held[i + 1], (n - i - 1) * sizeof(Held));
        --tl_nheld;
        return;
    }
#endif
}

// Before blocking on m: does this thread hold it already?
void before_lock(uintptr_t m, LockKind k) {
    if (k == LockKind::Mutex)
        drop_stolen(m);
    const uint32_t n = tl_nheld < kMaxHeld ? tl_nheld : kMaxHeld;
    for (uint32_t i = 0; i < n; ++i) {
        if (tl_held[i].m != m || !waits_for_itself(m, k, tl_held[i]))
            continue;
        report::Finding f;
        f.type = lcproto::kDoubleLock;
        f.category = lcproto::kCatLock;
        f.addr = m;
        f.tid = current_tid();
        f.msg = k == LockKind::Write
                    ? "this thread write-locks a read-write lock it holds for "
                      "reading: it waits for itself forever"
                : k == LockKind::Spin
                    ? "this thread locks a spin lock it already holds: it "
                      "spins forever"
                    : "this thread locks a mutex it already holds: it waits "
                      "for itself forever";
        f.access_stack = stacks::capture();
        f.alloc_stack = stacks::intern(&tl_held[i].pc, 1);
        f.fatal = true;
        f.untraced_too = true; // the program is stopped: say why, in a child too
        report::emit(f);
        stop_program("leakcheck: stopped the program, which deadlocked "
                     "taking a lock it already holds\n");
    }
}

// Only an exclusive acquisition makes an order: it waits for any holder, a
// reader included, while a read lock waits for writers only. So in a cycle
// of such edges every lock is wanted exclusively while held: a deadlock.
void acquired(uintptr_t m, uintptr_t pc, bool order, bool shared, LockKind k) {
    const uint32_t n = tl_nheld < kMaxHeld ? tl_nheld : kMaxHeld;
    if (order && !shared)
        for (uint32_t i = 0; i < n; ++i)
            if (tl_held[i].m != m)
                ordered(tl_held[i], m);
    if (tl_nheld < kMaxHeld)
        tl_held[tl_nheld] = Held{m, pc, shared, k};
    ++tl_nheld;
}

void released(uintptr_t m) {
    const uint32_t n = tl_nheld < kMaxHeld ? tl_nheld : kMaxHeld;
    for (uint32_t i = n; i-- > 0;) {
        if (tl_held[i].m != m)
            continue;
        memmove(&tl_held[i], &tl_held[i + 1], (n - i - 1) * sizeof(Held));
        --tl_nheld;
        return;
    }
    if (tl_nheld > kMaxHeld) // one of the untracked ones
        --tl_nheld;
}

void forget(uintptr_t lo, uintptr_t hi) {
    if (!__atomic_load_n(&g_nnodes, __ATOMIC_RELAXED))
        return;
    LockGuard g(g_lock);
    forget_locked(lo, hi);
}

template <class F> F real(F &slot, const char *name) {
    F f = __atomic_load_n(&slot, __ATOMIC_ACQUIRE);
    if (LC_UNLIKELY(!f)) {
        {
            HookGuard hg;
            f = reinterpret_cast<F>(dlsym(RTLD_NEXT, name));
        }
        if (!f)
            die("cannot find a pthread mutex function to forward to");
        __atomic_store_n(&slot, f, __ATOMIC_RELEASE);
    }
    return f;
}

#define REAL(name) real(real_##name, #name)
#define SLOT(name) decltype(&::name) real_##name
SLOT(pthread_mutex_lock);
SLOT(pthread_mutex_trylock);
#if !defined(__APPLE__)
SLOT(pthread_mutex_timedlock);   // POSIX, but Darwin never implemented it
SLOT(pthread_mutex_clocklock);   // glibc extension
#endif
SLOT(pthread_mutex_unlock);
SLOT(pthread_mutex_init);
SLOT(pthread_mutex_destroy);
SLOT(pthread_rwlock_rdlock);
SLOT(pthread_rwlock_wrlock);
SLOT(pthread_rwlock_tryrdlock);
SLOT(pthread_rwlock_trywrlock);
SLOT(pthread_rwlock_timedrdlock);
SLOT(pthread_rwlock_timedwrlock);
#if !defined(__APPLE__)
SLOT(pthread_rwlock_clockrdlock); // glibc extension
SLOT(pthread_rwlock_clockwrlock);
#endif
SLOT(pthread_rwlock_unlock);
SLOT(pthread_rwlock_init);
SLOT(pthread_rwlock_destroy);
#if !defined(__APPLE__)
SLOT(pthread_spin_lock); // Darwin has no spin locks
SLOT(pthread_spin_trylock);
SLOT(pthread_spin_unlock);
SLOT(pthread_spin_init);
SLOT(pthread_spin_destroy);
SLOT(pthread_cond_clockwait);
#endif
SLOT(pthread_cond_wait);
SLOT(pthread_cond_timedwait);

bool tracking() {
    if (tl_in_hook)
        return false;
    ensure_init();
    return g_cfg.active;
}

// A lock call that may wait: a self-deadlock is reported before it, the
// order after it.
template <class F> int blocking(uintptr_t m, uintptr_t pc, LockKind k, F lock) {
    if (!tracking())
        return lock();
    {
        HookGuard hg;
        ErrnoSaver es;
        before_lock(m, k);
    }
    const int rc = lock();
    if (rc == 0) {
        HookGuard hg;
        ErrnoSaver es;
        acquired(m, pc, true, k == LockKind::Read, k);
    }
    return rc;
}

// A try-lock (cannot wait: no order) or a timed one (gives up, but waited in
// that order).
template <class F>
int bounded(uintptr_t m, uintptr_t pc, bool order, bool shared, LockKind k, F lock) {
    const int rc = lock();
    if (rc == 0 && tracking()) {
        HookGuard hg;
        ErrnoSaver es;
        acquired(m, pc, order, shared, k);
    }
    return rc;
}

int unlocked(uintptr_t m, int rc) {
    if (rc == 0 && !tl_in_hook)
        released(m);
    return rc;
}

// The calling thread no longer holds the locks in [lo, hi): they were
// freed, initialised or destroyed. True if it held one.
bool drop_held(uintptr_t lo, uintptr_t hi) {
    bool any = false;
    uint32_t n = tl_nheld < kMaxHeld ? tl_nheld : kMaxHeld;
    for (uint32_t i = n; i-- > 0;)
        if (tl_held[i].m >= lo && tl_held[i].m < hi) {
            memmove(&tl_held[i], &tl_held[i + 1], (--n - i) * sizeof(Held));
            --tl_nheld;
            any = true;
        }
    return any;
}

// Initialised or destroyed: from now on a new lock at that address. (A
// fork() child's handler may initialise again a mutex it holds.)
void gone(uintptr_t m) {
    if (!tl_in_hook) {
        forget(m, m + 1);
        drop_held(m, m + 1);
    }
}

// glibc's owner of a locked mutex is this thread: in a fork() child also
// the parent's thread that forked (pthread_atfork prepare handlers lock,
// child handlers unlock).
bool owned_by_me(int owner) {
    return owner == int(current_tid()) ||
           (g_fork_tid && owner == int(g_fork_tid) &&
            current_tid() == g_self_pid);
}

void report_misuse(const char *type, uintptr_t m, const char *msg) {
    HookGuard hg;
    ErrnoSaver es;
    report::Finding f;
    f.type = type;
    f.category = lcproto::kCatLock;
    f.addr = m;
    f.tid = current_tid();
    f.msg = msg;
    f.access_stack = stacks::capture();
    f.fatal = true;
    report::emit(f);
}

// A wait unlocks m and takes it back: the caller must hold it. Otherwise
// a signal sent before the wait starts is lost (the waiter sleeps on), and
// the mutex is unlocked by a thread that does not own it.
void before_wait(uintptr_t m) {
    if (!tracking() || tl_nheld > kMaxHeld)
        return;
    for (uint32_t i = 0; i < tl_nheld; ++i)
        if (tl_held[i].m == m)
            return;
    report_misuse(lcproto::kUnlockedWait, m,
                  "a condition wait with a mutex this thread does not hold: a "
                  "signal sent before the wait starts is lost");
}

// glibc records which thread owns a locked mutex. Unlocking one this thread
// does not own is undefined for normal and adaptive mutexes (the others
// answer EPERM): it works until two threads end up inside together.
void before_unlock(pthread_mutex_t *m) {
#if defined(__APPLE__)
    (void)m;
    return;
#else
    if (!tracking() || !relock_deadlocks(uintptr_t(m)))
        return;
    const int owner = m->__data.__owner;
    if (owned_by_me(owner))
        return;
    report_misuse(lcproto::kForeignUnlock, uintptr_t(m),
                  owner ? "unlocks a mutex that another thread holds"
                        : "unlocks a mutex that is not locked");
#endif
}

// A locked mutex whose owner thread is gone: it ended holding the lock, or it
// was another thread of the parent when this process forked (the child has
// only the thread that called fork()). Nobody can ever unlock it. Robust
// mutexes answer EOWNERDEAD and process-shared ones may be owned by another
// process, so they are left alone.
bool owner_is_gone(const pthread_mutex_t *m) {
#if defined(__APPLE__)
    (void)m;
    return false;
#else
    const int kind = m->__data.__kind;
    if (kind < 0 || (kind & (0x10 | 0x80)))
        return false;
    const int owner = m->__data.__owner;
    if (!m->__data.__lock || !owner || owned_by_me(owner))
        return false;
    if (syscall(SYS_tgkill, int(g_self_pid ? g_self_pid : uint32_t(getpid())),
                owner, 0) == 0 ||
        errno != ESRCH)
        return false;
    return m->__data.__lock && m->__data.__owner == owner; // still the same
#endif
}

// Before blocking on m: would it wait for a thread that does not exist?
void before_orphan_lock(pthread_mutex_t *m) {
#if defined(__APPLE__)
    (void)m;
    return;
#else
    if (LC_LIKELY(!m->__data.__lock) || !tracking())
        return;
    HookGuard hg;
    ErrnoSaver es;
    if (!owner_is_gone(m))
        return;
    report::Finding f;
    f.type = lcproto::kOrphanedLock;
    f.category = lcproto::kCatLock;
    f.addr = uintptr_t(m);
    f.tid = current_tid();
    f.msg = g_fork_tid
                ? "locks a mutex that another thread of the parent held when "
                  "the process forked: that thread does not exist here, so "
                  "nothing unlocks it and this thread waits forever"
                : "locks a mutex whose owner thread has ended: nothing "
                  "unlocks it and this thread waits forever";
    f.access_stack = stacks::capture();
    f.fatal = true;
    f.untraced_too = true; // a fork() child is the usual place
    report::emit(f);
    stop_program("leakcheck: stopped the program, which would wait forever "
                 "for a lock whose owner is gone\n");
#endif
}

// glibc marks a destroyed mutex with __kind -1 until pthread_mutex_init or
// an initializer makes it new. Using it is undefined: a lock answers EINVAL
// and a caller that does not check runs unprotected. True if reported.
bool destroyed(pthread_mutex_t *m, const char *msg) {
#if defined(__APPLE__)
    (void)m;
    (void)msg;
    return false; // ponytail: glibc __kind == -1 is Linux-only
#else
    if (LC_LIKELY(m->__data.__kind != -1) || !tracking())
        return false;
    report_misuse(lcproto::kUseAfterDestroy, uintptr_t(m), msg);
    return true;
#endif
}

constexpr const char *kLockDestroyed =
    "locks a mutex that was destroyed: glibc answers EINVAL, and a caller "
    "that does not check it runs unprotected";

// Destroying a held lock is undefined: glibc answers EBUSY for a mutex
// (programs rarely check) and the memory is then freed or reused while
// another thread may still unlock it or wait for it.
// other_holds() asks whether some other thread holds it.
template <class F>
void before_destroy(uintptr_t l, F other_holds, const char *mine,
                    const char *other) {
    if (!tracking())
        return;
    if (drop_held(l, l + 1))
        report_misuse(lcproto::kDestroyLocked, l, mine);
    else if (other_holds())
        report_misuse(lcproto::kDestroyLocked, l, other);
}

} // namespace

// The unwinder and dl_iterate_phdr take locks while the runtime captures
// stacks: their real functions must not need a dlsym then.
void init() {
    REAL(pthread_mutex_lock);
    REAL(pthread_mutex_trylock);
    REAL(pthread_mutex_unlock);
    REAL(pthread_rwlock_rdlock);
    REAL(pthread_rwlock_wrlock);
    REAL(pthread_rwlock_unlock);
#if !defined(__APPLE__)
    REAL(pthread_spin_lock);
    REAL(pthread_spin_unlock);
#endif
}

// Freeing a lock this thread holds is left alone: the last reference to an
// object often frees it with its lock held, as nobody can take it any more.
void block_freed(uintptr_t lo, size_t size) {
    forget(lo, lo + size);
    drop_held(lo, lo + size);
}

size_t held_snapshot(uintptr_t *out, size_t max) {
    size_t n = 0;
    for (uint32_t i = 0; i < tl_nheld && i < kMaxHeld && n < max; ++i)
        out[n++] = tl_held[i].m;
    return n;
}

void thread_exiting(uint32_t create_stack) {
    const uint32_t n = tl_nheld < kMaxHeld ? tl_nheld : kMaxHeld;
    for (uint32_t i = 0; i < n; ++i) {
        // A foreign unlock already released this mutex (glibc cleared
        // __owner). The record stayed, because only the unlocking thread's
        // list is updated.
#if !defined(__APPLE__)
        if (tl_held[i].kind == LockKind::Mutex &&
            !owned_by_me(reinterpret_cast<const pthread_mutex_t *>(tl_held[i].m)
                             ->__data.__owner))
            continue;
#endif
        report::Finding f;
        f.type = lcproto::kLockLeak;
        f.category = lcproto::kCatLock;
        f.addr = tl_held[i].m;
        f.tid = current_tid();
        f.msg = "the thread ends while holding this lock: any thread that "
                "takes it later waits forever";
        f.access_stack = stacks::intern(&tl_held[i].pc, 1);
        f.alloc_stack = create_stack;
        f.fatal = true;
        report::emit(f);
    }
    tl_nheld = 0;
}

void lock() { g_lock.lock(); }
void unlock() { g_lock.unlock(); }
void reset_lock() { g_lock.reset(); }

} // namespace lc::locks

using namespace lc;
using namespace lc::locks;

#include "lc_api.h"
// The caller's address: where the program took the lock.
#define LC_PC uintptr_t(__builtin_return_address(0))

// ---- mutexes ----------------------------------------------------------------

LC_API int LC_FN(pthread_mutex_lock)(pthread_mutex_t *m) noexcept {
    if (!destroyed(m, kLockDestroyed))
        before_orphan_lock(m);
    return blocking(uintptr_t(m), LC_PC, LockKind::Mutex,
                    [m] { return REAL(pthread_mutex_lock)(m); });
}

LC_API int LC_FN(pthread_mutex_trylock)(pthread_mutex_t *m) noexcept {
    destroyed(m, kLockDestroyed);
    return bounded(uintptr_t(m), LC_PC, false, false, LockKind::Mutex,
                   [m] { return REAL(pthread_mutex_trylock)(m); });
}

#if !defined(__APPLE__)
LC_API int LC_FN(pthread_mutex_timedlock)(pthread_mutex_t *m,
                                   const struct timespec *until) noexcept {
    destroyed(m, kLockDestroyed);
    return bounded(uintptr_t(m), LC_PC, true, false, LockKind::Mutex,
                   [=] { return REAL(pthread_mutex_timedlock)(m, until); });
}

LC_API int LC_FN(pthread_mutex_clocklock)(pthread_mutex_t *m, clockid_t clock,
                                   const struct timespec *until) noexcept {
    destroyed(m, kLockDestroyed);
    return bounded(uintptr_t(m), LC_PC, true, false, LockKind::Mutex, [=] {
        return REAL(pthread_mutex_clocklock)(m, clock, until);
    });
}
#endif

LC_API int LC_FN(pthread_mutex_unlock)(pthread_mutex_t *m) noexcept {
    if (!destroyed(m, "unlocks a mutex that was destroyed"))
        before_unlock(m);
    return unlocked(uintptr_t(m), REAL(pthread_mutex_unlock)(m));
}

LC_API int LC_FN(pthread_mutex_init)(pthread_mutex_t *m,
                              const pthread_mutexattr_t *attr) noexcept {
    gone(uintptr_t(m));
    return REAL(pthread_mutex_init)(m, attr);
}

LC_API int LC_FN(pthread_mutex_destroy)(pthread_mutex_t *m) noexcept {
    before_destroy(
        uintptr_t(m),
        [m] {
#if defined(__APPLE__)
            (void)m;
            return false;
#else
            const int owner = m->__data.__owner;
            return owner && !owned_by_me(owner);
#endif
        },
        "destroys a mutex this thread holds",
        "destroys a mutex that another thread holds");
    gone(uintptr_t(m));
    return REAL(pthread_mutex_destroy)(m);
}

// ---- read-write locks (std::shared_mutex) -----------------------------------

LC_API int LC_FN(pthread_rwlock_rdlock)(pthread_rwlock_t *l) noexcept {
    return blocking(uintptr_t(l), LC_PC, LockKind::Read,
                    [l] { return REAL(pthread_rwlock_rdlock)(l); });
}

LC_API int LC_FN(pthread_rwlock_wrlock)(pthread_rwlock_t *l) noexcept {
    return blocking(uintptr_t(l), LC_PC, LockKind::Write,
                    [l] { return REAL(pthread_rwlock_wrlock)(l); });
}

LC_API int LC_FN(pthread_rwlock_tryrdlock)(pthread_rwlock_t *l) noexcept {
    return bounded(uintptr_t(l), LC_PC, false, true, LockKind::Read,
                   [l] { return REAL(pthread_rwlock_tryrdlock)(l); });
}

LC_API int LC_FN(pthread_rwlock_trywrlock)(pthread_rwlock_t *l) noexcept {
    return bounded(uintptr_t(l), LC_PC, false, false, LockKind::Write,
                   [l] { return REAL(pthread_rwlock_trywrlock)(l); });
}

LC_API int LC_FN(pthread_rwlock_timedrdlock)(pthread_rwlock_t *l,
                                      const struct timespec *until) noexcept {
    return bounded(uintptr_t(l), LC_PC, true, true, LockKind::Read,
                   [=] { return REAL(pthread_rwlock_timedrdlock)(l, until); });
}

LC_API int LC_FN(pthread_rwlock_timedwrlock)(pthread_rwlock_t *l,
                                      const struct timespec *until) noexcept {
    return bounded(uintptr_t(l), LC_PC, true, false, LockKind::Write,
                   [=] { return REAL(pthread_rwlock_timedwrlock)(l, until); });
}

#if !defined(__APPLE__)
LC_API int LC_FN(pthread_rwlock_clockrdlock)(pthread_rwlock_t *l, clockid_t clock,
                                      const struct timespec *until) noexcept {
    return bounded(uintptr_t(l), LC_PC, true, true, LockKind::Read, [=] {
        return REAL(pthread_rwlock_clockrdlock)(l, clock, until);
    });
}

LC_API int LC_FN(pthread_rwlock_clockwrlock)(pthread_rwlock_t *l, clockid_t clock,
                                      const struct timespec *until) noexcept {
    return bounded(uintptr_t(l), LC_PC, true, false, LockKind::Write, [=] {
        return REAL(pthread_rwlock_clockwrlock)(l, clock, until);
    });
}
#endif

LC_API int LC_FN(pthread_rwlock_unlock)(pthread_rwlock_t *l) noexcept {
    return unlocked(uintptr_t(l), REAL(pthread_rwlock_unlock)(l));
}

LC_API int LC_FN(pthread_rwlock_init)(pthread_rwlock_t *l,
                               const pthread_rwlockattr_t *attr) noexcept {
    gone(uintptr_t(l));
    return REAL(pthread_rwlock_init)(l, attr);
}

LC_API int LC_FN(pthread_rwlock_destroy)(pthread_rwlock_t *l) noexcept {
    // Held by someone if a write lock cannot be had (a probe, untracked).
    before_destroy(
        uintptr_t(l),
        [l] {
            if (REAL(pthread_rwlock_trywrlock)(l) != 0)
                return true;
            REAL(pthread_rwlock_unlock)(l);
            return false;
        },
        "destroys a read-write lock this thread holds",
        "destroys a read-write lock that another thread holds");
    gone(uintptr_t(l));
    return REAL(pthread_rwlock_destroy)(l);
}

// ---- spin locks (glibc; Darwin has none) ------------------------------------

#if !defined(__APPLE__)
LC_API int LC_FN(pthread_spin_lock)(pthread_spinlock_t *l) noexcept {
    return blocking(uintptr_t(l), LC_PC, LockKind::Spin,
                    [l] { return REAL(pthread_spin_lock)(l); });
}

LC_API int LC_FN(pthread_spin_trylock)(pthread_spinlock_t *l) noexcept {
    return bounded(uintptr_t(l), LC_PC, false, false, LockKind::Spin,
                   [l] { return REAL(pthread_spin_trylock)(l); });
}

LC_API int LC_FN(pthread_spin_unlock)(pthread_spinlock_t *l) noexcept {
    return unlocked(uintptr_t(l), REAL(pthread_spin_unlock)(l));
}

LC_API int LC_FN(pthread_spin_init)(pthread_spinlock_t *l, int pshared) noexcept {
    gone(uintptr_t(l));
    return REAL(pthread_spin_init)(l, pshared);
}

LC_API int LC_FN(pthread_spin_destroy)(pthread_spinlock_t *l) noexcept {
    before_destroy(
        uintptr_t(l),
        [l] {
            if (REAL(pthread_spin_trylock)(l) != 0)
                return true;
            REAL(pthread_spin_unlock)(l);
            return false;
        },
        "destroys a spin lock this thread holds",
        "destroys a spin lock that another thread holds");
    gone(uintptr_t(l));
    return REAL(pthread_spin_destroy)(l);
}
#endif

// ---- condition variables
// ------------------------------------------------------ (The mutex stays in
// the held list while waiting: glibc unlocks and relocks it internally, and the
// thread takes nothing else meanwhile.)

constexpr const char *kWaitDestroyed = "waits with a mutex that was destroyed";

LC_API int LC_FN(pthread_cond_wait)(pthread_cond_t *c, pthread_mutex_t *m) {
    if (!destroyed(m, kWaitDestroyed))
        before_wait(uintptr_t(m));
    return REAL(pthread_cond_wait)(c, m);
}

LC_API int LC_FN(pthread_cond_timedwait)(pthread_cond_t *c, pthread_mutex_t *m,
                                  const struct timespec *until) {
    if (!destroyed(m, kWaitDestroyed))
        before_wait(uintptr_t(m));
    return REAL(pthread_cond_timedwait)(c, m, until);
}

#if !defined(__APPLE__)
LC_API int LC_FN(pthread_cond_clockwait)(pthread_cond_t *c, pthread_mutex_t *m,
                                  clockid_t clock,
                                  const struct timespec *until) {
    if (!destroyed(m, kWaitDestroyed))
        before_wait(uintptr_t(m));
    return REAL(pthread_cond_clockwait)(c, m, clock, until);
}
#endif
