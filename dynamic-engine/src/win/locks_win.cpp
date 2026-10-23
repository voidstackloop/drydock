// Locks on Windows (locks.cpp is the Linux side): the order in which a program
// takes critical sections, slim reader/writer locks, mutex handles and the
// pthread locks that MinGW's std::mutex is made of; a thread locking what it
// holds, ending with a lock held, waiting with a lock it does not hold,
// unlocking what another thread holds, using a lock after it was destroyed.
//
// The order graph and the reports are the Linux ones. Windows does not tell us
// who owns a pthread mutex or an SRW lock, so the runtime keeps its own record:
// each thread's held locks (for the order) and one table of who holds what.
#include "locks.h"
#include "init.h"
#include "protocol.h"
#include "report.h"
#include "stacks.h"
#include "win_hooks.h"

#include <pthread.h>
#include <time.h>

#include <cstring>

namespace lc::locks {
namespace {

constexpr uint32_t kMaxHeld = 16;            // per thread; deeper ones untracked
constexpr size_t kEdgeCap = size_t(1) << 16; // power of two
constexpr size_t kNodeCap = size_t(1) << 14;
constexpr int kMaxCycle = 5; // longest cycle searched for, in locks
constexpr uintptr_t kDead = 1;
constexpr size_t kOwnerCap = size_t(1) << 14;
constexpr size_t kGoneCap = size_t(1) << 12;

// What a lock is decides whether taking it again waits for the thread itself.
enum class LockKind : uint8_t {
    Mutex,      // pthread, normal: a second lock waits for itself
    Recursive,  // pthread recursive, critical section, mutex handle: may be relocked
    ErrorCheck, // pthread: the second lock answers EDEADLK
    Spin,
    Write,      // pthread rwlock
    Read,
    Srw,        // slim reader/writer lock
};

struct Held {
    uintptr_t m;
    uintptr_t pc; // where it was locked: the hook's return address
    bool shared;  // held for reading
    LockKind kind;
};

struct HeldList {
    Held h[kMaxHeld];
    uint32_t n; // may exceed kMaxHeld
};

HeldList &held() {
    auto *&p = reinterpret_cast<HeldList *&>(ts().locks);
    if (LC_UNLIKELY(!p))
        p = static_cast<HeldList *>(map_pages(sizeof(HeldList)));
    return *p;
}

// "a was held while b was locked". a == 0: empty slot, kDead: removed.
struct Edge {
    uintptr_t a, b;
    uint32_t stack; // where b was locked
    uint32_t held;  // where a was locked (one frame)
    bool reported;
};

SpinLock g_lock; // the order graph, and the tables below
Edge *g_edges;
size_t g_used;
uintptr_t *g_nodes; // sorted addresses of the locks in some edge
size_t g_nnodes;

// Who holds an exclusive lock now (kept after the thread ends: nobody can
// unlock it then).
struct Owner {
    uintptr_t m; // 0 = empty
    uint32_t tid;
    uint32_t depth;
};
Owner *g_owners;
// Locks that were destroyed and not made again.
uintptr_t *g_gone;

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
        g_nodes = static_cast<uintptr_t *>(map_pages(kNodeCap * sizeof(uintptr_t)));
        g_owners = static_cast<Owner *>(map_pages(kOwnerCap * sizeof(Owner)));
        g_gone = static_cast<uintptr_t *>(map_pages(kGoneCap * sizeof(uintptr_t)));
    }
    return g_edges && g_nodes && g_owners && g_gone;
}

Edge *slot(Edge *t, uintptr_t a, uintptr_t b) {
    for (size_t i = mix(a * 31 + b) & (kEdgeCap - 1);; i = (i + 1) & (kEdgeCap - 1))
        if (!t[i].a || (t[i].a == a && t[i].b == b))
            return &t[i];
}

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

// Locks in [lo, hi) are gone (freed, destroyed or made again): a new lock at the
// same address must not inherit their order or their owner.
void forget_locked(uintptr_t lo, uintptr_t hi) {
    if (!tables())
        return;
    for (size_t i = 0; i < kGoneCap; ++i)
        if (g_gone[i] >= lo && g_gone[i] < hi)
            g_gone[i] = kDead;
    for (size_t i = 0; i < kOwnerCap; ++i) // an emptied slot would break the probe chain
        if (g_owners[i].m >= lo && g_owners[i].m < hi) {
            g_owners[i].m = kDead;
            g_owners[i].depth = 0;
        }
    const size_t first = lower_bound(lo);
    size_t last = first;
    while (last < g_nnodes && g_nodes[last] < hi)
        ++last;
    if (first == last)
        return;
    memmove(&g_nodes[first], &g_nodes[last], (g_nnodes - last) * sizeof(uintptr_t));
    g_nnodes -= last - first;
    for (size_t i = 0; i < kEdgeCap; ++i) {
        Edge &e = g_edges[i];
        if (e.a > kDead && ((e.a >= lo && e.a < hi) || (e.b >= lo && e.b < hi)))
            e.a = e.b = kDead;
    }
}

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

void report_inversion(uintptr_t a, uintptr_t b, int chain, uint32_t stack, uint32_t held, uint32_t other) {
    char m[384];
    Buf msg(m, sizeof m);
    msg.s("lock ").p(b).s(" is taken while holding lock ").p(a);
    if (chain == 1)
        msg.s(", but elsewhere they are taken in the opposite order");
    else
        msg.s(", but other lock orders lead from it back to ").p(a).s(" (a cycle of ").u(uint64_t(chain + 1)).s(" locks)");
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

// ---- who holds what -------------------------------------------------------------------------

Owner *owner_slot(uintptr_t m) {
    for (size_t i = mix(m) & (kOwnerCap - 1);; i = (i + 1) & (kOwnerCap - 1))
        if (g_owners[i].m == m || !g_owners[i].m)
            return &g_owners[i];
}

void owner_take(uintptr_t m, bool recursive) {
    LockGuard g(g_lock);
    if (!tables())
        return;
    Owner *o = owner_slot(m);
    if (o->m == m && o->tid == current_tid() && recursive && o->depth) {
        ++o->depth;
        return;
    }
    // (a kDead slot is reused only when the probe reaches an empty one: simple, and
    // the table is large)
    o->m = m;
    o->tid = current_tid();
    o->depth = 1;
}

void owner_drop(uintptr_t m) {
    LockGuard g(g_lock);
    if (!tables())
        return;
    Owner *o = owner_slot(m);
    if (o->m != m)
        return;
    if (o->depth > 1)
        --o->depth;
    else {
        o->m = kDead;
        o->depth = 0;
    }
}

// The thread that holds m (0 if nobody is known to, or it is this one).
uint32_t other_owner(uintptr_t m) {
    LockGuard g(g_lock);
    if (!tables())
        return 0;
    Owner *o = owner_slot(m);
    return o->m == m && o->depth && o->tid != current_tid() ? o->tid : 0;
}

bool owned_by_me(uintptr_t m) {
    LockGuard g(g_lock);
    if (!tables())
        return true;
    Owner *o = owner_slot(m);
    return o->m == m && o->depth && o->tid == current_tid();
}

bool thread_exists(uint32_t tid) {
    HANDLE h = OpenThread(SYNCHRONIZE, FALSE, tid);
    if (!h)
        return GetLastError() != ERROR_INVALID_PARAMETER; // access denied: it exists
    const bool alive = WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
    CloseHandle(h);
    return alive;
}

bool is_gone(uintptr_t m) {
    LockGuard g(g_lock);
    if (!tables())
        return false;
    for (size_t i = mix(m) & (kGoneCap - 1);; i = (i + 1) & (kGoneCap - 1)) {
        if (g_gone[i] == m)
            return true;
        if (!g_gone[i])
            return false;
    }
}

void mark_gone(uintptr_t m) {
    LockGuard g(g_lock);
    if (!tables())
        return;
    for (size_t i = mix(m) & (kGoneCap - 1);; i = (i + 1) & (kGoneCap - 1)) {
        if (g_gone[i] == m)
            return;
        if (!g_gone[i] || g_gone[i] == kDead) {
            g_gone[i] = m;
            return;
        }
    }
}

// ---- what a lock does when taken again ---------------------------------------------------

bool waits_for_itself(LockKind k, bool want_shared, const Held &h) {
    switch (k) {
    case LockKind::Mutex:
    case LockKind::Spin:
        return true;
    case LockKind::Write: // its own read lock never goes away
        return h.shared;
    case LockKind::Srw: // a writer waits for every holder, a reader for a writer
        return !(want_shared && h.shared);
    default: // recursive and error-checking locks, readers
        return false;
    }
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

bool holds(uintptr_t m) {
    HeldList &l = held();
    const uint32_t n = l.n < kMaxHeld ? l.n : kMaxHeld;
    for (uint32_t i = 0; i < n; ++i)
        if (l.h[i].m == m)
            return true;
    return false;
}

// Before blocking on m: does this thread hold it already, and would that wait
// for itself? And does it wait for a thread that no longer exists?
void before_lock(uintptr_t m, LockKind k, bool want_shared) {
    HeldList &l = held();
    const uint32_t n = l.n < kMaxHeld ? l.n : kMaxHeld;
    for (uint32_t i = 0; i < n; ++i) {
        if (l.h[i].m != m || !waits_for_itself(k, want_shared, l.h[i]))
            continue;
        report::Finding f;
        f.type = lcproto::kDoubleLock;
        f.category = lcproto::kCatLock;
        f.addr = m;
        f.tid = current_tid();
        f.msg = k == LockKind::Write ? "this thread write-locks a read-write lock it holds for "
                                       "reading: it waits for itself forever"
                : k == LockKind::Spin ? "this thread locks a spin lock it already holds: it "
                                        "spins forever"
                : k == LockKind::Srw  ? "this thread acquires a slim reader/writer lock it "
                                        "already holds: it waits for itself forever"
                                      : "this thread locks a mutex it already holds: it waits "
                                        "for itself forever";
        f.access_stack = stacks::capture();
        f.alloc_stack = stacks::intern(&l.h[i].pc, 1);
        f.fatal = true;
        f.untraced_too = true;
        report::emit(f);
        stop_program("leakcheck: stopped the program, which deadlocked "
                     "taking a lock it already holds\n");
    }
    if (const uint32_t owner = other_owner(m); owner && !thread_exists(owner)) {
        report::Finding f;
        f.type = lcproto::kOrphanedLock;
        f.category = lcproto::kCatLock;
        f.addr = m;
        f.tid = current_tid();
        f.msg = "locks a lock whose owner thread has ended: nothing unlocks it and this "
                "thread waits forever";
        f.access_stack = stacks::capture();
        f.fatal = true;
        f.untraced_too = true;
        report::emit(f);
        stop_program("leakcheck: stopped the program, which would wait forever "
                     "for a lock whose owner is gone\n");
    }
}

// Only an exclusive acquisition makes an order: it waits for any holder, a
// reader included, while a read lock waits for writers only.
void acquired(uintptr_t m, uintptr_t pc, bool order, bool shared, LockKind k) {
    HeldList &l = held();
    const bool again = holds(m) && (k == LockKind::Recursive || k == LockKind::ErrorCheck);
    const uint32_t n = l.n < kMaxHeld ? l.n : kMaxHeld;
    if (order && !shared && !again)
        for (uint32_t i = 0; i < n; ++i)
            if (l.h[i].m != m)
                ordered(l.h[i], m);
    if (!shared)
        owner_take(m, k == LockKind::Recursive);
    if (l.n < kMaxHeld)
        l.h[l.n] = Held{m, pc, shared, k};
    ++l.n;
}

void released(uintptr_t m, bool shared) {
    HeldList &l = held();
    if (!shared)
        owner_drop(m);
    const uint32_t n = l.n < kMaxHeld ? l.n : kMaxHeld;
    for (uint32_t i = n; i-- > 0;) {
        if (l.h[i].m != m)
            continue;
        memmove(&l.h[i], &l.h[i + 1], (n - i - 1) * sizeof(Held));
        --l.n;
        return;
    }
    if (l.n > kMaxHeld) // one of the untracked ones
        --l.n;
}

void forget(uintptr_t lo, uintptr_t hi) {
    LockGuard g(g_lock);
    forget_locked(lo, hi);
}

bool drop_held(uintptr_t lo, uintptr_t hi) {
    HeldList &l = held();
    bool any = false;
    uint32_t n = l.n < kMaxHeld ? l.n : kMaxHeld;
    for (uint32_t i = n; i-- > 0;)
        if (l.h[i].m >= lo && l.h[i].m < hi) {
            memmove(&l.h[i], &l.h[i + 1], (--n - i) * sizeof(Held));
            --l.n;
            any = true;
        }
    return any;
}

bool g_on;

bool tracking() { return g_on && !tl_in_hook; }

// ---- the events the hooks report -------------------------------------------------------------

void use_of_destroyed(uintptr_t m, const char *msg) {
    if (is_gone(m))
        report_misuse(lcproto::kUseAfterDestroy, m, msg);
}

// A wait unlocks m and takes it back: the caller must hold it.
void before_wait(uintptr_t m) {
    HeldList &l = held();
    if (l.n > kMaxHeld || holds(m))
        return;
    report_misuse(lcproto::kUnlockedWait, m,
                  "a condition wait with a lock this thread does not hold: a "
                  "signal sent before the wait starts is lost");
}

// Unlocking a lock the thread does not hold is undefined for critical sections and
// normal mutexes: it works until two threads end up inside together.
void before_unlock(uintptr_t m) {
    HeldList &l = held();
    if (l.n > kMaxHeld || holds(m))
        return;
    report_misuse(lcproto::kForeignUnlock, m,
                  other_owner(m) ? "unlocks a lock that another thread holds"
                                 : "unlocks a lock that is not locked");
}

void before_destroy(uintptr_t m, const char *mine, const char *other) {
    if (drop_held(m, m + 1)) {
        owner_drop(m);
        report_misuse(lcproto::kDestroyLocked, m, mine);
    } else if (const uint32_t o = other_owner(m); o && thread_exists(o)) {
        report_misuse(lcproto::kDestroyLocked, m, other);
    }
}

void gone(uintptr_t m) { // initialised or destroyed
    forget(m, m + 1);
    drop_held(m, m + 1);
}

} // namespace

void init() {}

// Freeing a lock this thread holds is left alone: the last reference to an
// object often frees it with its lock held.
void block_freed(uintptr_t lo, size_t size) {
    if (!g_edges)
        return;
    forget(lo, lo + size);
    drop_held(lo, lo + size);
}

size_t held_snapshot(uintptr_t *out, size_t max) {
    HeldList &l = held();
    size_t n = 0;
    for (uint32_t i = 0; i < l.n && i < kMaxHeld && n < max; ++i)
        out[n++] = l.h[i].m;
    return n;
}

void thread_exiting(uint32_t create_stack) {
    auto *l = static_cast<HeldList *>(ts().locks);
    if (!l)
        return;
    const uint32_t n = l->n < kMaxHeld ? l->n : kMaxHeld;
    for (uint32_t i = 0; i < n; ++i) {
        // a foreign unlock released it already: the record here is stale
        if (l->h[i].shared || !owned_by_me(l->h[i].m))
            continue;
        report::Finding f;
        f.type = lcproto::kLockLeak;
        f.category = lcproto::kCatLock;
        f.addr = l->h[i].m;
        f.tid = current_tid();
        f.msg = "the thread ends while holding this lock: any thread that "
                "takes it later waits forever";
        f.access_stack = stacks::intern(&l->h[i].pc, 1);
        f.alloc_stack = create_stack;
        f.fatal = true;
        report::emit(f);
    }
    l->n = 0;
}

void set_on() { g_on = true; }

void thread_gone() {
    auto *l = static_cast<HeldList *>(ts().locks);
    if (l) {
        ts().locks = nullptr;
        unmap_pages(l, sizeof(HeldList));
    }
}

void lock() { g_lock.lock(); }
void unlock() { g_lock.unlock(); }
void reset_lock() { g_lock.reset(); }

} // namespace lc::locks

// ---- the hooks ----------------------------------------------------------------------------------

namespace lc::win {
namespace {

using namespace lc::locks;

#define LC_PC uintptr_t(__builtin_return_address(0))

// What a pthread mutex is, from the way it was made: PTHREAD_*_MUTEX_INITIALIZER
// are the values -1, -2 and -3 until the first lock turns them into a pointer.
struct MutexType {
    uintptr_t m;
    LockKind kind;
};
constexpr size_t kTypeCap = 1 << 10;
MutexType g_types[kTypeCap];
SpinLock g_types_lock;

void remember_kind(uintptr_t m, LockKind k);

LockKind mutex_kind(pthread_mutex_t *m) {
    const intptr_t v = *reinterpret_cast<const intptr_t *>(m);
    if (v == -2 || v == -3) {
        const LockKind k = v == -2 ? LockKind::Recursive : LockKind::ErrorCheck;
        remember_kind(uintptr_t(m), k);
        return k;
    }
    LockGuard g(g_types_lock);
    for (const MutexType &t : g_types)
        if (t.m == uintptr_t(m))
            return t.kind;
    return LockKind::Mutex;
}

void remember_kind(uintptr_t m, LockKind k) {
    LockGuard g(g_types_lock);
    MutexType *free_slot = nullptr;
    for (MutexType &t : g_types) {
        if (t.m == m) {
            t.kind = k;
            return;
        }
        if (!t.m && !free_slot)
            free_slot = &t;
    }
    if (free_slot)
        *free_slot = MutexType{m, k};
}

void forget_kind(uintptr_t m) {
    LockGuard g(g_types_lock);
    for (MutexType &t : g_types)
        if (t.m == m)
            t.m = 0;
}

constexpr const char *kLockDestroyed = "locks a lock that was destroyed: a caller that does "
                                       "not check the result runs unprotected";

// A lock call that may wait: a self-deadlock is reported before it, the order after it.
template <class F> auto blocking(uintptr_t m, uintptr_t pc, LockKind k, bool shared, F lock) {
    (void)pc;
    if (!tracking())
        return lock();
    {
        HookGuard hg;
        ErrnoSaver es;
        use_of_destroyed(m, kLockDestroyed);
        before_lock(m, k, shared);
    }
    auto rc = lock();
    return rc;
}

// ... and the part that follows a successful acquisition.
void got(uintptr_t m, uintptr_t pc, bool order, bool shared, LockKind k) {
    HookGuard hg;
    ErrnoSaver es;
    acquired(m, pc, order, shared, k);
}

void let_go(uintptr_t m, bool shared) {
    HookGuard hg;
    ErrnoSaver es;
    released(m, shared);
}

// ---- critical sections -------------------------------------------------------------------------

decltype(&EnterCriticalSection) real_EnterCriticalSection;
VOID WINAPI hk_EnterCriticalSection(LPCRITICAL_SECTION cs) {
    const uintptr_t pc = LC_PC;
    if (!tracking()) {
        real_EnterCriticalSection(cs);
        return;
    }
    blocking(uintptr_t(cs), pc, LockKind::Recursive, false, [&] {
        real_EnterCriticalSection(cs);
        return 0;
    });
    got(uintptr_t(cs), pc, true, false, LockKind::Recursive);
}

decltype(&TryEnterCriticalSection) real_TryEnterCriticalSection;
BOOL WINAPI hk_TryEnterCriticalSection(LPCRITICAL_SECTION cs) {
    const uintptr_t pc = LC_PC;
    BOOL ok = real_TryEnterCriticalSection(cs);
    if (ok && tracking())
        got(uintptr_t(cs), pc, false, false, LockKind::Recursive);
    return ok;
}

decltype(&LeaveCriticalSection) real_LeaveCriticalSection;
VOID WINAPI hk_LeaveCriticalSection(LPCRITICAL_SECTION cs) {
    if (tracking()) {
        HookGuard hg;
        ErrnoSaver es;
        use_of_destroyed(uintptr_t(cs), "unlocks a critical section that was destroyed");
        before_unlock(uintptr_t(cs));
    }
    real_LeaveCriticalSection(cs);
    if (tracking())
        let_go(uintptr_t(cs), false);
}

decltype(&InitializeCriticalSection) real_InitializeCriticalSection;
VOID WINAPI hk_InitializeCriticalSection(LPCRITICAL_SECTION cs) {
    if (tracking()) {
        HookGuard hg;
        gone(uintptr_t(cs));
    }
    real_InitializeCriticalSection(cs);
}
decltype(&InitializeCriticalSectionAndSpinCount) real_InitializeCriticalSectionAndSpinCount;
BOOL WINAPI hk_InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION cs, DWORD n) {
    if (tracking()) {
        HookGuard hg;
        gone(uintptr_t(cs));
    }
    return real_InitializeCriticalSectionAndSpinCount(cs, n);
}
decltype(&InitializeCriticalSectionEx) real_InitializeCriticalSectionEx;
BOOL WINAPI hk_InitializeCriticalSectionEx(LPCRITICAL_SECTION cs, DWORD n, DWORD f) {
    if (tracking()) {
        HookGuard hg;
        gone(uintptr_t(cs));
    }
    return real_InitializeCriticalSectionEx(cs, n, f);
}
decltype(&DeleteCriticalSection) real_DeleteCriticalSection;
VOID WINAPI hk_DeleteCriticalSection(LPCRITICAL_SECTION cs) {
    if (tracking()) {
        HookGuard hg;
        ErrnoSaver es;
        before_destroy(uintptr_t(cs), "deletes a critical section this thread holds",
                       "deletes a critical section that another thread holds");
        gone(uintptr_t(cs));
        mark_gone(uintptr_t(cs));
    }
    real_DeleteCriticalSection(cs);
}

// ---- slim reader/writer locks -------------------------------------------------------------

decltype(&AcquireSRWLockExclusive) real_AcquireSRWLockExclusive;
VOID WINAPI hk_AcquireSRWLockExclusive(PSRWLOCK l) {
    const uintptr_t pc = LC_PC;
    if (!tracking()) {
        real_AcquireSRWLockExclusive(l);
        return;
    }
    blocking(uintptr_t(l), pc, LockKind::Srw, false, [&] {
        real_AcquireSRWLockExclusive(l);
        return 0;
    });
    got(uintptr_t(l), pc, true, false, LockKind::Srw);
}
decltype(&AcquireSRWLockShared) real_AcquireSRWLockShared;
VOID WINAPI hk_AcquireSRWLockShared(PSRWLOCK l) {
    const uintptr_t pc = LC_PC;
    if (!tracking()) {
        real_AcquireSRWLockShared(l);
        return;
    }
    blocking(uintptr_t(l), pc, LockKind::Srw, true, [&] {
        real_AcquireSRWLockShared(l);
        return 0;
    });
    got(uintptr_t(l), pc, true, true, LockKind::Srw);
}
decltype(&TryAcquireSRWLockExclusive) real_TryAcquireSRWLockExclusive;
BOOLEAN WINAPI hk_TryAcquireSRWLockExclusive(PSRWLOCK l) {
    const uintptr_t pc = LC_PC;
    BOOLEAN ok = real_TryAcquireSRWLockExclusive(l);
    if (ok && tracking())
        got(uintptr_t(l), pc, false, false, LockKind::Srw);
    return ok;
}
decltype(&TryAcquireSRWLockShared) real_TryAcquireSRWLockShared;
BOOLEAN WINAPI hk_TryAcquireSRWLockShared(PSRWLOCK l) {
    const uintptr_t pc = LC_PC;
    BOOLEAN ok = real_TryAcquireSRWLockShared(l);
    if (ok && tracking())
        got(uintptr_t(l), pc, false, true, LockKind::Srw);
    return ok;
}
decltype(&ReleaseSRWLockExclusive) real_ReleaseSRWLockExclusive;
VOID WINAPI hk_ReleaseSRWLockExclusive(PSRWLOCK l) {
    real_ReleaseSRWLockExclusive(l);
    if (tracking())
        let_go(uintptr_t(l), false);
}
decltype(&ReleaseSRWLockShared) real_ReleaseSRWLockShared;
VOID WINAPI hk_ReleaseSRWLockShared(PSRWLOCK l) {
    real_ReleaseSRWLockShared(l);
    if (tracking())
        let_go(uintptr_t(l), true);
}

// ---- condition variables of Windows -----------------------------------------------------

decltype(&SleepConditionVariableCS) real_SleepConditionVariableCS;
BOOL WINAPI hk_SleepConditionVariableCS(PCONDITION_VARIABLE cv, PCRITICAL_SECTION cs, DWORD ms) {
    if (tracking()) {
        HookGuard hg;
        ErrnoSaver es;
        before_wait(uintptr_t(cs));
    }
    return real_SleepConditionVariableCS(cv, cs, ms);
}
decltype(&SleepConditionVariableSRW) real_SleepConditionVariableSRW;
BOOL WINAPI hk_SleepConditionVariableSRW(PCONDITION_VARIABLE cv, PSRWLOCK l, DWORD ms, ULONG fl) {
    if (tracking()) {
        HookGuard hg;
        ErrnoSaver es;
        before_wait(uintptr_t(l));
    }
    return real_SleepConditionVariableSRW(cv, l, ms, fl);
}

// ---- pthread locks (winpthreads: std::mutex, std::shared_mutex, std::condition_variable) ----

decltype(&pthread_mutex_lock) real_pthread_mutex_lock;
int hk_pthread_mutex_lock(pthread_mutex_t *m) {
    const uintptr_t pc = LC_PC;
    if (!tracking())
        return real_pthread_mutex_lock(m);
    const LockKind k = mutex_kind(m);
    int rc = blocking(uintptr_t(m), pc, k, false, [&] { return real_pthread_mutex_lock(m); });
    if (rc == 0)
        got(uintptr_t(m), pc, true, false, k);
    return rc;
}
decltype(&pthread_mutex_trylock) real_pthread_mutex_trylock;
int hk_pthread_mutex_trylock(pthread_mutex_t *m) {
    const uintptr_t pc = LC_PC;
    const LockKind k = tracking() ? mutex_kind(m) : LockKind::Mutex;
    int rc = real_pthread_mutex_trylock(m);
    if (rc == 0 && tracking())
        got(uintptr_t(m), pc, false, false, k);
    return rc;
}
decltype(&pthread_mutex_timedlock) real_pthread_mutex_timedlock;
int hk_pthread_mutex_timedlock(pthread_mutex_t *m, const struct timespec *t) {
    const uintptr_t pc = LC_PC;
    const LockKind k = tracking() ? mutex_kind(m) : LockKind::Mutex;
    int rc = real_pthread_mutex_timedlock(m, t);
    if (rc == 0 && tracking())
        got(uintptr_t(m), pc, true, false, k);
    return rc;
}
decltype(&pthread_mutex_unlock) real_pthread_mutex_unlock;
int hk_pthread_mutex_unlock(pthread_mutex_t *m) {
    if (!tracking())
        return real_pthread_mutex_unlock(m);
    const LockKind k = mutex_kind(m);
    if (k == LockKind::Mutex) {
        HookGuard hg;
        ErrnoSaver es;
        use_of_destroyed(uintptr_t(m), "unlocks a mutex that was destroyed");
        before_unlock(uintptr_t(m));
    }
    int rc = real_pthread_mutex_unlock(m);
    if (rc == 0)
        let_go(uintptr_t(m), false);
    return rc;
}
decltype(&pthread_mutex_init) real_pthread_mutex_init;
decltype(&pthread_mutexattr_gettype) real_pthread_mutexattr_gettype;
int hk_pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a) {
    if (tracking()) {
        HookGuard hg;
        ErrnoSaver es;
        gone(uintptr_t(m));
        forget_kind(uintptr_t(m));
        if (a) {
            if (!real_pthread_mutexattr_gettype)
                real_pthread_mutexattr_gettype = proc_address<decltype(real_pthread_mutexattr_gettype)>(
                    GetModuleHandleA("libwinpthread-1.dll"), "pthread_mutexattr_gettype");
            int type = PTHREAD_MUTEX_NORMAL;
            if (real_pthread_mutexattr_gettype && real_pthread_mutexattr_gettype(a, &type) == 0)
                remember_kind(uintptr_t(m), type == PTHREAD_MUTEX_RECURSIVE   ? LockKind::Recursive
                                            : type == PTHREAD_MUTEX_ERRORCHECK ? LockKind::ErrorCheck
                                                                               : LockKind::Mutex);
        }
    }
    return real_pthread_mutex_init(m, a);
}
decltype(&pthread_mutex_destroy) real_pthread_mutex_destroy;
int hk_pthread_mutex_destroy(pthread_mutex_t *m) {
    if (tracking()) {
        HookGuard hg;
        ErrnoSaver es;
        before_destroy(uintptr_t(m), "destroys a mutex this thread holds",
                       "destroys a mutex that another thread holds");
        gone(uintptr_t(m));
        forget_kind(uintptr_t(m));
        mark_gone(uintptr_t(m));
    }
    return real_pthread_mutex_destroy(m);
}

#define RW_BLOCKING(NAME, KIND, SHARED)                                     \
    decltype(&NAME) real_##NAME;                                            \
    int hk_##NAME(pthread_rwlock_t *l) {                                    \
        const uintptr_t pc = LC_PC;                                         \
        if (!tracking())                                                    \
            return real_##NAME(l);                                          \
        int rc = blocking(uintptr_t(l), pc, KIND, SHARED, [&] { return real_##NAME(l); }); \
        if (rc == 0)                                                        \
            got(uintptr_t(l), pc, true, SHARED, KIND);                      \
        return rc;                                                          \
    }
#define RW_BOUNDED(NAME, KIND, SHARED, ORDER, PARAMS, ARGS)                 \
    decltype(&NAME) real_##NAME;                                            \
    int hk_##NAME PARAMS {                                                  \
        const uintptr_t pc = LC_PC;                                         \
        int rc = real_##NAME ARGS;                                          \
        if (rc == 0 && tracking())                                          \
            got(uintptr_t(l), pc, ORDER, SHARED, KIND);                     \
        return rc;                                                          \
    }
RW_BLOCKING(pthread_rwlock_rdlock, LockKind::Read, true)
RW_BLOCKING(pthread_rwlock_wrlock, LockKind::Write, false)
RW_BOUNDED(pthread_rwlock_tryrdlock, LockKind::Read, true, false, (pthread_rwlock_t * l), (l))
RW_BOUNDED(pthread_rwlock_trywrlock, LockKind::Write, false, false, (pthread_rwlock_t * l), (l))
RW_BOUNDED(pthread_rwlock_timedrdlock, LockKind::Read, true, true,
           (pthread_rwlock_t * l, const struct timespec *t), (l, t))
RW_BOUNDED(pthread_rwlock_timedwrlock, LockKind::Write, false, true,
           (pthread_rwlock_t * l, const struct timespec *t), (l, t))

decltype(&pthread_rwlock_unlock) real_pthread_rwlock_unlock;
int hk_pthread_rwlock_unlock(pthread_rwlock_t *l) {
    int rc = real_pthread_rwlock_unlock(l);
    if (rc == 0 && tracking()) {
        // held for reading or writing: the held list knows
        bool shared = false;
        {
            HeldList &hl = held();
            for (uint32_t i = 0; i < hl.n && i < kMaxHeld; ++i)
                if (hl.h[i].m == uintptr_t(l))
                    shared = hl.h[i].shared;
        }
        let_go(uintptr_t(l), shared);
    }
    return rc;
}
decltype(&pthread_rwlock_init) real_pthread_rwlock_init;
int hk_pthread_rwlock_init(pthread_rwlock_t *l, const pthread_rwlockattr_t *a) {
    if (tracking()) {
        HookGuard hg;
        gone(uintptr_t(l));
    }
    return real_pthread_rwlock_init(l, a);
}
decltype(&pthread_rwlock_destroy) real_pthread_rwlock_destroy;
int hk_pthread_rwlock_destroy(pthread_rwlock_t *l) {
    if (tracking()) {
        HookGuard hg;
        ErrnoSaver es;
        before_destroy(uintptr_t(l), "destroys a read-write lock this thread holds",
                       "destroys a read-write lock that another thread holds");
        gone(uintptr_t(l));
    }
    return real_pthread_rwlock_destroy(l);
}

decltype(&pthread_spin_lock) real_pthread_spin_lock;
int hk_pthread_spin_lock(pthread_spinlock_t *l) {
    const uintptr_t pc = LC_PC;
    if (!tracking())
        return real_pthread_spin_lock(l);
    int rc = blocking(uintptr_t(l), pc, LockKind::Spin, false, [&] { return real_pthread_spin_lock(l); });
    if (rc == 0)
        got(uintptr_t(l), pc, true, false, LockKind::Spin);
    return rc;
}
decltype(&pthread_spin_trylock) real_pthread_spin_trylock;
int hk_pthread_spin_trylock(pthread_spinlock_t *l) {
    const uintptr_t pc = LC_PC;
    int rc = real_pthread_spin_trylock(l);
    if (rc == 0 && tracking())
        got(uintptr_t(l), pc, false, false, LockKind::Spin);
    return rc;
}
decltype(&pthread_spin_unlock) real_pthread_spin_unlock;
int hk_pthread_spin_unlock(pthread_spinlock_t *l) {
    int rc = real_pthread_spin_unlock(l);
    if (rc == 0 && tracking())
        let_go(uintptr_t(l), false);
    return rc;
}
decltype(&pthread_spin_destroy) real_pthread_spin_destroy;
int hk_pthread_spin_destroy(pthread_spinlock_t *l) {
    if (tracking()) {
        HookGuard hg;
        ErrnoSaver es;
        before_destroy(uintptr_t(l), "destroys a spin lock this thread holds",
                       "destroys a spin lock that another thread holds");
        gone(uintptr_t(l));
    }
    return real_pthread_spin_destroy(l);
}

decltype(&pthread_cond_wait) real_pthread_cond_wait;
int hk_pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m) {
    if (tracking()) {
        HookGuard hg;
        ErrnoSaver es;
        before_wait(uintptr_t(m));
    }
    return real_pthread_cond_wait(c, m);
}
decltype(&pthread_cond_timedwait) real_pthread_cond_timedwait;
int hk_pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m, const struct timespec *t) {
    if (tracking()) {
        HookGuard hg;
        ErrnoSaver es;
        before_wait(uintptr_t(m));
    }
    return real_pthread_cond_timedwait(c, m, t);
}

#define HK(NAME) {#NAME, reinterpret_cast<void *>(hk_##NAME), (void **)&real_##NAME, false}
const Hook g_hooks[] = {
    HK(EnterCriticalSection), HK(TryEnterCriticalSection), HK(LeaveCriticalSection),
    HK(InitializeCriticalSection), HK(InitializeCriticalSectionAndSpinCount),
    HK(InitializeCriticalSectionEx), HK(DeleteCriticalSection),
    {"RtlEnterCriticalSection", reinterpret_cast<void *>(hk_EnterCriticalSection),
     (void **)&real_EnterCriticalSection, false},
    {"RtlTryEnterCriticalSection", reinterpret_cast<void *>(hk_TryEnterCriticalSection),
     (void **)&real_TryEnterCriticalSection, false},
    {"RtlLeaveCriticalSection", reinterpret_cast<void *>(hk_LeaveCriticalSection),
     (void **)&real_LeaveCriticalSection, false},
    {"RtlDeleteCriticalSection", reinterpret_cast<void *>(hk_DeleteCriticalSection),
     (void **)&real_DeleteCriticalSection, false},
    HK(AcquireSRWLockExclusive), HK(AcquireSRWLockShared), HK(TryAcquireSRWLockExclusive),
    HK(TryAcquireSRWLockShared), HK(ReleaseSRWLockExclusive), HK(ReleaseSRWLockShared),
    {"RtlAcquireSRWLockExclusive", reinterpret_cast<void *>(hk_AcquireSRWLockExclusive),
     (void **)&real_AcquireSRWLockExclusive, false},
    {"RtlAcquireSRWLockShared", reinterpret_cast<void *>(hk_AcquireSRWLockShared),
     (void **)&real_AcquireSRWLockShared, false},
    {"RtlReleaseSRWLockExclusive", reinterpret_cast<void *>(hk_ReleaseSRWLockExclusive),
     (void **)&real_ReleaseSRWLockExclusive, false},
    {"RtlReleaseSRWLockShared", reinterpret_cast<void *>(hk_ReleaseSRWLockShared),
     (void **)&real_ReleaseSRWLockShared, false},
    HK(SleepConditionVariableCS), HK(SleepConditionVariableSRW),
    HK(pthread_mutex_lock), HK(pthread_mutex_trylock), HK(pthread_mutex_timedlock), HK(pthread_mutex_unlock),
    HK(pthread_mutex_init), HK(pthread_mutex_destroy),
    HK(pthread_rwlock_rdlock), HK(pthread_rwlock_wrlock), HK(pthread_rwlock_tryrdlock),
    HK(pthread_rwlock_trywrlock), HK(pthread_rwlock_timedrdlock), HK(pthread_rwlock_timedwrlock),
    HK(pthread_rwlock_unlock), HK(pthread_rwlock_init), HK(pthread_rwlock_destroy),
    HK(pthread_spin_lock), HK(pthread_spin_trylock), HK(pthread_spin_unlock), HK(pthread_spin_destroy),
    HK(pthread_cond_wait), HK(pthread_cond_timedwait),
};
#undef HK

} // namespace

const Hook *lock_hooks(size_t *n) {
    *n = sizeof g_hooks / sizeof g_hooks[0];
    return g_hooks;
}

void locks_on() { locks::set_on(); }

// ---- mutex handles (CreateMutex): the lock is taken by waiting for the handle ----

namespace {
constexpr size_t kHandleCap = 1 << 10;
uintptr_t g_mutex_handles[kHandleCap];
SpinLock g_mutex_lock;

bool is_mutex_handle(HANDLE h) {
    LockGuard g(g_mutex_lock);
    for (uintptr_t v : g_mutex_handles)
        if (v == uintptr_t(h))
            return true;
    return false;
}
} // namespace

void lock_note_mutex(HANDLE h) {
    LockGuard g(g_mutex_lock);
    for (uintptr_t &v : g_mutex_handles)
        if (!v) {
            v = uintptr_t(h);
            return;
        }
}

void lock_forget_mutex(HANDLE h) {
    {
        LockGuard g(g_mutex_lock);
        bool found = false;
        for (uintptr_t &v : g_mutex_handles)
            if (v == uintptr_t(h)) {
                v = 0;
                found = true;
            }
        if (!found)
            return;
    }
    HookGuard hg;
    gone(uintptr_t(h));
}

void lock_mutex_waited(HANDLE h, DWORD result, uintptr_t pc) {
    if (!tracking() || (result != WAIT_OBJECT_0 && result != WAIT_ABANDONED) || !is_mutex_handle(h))
        return;
    got(uintptr_t(h), pc, true, false, LockKind::Recursive);
}

void lock_mutex_released(HANDLE h) {
    if (tracking() && is_mutex_handle(h))
        let_go(uintptr_t(h), false);
}

} // namespace lc::win
